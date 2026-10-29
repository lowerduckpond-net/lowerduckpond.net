"""Exact owned host stopping, DNS cleanup and three-role negative probes.

All effects require an existing approved manifest, native admission and verified
shared volume. This adapter has no qualification, Spaces or Page Rules action.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid7

from scripts import m3_11_isolation_preparation as preparation
from scripts.check_m3_7_production_edge import CloudflareClient
from scripts.m3_11_dns_witness import FORMAT as DNS_FORMAT
from scripts.m3_11_dns_witness import MAX_OBSERVATIONS
from scripts.m3_11_isolation_access import CleanupAccess
from scripts.m3_11_isolation_contract import provider_id
from scripts.m3_11_isolation_dns import IsolationWitness, Readers
from scripts.m3_11_isolation_journal import Journal
from scripts.m3_11_isolation_lease import Lease, Provider
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_isolation_runtime import Evidence
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import directory, record
from scripts.m3_11_unattended.cloudflare import ORIGIN, result
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.model import digest, stamp

INSPECT = (
    '{"id":{{json .Id}},'
    '"name":{{json .Name}},'
    '"image":{{json .Image}},'
    '"owner":{{json (index .Config.Labels "lowerduckpond.qualification.run")}},'
    '"running":{{json .State.Running}},'
    '"pid":{{json .State.Pid}},'
    '"paused":{{json .State.Paused}},'
    '"restarting":{{json .State.Restarting}},'
    '"restart_policy":{{json .HostConfig.RestartPolicy.Name}},'
    '"network_mode":{{json .HostConfig.NetworkMode}}}'
)


def readers(root: Path) -> Readers:
    def value(role: str) -> str:
        raw = fields(read_private(root / (role + ".credential")), {"value"})["value"]
        if not isinstance(raw, str) or not raw:
            raise ValueError("isolated private child credential is invalid")
        return raw

    return Readers(value("audit"), value("caddy"), value("observer"))


class Host:
    def __init__(
        self, manifest: Manifest, evidence: Evidence, *, directory_path: Path, docker: Docker
    ) -> None:
        self.manifest, self.evidence, self.docker = manifest, evidence, docker
        self.root = directory_path
        if self.root != evidence.root / "runs" / manifest.plan.run_id:
            raise ValueError("isolated host directory differs from its native volume")
        directory(self.root)
        self.phase = self.root / "phase"
        self.credentials = self.root / "credentials"
        self.credentials.mkdir(mode=0o700, exist_ok=True)
        directory(self.phase)
        directory(self.credentials)
        self.prepared = preparation.require(
            read_private(self.phase / "isolation-prepared.json"), manifest.plan
        )

    def require(self, *, consumed: bool = False) -> None:
        self.evidence.require()
        self.evidence.fence.require(self.manifest)
        if (
            preparation.require(
                read_private(self.phase / "isolation-prepared.json"), self.manifest.plan
            )
            != self.prepared
        ):
            raise ValueError("isolated original preparation changed")
        if consumed:
            self.evidence.require_consumed(self.manifest)

    def actor(self, name: str) -> dict[str, object]:
        self.require()
        original = cast(dict[str, dict[str, object]], self.prepared["actors"])[name]
        raw = json.loads(
            self.docker.command("inspect", "--format", INSPECT, str(original["id"]), timeout=30)
        )
        if (
            not isinstance(raw, dict)
            or any(raw.get(key) != original[key] for key in ("id", "name", "image", "owner"))
            or raw.get("network_mode") != ("host" if name == "controller" else "bridge")
        ):
            raise ValueError("isolated actor identity or native network path changed")
        return raw

    def guest_program(self) -> str:
        program = read_private(self.phase / "isolation-guest-program.json").get("program")
        if (
            not isinstance(program, str)
            or hashlib.sha256(program.encode()).hexdigest() != self.prepared["guest_program_sha256"]
        ):
            raise ValueError("isolated guest program differs from original preparation")
        return program

    def controller_stopped(self) -> None:
        actual = self.actor("controller")
        if (
            actual.get("running") is not False
            or actual.get("pid") != 0
            or actual.get("restart_policy") != "no"
        ):
            raise ValueError("isolated credential issuer is not positively stopped")

    def stop_actor(self, name: str) -> dict[str, object]:
        actor = self.actor(name)
        if actor.get("restart_policy") != "no":
            self.docker.command("update", "--restart=no", str(actor["id"]), timeout=30)
        if actor.get("running") is True:
            try:
                self.docker.command("stop", "--time", "20", str(actor["id"]), timeout=40)
            except ValueError, RuntimeError, OSError:
                # Inspect before KILL: a lost stop reply may already have stopped it.
                actor = self.actor(name)
                if actor.get("running") is True:
                    self.docker.command("kill", "--signal=KILL", str(actor["id"]), timeout=30)
        actor = self.actor(name)
        if (
            actor.get("running") is not False
            or actor.get("pid") != 0
            or actor.get("restart_policy") != "no"
        ):
            raise ValueError("isolated actor did not positively stop")
        return {
            key: actor[key] for key in ("id", "name", "image", "owner", "running", "restart_policy")
        }

    def stop(self, journal: Journal | None) -> dict[str, object]:
        self.require(consumed=True)
        record(self.root / "stop-requested.json", {"manifest_sha256": self.manifest.sha256})
        outcomes: dict[str, object] = {}
        # Fence the credential issuer first, then give the unchanged guest stop
        # guard a chance to quiesce Caddy before its container stops.
        try:
            outcomes["controller"] = self.stop_actor("controller")
        except Exception as error:
            outcomes["controller"] = {"error_type": type(error).__name__}
        context_path = self.phase / "isolation-context.json"
        context = None
        try:
            context = read_private(context_path) if context_path.exists() else None
        except Exception:
            outcomes["context"] = {"error_type": "InvalidContext"}
        if context is not None:
            try:
                actor = self.actor("destination")
                if actor.get("running") is True:
                    program = self.guest_program()
                    self.docker.command(
                        "exec",
                        "--interactive",
                        str(actor["id"]),
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-c",
                        program,
                        stdin=json.dumps(
                            {"action": "stop_failed", "context_sha256": digest(context)}
                        ).encode(),
                        timeout=40,
                    )
            except Exception:  # noqa: S110 - aggregate all pinned local stops below
                # Evidence I/O must not prevent the remaining owned stops.
                pass
        for name in ("destination", "source", "acme", "archive"):
            try:
                outcomes[name] = self.stop_actor(name)
            except Exception as error:
                outcomes[name] = {"error_type": type(error).__name__}
        if any(not isinstance(value, dict) or "error_type" in value for value in outcomes.values()):
            record(self.root / ("stop-pending-" + str(uuid7()) + ".json"), {"actors": outcomes})
            raise ValueError("isolated consumer stop remains pending")
        path = self.root / "quiesced.json"
        value: dict[str, object] = (
            read_private(path)
            if path.exists()
            else {
                "context_sha256": None if context is None else digest(context),
                "public_phase": "entered"
                if (self.phase / "isolation-phase-started.json").exists()
                else "not-started",
                "actors": outcomes,
                "observed_at": stamp(datetime.now(UTC)),
            }
        )
        if value["actors"] != outcomes:
            raise ValueError("isolated stopped graph differs from its first positive observation")
        record(path, value)
        if journal is not None:
            journal.put("quiesced", value)
        return value

    def _witness(self, observer: str) -> IsolationWitness:
        context = read_private(self.phase / "isolation-context.json")
        names = read_private(self.phase / "isolation-names.json")
        witness = IsolationWitness(
            self.phase,
            CloudflareClient(observer),
            digest(context),
            digest(names),
            tuple(
                (
                    domain,
                    zone,
                    f"_acme-challenge.m3-11-{self.manifest.plan.nonce.replace('-', '')}.{domain}",
                )
                for domain, zone in sorted(self.manifest.plan.zones.items())
            ),
        )
        output = self.phase / "isolation-dns-cleanup"
        output.mkdir(mode=0o700, exist_ok=True)
        target = output / str(uuid7())
        target.mkdir(mode=0o700)
        witness.output_directory = target
        return witness

    def _observed_records(self) -> dict[tuple[str, str], dict[str, str]]:
        context = read_private(self.phase / "isolation-context.json")
        names = read_private(self.phase / "isolation-names.json")
        paths = sorted((self.phase / "isolation-dns").glob("*.json"))
        if len(paths) > MAX_OBSERVATIONS:
            raise ValueError("isolated original DNS observations exceed their bound")
        known: dict[tuple[str, str], dict[str, str]] = {}
        for sequence, path in enumerate(paths):
            value = fields(
                read_private(path),
                {
                    "format",
                    "context_sha256",
                    "names_sha256",
                    "kind",
                    "sequence",
                    "started_at",
                    "completed_at",
                    "zones",
                },
            )
            if (
                path.name != f"{sequence:04d}.json"
                or value["format"] != DNS_FORMAT
                or value["sequence"] != sequence
                or value["context_sha256"] != digest(context)
                or value["names_sha256"] != digest(names)
            ):
                raise ValueError("isolated original DNS observation provenance differs")
            zones = fields(value["zones"], set(self.manifest.plan.zones))
            for domain, zone in self.manifest.plan.zones.items():
                expected_name = (
                    f"_acme-challenge.m3-11-{self.manifest.plan.nonce.replace('-', '')}.{domain}"
                )
                selected = fields(zones[domain], {"zone_id", "name", "records"})
                if (
                    selected["zone_id"] != zone
                    or selected["name"] != expected_name
                    or not isinstance(selected["records"], list)
                ):
                    raise ValueError("isolated original DNS coordinates differ")
                for raw in selected["records"]:
                    item = fields(raw, {"id", "name", "type", "content"})
                    if (
                        any(not isinstance(value, str) for value in item.values())
                        or item["name"] != expected_name
                        or item["type"] != "TXT"
                        or re.fullmatch(
                            r'(?:[A-Za-z0-9_-]{43}|"[A-Za-z0-9_-]{43}")', str(item["content"])
                        )
                        is None
                    ):
                        raise ValueError("isolated original record is not an owned ACME challenge")
                    key = (zone, provider_id(item["id"]))
                    if key in known and known[key] != item:
                        raise ValueError("isolated original DNS record identity changed")
                    known[key] = cast(dict[str, str], item)
        return known

    def cleanup_dns(self, journal: Journal, provider: Provider) -> dict[str, object]:
        self.controller_stopped()
        for name in ("destination", "source", "acme", "archive"):
            if self.actor(name)["running"] is not False:
                raise ValueError("isolated DNS cleanup requires stopped consumers")
        existing = self.phase / "isolation-dns-clean.json"
        if existing.exists():
            value = read_private(existing)
            journal.put("dns-clean", value)
            return value
        if not (self.phase / "isolation-phase-started.json").exists():
            # Positive cold observation is captured before consumers are stopped.
            observed = read_private(self.root / "cold-before-stop.json")
            if observed != self.prepared["restore"]:
                raise ValueError("isolated no-public-action observation differs")
            context_path = self.phase / "isolation-context.json"
            context_sha = digest(read_private(context_path)) if context_path.exists() else None
            value = {
                "context_sha256": context_sha,
                "basis": "public-not-started",
                "observation": observed,
                "observation_sha256": digest(observed),
                "observed_at": stamp(datetime.now(UTC)),
            }
        else:
            private = readers(self.credentials)
            issued = read_private(self.credentials / "issued.json")
            expected_ids = cast(dict[str, str], issued["ids"])
            for role, secret in (("caddy", private.caddy), ("observer", private.observer)):
                intent = next(item for item in self.manifest.intents if item.role == role)
                selected = expected_ids[role]
                metadata = provider.inspect(selected)
                if (
                    metadata is None
                    or intent.require_owned(metadata) != selected
                    or not provider.active(selected, secret)
                ):
                    raise ValueError("isolated cleanup child identity/activity differs")
            witness = self._witness(private.observer)
            known = self._observed_records()
            caddy = Api(ORIGIN, private.caddy)
            # Never infer record ownership from its name. Delete only immutable
            # id/name/type/content tuples actually observed during this attempt.
            for _, zone, name in witness.coordinates:
                for item in witness._records(zone, name):
                    if known.get((zone, item["id"])) != item:
                        raise ValueError(
                            "isolated DNS inventory contains an unowned or changed record"
                        )
                    response = caddy.request("DELETE", f"/zones/{zone}/dns_records/{item['id']}")
                    deleted = result(response.status, response.body)
                    if not isinstance(deleted, dict) or deleted.get("id") != item["id"]:
                        raise ValueError("isolated exact record deletion was not acknowledged")
            absence = witness.require_absent("teardown")
            observation = read_private(absence.path)
            value = {
                "context_sha256": witness.context_sha256,
                "basis": "observed-absent",
                "observation": observation,
                "observation_sha256": absence.sha256,
                "observed_at": stamp(datetime.now(UTC)),
            }
        record(existing, value)
        journal.put("dns-clean", value)
        return value

    def cleanup(self, access: CleanupAccess) -> dict[str, object]:
        self.require(consumed=True)
        failures: list[str] = []
        # Stop CREATE authority before observing a no-public-action state.
        # If the issuer stop is uncertain, continue owned cleanup but never
        # claim cold/not-submitted closure.
        try:
            self.stop_actor("controller")
        except Exception:
            failures.append("issuer-stop-unverified")
        if not (self.phase / "isolation-phase-started.json").exists() and not failures:
            try:
                actor = self.actor("destination")
                if actor.get("running") is True:
                    guest = self.guest_program()
                    raw = self.docker.command(
                        "exec",
                        "--interactive",
                        str(actor["id"]),
                        "/usr/bin/python3",
                        "-I",
                        "-B",
                        "-c",
                        str(guest),
                        stdin=json.dumps(
                            {
                                "action": "observe_prepared",
                                "binary": cast(
                                    dict[str, object],
                                    read_private(self.phase / "restore/inputs/target.json")[
                                        "caddy"
                                    ],
                                )["binaryPath"],
                                "binary_sha256": self.manifest.plan.caddy_binary_sha256,
                                "restore_id": cast(dict[str, object], self.prepared["restore"])[
                                    "restore_id"
                                ],
                            }
                        ).encode(),
                        timeout=60,
                    )
                    record(self.root / "cold-before-stop.json", json.loads(raw))
            except Exception:
                failures.append("cold-observation-unverified")
        try:
            stopped = self.stop(None)
        except Exception:
            failures.append("consumer-stop-unverified")
        # Local fencing must not depend on Connect or provider availability.
        try:
            client = access.client(self.manifest)
            provider = access.provider(self.manifest, client=client)
            journal = Journal(
                client,
                self.manifest,
                spool=self.root / "pending-watchdog",
                guard=lambda: self.require(consumed=True),
            )
        except Exception:
            return self._receipt([*failures, "cleanup-authority-unavailable"], None)
        if "consumer-stop-unverified" not in failures:
            try:
                journal.put("quiesced", stopped)
            except Exception:
                failures.append("consumer-stop-publication-pending")
        try:
            self.cleanup_dns(journal, provider)
        except Exception:
            failures.append("dns-cleanup-unverified")
        lease = Lease(self.credentials, self.manifest.intents, journal)
        try:
            closure = lease.cleanup(provider, require_issuer_stopped=self.controller_stopped)
        except Exception:
            failures.append("credential-closure-unverified")
            # Owned revocation remains useful even if a consumer/transport has
            # failed. Never promote this secretless fallback into a denied proof.
            try:
                lease.revoke_remote(
                    provider,
                    require_issuer_stopped=lambda: self.require(consumed=True),
                    allow_not_submitted=False,
                )
            except Exception:
                failures.append("credential-revocation-unverified")
            closure = None
        return self._receipt(failures, closure)

    def _receipt(self, failures: list[str], closure: str | None) -> dict[str, object]:
        return {
            "format": "lowerduckpond-isolated-public-ca-host-cleanup-v1",
            "manifest_sha256": self.manifest.sha256,
            "status": "verified" if not failures else "pending",
            "failures": failures,
            "closure_sha256": closure,
            "observed_at": stamp(datetime.now(UTC)),
        }
