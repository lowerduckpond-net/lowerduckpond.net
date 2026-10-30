"""Actual GET/ZIP proof parsing and native producer shape regressions, offline."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Callable
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_isolation_host as host_module
from scripts import m3_11_public_caddy as policy
from scripts.m3_11_isolation_action import FORMAT, REPOSITORY, WORKFLOW
from scripts.m3_11_isolation_contract import CONTEXT_FORMAT, RESULT_FORMAT
from scripts.m3_11_isolation_github import capture
from scripts.m3_11_isolation_host import Host
from scripts.m3_11_isolation_journal import Journal
from scripts.m3_11_isolation_lease import Lease, Provider
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_isolation_seal import functional, seal
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended.model import digest

from .test_m3_11_isolation_integration import (
    graph as graph,  # noqa: PLC0414 - pytest fixture export
)
from .test_m3_11_isolation_integration import (
    manifest as manifest,  # noqa: PLC0414 - pytest fixture export
)
from .test_m3_11_isolation_integration import (
    prepared as prepared,  # noqa: PLC0414 - pytest fixture export
)
from .test_m3_11_public_isolation import EXPIRES, NOW, START, FakeProvider, issue
from .test_m3_11_public_isolation import intents as intents  # noqa: PLC0414 - pytest fixture export
from .test_m3_11_public_isolation import plan as plan  # noqa: PLC0414 - pytest fixture export


def transport(manifest: Manifest, operation: str = "confirm") -> dict[str, Any]:
    base = "repos/" + REPOSITORY
    repo = {"id": 1, "full_name": REPOSITORY}
    run = {
        "id": 12,
        "run_attempt": 1,
        "head_sha": manifest.plan.source_revision,
        "workflow_id": 2,
        "path": ".github/workflows/" + WORKFLOW,
        "head_branch": "main",
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch" if operation == "confirm" else "schedule",
        "display_title": "M3.11 isolated public CA " + operation,
        "created_at": START,
        "run_started_at": "2026-10-29T00:00:01Z",
        "updated_at": "2026-10-29T00:01:00Z",
        "repository": repo,
        "head_repository": repo,
    }
    auth = {**manifest.independent_access, "authenticated": True, "forbidden_vaults_denied": 2}
    metadata = {
        "run_id": 12,
        "run_attempt": 1,
        "event": run["event"],
        "helper_revision": manifest.plan.source_revision,
        "independent_server_id": manifest.independent_server_id,
        "authentication_sha256": digest(auth),
        "observed_at": "2026-10-29T00:00:20Z",
    }
    receipt = {
        "format": FORMAT,
        "status": "ready",
        "manifest_sha256": manifest.sha256,
        "plan_sha256": manifest.plan.sha256,
        "operation": operation,
        "github": metadata,
        "observed_at": "2026-10-29T00:00:30Z",
        "credential_creation": False,
        "temporary_runtime_closed": True,
        "confirmation": "exact-three-role-manifest",
        "create_verified": False,
    }
    if operation == "reconcile":
        receipt.update(lease_state="closed", closure_sha256="a" * 64)
    bodies: dict[str, Any] = {
        base: repo,
        base + "/actions/workflows/" + WORKFLOW: {"id": 2, "path": run["path"], "state": "active"},
        base + "/actions/runs/12": run,
        base + "/actions/runs/12/attempts/1": deepcopy(run),
        base + "/actions/runs/12/attempts/1/jobs?per_page=100": {
            "total_count": 1,
            "jobs": [
                {
                    "id": 3,
                    "run_id": 12,
                    "run_attempt": 1,
                    "head_sha": manifest.plan.source_revision,
                    "name": "isolation",
                    "status": "completed",
                    "conclusion": "success",
                    "started_at": "2026-10-29T00:00:02Z",
                    "completed_at": "2026-10-29T00:00:59Z",
                    "steps": [
                        {"name": name, "conclusion": "success"}
                        for name in (
                            "Select the exact public diagnostic manifest",
                            "Require trusted main history",
                            "Run the bounded independent diagnostic operation",
                        )
                    ],
                }
            ],
        },
        base + "/actions/runs/12/artifacts?per_page=100": {"total_count": 2, "artifacts": []},
    }
    for index, (kind, filename, body) in enumerate(
        (
            ("", "receipt.json", receipt),
            (
                "authentication-",
                "authentication.json",
                {**auth, "status": "verified", "observed_at": "2026-10-29T00:00:15Z"},
            ),
        ),
        4,
    ):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr(filename, json.dumps(body))
        raw = buf.getvalue()
        bodies[base + f"/actions/artifacts/{index}/zip"] = raw
        bodies[base + "/actions/runs/12/artifacts?per_page=100"]["artifacts"].append(
            {
                "id": index,
                "name": "m3-11-public-ca-" + kind + "12-attempt-1",
                "expired": False,
                "workflow_run": {
                    "id": 12,
                    "head_sha": manifest.plan.source_revision,
                    "head_branch": "main",
                    "repository_id": 1,
                    "head_repository_id": 1,
                },
                "created_at": "2026-10-29T00:00:40Z",
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
        )
    return bodies


def api(bodies: dict[str, Any]) -> Callable[[str], bytes]:
    def get(path: str) -> bytes:
        value = bodies[path]
        return value if isinstance(value, bytes) else json.dumps(value).encode()

    return get


def test_complete_actual_get_and_two_zip_capture(manifest: Manifest) -> None:
    bodies = transport(manifest)
    proof = capture(manifest, 12, operation="confirm", api=api(bodies))
    assert proof.receipt["confirmation"] == "exact-three-role-manifest"
    assert proof.provenance["run_id"] == cast(dict[str, Any], proof.receipt["github"])["run_id"]
    assert set(cast(dict[str, object], proof.provenance["artifacts"])) == {
        "receipt",
        "authentication",
    }


@pytest.mark.parametrize(
    "fault",
    [
        "head",
        "attempt",
        "event",
        "step",
        "truncated",
        "zip-digest",
        "zip-member",
        "auth-server",
        "teardown",
    ],
)
def test_capture_rejects_wrong_native_provenance(manifest: Manifest, fault: str) -> None:
    bodies = transport(manifest)
    prefix = "repos/" + REPOSITORY + "/actions"
    if fault in {"head", "attempt", "event"}:
        bodies[prefix + "/runs/12"][
            {"head": "head_sha", "attempt": "run_attempt", "event": "event"}[fault]
        ] = {"head": "f" * 40, "attempt": 2, "event": "push"}[fault]
    elif fault == "step":
        bodies[prefix + "/runs/12/attempts/1/jobs?per_page=100"]["jobs"][0]["steps"][0][
            "conclusion"
        ] = "skipped"
    elif fault == "truncated":
        bodies[prefix + "/runs/12/artifacts?per_page=100"]["total_count"] = 3
    else:
        index = 5 if fault == "auth-server" else 4
        path = prefix + f"/artifacts/{index}/zip"
        if fault == "zip-digest":
            bodies[path] += b"changed"
        else:
            with zipfile.ZipFile(io.BytesIO(bodies[path])) as archive:
                filename = archive.namelist()[0]
                body = json.loads(archive.read(filename))
            if fault == "auth-server":
                body["server_sha256"] = "0" * 64
            elif fault == "teardown":
                body["temporary_runtime_closed"] = False
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr(
                    "unexpected.json" if fault == "zip-member" else filename, json.dumps(body)
                )
            bodies[path] = buffer.getvalue()
            bodies[prefix + "/runs/12/artifacts?per_page=100"]["artifacts"][index - 4]["digest"] = (
                "sha256:" + hashlib.sha256(bodies[path]).hexdigest()
            )
    with pytest.raises((ValueError, RuntimeError)):
        capture(manifest, 12, operation="confirm", api=api(bodies))


def native(value: dict[str, object]) -> dict[str, object]:
    return {"sha256": digest(value), "value": value}


def functional_fixture(host: Host) -> dict[str, Any]:
    plan = host.manifest.plan
    context_path = host.phase / "isolation-context.json"
    context: dict[str, Any]
    if context_path.exists():
        context = json.loads(context_path.read_bytes())
    else:
        context = {"synthetic": "bound context"}
        write_private(context_path, context)
    dns = host.phase / "isolation-dns"
    dns.mkdir(mode=0o700)
    names: dict[str, object] = {
        "format": "lowerduckpond-isolated-public-ca-names-v1",
        "plan_sha256": plan.sha256,
        "nonce": plan.nonce,
    }

    if not (host.phase / "isolation-names.json").exists():
        write_private(host.phase / "isolation-names.json", names)

    def observation(kind: str, sequence: int, records: bool) -> dict[str, object]:
        return {
            "format": "lowerduckpond-m3-11-private-dns-observation-v1",
            "context_sha256": digest(context),
            "names_sha256": digest(names),
            "kind": kind,
            "sequence": sequence,
            "started_at": START,
            "completed_at": START,
            "zones": {
                domain: {
                    "zone_id": zone,
                    "name": f"_acme-challenge.m3-11-{plan.nonce.replace('-', '')}.{domain}",
                    "records": [
                        {
                            "id": "7" * 32,
                            "name": f"_acme-challenge.m3-11-{plan.nonce.replace('-', '')}.{domain}",
                            "type": "TXT",
                            "content": "x" * 43,
                        }
                    ]
                    if records
                    else [],
                }
                for domain, zone in plan.zones.items()
            },
        }

    active, clean = observation("activity", 0, True), observation("cleanup", 1, False)
    write_private(dns / "0000.json", active)
    write_private(dns / "0001.json", clean)
    tls = {
        "issuer": policy.ISSUER_STORAGE,
        "certificates": [
            {"subject": name, "leafSha256": "1" * 64}
            for name in policy.disposable_subjects(plan.nonce)
        ],
    }
    original: dict[str, object] = {
        "context_sha256": digest(context),
        "binary_sha256": plan.caddy_binary_sha256,
        "nonce": plan.nonce,
        "journal_sha256": cast(dict[str, str], host.prepared["restore"])["journal_sha256"],
        "isolation_network": plan.network.document(),
    }
    return {
        "original": native(original),
        "interrupted": native({"storage": {"acme/account.key": "1" * 64}, "pid_one": "100"}),
        "interruption_cleanup": {
            "activity_sha256": [digest(active)],
            "absence_sha256": digest(clean),
        },
        "rebooted": native({"storage": {"acme/account.key": "1" * 64}, "pid_one": "200"}),
        "tls": tls,
        "opened": native({"tls_sha256": digest(tls)}),
        "restored": native({"journal_sha256": original["journal_sha256"]}),
        "dns_activity_sha256": [digest(active)],
        "dns_cleanup_sha256": digest(clean),
    }


def test_native_envelopes_and_full_observation_graph_accept_real_shape(
    graph: tuple[Host, Journal, Mock],
) -> None:
    host, _, _ = graph
    values = functional_fixture(host)
    write_private(host.phase / "isolation-observations.json", values)
    write_private(host.phase / "isolation-functional.json", {"observations_sha256": digest(values)})
    assert functional(host)["observations_sha256"] == digest(values)


@pytest.mark.parametrize(
    "fault",
    ["envelope", "reboot", "issuer", "subjects", "readiness", "cleanup", "missing-activity"],
)
def test_native_functional_proof_rejects_shortcuts(
    graph: tuple[Host, Journal, Mock], fault: str
) -> None:
    host, _, _ = graph
    value = functional_fixture(host)
    if fault == "envelope":
        value["original"]["sha256"] = "0" * 64
    elif fault == "reboot":
        value["rebooted"] = value["interrupted"]
    elif fault == "issuer":
        value["tls"]["issuer"] = "local"
    elif fault == "subjects":
        value["tls"]["certificates"].pop()
    elif fault == "readiness":
        value["opened"] = native({"tls_sha256": "0" * 64})
    elif fault == "cleanup":
        value["dns_cleanup_sha256"] = value["dns_activity_sha256"][0]
    elif fault == "missing-activity":
        value["dns_activity_sha256"] = []
    write_private(host.phase / "isolation-observations.json", value)
    write_private(host.phase / "isolation-functional.json", {"observations_sha256": digest(value)})
    with pytest.raises((ValueError, RuntimeError)):
        functional(host)


def closed_graph(host: Host, journal: Journal, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:

    provider = FakeProvider(host.manifest.plan)
    lease = Lease(host.credentials, host.manifest.intents, journal)
    ids = issue(lease, provider)
    context: dict[str, Any] = {
        "format": CONTEXT_FORMAT,
        "plan_sha256": host.manifest.plan.sha256,
        "run_id": host.manifest.plan.run_id,
        "captured_at": START,
        "source_fixture_sha256": digest(cast(dict[str, object], host.prepared["actors"])["source"]),
        "actors": host.prepared["actors"],
        "topology": host.prepared["topology"],
        "guest_program_sha256": host.prepared["guest_program_sha256"],
        "preparation_sha256": host.manifest.plan.preparation_sha256,
        "credentials": {
            "ids": ids,
            "intents": {item.role: item.sha256 for item in host.manifest.intents},
            "expires_at": EXPIRES,
        },
    }
    write_private(host.phase / "isolation-context.json", context)
    write_private(
        host.phase / "isolation-names.json",
        {
            "format": "lowerduckpond-isolated-public-ca-names-v1",
            "plan_sha256": host.manifest.plan.sha256,
            "nonce": host.manifest.plan.nonce,
        },
    )
    journal.put("context", context)
    phase: dict[str, object] = {
        "context_sha256": digest(context),
        "started_at": START,
        "deadline_at": "2026-10-29T00:30:00Z",
    }
    write_private(host.phase / "isolation-phase-started.json", phase)
    journal.put("phase-started", phase)
    observations = functional_fixture(host)
    result: dict[str, object] = {
        "format": RESULT_FORMAT,
        "qualification_authority": "none",
        "plan_sha256": host.manifest.plan.sha256,
        "context_sha256": digest(context),
        "observations_sha256": digest(observations),
        "network": host.manifest.plan.network.document(),
        "functional_recovery": "passed",
        "cleanup": "pending-independent-closure",
    }
    write_private(host.phase / "isolation-observations.json", observations)
    write_private(host.phase / "isolation-functional.json", result)
    journal.put("functional", result)
    teardown = json.loads((host.phase / "isolation-dns/0001.json").read_bytes())
    teardown.update(kind="teardown", sequence=2)
    write_private(host.phase / "isolation-dns/0002.json", teardown)
    clean: dict[str, object] = {
        "context_sha256": digest(context),
        "basis": "observed-absent",
        "observation": teardown,
        "observation_sha256": digest(teardown),
        "observed_at": START,
    }
    write_private(host.phase / "isolation-dns-clean.json", clean)
    journal.put("dns-clean", clean)
    monkeypatch.setattr(host_module, "datetime", SimpleNamespace(now=lambda _tz: NOW))
    host.stop(journal)
    closure = lease.cleanup(
        cast(Provider, provider), require_issuer_stopped=host.controller_stopped
    )
    bodies = transport(host.manifest, "reconcile")
    path = "repos/" + REPOSITORY + "/actions/artifacts/4/zip"
    with zipfile.ZipFile(io.BytesIO(bodies[path])) as archive:
        receipt = json.loads(archive.read("receipt.json"))
    receipt["closure_sha256"] = closure
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("receipt.json", json.dumps(receipt))
    bodies[path] = buffer.getvalue()
    bodies["repos/" + REPOSITORY + "/actions/runs/12/artifacts?per_page=100"]["artifacts"][0][
        "digest"
    ] = "sha256:" + hashlib.sha256(bodies[path]).hexdigest()
    journal.put(
        "readback",
        {
            "github": receipt["github"],
            "closure_sha256": closure,
            "status": "provider-absence-and-host-denials-verified",
        },
    )
    return bodies


def test_complete_prerequisite_seal_requires_real_adapter_facts_and_native_zip_proof(
    graph: tuple[Host, Journal, Mock], monkeypatch: pytest.MonkeyPatch
) -> None:

    host, journal, docker = graph
    bodies = closed_graph(host, journal, monkeypatch)
    result = seal(host, journal, run_id=12, api=api(bodies))
    assert result["status"] == "passed" and result["qualification_authority"] == "none"
    assert result["manifest_sha256"] == host.manifest.sha256
    docker.remove_controller.assert_not_called()


def test_native_drift_during_proof_gets_cannot_publish_prerequisite(
    graph: tuple[Host, Journal, Mock], monkeypatch: pytest.MonkeyPatch
) -> None:

    host, journal, _ = graph
    bodies = closed_graph(host, journal, monkeypatch)
    original = host.actor
    drift = False

    def actor(name: str) -> dict[str, object]:
        value = original(name)
        return {**value, "running": True} if drift and name == "destination" else value

    monkeypatch.setattr(host, "actor", actor)

    def get(path: str) -> bytes:
        nonlocal drift
        result = api(bodies)(path)
        if path.endswith("/artifacts/5/zip"):
            drift = True
        return result

    with pytest.raises(ValueError, match="changed during"):
        seal(host, journal, run_id=12, api=get)
    assert not (host.root / "prerequisite.json").exists()
