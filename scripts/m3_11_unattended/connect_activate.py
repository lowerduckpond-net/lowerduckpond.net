"""Activate already-delivered Connect clients without retrieving new bootstrap secrets."""

from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_configuration as backend
from scripts.m3_11_unattended import connect_genesis as genesis
from scripts.m3_11_unattended.cleanup import require_independent_ready
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.connect_control import BACKEND, SETTING, GitHub
from scripts.m3_11_unattended.connect_journal import acknowledgement
from scripts.m3_11_unattended.connect_ledger import ConnectLedger
from scripts.m3_11_unattended.connect_setup import FORMAT, role_vaults
from scripts.m3_11_unattended.journal import event, validate
from scripts.m3_11_unattended.model import (
    LifecycleError,
    Targets,
    digest,
    identity,
    instant,
    strings,
)
from scripts.m3_11_unattended.state import cleanup_lock, private_directory, replace_private
from scripts.production_qualification_inputs import current_candidate, revision

INITIALIZING_FORMAT = "lowerduckpond-m3-11-connect-initializing-v1"


def retain(path: Path, value: dict[str, object]) -> dict[str, object]:
    if path.exists():
        saved = read_private(path)
        if saved != value:
            raise LifecycleError("saved Connect activation inputs changed; retain all evidence")
        return saved
    write_private(path, value)
    return value


def activation_probes(value: object) -> dict[str, object]:
    probes = fields(value, {"shared", "independent"})
    shared, independent = (validate(probes[role]) for role in ("shared", "independent"))
    epoch = identity(shared["run_id"])
    for role, probe in (("shared", shared), ("independent", independent)):
        if (
            probe["kind"] != "run"
            or probe["run_id"] != epoch
            or probe["payload"] != {"format": genesis.PROBE_FORMAT, "epoch": epoch, "actor": role}
            or shared["event_id"] == independent["event_id"]
        ):
            raise LifecycleError("retained Connect activation probes changed")
    return probes


def readers(bundle: dict[str, object]) -> dict[str, dict[str, object]]:
    fields(bundle, {"format", "manifest", "url", "tokens", "provider_metadata"})
    if bundle["format"] != FORMAT or not isinstance(bundle["manifest"], dict):
        raise LifecycleError("Connect activation requires the delivered bootstrap bundle")
    vaults = role_vaults(bundle["manifest"])
    entries = fields(bundle["tokens"], {"provision", "cleanup", "production"})
    result = {
        role: {
            "url": bundle["url"],
            "role": role,
            "vaults": vaults,
            "entry": entries[role],
            "metadata": bundle["provider_metadata"],
        }
        for role in entries
    }
    accesses = [backend.reader_access(value)[1] for value in result.values()]
    if (
        len({access.token_id for access in accesses}) != len(accesses)
        or len({access.token for access in accesses}) != len(accesses)
        or len({access.server_id for access in accesses}) != 1
    ):
        raise LifecycleError("Connect activation clients are not separate roles of one server")
    return result


def document(bundle: dict[str, object], selected: dict[str, object]) -> dict[str, object]:
    configured = readers(bundle)
    manifest = cast(dict[str, object], bundle["manifest"])
    approved = cast(dict[str, object], selected["request"])
    proof = fields(selected["receipt"], action.GENESIS_RECEIPT_FIELDS)
    witness = action.witness(proof, active_helper=revision(selected["active_helper"]))
    common = {
        "format": backend.ROLE_FORMAT,
        "witness": {
            "epoch": witness.epoch,
            "helper": witness.helper,
            "active_helper": witness.current_helper,
            "server": witness.server,
            "author": witness.author,
            "genesis_id": str(witness.genesis.identity),
            "genesis_sha256": witness.genesis.sha256,
        },
        "initial": proof["initial"],
        "anchor": approved["anchor"],
        "anchor_sha256": approved["anchor_sha256"],
        "independent_expires_at": proof["authority_expires_at"],
    }
    value: dict[str, object] = {
        "format": "lowerduckpond-m3-11-controller-connect-v1",
        "targets": manifest["targets"],
        "journal_vault": manifest["journal_vault"],
        "production": {
            "connect": configured["production"],
            "references": cast(dict[str, object], manifest["production"])["references"],
        },
    }
    for role in ("provision", "cleanup"):
        references = cast(dict[str, object], manifest[role])
        value[role] = {
            **copy.deepcopy(common),
            "reader": configured[role],
            "values": {key: references[key] for key in backend.PROVIDER_REFERENCES},
        }
    return value


class Activation:
    def __init__(  # noqa: PLR0913 - exact helper, approved anchor and private storage are explicit
        self,
        bundle: dict[str, object],
        *,
        helper: str,
        reference: str,
        anchor_sha256: str,
        directory: Path,
        github: GitHub,
    ) -> None:
        self.bundle, self.helper, self.directory, self.github = (
            bundle,
            revision(helper),
            directory,
            github,
        )
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(directory)
        self.configured = readers(bundle)
        self.manifest = cast(dict[str, object], bundle["manifest"])
        self.vaults = role_vaults(self.manifest)
        self.targets = Targets.parse(self.manifest["targets"])
        match = re.fullmatch(r"op://([a-z0-9]{26})/([a-z0-9]{26})/notesPlain", reference)
        if (
            match is None
            or match[1] != self.vaults["journal"]
            or re.fullmatch(r"[0-9a-f]{64}", anchor_sha256) is None
        ):
            raise LifecycleError("activation requires the approved immutable setup manifest")
        self.anchor, self.anchor_sha256 = match[2], anchor_sha256
        self.github.protection()
        self.github.merged(helper)
        # Authenticate all roles and forbidden vaults; production secret items are
        # never read. Only the journal manifest is retrieved by this helper.
        clients = {role: backend.reader(value) for role, value in self.configured.items()}
        manifest_record = validate(json.loads(clients["cleanup"].read(reference)))
        payload = manifest_record["payload"]
        if (
            digest(manifest_record) != anchor_sha256
            or not isinstance(payload, dict)
            or payload.get("manifest") != self.manifest
        ):
            raise LifecycleError("delivered Connect bootstrap differs from the approved manifest")
        self.retained_inputs = (directory / "inputs.json").exists()
        if not self.retained_inputs and any(
            path.name != "cleanup.lock" for path in directory.iterdir()
        ):
            raise LifecycleError(
                "existing activation evidence has lost its original private inputs"
            )
        retain(
            directory / "inputs.json",
            {
                "bundle_sha256": digest(bundle),
                "reference": reference,
                "anchor_sha256": anchor_sha256,
            },
        )
        self.ledger = ConnectLedger(
            clients["cleanup"],
            self.vaults["journal"],
            spool=directory / "journal",
            anchor=self.anchor,
            anchor_sha256=anchor_sha256,
            minimum={identity(manifest_record["event_id"]): anchor_sha256},
        )

    def bind(self, selected: dict[str, object]) -> None:
        approved = cast(dict[str, object], selected["request"])
        access = backend.reader_access(self.configured["cleanup"])[1]
        if any(
            approved[key] != value
            for key, value in {
                "vaults": self.vaults,
                "anchor": self.anchor,
                "anchor_sha256": self.anchor_sha256,
                "targets_sha256": digest(dataclasses.asdict(self.targets)),
                "shared_server": access.server_id,
            }.items()
        ):
            raise LifecycleError("protected Connect epoch differs from approved bootstrap inputs")

    def publish(self, selected: dict[str, object], *, previous: dict[str, object] | None) -> None:
        action.selection(selected, helper=self.helper)
        self.bind(selected)
        variables = self.github.variables()
        current = json.loads(variables[SETTING]) if SETTING in variables else None
        if current not in (previous, selected) or variables.get(BACKEND, "") not in {
            "",
            "service-account",
            "connect-initializing",
            "connect",
        }:
            raise LifecycleError("protected Connect configuration changed; never reset its epoch")
        if variables.get(BACKEND) == "connect" and selected["stage"] != "active":
            raise LifecycleError("active Connect cleanup cannot return to initialization")
        # The executable pin travels in the same atomic publication. The legacy
        # service-account helper variable is deliberately left unchanged.
        self.github.set_variable(SETTING, canonical_bytes(selected).decode())

    def step(
        self, operation: str, selected: dict[str, object], *, previous: dict[str, object] | None
    ) -> dict[str, object]:
        directory = self.directory / operation
        if not (directory / "receipt.json").exists():
            self.publish(selected, previous=previous)
        dispatch = self.github.dispatch(directory, operation=operation, selection=selected)
        return self.github.wait(dispatch, helper=self.helper, directory=directory)

    def discovery(self) -> dict[str, object]:
        path = self.directory / "discovery-request.json"
        if path.exists():
            value = genesis.discovery_request(read_private(path))
            if value["helper_revision"] != self.helper:
                raise LifecycleError("unfinished activation requires its original approved helper")
            return value
        path = self.directory / "probes.json"
        if path.exists():
            probes = activation_probes(read_private(path))
        else:
            epoch = str(uuid.uuid7())
            probes = {
                role: event(
                    "run", epoch, {"format": genesis.PROBE_FORMAT, "epoch": epoch, "actor": role}
                )
                for role in ("shared", "independent")
            }
            write_private(path, probes)
        shared = validate(probes["shared"])
        # Persist the exact logical probe before its first POST. stage reconciles
        # a lost reply; it does not issue another untracked item.
        self.ledger.stage(shared)
        records = [row for row in self.ledger.records() if not acknowledgement(row)]
        authors = self.ledger.authors(shared)
        if len(authors) != 1 or any(row["kind"] == "intent" for row in records):
            raise LifecycleError("initial Connect activation cannot discard existing obligations")
        access = backend.reader_access(self.configured["cleanup"])[1]
        value = genesis.discovery_request(
            {
                "format": genesis.DISCOVERY_FORMAT,
                "epoch": shared["run_id"],
                "helper_revision": self.helper,
                "registry_revision": self.helper,
                "vaults": self.vaults,
                "anchor": self.anchor,
                "anchor_sha256": self.anchor_sha256,
                "initial": {str(row["event_id"]): digest(row) for row in records},
                "shared_server": access.server_id,
                "shared_author": authors.pop(),
                "shared_probe": shared,
                "independent_probe": probes["independent"],
                "targets_sha256": digest(dataclasses.asdict(self.targets)),
            }
        )
        return retain(self.directory / "discovery-request.json", value)

    def initializing_evidence(self) -> tuple[dict[str, object], dict[str, object]]:
        """Require the original private state; never replace an uncertain probe."""
        if not self.retained_inputs:
            raise LifecycleError("initializing helper upgrade requires retained private inputs")
        probes = activation_probes(read_private(self.directory / "probes.json"))
        shared = cast(dict[str, object], probes["shared"])
        intent = str(shared["event_id"]) + ".json"
        returned = str(shared["event_id"]) + ".returned.json"
        spool = self.directory / "journal"
        if (
            not {path.name for path in spool.iterdir()} <= {intent, returned}
            or read_private(spool / intent) != shared
        ):
            raise LifecycleError("initializing helper upgrade has changed or later stage evidence")
        return probes, {
            "inputs_sha256": digest(read_private(self.directory / "inputs.json")),
            "probes_sha256": digest(probes),
            "spool": {path.name: digest(read_private(path)) for path in spool.iterdir()},
        }

    def upgrade_initializing(
        self,
        current: dict[str, object],
        marker: dict[str, object],
        records: list[dict[str, object]],
    ) -> None:
        """Migrate only the same pre-discovery epoch to a reviewed merged helper."""
        path = self.directory / ("initializing-upgrade-" + self.helper + ".json")
        saved = read_private(path) if path.exists() else None
        previous = fields(saved["previous"], set(marker)) if saved else current
        prior_helper = revision(previous.get("active_helper"))
        if (
            prior_helper == self.helper
            or previous != {**marker, "active_helper": prior_helper}
            or current not in (previous, marker)
        ):
            raise LifecycleError("initializing helper upgrade changed protected bootstrap bindings")
        self.github.merged(prior_helper)
        probes, evidence = self.initializing_evidence()
        shared = cast(dict[str, object], probes["shared"])
        allowed = {"inputs.json", "probes.json", "journal", "cleanup.lock", path.name}
        request_path = self.directory / "discovery-request.json"
        if request_path.exists() and saved and current == marker:
            request = genesis.discovery_request(read_private(request_path))
            self.bind({"request": request})
            if (
                request["helper_revision"] != self.helper
                or request["registry_revision"] != self.helper
                or any(request[role + "_probe"] != probes[role] for role in probes)
            ):
                raise LifecycleError(
                    "retained discovery request differs from the completed upgrade"
                )
            allowed.add(request_path.name)
        if any(entry.name not in allowed for entry in self.directory.iterdir()):
            raise LifecycleError("unfinished discovery or genesis requires its original helper")
        if (
            shared not in records
            or len(self.ledger.authors(shared)) != 1
            or any(row["kind"] == "intent" for row in records)
            or any(row["run_id"] == shared["run_id"] and row != shared for row in records)
        ):
            raise LifecycleError("initializing helper upgrade cannot discard later journal history")
        initial = {str(row["event_id"]): digest(row) for row in records}
        audit = {"previous": previous, "selected": marker, **evidence, "initial": initial}
        if saved:
            if {**saved, "initial": initial} != audit or not strings(
                saved["initial"]
            ).items() <= initial.items():
                raise LifecycleError("retained initializing upgrade evidence changed")
        else:
            retain(path, audit)
        variables = self.github.variables()
        if variables.get(BACKEND) != "connect-initializing" or json.loads(
            variables.get(SETTING, "null")
        ) not in (previous, marker):
            raise LifecycleError("protected initialization changed before helper publication")
        self.github.set_variable(SETTING, canonical_bytes(marker).decode())

    def quiesce(self) -> dict[str, object]:
        marker: dict[str, object] = {
            "format": INITIALIZING_FORMAT,
            "stage": "initializing",
            "active_helper": self.helper,
            "request": {
                "vaults": self.vaults,
                "anchor": self.anchor,
                "anchor_sha256": self.anchor_sha256,
                "targets_sha256": digest(dataclasses.asdict(self.targets)),
                "shared_server": backend.reader_access(self.configured["cleanup"])[1].server_id,
            },
            "receipt": None,
        }
        variables = self.github.variables()
        current = json.loads(variables[SETTING]) if SETTING in variables else None
        if variables.get(BACKEND, "") not in {"", "service-account", "connect-initializing"}:
            raise LifecycleError("active Connect cleanup cannot return to initialization")
        records = self.ledger.records()
        if any(row["kind"] == "intent" for row in records):
            raise LifecycleError("initial Connect activation cannot discard existing obligations")
        audit = self.directory / ("initializing-upgrade-" + self.helper + ".json")
        if (
            isinstance(current, dict)
            and current.get("format") == INITIALIZING_FORMAT
            and (current != marker or audit.exists())
        ):
            self.upgrade_initializing(current, marker, records)
        elif current is not None and current != marker:
            prior = action.selection(current, helper=self.helper)
            if prior["stage"] not in {"discovery", "genesis"}:
                raise LifecycleError("an existing Connect epoch cannot be reinitialized")
            self.bind(prior)
        if current is None:
            self.github.set_variable(SETTING, canonical_bytes(marker).decode())
        # Independent cleanup continues. Only an empty journal suppresses idle
        # heartbeat writes; any intent still takes the normal native sweep.
        self.github.set_variable(BACKEND, "connect-initializing")
        self.github.drain()
        return marker

    def initialize(self) -> dict[str, object]:
        marker = self.quiesce()
        discovery = self.discovery()
        selected: dict[str, object] = {
            "format": action.FORMAT,
            "stage": "discovery",
            "active_helper": self.helper,
            "request": discovery,
            "receipt": None,
        }
        receipt = self.step("discovery", selected, previous=marker)
        proof = fields(
            receipt["proof"],
            {
                "format",
                "request_sha256",
                "epoch",
                "helper_revision",
                "independent_server",
                "independent_author",
                "shared_author",
                "forged_author_ignored",
                "observed_at",
                "provider_children_created",
                "initial",
            },
        )
        if (
            proof["format"] != genesis.DISCOVERY_RECEIPT
            or proof["request_sha256"] != digest(discovery)
            or any(
                proof[key] != discovery[key]
                for key in ("epoch", "helper_revision", "shared_author")
            )
            or proof["independent_author"] == discovery["shared_author"]
            or proof["independent_server"] == discovery["shared_server"]
            or proof["forged_author_ignored"] is not True
            or proof["provider_children_created"] is not False
        ):
            raise LifecycleError("independent discovery proof differs from its exact request")
        initial = strings(proof["initial"])
        if not strings(discovery["initial"]).items() <= initial.items():
            raise LifecycleError("independent discovery lost previously observed journal records")

        expected = {
            **initial,
            str(cast(dict[str, object], discovery["independent_probe"])["event_id"]): digest(
                discovery["independent_probe"]
            ),
        }
        payload = {
            "format": genesis.PROBE_FORMAT,
            "epoch": discovery["epoch"],
            "actor": "shared-forgery",
            "claimed_author": proof["independent_author"],
        }
        path = self.directory / "shared-forgery.json"
        if path.exists():
            forged = validate(read_private(path))
        else:
            forged = event("run", identity(discovery["epoch"]), payload)
            write_private(path, forged)
        if (
            forged["kind"] != "run"
            or forged["run_id"] != discovery["epoch"]
            or forged["payload"] != payload
            or str(forged["event_id"]) in expected
        ):
            raise LifecycleError("retained shared provenance probe differs from discovery")

        def synchronized() -> bool:
            records = [row for row in self.ledger.records() if not acknowledgement(row)]
            observed = {str(row["event_id"]): digest(row) for row in records}
            # A restart may precede or follow this exact probe's first POST.
            # Its private identity and native author permit no other additions.
            return observed == expected or (
                observed == {**expected, str(forged["event_id"]): digest(forged)}
                and self.ledger.authors(forged) == {discovery["shared_author"]}
            )

        if not action.synchronize(synchronized):
            raise LifecycleError(
                "shared Connect has not reached the independent complete inventory"
            )
        self.ledger.stage(forged, claimed_author=str(proof["independent_author"]))
        self.ledger.records()
        if self.ledger.authors(forged) != {discovery["shared_author"]}:
            raise LifecycleError("shared Connect endpoint accepted forged provenance")
        request = genesis.request(
            {
                **discovery,
                "format": genesis.REQUEST_FORMAT,
                "shared_forgery_probe": forged,
                "initial": {
                    **initial,
                    str(forged["event_id"]): digest(forged),
                },
            }
        )
        initialized: dict[str, object] = {**selected, "stage": "genesis", "request": request}
        receipt = self.step("genesis", initialized, previous=selected)
        active = {**initialized, "stage": "active", "receipt": receipt["proof"]}
        self.publish(active, previous=initialized)
        return active

    def selected(self) -> dict[str, object]:
        variables = self.github.variables()
        value = json.loads(variables[SETTING]) if SETTING in variables else None
        if isinstance(value, dict) and value.get("stage") == "active":
            previous = action.selection(value, helper=revision(value.get("active_helper")))
            self.bind(previous)
            selected = {**previous, "active_helper": self.helper}
            # A reviewed helper upgrade retains every original genesis binding,
            # all historical events and obligations, and the same registry.
            self.publish(selected, previous=previous)
            return selected
        if (
            isinstance(value, dict)
            and value.get("stage") in {"discovery", "genesis"}
            and value.get("active_helper") != self.helper
        ):
            return self.resume_original(value)
        return self.initialize()

    def require_original_dispatch(self, selected: dict[str, object]) -> None:
        """A successor must not replace an operation whose private identity was lost."""
        operation = str(selected["stage"])
        directory = self.directory / operation
        expected = {"operation": operation, "selection_sha256": digest(selected), "run_sha256": ""}
        saved = fields(
            read_private(directory / "dispatch.json"), {*expected, "dispatch_id", "requested_at"}
        )
        identity(saved["dispatch_id"])
        instant(saved["requested_at"])
        if any(saved[key] != item for key, item in expected.items()) or read_private(
            directory / "submitted.json"
        ) != {"dispatch_sha256": digest(saved)}:
            raise LifecycleError(
                "coordinator recovery requires the exact original submitted dispatch"
            )

    def resume_original(self, value: dict[str, object]) -> dict[str, object]:
        """A reviewed coordinator can recover receipts without rebinding the ceremony."""
        stage_helper = revision(value.get("active_helper"))
        previous = action.selection(value, helper=stage_helper)
        self.bind(previous)
        if not self.retained_inputs or previous["stage"] not in {"discovery", "genesis"}:
            raise LifecycleError("coordinator recovery requires the original pending ceremony")
        original = Activation(
            self.bundle,
            helper=stage_helper,
            reference=f"op://{self.vaults['journal']}/{self.anchor}/notesPlain",
            anchor_sha256=self.anchor_sha256,
            directory=self.directory,
            github=self.github,
        )
        discovery = genesis.discovery_request(
            read_private(self.directory / "discovery-request.json")
        )
        probes = activation_probes(read_private(self.directory / "probes.json"))
        request = cast(dict[str, object], previous["request"])
        if (
            discovery["helper_revision"] != stage_helper
            or any(discovery[role + "_probe"] != probes[role] for role in probes)
            or any(
                discovery[key] != request[key]
                for key in discovery
                if key not in {"format", "initial"}
            )
            or (previous["stage"] == "discovery" and request != discovery)
            or not strings(discovery["initial"]).items() <= strings(request["initial"]).items()
        ):
            raise LifecycleError("coordinator recovery changed the original discovery bindings")
        shared = cast(dict[str, object], probes["shared"])
        if read_private(self.directory / "journal" / (str(shared["event_id"]) + ".json")) != shared:
            raise LifecycleError("coordinator recovery has lost the original shared probe intent")
        self.require_original_dispatch(
            {**previous, "stage": "discovery", "request": discovery, "receipt": None}
        )
        if previous["stage"] == "genesis":
            self.require_original_dispatch(previous)
            if (
                read_private(self.directory / "shared-forgery.json")
                != request["shared_forgery_probe"]
            ):
                raise LifecycleError("coordinator recovery has lost the original forgery probe")
        if any(row["kind"] == "intent" for row in original.ledger.records()):
            raise LifecycleError("coordinator recovery cannot discard credential obligations")
        path = self.directory / ("coordinator-resume-" + self.helper + ".json")
        files = {
            str(entry.relative_to(self.directory)): digest(read_private(entry))
            for entry in self.directory.rglob("*.json")
            if entry != path
        }
        binding = {
            "format": "lowerduckpond-m3-11-connect-coordinator-resume-v1",
            "coordinator_revision": self.helper,
            "stage_helper_revision": stage_helper,
            "discovery_sha256": digest(discovery),
            "probes_sha256": digest(probes),
            "inputs_sha256": digest(read_private(self.directory / "inputs.json")),
        }
        if path.exists():
            saved = fields(read_private(path), {*binding, "files", "original_selection"})
            if (
                any(saved[key] != item for key, item in binding.items())
                or not strings(saved["files"]).items() <= files.items()
            ):
                raise LifecycleError("retained coordinator recovery evidence changed")
            initial = action.selection(saved["original_selection"], helper=stage_helper)
            self.bind(initial)
            initial_request = cast(dict[str, object], initial["request"])
            if (
                initial["stage"] not in {"discovery", "genesis"}
                or any(
                    discovery[key] != initial_request[key]
                    for key in discovery
                    if key not in {"format", "initial"}
                )
                or (initial["stage"] == "discovery" and initial_request != discovery)
                or not strings(discovery["initial"]).items()
                <= strings(initial_request["initial"]).items()
            ):
                raise LifecycleError(
                    "coordinator recovery audit differs from the original ceremony"
                )
        else:
            retain(path, {**binding, "files": files, "original_selection": previous})
        # Every pending request, dispatch, probe, registry and independent worker
        # retains its original helper. Only a valid active genesis may advance.
        active = original.initialize()
        selected = {**active, "active_helper": self.helper}
        self.publish(selected, previous=active)
        return selected

    def activate(self, output: Path) -> None:
        selected = self.selected()
        value = document(self.bundle, selected)
        candidate = self.directory / ("controller-" + digest(value) + ".json")
        retain(candidate, value)
        configuration = Configuration.load(candidate)
        self.github.set_variable(BACKEND, "connect")
        directory = self.directory / "readiness" / str(uuid.uuid7())
        dispatch = self.github.dispatch(directory, operation="reconcile", selection=selected)
        self.github.wait(dispatch, helper=self.helper, directory=directory)
        journal = configuration.cleanup.journal(
            configuration.journal_vault, directory=directory / "journal"
        )
        if not action.synchronize(lambda: self.ready(journal)):
            raise LifecycleError(
                "independent Connect readiness remains unproven; controller not installed"
            )
        self.install(output, value)

    def ready(self, journal: object) -> bool:
        from scripts.m3_11_unattended.connect_journal import ConnectJournal  # noqa: PLC0415

        if not isinstance(journal, ConnectJournal):
            raise LifecycleError("activation cannot select another credential backend")
        require_independent_ready(journal, helper=self.helper, now=datetime.now(UTC))
        return True

    def install(self, output: Path, value: dict[str, object]) -> None:
        private_directory(output.parent)
        if output.exists():
            previous = read_private(output)
            if previous == value:
                return
            configured = Configuration.load(output)
            if (
                configured.targets != self.targets
                or configured.journal_vault != self.vaults["journal"]
            ):
                raise LifecycleError("existing controller configuration belongs to another target")
            if configured.cleanup.connect_settings is not None:
                expected = copy.deepcopy(value)
                for role in ("cleanup", "provision"):
                    cast(dict[str, object], cast(dict[str, object], expected[role])["witness"])[
                        "active_helper"
                    ] = cast(dict[str, object], cast(dict[str, object], previous[role])["witness"])[
                        "active_helper"
                    ]
                if expected != previous:
                    raise LifecycleError(
                        "existing Connect controller differs beyond the reviewed helper"
                    )
            elif (
                any(
                    bootstrap.values[key] != cast(dict[str, object], self.manifest[role])[key]
                    for role, bootstrap in (
                        ("provision", configured.provision),
                        ("cleanup", configured.cleanup),
                    )
                    for key in backend.PROVIDER_REFERENCES
                )
                or configured.production["references"]
                != cast(dict[str, object], self.manifest["production"])["references"]
            ):
                raise LifecycleError("existing controller references differ from approved setup")
            retain(self.directory / ("previous-controller-" + digest(previous) + ".json"), previous)
            replace_private(output, value)
        else:
            write_private(output, value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--manifest-reference", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        current_candidate(Path(__file__).resolve().parents[2], arguments.revision)
        arguments.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(arguments.directory)
        with cleanup_lock(arguments.directory):
            Activation(
                read_private(arguments.bootstrap),
                helper=arguments.revision,
                reference=arguments.manifest_reference,
                anchor_sha256=arguments.manifest_sha256,
                directory=arguments.directory,
                github=GitHub(),
            ).activate(arguments.output)
        print(
            "Connect controller installed after independent cleanup verification. "
            "No provider credentials created."
        )
        return 0
    except LifecycleError, OSError, ValueError, KeyError, TypeError:
        print(
            "Connect activation unresolved; retain private activation evidence. "
            "No qualification launched."
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
