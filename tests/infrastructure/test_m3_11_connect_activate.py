"""Exercise the activation helper across real ledger, genesis, cleanup and configuration paths."""

# ruff: noqa: PLR2004 - exact external operation counts are the safety contract

from __future__ import annotations

import copy
import dataclasses
import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast, override

import pytest

from infrastructure import test_m3_11_connect_configuration as configuration_tests
from infrastructure.test_m3_11_connect_checkpoint import StoreDouble
from infrastructure.test_m3_11_connect_control import GitHubDouble
from infrastructure.test_m3_11_connect_journal import RemoteReplica, sync
from infrastructure.test_m3_11_connect_ledger import ANCHOR, CANARY, VAULT, Replica, note
from infrastructure.test_m3_11_unattended_lifecycle import TARGETS, ProviderDouble
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_activate as activate
from scripts.m3_11_unattended import connect_configuration as backend
from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended import connect_genesis as genesis
from scripts.m3_11_unattended.config import Configuration, Connections
from scripts.m3_11_unattended.connect_auth import Access
from scripts.m3_11_unattended.connect_ledger import ConnectLedger
from scripts.m3_11_unattended.connect_setup import FORMAT
from scripts.m3_11_unattended.github_checkpoint import GitHubArtifacts
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import Authority, LifecycleError, digest, stamp, strings
from scripts.m3_11_unattended.production import REFERENCES

HELPER = "a" * 40
VAULTS = {"provision": "p" * 26, "cleanup": "c" * 26, "production": "d" * 26, "journal": VAULT}


class GitHub(GitHubDouble):
    def __init__(self, case: Case) -> None:
        super().__init__()
        self.case = case
        self.values: dict[str, str] = {control.HELPER: "0" * 40}
        self.allowed = {HELPER, "f" * 40}
        self.selection_history: list[dict[str, object]] = []

    @override
    def protection(self) -> None:
        pass

    @override
    def merged(self, helper: str) -> None:
        if helper not in self.allowed:
            raise LifecycleError("helper is not merged")

    @override
    def variables(self) -> dict[str, str]:
        return dict(self.values)

    @override
    def set_variable(self, name: str, value: str) -> None:
        assert name in {control.SETTING, control.BACKEND}
        self.values[name] = value
        if name == control.SETTING:
            self.selection_history.append(json.loads(value))

    @override
    def api(
        self, path: str, *, method: str = "GET", body: object = None, binary: bool = False
    ) -> object:
        if method != "POST":
            return super().api(path, method=method, body=body, binary=binary)
        fail = self.fail_after_dispatch
        self.fail_after_dispatch = False
        result = super().api(path, method=method, body=body, binary=binary)
        self.fail_after_dispatch = fail
        assert isinstance(body, dict)
        inputs = cast(dict[str, str], body["inputs"])
        snapshot = json.loads(self.values[control.SETTING])
        selected = action.selection(snapshot, helper=snapshot["active_helper"])
        approved = cast(dict[str, object], selected["request"])
        sync(self.case.shared, self.case.remote)
        if inputs["operation"] == "discovery" and self.case.late_heartbeat is not None:
            identifier = "9".zfill(26)
            self.case.remote.items[identifier] = note(self.case.late_heartbeat, identifier)
            self.case.remote.version += 1
        proof = (
            cast(dict[str, object], selected["receipt"])
            if selected["stage"] == "active"
            else approved
        )
        ledger = ConnectLedger(
            self.case.remote,
            VAULT,
            spool=self.case.path / "workers" / str(len(self.executions)),
            anchor=ANCHOR,
            anchor_sha256=digest(self.case.anchor),
            minimum=strings(proof["initial"]),
        )
        helper, server = str(selected["active_helper"]), "I" * 26
        if inputs["operation"] == "discovery":
            proof = genesis.discover(
                ledger,
                approved,
                helper=helper,
                server=server,
                now=datetime.now(UTC),
            )
        elif inputs["operation"] == "genesis":
            proof = genesis.initialize(
                ledger,
                self.case.store,
                approved,
                helper=helper,
                server=server,
                authority=self.case.authority,
                now=datetime.now(UTC),
            )
        else:
            access = Access(
                "I" * 26, "T" * 26, "A" * 26, datetime.now(UTC) + timedelta(days=7), {}, CANARY
            )
            journal = action.restore(
                ledger, cast(GitHubArtifacts, self.case.store), selected, access
            )
            proof = action.reconcile(
                journal,
                lambda: Connections(journal, {"spaces": self.case.provider}, self.case.authority),
                targets=TARGETS,
                request_sha256=inputs["run_sha256"],
                dispatch_id=inputs["dispatch_id"],
                run_id=len(self.executions),
                attempt=1,
                fallback=lambda: Lifecycle(journal, {"spaces": self.case.provider}),
            )
        if inputs["operation"] != "discovery" or not self.case.defer_discovery_sync:
            sync(self.case.remote, self.case.shared)
        self.receipts[len(self.executions)] = {
            "format": action.RECEIPT_FORMAT,
            "status": "ready",
            "helper_revision": helper,
            "operation": inputs["operation"],
            "dispatch_id": inputs["dispatch_id"],
            "selection_sha256": digest(selected),
            "proof": proof,
            "observed_at": stamp(datetime.now(UTC)),
        }
        if inputs["operation"] == "witness":
            self.executions[-1].update(status="in_progress", conclusion=None)
        if fail:
            raise LifecycleError("lost dispatch response")
        return result

    @override
    def receipt(self, run_id: int) -> dict[str, object]:
        return copy.deepcopy(self.receipts[run_id])


class Case:
    def __init__(self, path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.path = path
        self.late_heartbeat: dict[str, object] | None = None
        self.defer_discovery_sync = False
        monkeypatch.setattr(control, "POLL_SECONDS", 0)
        monkeypatch.setattr(configuration_tests, "VAULTS", VAULTS)
        configured = {
            role: configuration_tests.reader_config(role)
            for role in ("provision", "cleanup", "production")
        }
        metadata = copy.deepcopy(cast(dict[str, object], configured["provision"]["metadata"]))
        metadata["tokens"] = [
            cast(list[dict[str, object]], cast(dict[str, object], value["metadata"])["tokens"])[0]
            for value in configured.values()
        ]
        manifest = {
            "format": "lowerduckpond-m3-11-setup-v1",
            "targets": dataclasses.asdict(TARGETS),
            "journal_vault": VAULT,
            **{
                role: {
                    key: f"op://{VAULTS[role]}/{'i' * 26}/{key}"
                    for key in backend.PROVIDER_REFERENCES
                }
                for role in ("provision", "cleanup")
            },
            "production": {
                "references": {
                    key: f"op://{VAULTS['production']}/{'i' * 26}/{key}" for key in REFERENCES
                }
            },
        }
        self.bundle: dict[str, object] = {
            "format": FORMAT,
            "manifest": manifest,
            "url": "https://connect.example.test",
            "tokens": {role: value["entry"] for role, value in configured.items()},
            "provider_metadata": metadata,
        }
        self.anchor = event(
            "run", str(uuid.uuid7()), {"manifest": manifest, "purpose": "approved-setup"}
        )
        self.shared, self.remote = Replica(self.anchor), RemoteReplica(self.anchor)
        monkeypatch.setattr(backend, "reader", lambda _value: self.shared)
        self.store = StoreDouble()
        self.store.remaining_capacity = lambda: 900  # type: ignore[attr-defined]
        self.authority = Authority("b" * 64, datetime.now(UTC) + timedelta(days=7))
        self.provider = ProviderDouble()
        self.github = GitHub(self)
        self.output = path / "controller.json"

    def activation(self, *, helper: str = HELPER) -> activate.Activation:
        return activate.Activation(
            self.bundle,
            helper=helper,
            reference=f"op://{VAULT}/{ANCHOR}/notesPlain",
            anchor_sha256=digest(self.anchor),
            directory=self.path / "activation",
            github=self.github,
        )


def test_activation_discovers_both_authors_persists_genesis_and_installs_verified_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.activation().activate(case.output)
    configured = Configuration.load(case.output)
    assert configured.targets == TARGETS
    assert configured.provision.connect_settings is not None
    assert case.github.values[control.BACKEND] == "connect"
    assert case.provider.creates == 0
    assert [value["stage"] for value in case.github.selection_history] == [
        "initializing",
        "discovery",
        "genesis",
        "active",
    ]
    proof = cast(dict[str, object], case.github.selection_history[-1]["receipt"])
    assert proof["forged_author_ignored"] is True and proof["shared_forged_author_ignored"] is True
    assert case.shared.posts == 2


def test_lost_discovery_reply_does_not_duplicate_remote_operation_or_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.github.fail_after_dispatch = True
    case.activation().activate(case.output)
    assert len(case.github.executions) == 3 and case.shared.posts == 2
    prior = json.loads(case.github.values[control.SETTING])
    case.activation().activate(case.output)
    assert case.shared.posts == 2
    assert json.loads(case.github.values[control.SETTING]) == prior
    assert case.provider.creates == 0


def pause_before_discovery(case: Case, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    stage = ConnectLedger.stage

    def interrupt(
        ledger: ConnectLedger, record: dict[str, object], *, claimed_author: str | None = None
    ) -> None:
        stage(ledger, record, claimed_author=claimed_author)
        raise LifecycleError("interrupted before discovery")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(ConnectLedger, "stage", interrupt)
        with pytest.raises(LifecycleError, match="interrupted before discovery"):
            case.activation().activate(case.output)
    assert not case.github.executions and case.shared.posts == 1
    return read_private(case.path / "activation/probes.json")


def test_initializing_helper_upgrade_preserves_probes_spool_and_existing_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    probes = pause_before_discovery(case, monkeypatch)
    before = json.loads(case.github.values[control.SETTING])
    files = {path: path.read_bytes() for path in (case.path / "activation/journal").iterdir()}
    case.shared.reported_count = 1
    case.activation(helper="f" * 40).activate(case.output)
    selected = json.loads(case.github.values[control.SETTING])
    assert selected["request"]["epoch"] == cast(dict[str, object], probes["shared"])["run_id"]
    assert selected["request"]["shared_probe"] == probes["shared"]
    assert selected["request"]["independent_probe"] == probes["independent"]
    assert selected["request"]["helper_revision"] == "f" * 40
    audit = read_private(case.path / "activation" / ("initializing-upgrade-" + "f" * 40 + ".json"))
    assert audit["previous"] == before
    assert audit["selected"] == {**before, "active_helper": "f" * 40}
    assert all(path.read_bytes() == value for path, value in files.items())
    assert case.shared.posts == 2 and len(case.github.executions) == 3
    assert case.provider.creates == 0 and Configuration.load(case.output).targets == TARGETS


@pytest.mark.parametrize("fault", ["before", "after", "discovery-request"])
def test_initializing_upgrade_interruption_reconciles_without_replacing_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    probes = pause_before_discovery(case, monkeypatch)
    publish = case.github.set_variable

    def interrupt(name: str, value: str) -> None:
        upgrading = name == control.SETTING and json.loads(value)["stage"] == "initializing"
        if upgrading and fault == "before":
            raise LifecycleError("interrupted publication")
        publish(name, value)
        if upgrading and fault == "after":
            raise LifecycleError("lost publication response")

    if fault == "discovery-request":
        activation = case.activation(helper="f" * 40)
        activation.quiesce()
        activation.discovery()
    else:
        with monkeypatch.context() as interrupted:
            interrupted.setattr(case.github, "set_variable", interrupt)
            with pytest.raises(LifecycleError):
                case.activation(helper="f" * 40).activate(case.output)
    assert not case.github.executions
    case.activation(helper="f" * 40).activate(case.output)
    assert read_private(case.path / "activation/probes.json") == probes
    assert case.shared.posts == 2 and case.provider.creates == 0


@pytest.mark.parametrize(
    "fault",
    [
        "old-unmerged",
        "targets",
        "receipt",
        "stage",
        "inputs",
        "missing-probes",
        "epoch",
        "actor",
        "same-id",
        "spool",
        "extra-spool",
        "independent",
        "ack",
        "intent",
        "discovery-request",
        "discovery",
        "genesis",
        "shared-forgery.json",
    ],
)
def test_initializing_upgrade_refuses_changed_bindings_history_or_missing_evidence(  # noqa: PLR0912 - boundary fault matrix
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    probes = pause_before_discovery(case, monkeypatch)
    directory = case.path / "activation"
    shared = cast(dict[str, object], probes["shared"])
    selected = json.loads(case.github.values[control.SETTING])
    if fault == "old-unmerged":
        case.github.allowed.remove(HELPER)
    elif fault == "targets":
        selected["request"]["targets_sha256"] = "0" * 64
    elif fault == "receipt":
        selected["receipt"] = {}
    elif fault == "stage":
        selected["stage"] = "genesis"
    elif fault in {"inputs", "missing-probes"}:
        (directory / ("inputs.json" if fault == "inputs" else "probes.json")).unlink()
    elif fault in {"epoch", "actor", "same-id"}:
        independent = cast(dict[str, object], probes["independent"])
        if fault == "epoch":
            independent["run_id"] = str(uuid.uuid7())
        elif fault == "actor":
            cast(dict[str, object], independent["payload"])["actor"] = "shared"
        else:
            independent["event_id"] = shared["event_id"]
        (directory / "probes.json").unlink()
        write_private(directory / "probes.json", probes)
    elif fault in {"spool", "extra-spool"}:
        path = directory / "journal" / (str(shared["event_id"]) + ".json")
        if fault == "spool":
            path.unlink()
        else:
            write_private(path.with_name("unexpected.json"), {})
    elif fault in {"independent", "ack", "intent"}:
        row = (
            cast(dict[str, object], probes["independent"])
            if fault == "independent"
            else event("intent" if fault == "intent" else "heartbeat", str(shared["run_id"]), {})
        )
        case.shared.items["b" * 26] = note(row, "b" * 26)
        case.shared.version += 1
    elif fault == "discovery-request":
        case.activation().discovery()
    else:
        # Even a submitted operation without a receipt prohibits helper migration.
        path = directory / fault
        path.mkdir() if "." not in fault else write_private(path, {})
    case.github.values[control.SETTING] = json.dumps(selected)
    before = dict(case.github.values)
    with pytest.raises((LifecycleError, ValueError, OSError)):
        case.activation(helper="f" * 40).activate(case.output)
    if fault == "inputs":
        assert not (directory / "inputs.json").exists()
    assert case.github.values == before
    assert case.shared.posts == 1 and not case.github.executions
    assert case.provider.creates == 0 and not case.output.exists()


@pytest.mark.parametrize("fault", ["probe", "spool", "inventory", "audit", "other-upgrade"])
def test_interrupted_initializing_upgrade_requires_exact_retained_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    probes = pause_before_discovery(case, monkeypatch)
    case.activation(helper="f" * 40).quiesce()
    directory = case.path / "activation"
    if fault == "inventory":
        del case.shared.items[str(1).zfill(26)]
    elif fault == "other-upgrade":
        write_private(directory / ("initializing-upgrade-" + "e" * 40 + ".json"), {})
    else:
        path = {
            "probe": directory / "probes.json",
            "spool": directory
            / "journal"
            / (str(cast(dict[str, object], probes["shared"])["event_id"]) + ".returned.json"),
            "audit": directory / ("initializing-upgrade-" + "f" * 40 + ".json"),
        }[fault]
        path.unlink()
        write_private(path, {"changed": True})
    before = dict(case.github.values)
    with pytest.raises((LifecycleError, ValueError, KeyError)):
        case.activation(helper="f" * 40).activate(case.output)
    assert case.github.values == before and case.shared.posts == 1
    assert case.provider.creates == 0 and not case.github.executions


@pytest.mark.parametrize(
    "fault",
    [
        "discovery-receipt",
        "before-stage",
        "after-stage",
        "genesis-dispatch",
        "genesis-receipt",
        "active-publication",
    ],
)
@pytest.mark.parametrize("coordinator", [HELPER, "f" * 40])
def test_interrupted_activation_resumes_exact_probes_genesis_and_dispatch(  # noqa: PLR0915 - exercise each real persistence boundary
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str, coordinator: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    stage, dispatch = ConnectLedger.stage, case.github.dispatch
    receipt, publish = case.github.receipt, case.github.set_variable

    def interrupted_stage(
        ledger: ConnectLedger, record: dict[str, object], *, claimed_author: str | None = None
    ) -> None:
        forged = cast(dict[str, object], record["payload"]).get("actor") == "shared-forgery"
        if forged and fault == "before-stage":
            raise LifecycleError("interrupted activation")
        stage(ledger, record, claimed_author=claimed_author)
        if forged and fault == "after-stage":
            raise LifecycleError("interrupted activation")

    def interrupted_dispatch(
        directory: Path, *, operation: str, selection: dict[str, object], run_sha256: str = ""
    ) -> dict[str, object]:
        if operation == "genesis" and fault == "genesis-dispatch":
            raise LifecycleError("interrupted activation")
        return dispatch(directory, operation=operation, selection=selection, run_sha256=run_sha256)

    def interrupted_receipt(run_id: int) -> dict[str, object]:
        value = receipt(run_id)
        if fault == str(value["operation"]) + "-receipt":
            raise LifecycleError("interrupted activation")
        return value

    def interrupted_publication(name: str, value: str) -> None:
        if (
            name == control.SETTING
            and json.loads(value)["stage"] == "active"
            and fault == "active-publication"
        ):
            raise LifecycleError("interrupted activation")
        publish(name, value)

    with monkeypatch.context() as interrupted:
        interrupted.setattr(ConnectLedger, "stage", interrupted_stage)
        interrupted.setattr(case.github, "dispatch", interrupted_dispatch)
        interrupted.setattr(case.github, "receipt", interrupted_receipt)
        interrupted.setattr(case.github, "set_variable", interrupted_publication)
        with pytest.raises(LifecycleError, match="interrupted activation"):
            case.activation().activate(case.output)
    assert not case.output.exists()
    directory = case.path / "activation"
    retained = {path: path.read_bytes() for path in directory.rglob("*.json")}
    original_genesis = [
        row["proof"] for row in case.github.receipts.values() if row["operation"] == "genesis"
    ]
    case.activation(helper=coordinator).activate(case.output)
    selected = json.loads(case.github.values[control.SETTING])
    assert selected["request"]["shared_forgery_probe"] == read_private(
        directory / "shared-forgery.json"
    )
    assert (
        selected["request"]["epoch"] == read_private(directory / "discovery-request.json")["epoch"]
    )
    assert all(path.read_bytes() == value for path, value in retained.items())
    assert selected["active_helper"] == coordinator
    assert selected["request"]["helper_revision"] == HELPER
    assert selected["request"]["registry_revision"] == HELPER
    assert selected["receipt"]["helper_revision"] == HELPER
    assert [value["helper_revision"] for value in case.github.receipts.values()] == [
        HELPER,
        HELPER,
        coordinator,
    ]
    if coordinator != HELPER:
        audit = read_private(directory / ("coordinator-resume-" + coordinator + ".json"))
        assert audit["stage_helper_revision"] == HELPER
        assert audit["coordinator_revision"] == coordinator
        assert audit["files"] == {
            str(path.relative_to(directory)): digest(json.loads(value))
            for path, value in retained.items()
        }
        assert all(
            value["active_helper"] == HELPER
            for value in case.github.selection_history
            if value["stage"] != "active"
        )
    if original_genesis:
        assert selected["receipt"] == original_genesis[0]
    assert len(case.github.executions) == 3 and case.shared.posts == 2
    assert Configuration.load(case.output).targets == TARGETS
    assert case.provider.creates == 0


@pytest.mark.parametrize("fault", ["epoch", "author", "unrelated", "native-author"])
def test_activation_retry_rejects_changed_probe_or_unrelated_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    stage = ConnectLedger.stage

    def interrupt(
        ledger: ConnectLedger, record: dict[str, object], *, claimed_author: str | None = None
    ) -> None:
        if cast(dict[str, object], record["payload"]).get("actor") == "shared-forgery":
            raise LifecycleError("interrupted activation")
        stage(ledger, record, claimed_author=claimed_author)

    with monkeypatch.context() as interrupted:
        interrupted.setattr(ConnectLedger, "stage", interrupt)
        with pytest.raises(LifecycleError, match="interrupted activation"):
            case.activation().activate(case.output)
    path = case.path / "activation/shared-forgery.json"
    forged = read_private(path)
    if fault in {"epoch", "author"}:
        payload = cast(dict[str, object], forged["payload"])
        payload["epoch" if fault == "epoch" else "claimed_author"] = (
            str(uuid.uuid7()) if fault == "epoch" else "X" * 26
        )
        path.unlink()
        write_private(path, forged)
    else:
        record = forged if fault == "native-author" else event("run", str(uuid.uuid7()), {})
        identifier = "8".zfill(26)
        case.shared.items[identifier] = note(record, identifier, author="X" * 26)
        case.shared.version += 1
    monkeypatch.setattr(action, "SYNC_SECONDS", 0)
    with pytest.raises(LifecycleError):
        case.activation().activate(case.output)
    assert not case.output.exists()
    assert len(case.github.executions) == 1 and case.provider.creates == 0


def pause_at_discovery_receipt(case: Case, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(_run_id: int) -> dict[str, object]:
        raise LifecycleError("interrupted receipt readback")

    with monkeypatch.context() as stopped:
        stopped.setattr(case.github, "receipt", interrupt)
        with pytest.raises(LifecycleError, match="interrupted receipt readback"):
            case.activation().activate(case.output)
    assert len(case.github.executions) == 1 and case.shared.posts == 1


@pytest.mark.parametrize(
    "fault",
    ["after-audit", "genesis-receipt", "old-before", "old-after", "new-before", "new-after"],
)
def test_successor_coordinator_restarts_without_rebinding_or_replaying_the_ceremony(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    pause_at_discovery_receipt(case, monkeypatch)
    directory = case.path / "activation"
    original_files = {path: path.read_bytes() for path in directory.rglob("*.json")}
    initialize, publish, receipt = (
        activate.Activation.initialize,
        case.github.set_variable,
        case.github.receipt,
    )

    def initialize_or_stop(self: activate.Activation) -> dict[str, object]:
        if self.helper == HELPER and fault == "after-audit":
            raise LifecycleError("interrupted coordinator")
        return initialize(self)

    def receipt_or_stop(run_id: int) -> dict[str, object]:
        value = receipt(run_id)
        if value["operation"] == "genesis" and fault == "genesis-receipt":
            raise LifecycleError("interrupted coordinator")
        return value

    def publish_or_stop(name: str, value: str) -> None:
        selected = json.loads(value) if name == control.SETTING else {}
        affected = selected.get("stage") == "active" and selected.get("active_helper") == (
            HELPER if fault.startswith("old-") else "f" * 40
        )
        if affected and fault.endswith("-before"):
            raise LifecycleError("interrupted coordinator")
        publish(name, value)
        if affected and fault.endswith("-after"):
            raise LifecycleError("interrupted coordinator")

    with monkeypatch.context() as stopped:
        stopped.setattr(activate.Activation, "initialize", initialize_or_stop)
        stopped.setattr(case.github, "receipt", receipt_or_stop)
        stopped.setattr(case.github, "set_variable", publish_or_stop)
        with pytest.raises(LifecycleError, match="interrupted coordinator"):
            case.activation(helper="f" * 40).activate(case.output)
    assert not case.output.exists()
    audit_path = directory / ("coordinator-resume-" + "f" * 40 + ".json")
    audit = audit_path.read_bytes()
    case.activation(helper="f" * 40).activate(case.output)
    assert audit_path.read_bytes() == audit
    assert all(path.read_bytes() == value for path, value in original_files.items())
    assert len(case.github.executions) == 3 and case.shared.posts == 2
    assert [value["helper_revision"] for value in case.github.receipts.values()] == [
        HELPER,
        HELPER,
        "f" * 40,
    ]
    assert Configuration.load(case.output).targets == TARGETS
    assert case.provider.creates == 0


@pytest.mark.parametrize(
    "fault",
    ["old-unmerged", "new-unmerged", "inputs", "request", "probes", "spool", "targets", "intent"],
)
def test_successor_coordinator_refuses_missing_or_changed_original_authority_and_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    pause_at_discovery_receipt(case, monkeypatch)
    directory = case.path / "activation"
    if fault.endswith("-unmerged"):
        case.github.allowed.remove(HELPER if fault == "old-unmerged" else "f" * 40)
    elif fault == "intent":
        intent = event("intent", str(uuid.uuid7()), {})
        case.shared.items["8" * 26] = note(intent, "8" * 26)
        case.shared.version += 1
    elif fault == "targets":
        selected = json.loads(case.github.values[control.SETTING])
        selected["request"]["targets_sha256"] = "b" * 64
        case.github.values[control.SETTING] = json.dumps(selected)
    else:
        paths = {
            "inputs": "inputs.json",
            "request": "discovery-request.json",
            "probes": "probes.json",
        }
        path = (
            directory / paths[fault]
            if fault in paths
            else next((directory / "journal").glob("*.json"))
        )
        path.unlink()
    before = dict(case.github.values)
    with pytest.raises((LifecycleError, ValueError, OSError)):
        case.activation(helper="f" * 40).activate(case.output)
    assert case.github.values == before
    assert len(case.github.executions) == 1 and case.shared.posts == 1
    assert case.provider.creates == 0 and not case.output.exists()


@pytest.mark.parametrize("fault", ["file", "missing-file", "audit", "audit-selection"])
def test_successor_coordinator_requires_its_immutable_recovery_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    pause_at_discovery_receipt(case, monkeypatch)

    def interrupt(_self: activate.Activation) -> dict[str, object]:
        raise LifecycleError("interrupted after audit")

    with monkeypatch.context() as stopped:
        stopped.setattr(activate.Activation, "initialize", interrupt)
        with pytest.raises(LifecycleError, match="interrupted after audit"):
            case.activation(helper="f" * 40).activate(case.output)
    directory = case.path / "activation"
    path = directory / (
        "coordinator-resume-" + "f" * 40 + ".json"
        if fault.startswith("audit")
        else "discovery/dispatch.json"
    )
    value = read_private(path)
    if fault == "audit-selection":
        request = cast(
            dict[str, object], cast(dict[str, object], value["original_selection"])["request"]
        )
        request["epoch"] = str(uuid.uuid7())
    else:
        value["unexpected"] = True
    path.unlink()
    if fault != "missing-file":
        write_private(path, value)
    before = dict(case.github.values)
    with pytest.raises((LifecycleError, ValueError, KeyError)):
        case.activation(helper="f" * 40).activate(case.output)
    assert case.github.values == before
    assert len(case.github.executions) == 1 and case.shared.posts == 1
    assert case.provider.creates == 0 and not case.output.exists()


def test_final_legacy_heartbeat_reaches_genesis_after_delayed_shared_synchronization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.late_heartbeat = event(
        "heartbeat",
        str(uuid.uuid7()),
        {
            "actor": "github",
            "helper_revision": "0" * 40,
            "observed_at": stamp(datetime.now(UTC)),
            "status": "ready",
            "overdue": 0,
            "results": [],
        },
    )
    case.defer_discovery_sync = True
    monkeypatch.setattr(time, "sleep", lambda _seconds: sync(case.remote, case.shared))
    case.activation().activate(case.output)
    discovery = read_private(case.path / "activation/discovery-request.json")
    selected = json.loads(case.github.values[control.SETTING])
    event_id = str(case.late_heartbeat["event_id"])
    assert event_id not in cast(dict[str, str], discovery["initial"])
    assert selected["receipt"]["initial"][event_id] == digest(case.late_heartbeat)
    assert selected["request"]["initial"][event_id] == digest(case.late_heartbeat)
    assert case.provider.creates == 0


def test_reviewed_helper_upgrade_preserves_genesis_and_private_previous_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.activation().activate(case.output)
    old = read_private(case.output)
    selected = json.loads(case.github.values[control.SETTING])
    case.activation(helper="f" * 40).activate(case.output)
    current = json.loads(case.github.values[control.SETTING])
    assert current == {**selected, "active_helper": "f" * 40}
    assert (
        read_private(case.path / "activation" / ("previous-controller-" + digest(old) + ".json"))
        == old
    )
    assert (
        Configuration.load(case.output).cleanup.connect_settings
        != Configuration.load(
            case.path / "activation" / ("previous-controller-" + digest(old) + ".json")
        ).cleanup.connect_settings
    )
    assert case.shared.posts == 2 and case.provider.creates == 0


@pytest.mark.parametrize("fault", ["before", "after"])
def test_interrupted_helper_publication_keeps_independent_cleanup_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.activation().activate(case.output)
    previous = read_private(case.output)
    publish = case.github.set_variable

    def interrupt(name: str, value: str) -> None:
        if name == control.SETTING and fault == "before":
            raise LifecycleError("interrupted publication")
        publish(name, value)
        if name == control.SETTING:
            raise LifecycleError("lost publication response")

    monkeypatch.setattr(case.github, "set_variable", interrupt)
    with pytest.raises(LifecycleError):
        case.activation(helper="f" * 40).activate(case.output)
    selected = json.loads(case.github.values[control.SETTING])
    helper = selected["active_helper"]
    assert helper == (HELPER if fault == "before" else "f" * 40)
    assert case.github.values[control.HELPER] == "0" * 40
    assert read_private(case.output) == previous
    # A separate scheduled execution needs neither the interrupted activation
    # process nor the old legacy pin to reach provider reconciliation.
    directory = tmp_path / "independent-after-interruption"
    dispatch = case.github.dispatch(directory, operation="reconcile", selection=selected)
    assert case.github.wait(dispatch, helper=helper, directory=directory)["status"] == "ready"


def test_unmerged_helper_and_changed_protected_targets_cannot_activate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    with pytest.raises(LifecycleError, match="not merged"):
        case.activation(helper="e" * 40)
    assert case.shared.posts == 0
    case.activation().activate(case.output)
    selected = json.loads(case.github.values[control.SETTING])
    selected["request"]["targets_sha256"] = "0" * 64
    case.github.values[control.SETTING] = json.dumps(selected)
    with pytest.raises(LifecycleError):
        case.activation().activate(case.output)


def test_existing_credential_intents_prevent_any_new_genesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    activation = case.activation()
    activation.ledger.stage(event("intent", str(uuid.uuid7()), {"unresolved": True}))
    with pytest.raises(LifecycleError, match="existing obligations"):
        activation.activate(case.output)
    assert not case.github.executions and not case.output.exists()


def test_failed_independent_readiness_leaves_controller_uninstalled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    monkeypatch.setattr(action, "SYNC_SECONDS", 0)
    monkeypatch.setattr(activate.Activation, "ready", lambda *_args: False)
    with pytest.raises(LifecycleError, match="unproven"):
        case.activation().activate(case.output)
    assert not case.output.exists()
    assert case.github.values[control.BACKEND] == "connect"
    assert case.provider.creates == 0


def test_unrelated_private_controller_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    write_private(case.output, {"unrelated": CANARY})
    with pytest.raises(ValueError):
        case.activation().activate(case.output)
    assert read_private(case.output) == {"unrelated": CANARY}


@pytest.mark.parametrize("fault", ["none", "dispatch", "execution", "attempt", "stopped"])
def test_launcher_requires_current_durable_witness_for_exact_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.activation().activate(case.output)
    configuration = Configuration.load(case.output)
    run_id = str(uuid.uuid7())
    request: dict[str, object] = {
        "binding": {
            "managed_run_id": run_id,
            "source_revision": HELPER,
            "helper_revision": HELPER,
            "qualification_inputs_sha256": "d" * 64,
            "artifact_sha256": "e" * 64,
            "storage_target_sha256": TARGETS.storage_digest,
        },
        "mode": "rehearsal",
        "approval_sha256": "c" * 64,
    }
    reconcile = action.reconcile

    def altered(*args: object, **kwargs: object) -> dict[str, object]:
        if fault == "dispatch":
            kwargs["dispatch_id"] = str(uuid.uuid7())
        elif fault == "execution":
            kwargs["run_id"] = 99
        elif fault == "attempt":
            kwargs["attempt"] = 2
        return reconcile(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(action, "reconcile", altered)
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    monkeypatch.setattr(control, "GitHub", lambda: case.github)
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(control, "POLL_SECONDS", 0)
    if fault == "stopped":
        run = case.github.run

        def stopped(run_id: int) -> dict[str, object]:
            return {**run(run_id), "status": "completed"}

        monkeypatch.setattr(case.github, "run", stopped)
    path = tmp_path / "dispatch" / run_id
    if fault == "none":
        control.await_witness(configuration, request, directory=path)
        proof = read_private(path / "witness-ready.json")
        assert proof["github_run_id"] == 4
    else:
        with pytest.raises(LifecycleError):
            control.await_witness(configuration, request, directory=path)
        assert not (path / "witness-ready.json").exists()
    assert case.provider.creates == 0
