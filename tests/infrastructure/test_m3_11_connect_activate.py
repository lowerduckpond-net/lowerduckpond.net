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
