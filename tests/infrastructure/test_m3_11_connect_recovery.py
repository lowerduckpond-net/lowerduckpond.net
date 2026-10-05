"""A failed activation can be replaced only before any registered genesis or children."""

# ruff: noqa: PLR2004 - native operation counts and identities are part of the contract

from __future__ import annotations

import copy
import json
import sys
import uuid
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_connect_activate import HELPER, Case
from infrastructure.test_m3_11_connect_ledger import note
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import connect_activate as activate
from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended import connect_recovery as recovery
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.connect_ledger import ConnectLedger
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import LifecycleError, digest
from scripts.m3_11_unattended.state import replace_private

SUCCESSOR = "f" * 40


class Failed:
    def __init__(
        self,
        path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        history: list[dict[str, object]] | None = None,
    ) -> None:
        self.case = Case(path, monkeypatch)
        for index, record in enumerate(history or [], start=100):
            identifier = str(index).zfill(26)
            self.case.shared.items[identifier] = note(record, identifier)
            self.case.shared.version += 1
        self.original = self.case.activation()

        def fail(_document: dict[str, object]) -> Stored:
            self.case.github.executions[-1]["conclusion"] = "failure"
            raise LifecycleError("upload completed but registry publication failed")

        with monkeypatch.context() as failed:
            failed.setattr(self.case.store, "create", fail)
            # The native failure has no successful receipt to recover.
            with pytest.raises((LifecycleError, KeyError)):
                self.original.activate(self.case.output)
        self.selected = json.loads(self.case.github.values[control.SETTING])
        assert self.selected["stage"] == "genesis"
        assert self.case.provider.creates == 0 and not self.case.store.values
        self.case.github.artifacts = [
            {
                "id": 123,
                "name": "encrypted-orphan-checkpoint",
                "digest": "sha256:" + "1" * 64,
                "workflow_run": {"id": 2},
            }
        ]
        self.statuses: object = []
        api = self.case.github.api

        def registry(
            path: str, *, method: str = "GET", body: object = None, binary: bool = False
        ) -> object:
            if "/statuses?" in path:
                self.case.github.requests.append((method, path, body))
                return copy.deepcopy(self.statuses)
            return api(path, method=method, body=body, binary=binary)

        monkeypatch.setattr(self.case.github, "api", registry)
        self.old_files = self.files()

    def files(self) -> dict[Path, bytes]:
        return {
            path: path.read_bytes() for path in self.original.directory.rglob("*") if path.is_file()
        }

    def successor(self) -> activate.Activation:
        return activate.Activation(
            self.case.bundle,
            helper=SUCCESSOR,
            reference=f"op://{self.original.vaults['journal']}/{self.original.anchor}/notesPlain",
            anchor_sha256=self.original.anchor_sha256,
            directory=self.case.path / "replacement",
            github=self.case.github,
        )

    def complete(self) -> None:
        successor = self.successor()
        recovery.replace_failed(successor, self.original.directory)
        successor.activate(self.case.output)
        active = json.loads(self.case.github.values[control.SETTING])
        assert active["stage"] == "active" and active["active_helper"] == SUCCESSOR
        assert active["request"]["epoch"] != self.selected["request"]["epoch"]
        assert self.case.provider.creates == 0
        assert self.case.github.executions[1]["conclusion"] == "failure"
        assert self.files() == self.old_files


@pytest.mark.parametrize("empty_revoke", [False, True])
def test_replacement_retains_failed_attempt_orphan_and_history_then_repeats_full_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, empty_revoke: bool
) -> None:
    historical = event("revoke", str(uuid.uuid7()), {"reason": "terminal-path"})
    failed = Failed(tmp_path, monkeypatch, history=[historical] if empty_revoke else [])
    before = {str(row["event_id"]): digest(row) for row in failed.original.ledger.records()}
    failed.complete()
    selected = json.loads(failed.case.github.values[control.SETTING])
    audit = read_private(tmp_path / "replacement/failed-activation-replacement.json")
    assert audit["previous_selection"] == failed.selected
    assert audit["previous_files"] == {
        str(path.relative_to(failed.original.directory)): digest(read_private(path))
        for path in failed.old_files
    }
    assert audit["failed_execution"] == {
        key: failed.case.github.executions[1][key]
        for key in ("id", "run_attempt", "head_sha", "status", "conclusion", "updated_at")
    }
    assert audit["failed_artifacts"] == [
        {"id": 123, "name": "encrypted-orphan-checkpoint", "digest": "sha256:" + "1" * 64}
    ]
    assert before.items() <= selected["receipt"]["initial"].items()
    if empty_revoke:
        assert selected["receipt"]["initial"][historical["event_id"]] == digest(historical)
        stored = failed.case.store.latest()
        assert stored is not None
        assert historical in cast(
            list[dict[str, object]], failed.case.store.read(stored)["records"]
        )
    transition = cast(dict[str, object], audit["transition"])
    assert selected["receipt"]["initial"][transition["event_id"]] == digest(transition)
    assert selected["receipt"]["forged_author_ignored"] is True
    assert selected["receipt"]["shared_forged_author_ignored"] is True
    assert [str(run["display_title"]).split()[2] for run in failed.case.github.executions] == [
        "discovery",
        "genesis",
        "discovery",
        "genesis",
        "reconcile",
    ]
    assert not any(method == "DELETE" for method, _, _ in failed.case.github.requests)


@pytest.mark.parametrize("stage", ["transition", "initializing"])
@pytest.mark.parametrize("when", ["before", "after"])
def test_replacement_resumes_same_epoch_across_every_configuration_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, when: str
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    successor = failed.successor()
    publish = failed.case.github.set_variable

    def interrupt(name: str, value: str) -> None:
        selected = json.loads(value) if name == control.SETTING else {}
        matches = selected.get("stage") == stage
        if matches and when == "before":
            raise LifecycleError("publication interrupted")
        publish(name, value)
        if matches and when == "after":
            raise LifecycleError("publication response lost")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(failed.case.github, "set_variable", interrupt)
        with pytest.raises(LifecycleError):
            recovery.replace_failed(successor, failed.original.directory)
    audit = read_private(successor.directory / "failed-activation-replacement.json")
    failed.complete()
    assert read_private(successor.directory / "failed-activation-replacement.json") == audit
    assert len(failed.case.github.executions) == 5


@pytest.mark.parametrize("when", ["before", "after"])
def test_replacement_resumes_immutable_external_transition_after_lost_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    successor = failed.successor()
    stage = ConnectLedger.stage

    def interrupt(
        ledger: ConnectLedger, record: dict[str, object], *, claimed_author: str | None = None
    ) -> None:
        if when == "before":
            raise LifecycleError("transition delivery interrupted")
        stage(ledger, record, claimed_author=claimed_author)
        raise LifecycleError("transition delivery response lost")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(ConnectLedger, "stage", interrupt)
        with pytest.raises(LifecycleError):
            recovery.replace_failed(successor, failed.original.directory)
    audit = read_private(successor.directory / "failed-activation-replacement.json")
    failed.complete()
    assert read_private(successor.directory / "failed-activation-replacement.json") == audit
    transition = cast(dict[str, object], audit["transition"])
    assert failed.successor().ledger.records().count(transition) == 1


@pytest.mark.parametrize("after", [False, True])
def test_registry_publication_before_or_during_draining_forbids_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after: bool
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    registered = [
        {"id": 7, "context": "m3-11/connect-checkpoint/" + failed.selected["request"]["epoch"]}
    ]
    if after:
        monkeypatch.setattr(
            failed.case.github, "drain", lambda: setattr(failed, "statuses", registered)
        )
    else:
        failed.statuses = registered
    with pytest.raises(LifecycleError, match="registered genesis"):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert not failed.case.output.exists() and not failed.case.store.values
    assert len(failed.case.github.executions) == 2 and failed.files() == failed.old_files
    current = json.loads(failed.case.github.values[control.SETTING])
    assert current["stage"] == ("transition" if after else "genesis")


@pytest.mark.parametrize(
    "records",
    [None, {}, [{"id": 1}], [{"id": 1, "context": 12}], [{"id": 1, "context": "other"}] * 100],
)
def test_unavailable_ambiguous_or_incomplete_registry_never_means_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, records: object
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    failed.statuses = records
    before = dict(failed.case.github.values)
    with pytest.raises(LifecycleError):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert failed.case.github.values == before and failed.case.provider.creates == 0


@pytest.mark.parametrize(
    "kind", ["intent", "created", "revoke", "cleanup", "resolved", "empty-revoke"]
)
@pytest.mark.parametrize("hidden", [False, True])
def test_any_credential_history_in_either_replica_blocks_new_genesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, hidden: bool
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    record = event(
        "revoke" if kind == "empty-revoke" else kind,
        str(uuid.uuid7()),
        {"reason": "terminal-path"} if kind == "empty-revoke" else {},
    )
    replica = failed.case.remote if hidden else failed.case.shared
    replica.items["h" * 26] = note(record, "h" * 26)
    replica.version += 1
    successor = failed.successor()
    with pytest.raises((LifecycleError, KeyError)):
        recovery.replace_failed(successor, failed.original.directory)
        successor.activate(failed.case.output)
    assert failed.case.provider.creates == 0 and not failed.case.store.values
    assert not failed.case.output.exists() and failed.files() == failed.old_files


@pytest.mark.parametrize(
    "fault",
    [
        "inputs",
        "probes",
        "spool",
        "request",
        "dispatch",
        "submitted",
        "forgery",
        "targets",
        "old-helper",
        "backend",
        "active",
        "success",
        "running",
        "orphan",
    ],
)
def test_replacement_refuses_changed_bindings_missing_evidence_or_nonfailed_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    directory = failed.original.directory
    if fault in {"inputs", "probes", "request", "dispatch", "submitted", "forgery"}:
        path = (
            directory
            / {
                "inputs": "inputs.json",
                "probes": "probes.json",
                "request": "discovery-request.json",
                "dispatch": "genesis/dispatch.json",
                "submitted": "genesis/submitted.json",
                "forgery": "shared-forgery.json",
            }[fault]
        )
        path.unlink()
    elif fault == "spool":
        probe = failed.selected["request"]["shared_probe"]
        (directory / "journal" / (probe["event_id"] + ".json")).unlink()
    elif fault in {"targets", "active"}:
        selected = copy.deepcopy(failed.selected)
        if fault == "targets":
            selected["request"]["targets_sha256"] = "0" * 64
        else:
            selected["stage"] = "active"
        failed.case.github.values[control.SETTING] = json.dumps(selected)
    elif fault == "old-helper":
        failed.case.github.allowed.remove(HELPER)
    elif fault == "backend":
        failed.case.github.values[control.BACKEND] = "connect"
    elif fault in {"success", "running"}:
        failed.case.github.executions[-1].update(
            status="in_progress" if fault == "running" else "completed", conclusion="success"
        )
    else:
        failed.case.github.artifacts = [{"id": 123}]
    before = dict(failed.case.github.values)
    with pytest.raises((LifecycleError, ValueError, OSError, KeyError)):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert failed.case.github.values == before
    assert failed.case.provider.creates == 0 and not failed.case.output.exists()


def test_draining_rechecks_failed_attempt_and_complete_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    monkeypatch.setattr(
        failed.case.github, "drain", lambda: failed.case.github.executions[-1].update(run_attempt=2)
    )
    with pytest.raises(LifecycleError, match="executed again"):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert not failed.case.output.exists() and failed.case.provider.creates == 0


def test_active_replacement_is_idempotent_and_does_not_repeat_the_ceremony(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    failed.complete()
    old_count = len(failed.case.github.executions)
    failed.complete()
    assert len(failed.case.github.executions) == old_count + 1
    assert str(failed.case.github.executions[-1]["display_title"]).split()[2] == "reconcile"


@pytest.mark.parametrize("fault", ["audit", "old-evidence", "lost-history", "selection"])
def test_interrupted_replacement_cannot_change_its_binding_or_lose_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    successor = failed.successor()
    recovery.replace_failed(successor, failed.original.directory)
    if fault == "audit":
        path = successor.directory / "failed-activation-replacement.json"
        value = read_private(path)
        value["helper_revision"] = "0" * 40
        replace_private(path, value)
    elif fault == "old-evidence":
        write_private(failed.original.directory / "changed.json", {})
    elif fault == "lost-history":
        failed.case.shared.items.pop(str(1).zfill(26))
        failed.case.shared.version += 1
    else:
        selected = json.loads(failed.case.github.values[control.SETTING])
        selected["request"]["anchor_sha256"] = "0" * 64
        failed.case.github.values[control.SETTING] = json.dumps(selected)
    with pytest.raises((LifecycleError, ValueError, KeyError)):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert not failed.case.output.exists() and failed.case.provider.creates == 0


@pytest.mark.parametrize("fault", ["intent", "revoke", "removed-probe", "backend", "selection"])
def test_no_advance_when_history_or_protected_configuration_changes_while_draining(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    failed = Failed(tmp_path, monkeypatch)

    def changed() -> None:
        if fault in {"intent", "revoke"}:
            record = event(
                fault,
                failed.selected["request"]["epoch"],
                {"reason": "terminal-path"} if fault == "revoke" else {},
            )
            failed.case.shared.items["h" * 26] = note(record, "h" * 26)
            failed.case.shared.version += 1
        elif fault == "removed-probe":
            failed.case.shared.items.pop(str(1).zfill(26))
            failed.case.shared.version += 1
        elif fault == "backend":
            failed.case.github.values[control.BACKEND] = "service-account"
        else:
            failed.case.github.values[control.SETTING] = json.dumps(failed.selected)

    monkeypatch.setattr(failed.case.github, "drain", changed)
    with pytest.raises(LifecycleError):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert not failed.case.output.exists() and failed.case.provider.creates == 0
    assert failed.files() == failed.old_files


def test_replacement_cli_serializes_both_sibling_attempts_with_one_parent_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    bootstrap = tmp_path / "bootstrap.json"
    write_private(bootstrap, failed.case.bundle)
    monkeypatch.setattr(activate, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(activate, "GitHub", lambda: failed.case.github)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "connect_activate",
            "--revision",
            SUCCESSOR,
            "--bootstrap",
            str(bootstrap),
            "--manifest-reference",
            f"op://{failed.original.vaults['journal']}/{failed.original.anchor}/notesPlain",
            "--manifest-sha256",
            failed.original.anchor_sha256,
            "--directory",
            str(tmp_path / "replacement"),
            "--output",
            str(failed.case.output),
            "--replace-failed-activation",
            str(failed.original.directory),
        ],
    )
    assert activate.main() == 0
    assert (tmp_path / ".credential-cleanup.lock").is_file()
    assert failed.files() == failed.old_files and failed.case.provider.creates == 0


def test_discovery_recovery_stays_with_its_original_epoch_and_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = Failed(tmp_path, monkeypatch)
    discovery = read_private(failed.original.directory / "discovery-request.json")
    selected = {**failed.selected, "stage": "discovery", "request": discovery}
    failed.case.github.values[control.SETTING] = json.dumps(selected)
    before = dict(failed.case.github.values)
    with pytest.raises(LifecycleError, match="requires failed genesis"):
        recovery.replace_failed(failed.successor(), failed.original.directory)
    assert failed.case.github.values == before and failed.case.provider.creates == 0
