"""Durable stage identity survives interrupts; observation never resubmits."""

from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts import m3_11_frozen_stage as stage
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_retirement_files import digest, record


@pytest.mark.parametrize("boundary", ["plan", "approval", "published"])
def test_interrupted_stage_publication_can_only_continue_same_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    tmp_path.chmod(0o700)
    root = tmp_path / "stage"
    plan: dict[str, object] = {"plan": "bound"}
    approval: dict[str, object] = {"approval": "bound"}
    original_record, original_rename = record, _rename_noreplace

    def interrupted_record(path: Path, value: dict[str, object]) -> None:
        original_record(path, value)
        if path.name == ("plan.json" if boundary == "plan" else "authorization.json"):
            raise KeyboardInterrupt

    def interrupted_plan(path: Path, value: dict[str, object], *, maximum: int) -> None:
        write_private(path, value, maximum=maximum)
        if boundary == "plan":
            raise KeyboardInterrupt

    def interrupted_rename(parent: int, source: str, target: str) -> None:
        original_rename(parent, source, target)
        raise KeyboardInterrupt

    monkeypatch.setattr(
        stage, "record", original_record if boundary == "published" else interrupted_record
    )
    monkeypatch.setattr(stage, "write_private", interrupted_plan)
    if boundary == "published":
        monkeypatch.setattr(stage, "_rename_noreplace", interrupted_rename)
    with pytest.raises(KeyboardInterrupt):
        stage.initialize(root, plan, approval)
    retained = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    assert retained and not list(tmp_path.rglob("*.submitted.json"))
    monkeypatch.setattr(stage, "record", original_record)
    monkeypatch.setattr(stage, "write_private", write_private)
    monkeypatch.setattr(stage, "_rename_noreplace", original_rename)
    stage.initialize(root, plan, approval, continuing=True)
    assert read_private(root / "plan.json") == plan
    assert read_private(root / "authorization.json") == approval
    assert all(path.read_bytes() == value for path, value in retained.items())
    with pytest.raises(FileExistsError, match="no replay"):
        stage.initialize(root, plan, approval)
    with pytest.raises(ValueError, match="authority differs"):
        stage.initialize(root, {"plan": "changed"}, approval, continuing=True)


@pytest.mark.parametrize("boundary", ["before-effect", "committed", "after-response"])
def test_interruption_consumes_exact_identity_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    tmp_path.chmod(0o700)
    ledger = stage.Effects(tmp_path, plan={"synthetic": 1}, approval={"synthetic": 2})
    identity: dict[str, object] = {"id": "a" * 64}
    calls = []

    def mutate() -> None:
        if boundary != "before-effect":
            calls.append(identity)
        if boundary != "after-response":
            raise KeyboardInterrupt

    if boundary == "after-response":

        def interrupted_record(*_args: object) -> None:
            raise KeyboardInterrupt

        monkeypatch.setattr(stage, "record", interrupted_record)
    with pytest.raises(KeyboardInterrupt):
        ledger.submit("remove-container-" + "a" * 64, identity, mutate)
    original = read_private(tmp_path / ("remove-container-" + "a" * 64 + ".submitted.json"))
    assert original["identity"] == identity
    assert original["plan_sha256"] == digest({"synthetic": 1})
    for absent in (False, True):
        receipt = ledger.observe("remove-container-" + "a" * 64, identity, absent=absent)
        assert receipt["mutation_submissions"] == 0 and receipt["absent"] is absent
    with pytest.raises(FileExistsError):
        ledger.submit("remove-container-" + "a" * 64, identity, mutate)
    assert len(calls) == (boundary != "before-effect")
    assert not list(tmp_path.glob("*.acknowledged.json"))


def test_absence_needs_original_exact_submission(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    ledger = stage.Effects(tmp_path, plan={}, approval={})
    with pytest.raises(ValueError, match="original exact"):
        ledger.observe("remove-directory", {"path": "synthetic"}, absent=True)
    ledger.submit("remove-directory", {"path": "synthetic"}, lambda: None)
    with pytest.raises(ValueError, match="ambiguous or changed"):
        ledger.observe("remove-directory", {"path": "another"}, absent=True)


def test_large_authority_does_not_expand_ordinary_approval_or_unbounded_plan_limits(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    with pytest.raises(ValueError, match="byte bound"):
        stage.initialize(tmp_path / "oversized", {"data": "x" * stage.MAX_PLAN_BYTES}, {})
    assert not (tmp_path / "oversized").exists()
    with pytest.raises(ValueError, match="exceeds its bound"):
        stage.initialize(tmp_path / "approval", {}, {"data": "x" * (256 * 1024)})
    assert not (tmp_path / "approval").exists()
    assert not list(tmp_path.rglob("*.submitted.json"))


def test_old_human_approval_is_not_an_operational_deadline() -> None:
    plan: dict[str, object] = {"synthetic": "exact"}
    approved = {
        "format": stage.AUTHORIZATION,
        "stage": "local-disposal",
        "plan_sha256": digest(plan),
        "approval_reference_sha256": "b" * 64,
        "approved_at": "2020-01-01T00:00:00Z",
        "acknowledge_irreversible_scoped_removal": True,
        "acknowledge_execution_remains_excluded": True,
        "acknowledge_no_automatic_replay": True,
    }
    assert stage.authorization(approved, plan, stage="local-disposal") == approved
    with pytest.raises(ValueError, match="separate effect authority"):
        stage.authorization(approved, plan, stage="remote-cleanup")
