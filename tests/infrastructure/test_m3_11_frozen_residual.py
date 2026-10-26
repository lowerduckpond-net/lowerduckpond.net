"""Per-entry interruption boundaries, preserved bytes and no mutation replay."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import m3_11_frozen_export as export
from scripts import m3_11_frozen_stage as stage
from scripts.m3_11_frozen_residual import Residual
from scripts.m3_11_frozen_retirement import reserve
from scripts.m3_11_retirement_files import record


@pytest.fixture
def case(tmp_path: Path) -> SimpleNamespace:
    root, saved, ledger = (tmp_path / name for name in ("source", "saved", "ledger"))
    root.mkdir(mode=0o700)
    ledger.mkdir(mode=0o700)
    (root / "nested").mkdir()
    (root / "nested/first").write_bytes(b"original content")
    (root / "other").write_bytes(b"second original")
    (root / "link").symlink_to("nested/first")
    limits = export.Limits(10000, 100)
    manifest = export.preserve(root, saved, limits=limits, guard=lambda: None)
    effects = stage.Effects(ledger, plan={"synthetic": True}, approval={"synthetic": "approved"})
    return SimpleNamespace(
        root=root,
        saved=saved,
        ledger=ledger,
        limits=limits,
        manifest=manifest,
        effects=effects,
        residual=Residual(root, manifest, effects, lambda: None),
    )


def test_exact_tree_disposal_preserves_all_bytes_and_intents(case: SimpleNamespace) -> None:
    result = case.residual.remove_unsubmitted()
    assert result["unsubmitted"] == result["pending"] == []
    assert not case.root.exists() and "." in result["absent"]
    assert (
        export.verify_preserved(case.saved, limits=case.limits, guard=lambda: None) == case.manifest
    )
    assert len(list(case.ledger.glob("*.submitted.json"))) == len(case.manifest["entries"]) + 1


@pytest.mark.parametrize("point", ["entry", "root"])
def test_lost_result_is_observed_without_replaying_then_only_unsubmitted_continue(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, point: str
) -> None:
    original = record
    failed = False

    def fail(path: Path, value: dict[str, object]) -> None:
        nonlocal failed
        match = (
            path.name.startswith("remove-entry-")
            if point == "entry"
            else path.name == "remove-directory.acknowledged.json"
        )
        if match and not failed:
            failed = True
            raise KeyboardInterrupt
        original(path, value)

    monkeypatch.setattr(stage, "record", fail)
    with pytest.raises(KeyboardInterrupt):
        case.residual.remove_unsubmitted()
    before = {path.name: path.read_bytes() for path in case.ledger.iterdir()}
    state = case.residual.observe()
    assert state["absent"] and not state["pending"]
    assert before == {path.name: path.read_bytes() for path in case.ledger.iterdir()}
    case.residual.remove_unsubmitted()  # Explicit continuation, never a callback.
    assert not case.root.exists()
    for name, body in before.items():
        assert (case.ledger / name).read_bytes() == body
    assert len(list(case.ledger.glob("*.acknowledged.json"))) == len(case.manifest["entries"])


def test_reserved_but_present_entry_stops_continuation(case: SimpleNamespace) -> None:
    row = next(row for row in case.manifest["entries"] if row["type"] == "file")
    name, identity = case.residual.slot(row)
    reserve(case.ledger / (name + ".submitted.json"), case.effects._value(name, identity))
    state = case.residual.observe()
    assert state["pending"] == [row["path"]]
    before = {path.name: path.read_bytes() for path in case.ledger.iterdir()}
    with pytest.raises(ValueError, match="submitted entries remain"):
        case.residual.remove_unsubmitted()
    assert before == {path.name: path.read_bytes() for path in case.ledger.iterdir()}


@pytest.mark.parametrize(
    "change", ["new-file", "same-inode-bytes", "root-replaced", "missing-original"]
)
def test_changed_source_fails_before_any_removal(case: SimpleNamespace, change: str) -> None:
    if change == "new-file":
        (case.root / "new").write_bytes(b"not in evidence")
    elif change == "same-inode-bytes":
        (case.root / "other").write_bytes(b"altered original")
    elif change == "root-replaced":
        case.root.rename(case.root.with_name("old"))
        case.root.mkdir(mode=0o700)
    else:
        (case.root / "other").unlink()
    with pytest.raises((ValueError, OSError)):
        case.residual.remove_unsubmitted()
    assert not list(case.ledger.iterdir())
