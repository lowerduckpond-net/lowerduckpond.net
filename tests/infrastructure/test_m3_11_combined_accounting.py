"""Retained source inputs and final live accounting cannot be assumed empty."""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest

from scripts import m3_11_pending_probe as pending
from scripts.m3_11_private_inputs import write_private


@pytest.fixture
def roots(tmp_path: Path) -> dict[str, Path]:
    result = {name: tmp_path / name for name in pending.ROOTS}
    for path in result.values():
        path.mkdir(mode=0o700)
    (result["intake"] / "original.artifact").write_bytes(b"excluded pending source intake")
    (result["exports"] / "original.bundle").write_bytes(b"unacknowledged original source export")
    return result


@pytest.mark.parametrize("change", ["content", "name", "mode", "empty-file", "remove"])
def test_source_input_observation_is_stable_and_detects_changes(
    roots: dict[str, Path], change: str
) -> None:
    original = pending.capture(roots)
    assert original == pending.capture(roots)
    assert original["files"] == {name: int(name in {"intake", "exports"}) for name in roots}
    path = roots["intake"] / "original.artifact"
    if change == "content":
        path.write_bytes(b"different excluded source input")
    elif change == "name":
        path.rename(path.with_suffix(".changed"))
    elif change == "mode":
        path.chmod(0o400)
    elif change == "empty-file":
        (roots["intents"] / "empty").touch()
    else:
        path.unlink()
    assert pending.capture(roots)["sha256"] != original["sha256"]


@pytest.mark.parametrize("fault", ["symlink-file", "symlink-directory", "hardlink", "fifo"])
def test_source_pending_proof_rejects_indirection_and_special_files(
    roots: dict[str, Path], fault: str
) -> None:
    path = roots["intake"] / "unexpected"
    original = roots["exports"] / "original.bundle"
    if fault == "symlink-file":
        path.symlink_to(original)
    elif fault == "symlink-directory":
        path.symlink_to(roots["exports"], target_is_directory=True)
    elif fault == "hardlink":
        os.link(original, path)
    else:
        os.mkfifo(path)
    with pytest.raises(ValueError, match="regular file or directory"):
        pending.capture(roots)


def test_missing_pending_root_is_not_an_empty_source(roots: dict[str, Path]) -> None:
    roots["staging"].rmdir()
    with pytest.raises(FileNotFoundError):
        pending.capture(roots)


def test_a_source_input_changed_during_hashing_cannot_publish_an_observation(
    roots: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = pending._file_digest

    def change(path: Path, before: os.stat_result) -> str:
        result = original(path, before)
        path.write_bytes(b"changed after its bounded read")
        return result

    monkeypatch.setattr(pending, "_file_digest", change)
    with pytest.raises(ValueError, match="changed during inventory"):
        pending.capture(roots)


@pytest.mark.parametrize("bound", ["MAX_ENTRIES", "MAX_BYTES"])
def test_source_pending_inventory_respects_its_bounds(
    roots: dict[str, Path], monkeypatch: pytest.MonkeyPatch, bound: str
) -> None:
    monkeypatch.setattr(pending, bound, 1)
    with pytest.raises(ValueError, match="bound"):
        pending.capture(roots)


@pytest.fixture
def accounting(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "config/ansible/molecule/m3_8/tests"))
    return importlib.import_module("combined_accounting")


@pytest.mark.parametrize("fault", ["source-inputs", "pair", "provider", "fence", "history", "none"])
def test_paired_receipt_requires_fresh_source_history_and_independent_absence(
    accounting: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    storage = Mock()
    public = Mock(directory=tmp_path, context_sha256="context")
    public.fixture.live_storage = storage
    public.fixture.fence = b"original fence"
    public.fixture.source.file.return_value.content = (
        b"changed" if fault == "fence" else b"original fence"
    )
    writer, observer = Mock(), Mock()
    storage.target.clients.return_value = writer, observer
    write_private(tmp_path / "public-ca.json", {"context_sha256": "context"})
    monkeypatch.setattr(
        accounting,
        "_source_inputs",
        Mock(
            side_effect=[
                {"sha256": "original"},
                {"sha256": "changed" if fault == "source-inputs" else "original"},
            ]
        ),
    )
    pair = {"destination": "owned-destination", "acme": "owned-acme"}
    monkeypatch.setattr(
        accounting.owned, "paired_proof", Mock(side_effect=[pair, {} if fault == "pair" else pair])
    )
    monkeypatch.setattr(
        accounting,
        "_protection",
        Mock(
            side_effect=ValueError("history") if fault == "history" else None,
            return_value={"index_sha256": "original"},
        ),
    )
    provider = Mock(side_effect=ValueError("provider") if fault == "provider" else None)
    monkeypatch.setattr(accounting, "assert_storage_empty", provider)
    observations: dict[str, object] = {}

    @contextmanager
    def phase(name: str) -> Iterator[dict[str, object]]:
        assert name == "paired-accounting"
        yield observations

    recorder = Mock(phase=phase)
    if fault != "none":
        with pytest.raises(ValueError):
            accounting.run(public, storage, recorder, {})
        assert not observations
        assert not (tmp_path / "paired-accounting.json").exists()
    else:
        result = accounting.run(public, storage, recorder, {})
        assert result["source_pending_inputs_sha256"] == "original"
        assert result["destination_quarantine"] is False
        assert observations["accounting"] == result
        provider.assert_called_once_with(observer, bucket=storage.target.archive_bucket)
        assert (tmp_path / "paired-accounting.json").is_file()


@pytest.mark.parametrize("changed", ["protected_segments", "index_sha256"])
def test_verified_protection_must_match_the_reconstructed_original(
    accounting: ModuleType, monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    original: dict[str, object] = {"protected_segments": 2, "index_sha256": "original"}
    actual = {**original, "inventory": {}, "snapshot_ids": []}
    actual[changed] = 3 if changed == "protected_segments" else "different"
    monkeypatch.setattr(accounting.audits, "root_agent", Mock(return_value=json.dumps(actual)))
    with pytest.raises(ValueError, match="reconstructed original"):
        accounting._protection(Mock(), original)
