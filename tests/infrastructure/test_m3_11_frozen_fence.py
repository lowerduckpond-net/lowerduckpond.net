"""Real flock boundaries and persistent execution exclusions, no live services."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path

import pytest

from scripts import qualification_fence as fence
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_retirement_files import record
from scripts.qualification_disposition import require_available
from scripts.qualification_mutation import ownership, protected_run


def fixture(root: Path, identity: str | None = None) -> Path:
    run = root / "runs" / str(uuid.uuid7()) / "qualification" / "spaces-synthetic.001"
    run.mkdir(mode=0o700, parents=True)
    write_private(run / "fixture.json", {"run_id": identity or str(uuid.uuid7())})
    return run


def retire(run: Path) -> dict[str, object]:
    with ownership(run, exclusive=True):
        return fence.commit(run, plan_sha256="a" * 64, authorization_sha256="b" * 64)


def test_shared_mutation_prevents_retirement_until_it_finishes(tmp_path: Path) -> None:
    run = fixture(tmp_path)
    with (
        ownership(run),
        ownership(run),
        pytest.raises(BlockingIOError),
        ownership(run, exclusive=True),
    ):
        pytest.fail("exclusive retirement passed an executing consumer")
    retire(run)
    with pytest.raises(ValueError, match="permanently"), ownership(run):
        pytest.fail("later consumer passed persistent exclusion")


def test_retirement_fences_late_consumers_before_marker_and_after_removal(tmp_path: Path) -> None:
    run = fixture(tmp_path)
    with ownership(run, exclusive=True):
        with pytest.raises(BlockingIOError), ownership(run):
            pytest.fail("consumer passed retiring owner")
        value = fence.commit(run, plan_sha256="a" * 64, authorization_sha256="b" * 64)
        shutil.rmtree(run)
        with pytest.raises((BlockingIOError, ValueError)), ownership(run):
            pytest.fail("missing root bypassed still-held lock")
    fence.require_committed(run, value)

    @protected_run
    def consumer(path: Path) -> None:
        path.mkdir()

    with pytest.raises(ValueError, match="permanently"):
        consumer(run)
    run.mkdir(mode=0o700)
    write_private(run / "fixture.json", {"run_id": str(uuid.uuid7())})
    with pytest.raises(ValueError, match="permanently"), ownership(run):
        pytest.fail("directory recreation lost persistent exclusion")


def test_same_immutable_identity_at_another_root_is_excluded(tmp_path: Path) -> None:
    identity = str(uuid.uuid7())
    first, second = fixture(tmp_path, identity), fixture(tmp_path, identity)
    with ownership(second), pytest.raises(BlockingIOError), ownership(first, exclusive=True):
        pytest.fail("alias mutation escaped immutable identity ownership")
    retire(first)
    with pytest.raises(ValueError, match="permanently"), ownership(second):
        pytest.fail("alias escaped immutable identity tombstone")


def test_copied_diagnostic_workspace_uses_original_external_ownership(tmp_path: Path) -> None:
    run = fixture(tmp_path)
    copy = run / "diagnostics/workspace"
    copy.mkdir(mode=0o700, parents=True)
    value: dict[str, object] = {
        "format": "lowerduckpond-m3-11-debug-v1",
        "original_run": str(run),
        "qualification_authority": "none",
    }
    write_private(run / "diagnostic-origin.json", value)
    write_private(copy / "diagnostic-origin.json", value)
    with ownership(copy), pytest.raises(BlockingIOError), ownership(run, exclusive=True):
        pytest.fail("copied workspace lost original ownership")
    retire(run)
    with pytest.raises(ValueError, match="permanently"), ownership(copy):
        pytest.fail("copied workspace escaped exclusion")


def test_first_tombstone_survives_crash_before_path_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = str(uuid.uuid7())
    run, alias = fixture(tmp_path, identity), fixture(tmp_path, identity)
    original = record

    def crash(path: Path, value: dict[str, object]) -> None:
        original(path, value)
        raise KeyboardInterrupt

    monkeypatch.setattr(fence, "record", crash)
    with pytest.raises(KeyboardInterrupt):
        retire(run)
    for path in (run, alias):
        with pytest.raises(ValueError, match="permanently"):
            require_available(path)


@pytest.mark.parametrize("kind", ["empty", "corrupt", "symlink"])
def test_partial_or_corrupt_registry_state_never_reopens_fixture(tmp_path: Path, kind: str) -> None:
    run = fixture(tmp_path)
    retire(run)
    root = fence.registry(run)
    assert root is not None
    path = root / (fence.keys(run)[0] + ".retired")
    shutil.rmtree(path)
    if kind == "empty":
        path.mkdir(mode=0o700)
    elif kind == "corrupt":
        path.write_bytes(b"partial")
    else:
        path.symlink_to(tmp_path / "missing")
    shutil.rmtree(run)
    with pytest.raises(ValueError, match="permanently"), ownership(run):
        pytest.fail("damaged tombstone reopened disposed root")


def test_unretired_missing_root_can_finish_ordinary_closeout(tmp_path: Path) -> None:
    run = fixture(tmp_path)
    with ownership(run):
        shutil.rmtree(run)
    with ownership(run):
        assert not run.exists()


def test_explicit_identity_cannot_open_shared_alias_after_original_removal(tmp_path: Path) -> None:
    selected = str(uuid.uuid7())
    run = fixture(tmp_path, selected)
    retire(run)
    alias = fixture(tmp_path)
    shutil.rmtree(alias)
    with pytest.raises(ValueError, match="exclusive"), ownership(alias, fixture_id=selected):
        pytest.fail("shared alias passed an explicit retired identity")
