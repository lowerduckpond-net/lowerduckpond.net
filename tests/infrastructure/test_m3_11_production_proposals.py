"""A new controller recovers exact bytes without remembering an interrupted write."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from infrastructure.test_m3_11_production_journal import records as records  # noqa: PLC0414
from infrastructure.test_m3_11_production_replica import (
    OWNER,
    Peer,
    replica,
    snapshot,
)
from infrastructure.test_m3_11_production_replica import (
    roots as roots,  # noqa: PLC0414
)
from scripts import m3_11_production_journal as journal
from scripts.m3_11_production_proposals import Proposals


@pytest.fixture
def directories(tmp_path: Path) -> tuple[Path, Path]:
    cache, attempt = tmp_path / "proposals", tmp_path / "attempt"
    for path in (cache, attempt):
        path.mkdir(mode=0o700)
    return cache, attempt


@pytest.mark.parametrize("point", ["write", "file-sync", "rename", "directory-sync"])
@pytest.mark.parametrize("position", [0, 2, 14])
def test_new_controller_recovers_locally_interrupted_publication(  # noqa: PLR0913,PLR0917 - fault matrix
    roots: tuple[Path, Path],
    directories: tuple[Path, Path],
    records: list[tuple[str, bytes]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    point: str,
    position: int,
) -> None:
    local, remote = roots
    cache, attempt = directories
    peer = Peer(remote, tmp_path / "first")
    with (
        journal.locked(local, owner=OWNER, create=True) as state,
        journal.locked(cache, owner=OWNER, create=True) as retained,
    ):
        pair, proposals = replica(state, peer), Proposals(retained, attempt)
        for record in records[:position]:
            proposals.publish(pair, *record)
        original = journal.Journal.publish

        def crash(where: str) -> None:
            if where == point:
                raise OSError("interrupted local journal")

        def interrupted(self: journal.Journal, name: str, raw: bytes) -> bool:
            return original(
                self, name, raw, failure_hook=crash if self.directory == local else lambda _: None
            )

        with monkeypatch.context() as patch:
            patch.setattr(journal.Journal, "publish", interrupted)
            with pytest.raises(OSError, match="interrupted local"):
                proposals.publish(pair, *records[position])
        before = snapshot(cache)
    # The restarted controller receives neither the receipt nor its timestamp.
    resumed = Peer(remote, tmp_path / "second")
    with (
        journal.locked(local, owner=OWNER) as state,
        journal.locked(cache, owner=OWNER) as retained,
    ):
        recovered = Proposals(retained, tmp_path / "unused").recover(replica(state, resumed))
        assert recovered == records[: position + 1]
        assert snapshot(cache) == before
    assert all(data in {raw for _, raw in recovered[-2:]} for _, data in resumed.sent if data)
    with journal.locked(remote, owner=OWNER) as state:
        assert state.records() == recovered


@pytest.mark.parametrize("point", ["write", "file-sync", "rename", "directory-sync"])
def test_cache_commit_point_precedes_any_journal_publication(
    roots: tuple[Path, Path],
    directories: tuple[Path, Path],
    records: list[tuple[str, bytes]],
    tmp_path: Path,
    point: str,
) -> None:
    local, remote = roots
    cache, attempt = directories

    def crash(where: str) -> None:
        if where == point:
            raise OSError("interrupted proposal staging")

    with (
        journal.locked(cache, owner=OWNER, create=True) as retained,
        pytest.raises(OSError, match="interrupted proposal"),
    ):
        Proposals(retained, attempt).retain(*records[0], failure_hook=crash)
    assert not remote.exists() and not list(local.iterdir())
    committed = point in {"rename", "directory-sync"}
    resumed = Peer(remote, tmp_path / "resumed")
    with (
        journal.locked(local, owner=OWNER, create=True) as state,
        journal.locked(cache, owner=OWNER) as retained,
    ):
        assert Proposals(retained, tmp_path / "unused").recover(replica(state, resumed)) == (
            records[:1] if committed else []
        )
    assert (attempt / "original.proposal").exists() != committed


def test_partial_staging_is_never_treated_as_an_original_proposal(
    directories: tuple[Path, Path],
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache, attempt = directories
    write = os.write

    def partial(fd: int, raw: bytes) -> int:
        write(fd, raw[:7])
        raise OSError("partial staged proposal")

    with journal.locked(cache, owner=OWNER, create=True) as retained:
        with monkeypatch.context() as patch:
            patch.setattr(os, "write", partial)
            with pytest.raises(OSError, match="partial staged"):
                Proposals(retained, attempt).retain(*records[0])
        assert retained.records() == []
        assert (attempt / "original.proposal").read_bytes() == records[0][1][:7]


@pytest.mark.parametrize("fault", ["missing-host", "missing-local", "missing-cache"])
def test_cache_does_not_reconstruct_missing_history(
    roots: tuple[Path, Path],
    directories: tuple[Path, Path],
    records: list[tuple[str, bytes]],
    tmp_path: Path,
    fault: str,
) -> None:
    local, remote = roots
    cache, attempt = directories
    peer = Peer(remote, tmp_path / "first")
    with (
        journal.locked(local, owner=OWNER, create=True) as state,
        journal.locked(cache, owner=OWNER, create=True) as retained,
    ):
        for record in records[:3]:
            Proposals(retained, attempt).publish(replica(state, peer), *record)
    changed = {"missing-host": remote, "missing-local": local, "missing-cache": cache}[fault]
    changed.rename(changed.with_name(changed.name + "-original"))
    if fault != "missing-host":
        changed.mkdir(mode=0o700)
    before = snapshot(remote) if remote.exists() else None
    with (
        journal.locked(local, owner=OWNER, create=True) as state,
        journal.locked(cache, owner=OWNER, create=True) as retained,
        pytest.raises(ValueError),
    ):
        Proposals(retained, attempt).recover(replica(state, peer))
    assert (snapshot(remote) if remote.exists() else None) == before
