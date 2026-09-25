"""Lost transport acknowledgements cannot replace or reconstruct rollout history."""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_production_journal import (
    records as records,  # noqa: PLC0414 - shared original receipt-chain fixture
)
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_records as wire
from scripts.m3_11_production_replica import Replica
from scripts.m3_11_production_session import Result, Session

OWNER = os.geteuid()


class Peer:
    helper = "/run/lowerduckpond-m3-11/" + "a" * 64 + ".pyz"
    token = "b" * 64

    def __init__(self, root: Path, logs: Path) -> None:
        self.root, self.logs = root, logs
        self.sent: list[tuple[tuple[str, ...], bytes]] = []
        self.drop: tuple[str, str] | None = None
        logs.mkdir(mode=0o700)

    def run(self, name: str, arguments: Sequence[str], *, data: bytes = b"") -> Result:
        assert name == "journal-sync"
        assert list(arguments[:6]) == [
            "/usr/bin/python3",
            "-I",
            "-B",
            self.helper,
            "journal",
            self.token,
        ]
        operation = tuple(arguments[6:])
        self.sent.append((operation, data))
        target = operation[1] if operation[0] == "publish" else "read"
        if self.drop == (target, "before"):
            raise ConnectionError("connection ended before host acknowledgement")
        raw = wire.operate(self.root, operation, data, owner=OWNER)
        if self.drop == (target, "after"):
            raise ConnectionError("connection ended after host publication")
        out, err = (self.logs / f"{len(self.sent)}.{suffix}" for suffix in ("stdout", "stderr"))
        out.write_bytes(raw)
        err.write_bytes(b"")
        return Result(0, out, err)


def replica(local: journal.Journal, peer: Peer) -> Replica:
    return Replica(local, cast(Session, peer))


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    local, parent = tmp_path / "local", tmp_path / "convergence"
    for path in (local, parent):
        path.mkdir(mode=0o700)
    return local, parent / "m3-11"


def snapshot(root: Path) -> dict[str, tuple[int, int, bytes]]:
    return {p.name: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for p in root.iterdir()}


def test_complete_chain_and_exact_retries_keep_every_original_record(
    roots: tuple[Path, Path], tmp_path: Path, records: list[tuple[str, bytes]]
) -> None:
    local, remote = roots
    peer = Peer(remote, tmp_path / "logs")
    with journal.locked(local, owner=OWNER, create=True) as state:
        pair = replica(state, peer)
        assert pair.synchronize() == [] and not remote.exists()
        for count, (name, raw) in enumerate(records, start=1):
            assert pair.publish(name, raw) == records[:count]
        before = snapshot(local), snapshot(remote)
        assert pair.synchronize() == records
        assert (snapshot(local), snapshot(remote)) == before
        assert state.inspect()["phase"] == "complete"


@pytest.mark.parametrize("point", ["before", "after"])
@pytest.mark.parametrize("position", [0, 1, 2, 14])
def test_lost_connection_replays_only_the_last_locally_retained_proposal(
    roots: tuple[Path, Path],
    tmp_path: Path,
    records: list[tuple[str, bytes]],
    position: int,
    point: str,
) -> None:
    local, remote = roots
    peer = Peer(remote, tmp_path / "first")
    with journal.locked(local, owner=OWNER, create=True) as state:
        pair = replica(state, peer)
        for name, raw in records[:position]:
            pair.publish(name, raw)
        peer.drop = (records[position][0], point)
        with pytest.raises(ConnectionError):
            pair.publish(*records[position])
        assert state.records() == records[: position + 1]
    before = snapshot(local)
    resumed = Peer(remote, tmp_path / "resumed")
    with journal.locked(local, owner=OWNER) as state:
        assert replica(state, resumed).synchronize() == records[: position + 1]
    assert resumed.sent == [(("publish", records[position][0]), records[position][1])]
    assert snapshot(local) == before
    with journal.locked(remote, owner=OWNER) as state:
        assert state.records() == records[: position + 1]


@pytest.mark.parametrize("point", ["write", "file-sync", "rename", "directory-sync"])
def test_interrupted_remote_publication_resumes_the_retained_proposal(
    roots: tuple[Path, Path],
    tmp_path: Path,
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
    point: str,
) -> None:
    local, remote = roots
    peer = Peer(remote, tmp_path / "logs")
    with journal.locked(local, owner=OWNER, create=True) as state:
        pair = replica(state, peer)
        pair.publish(*records[0])
        original = journal.Journal.publish

        def crash(where: str) -> None:
            if where == point:
                raise OSError("interrupted durable write")

        def interrupted(self: journal.Journal, name: str, raw: bytes) -> bool:
            return original(
                self, name, raw, failure_hook=crash if self.directory == remote else lambda _: None
            )

        with monkeypatch.context() as patch:
            patch.setattr(journal.Journal, "publish", interrupted)
            with pytest.raises(OSError):
                pair.publish(*records[1])
        assert state.records() == records[:2]
        assert pair.synchronize() == records[:2]


@pytest.mark.parametrize("point", ["write", "file-sync", "rename", "directory-sync"])
def test_local_interruption_never_sends_an_unretained_proposal(
    roots: tuple[Path, Path],
    tmp_path: Path,
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
    point: str,
) -> None:
    local, remote = roots
    peer = Peer(remote, tmp_path / "logs")
    with journal.locked(local, owner=OWNER, create=True) as state:
        pair = replica(state, peer)
        pair.publish(*records[0])
        original = journal.Journal.publish

        def crash(where: str) -> None:
            if where == point:
                raise OSError("local proposal durability interrupted")

        def interrupted(self: journal.Journal, name: str, raw: bytes) -> bool:
            return original(
                self, name, raw, failure_hook=crash if self.directory == local else lambda _: None
            )

        with monkeypatch.context() as patch:
            patch.setattr(journal.Journal, "publish", interrupted)
            with pytest.raises(OSError):
                pair.publish(*records[1])
        assert all(data != records[1][1] for _, data in peer.sent)
        assert pair.publish(*records[1]) == records[:2]
    with journal.locked(remote, owner=OWNER) as state:
        assert state.records() == records[:2]


@pytest.mark.parametrize("fault", ["missing", "truncated", "ahead", "changed"])
def test_remote_drift_is_refused_without_replaying_old_completed_phases(
    roots: tuple[Path, Path], tmp_path: Path, records: list[tuple[str, bytes]], fault: str
) -> None:
    local, remote = roots
    peer = Peer(remote, tmp_path / "logs")
    with journal.locked(local, owner=OWNER, create=True) as state:
        pair = replica(state, peer)
        for record in records[:3]:
            pair.publish(*record)
        if fault in {"missing", "truncated", "changed"}:
            remote.rename(remote.with_name("preserved-original"))
            if fault == "truncated":
                wire.operate(remote, ["publish", "original"], records[0][1], owner=OWNER)
            elif fault == "changed":
                original = json.loads(records[0][1])
                original["candidate"]["source_revision"] = "f" * 40
                wire.operate(
                    remote, ["publish", "original"], journal.canonical(original), owner=OWNER
                )
        else:
            wire.operate(remote, ["publish", records[3][0]], records[3][1], owner=OWNER)
        before = snapshot(remote) if remote.exists() else None
        with pytest.raises(ValueError):
            pair.synchronize()
        assert (snapshot(remote) if remote.exists() else None) == before


def test_missing_local_proposals_cannot_adopt_a_remote_history(
    roots: tuple[Path, Path], tmp_path: Path, records: list[tuple[str, bytes]]
) -> None:
    local, remote = roots
    wire.operate(remote, ["publish", "original"], records[0][1], owner=OWNER)
    peer = Peer(remote, tmp_path / "logs")
    with journal.locked(local, owner=OWNER, create=True) as state:
        with pytest.raises(ValueError, match="differs"):
            replica(state, peer).synchronize()
        assert state.records() == []


@pytest.mark.parametrize("fault", ["parent-mode", "parent-link", "root-link", "owner", "oversize"])
def test_unsafe_remote_authority_is_refused(
    roots: tuple[Path, Path], records: list[tuple[str, bytes]], fault: str
) -> None:
    _, remote = roots
    owner, raw = OWNER, records[0][1]
    if fault == "parent-mode":
        remote.parent.chmod(0o755)
    elif fault == "parent-link":
        other = remote.parent.with_name("original-parent")
        remote.parent.rename(other)
        remote.parent.symlink_to(other, target_is_directory=True)
    elif fault == "root-link":
        remote.symlink_to(remote.parent, target_is_directory=True)
    elif fault == "owner":
        owner += 1
    else:
        raw = b" " * (journal.MAX_BYTES + 1)
    with pytest.raises((ValueError, OSError)):
        wire.operate(remote, ["publish", "original"], raw, owner=owner)
    assert not (remote / "original.json").exists()


def test_wire_refuses_changed_envelopes_and_preserves_original_bytes(
    records: list[tuple[str, bytes]],
) -> None:
    raw = wire.encode(records)
    assert len(raw) < wire.MAX_WIRE_BYTES
    assert wire.decode(raw) == records
    for changed in (
        raw + b" ",
        raw.replace(b'"records":', b'"extra":0,"records":'),
        raw.replace(b'"records":', b'"records":[],"records":'),
        b" " * (wire.MAX_WIRE_BYTES + 1),
    ):
        with pytest.raises(ValueError):
            wire.decode(changed)
