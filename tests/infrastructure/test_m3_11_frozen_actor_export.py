"""Stopped actor export preserves private bytes and refuses hidden mounted data."""

from __future__ import annotations

import io
import tarfile
from collections.abc import Callable, Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts import m3_11_frozen_actor_export as export
from scripts.m3_11_frozen_context import actor


class Reader:
    def __init__(self) -> None:
        self.raw: dict[str, Any] = {
            "Id": "a" * 64,
            "Name": "/ldp-m3-synthetic-host",
            "Image": "sha256:" + "b" * 64,
            "State": {"Running": False, "Pid": 0, "StartedAt": "original", "FinishedAt": "stopped"},
            "HostConfig": {"RestartPolicy": {"Name": "no"}},
            "Config": {
                "Labels": {"lowerduckpond.qualification.run": "synthetic"},
                "Env": ["SYNTHETIC_PRIVATE_VALUE=retained-privately"],
            },
            "Mounts": [{"Type": "tmpfs", "Destination": "/run"}],
        }
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            header = tarfile.TarInfo("var/lib/synthetic-state")
            header.size = len(b"native filesystem bytes")
            archive.addfile(header, io.BytesIO(b"native filesystem bytes"))
        self.archive = stream.getvalue()
        self.calls: list[str] = []
        self.interrupt = False
        self.restart = False

    def inspect_actor(self, selected: str) -> dict[str, object]:
        assert selected == self.raw["Id"]
        return deepcopy(self.raw)

    def actor_bytes(
        self, operation: str, selected: str, guard: Callable[[], None]
    ) -> Iterator[bytes]:
        assert selected == self.raw["Id"]
        self.calls.append(operation)
        guard()
        yield self.archive if operation == "export" else b"private native log\n"
        if self.interrupt:
            raise KeyboardInterrupt
        if self.restart:
            self.raw["State"]["StartedAt"] = "restarted"


def test_full_rootfs_metadata_logs_and_independent_reread(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    reader = Reader()
    expected = actor(reader.raw)
    root = tmp_path / "actor"
    value = export.capture(
        reader, expected, root, maximum_bytes=100000, maximum_entries=100, guard=lambda: None
    )
    assert reader.calls == ["export", "logs"]
    assert (
        export.verify(root, expected, maximum_bytes=100000, maximum_entries=100, guard=lambda: None)
        == value
    )
    assert "retained-privately" in (root / "inspect.json").read_text()
    assert value["automatic_recovery"] is False
    assert (root / "rootfs.tar").read_bytes() == reader.archive
    (root / "logs").write_bytes(b"changed native logs")
    with pytest.raises(ValueError):
        export.verify(root, expected, maximum_bytes=100000, maximum_entries=100, guard=lambda: None)


@pytest.mark.parametrize(
    "kind", ["volume", "bind", "declared-volume", "configured-mount", "device", "active"]
)
def test_rejects_any_unpreserved_mount_before_capture(tmp_path: Path, kind: str) -> None:
    tmp_path.chmod(0o700)
    reader = Reader()
    expected = actor(reader.raw)
    if kind in {"volume", "bind"}:
        reader.raw["Mounts"] = [{"Type": kind, "Destination": "/data"}]
    elif kind == "declared-volume":
        reader.raw["Config"]["Volumes"] = {"/data": {}}
    elif kind == "configured-mount":
        reader.raw["HostConfig"]["Mounts"] = [{"Type": "bind", "Target": "/data"}]
    elif kind == "device":
        reader.raw["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/synthetic"}]
    else:
        reader.raw["State"]["Pid"] = 10
    with pytest.raises(ValueError):
        export.capture(
            reader,
            expected,
            tmp_path / "actor",
            maximum_bytes=100000,
            maximum_entries=100,
            guard=lambda: None,
        )
    assert reader.calls == [] and not (tmp_path / "actor").exists()


@pytest.mark.parametrize("kind", ["interrupt", "restart", "byte-bound", "malformed-tar"])
def test_incomplete_export_cannot_produce_verified_receipt(tmp_path: Path, kind: str) -> None:
    tmp_path.chmod(0o700)
    reader = Reader()
    reader.interrupt = kind == "interrupt"
    reader.restart = kind == "restart"
    if kind == "malformed-tar":
        reader.archive = b"not a complete native export"
    with pytest.raises((ValueError, KeyboardInterrupt, tarfile.TarError)):
        export.capture(
            reader,
            actor(reader.raw),
            tmp_path / "actor",
            maximum_bytes=1 if kind == "byte-bound" else 100000,
            maximum_entries=100,
            guard=lambda: None,
        )
    assert not (tmp_path / "actor/verified.json").exists()
