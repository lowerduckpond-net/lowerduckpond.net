"""Reject unsupported closeout work before the permanent exclusion effect."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_frozen_envelope as envelope
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_frozen_context import NativeFixture, actor
from scripts.m3_11_unattended.model import stamp
from scripts.qualification_fence import registry

from .test_m3_11_backup_removal import Storage
from .test_m3_11_backup_removal import removal as removal  # noqa: PLC0414
from .test_m3_11_frozen_actor_export import Reader
from .test_m3_11_frozen_backups import prepared
from .test_m3_11_frozen_fence import fixture


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "expired",
        "mount",
        "unknown-size",
        "oversized-tree",
        "multipart",
        "disagreement",
        "capacity",
    ],
)
def test_native_envelope_rejects_unpreservable_resources_before_any_effect(
    tmp_path: Path,
    removal: tuple[Removal, Storage],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    item, store, _expected = prepared(removal)
    run = fixture(tmp_path / "managed")
    root = registry(run)
    assert root is not None
    root.mkdir(mode=0o700)
    raw = Reader().raw
    raw["SizeRootFs"] = 1024
    expected = actor(raw)
    if change == "mount":
        raw["Mounts"] = [{"Type": "volume"}]
    elif change == "unknown-size":
        raw.pop("SizeRootFs")
    elif change == "oversized-tree":
        (run / "large").write_bytes(b"x" * 4096)
    elif change == "multipart":
        store.uploads.add((store.target.prefix + "unfinished", "unknown"))

    def versions(**kwargs: Any) -> dict[str, object]:  # noqa: ANN401 - exact fake SDK kwargs
        value = store.version_list(**kwargs)
        for row in cast(list[dict[str, object]], value["Versions"]):
            row["Size"] = 0 if row["VersionId"] == "data-version" else 100
        return value

    def observer_versions(**kwargs: Any) -> dict[str, object]:  # noqa: ANN401
        value = versions(**kwargs)
        if change == "disagreement":
            cast(list[dict[str, object]], value["Versions"])[0]["Size"] = 200
        return value

    cast(Mock, item.writer).list_object_versions.side_effect = versions
    cast(Mock, item.observer).list_object_versions.side_effect = observer_versions
    checks: list[int] = []

    def capacity(path: Path, size: int) -> None:
        assert path == root
        checks.append(size)
        if change == "capacity":
            raise ValueError("insufficient private evidence capacity")

    monkeypatch.setattr(envelope, "capacity", capacity)
    monkeypatch.setattr(envelope, "MAX_LOCAL_BYTES", 4096)
    monkeypatch.setattr(envelope, "MAX_REMOTE_BYTES", 1024)
    monkeypatch.setattr(envelope, "Removal", lambda *_args: item)
    native = cast(
        NativeFixture,
        SimpleNamespace(
            owner=lambda: None,
            run=run,
            fixture={"actors": [expected]},
            docker=SimpleNamespace(command=lambda *_args: json.dumps([raw])),
            client=lambda role: item.writer if role == "backup" else item.observer,
            storage=SimpleNamespace(
                target=item.target, binding=item.binding, owner_version=item.owner_version
            ),
            manifest=SimpleNamespace(
                intents=[
                    SimpleNamespace(
                        deadline=stamp(
                            datetime.now(UTC) + timedelta(hours=1 if change == "expired" else 24)
                        )
                    )
                ]
            ),
        ),
    )
    before = {path: path.read_bytes() for path in run.rglob("*") if path.is_file()}
    if change == "none":
        proof = envelope.verify(native)
        assert proof["provider_mutations"] == 0 and proof["backup_bytes"] == 100  # noqa: PLR2004
        assert checks == [5120]
    else:
        with pytest.raises(ValueError):
            envelope.verify(native)
    assert before == {path: path.read_bytes() for path in run.rglob("*") if path.is_file()}
    assert store.operations == [] and list(root.iterdir()) == []
