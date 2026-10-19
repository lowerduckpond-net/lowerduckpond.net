"""Preservation precedes remote cleanup and never omits unpublished bytes."""

from __future__ import annotations

import io
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_frozen_backups as backups
from scripts.m3_11_backup_removal import Removal

from .test_m3_11_backup_removal import Storage
from .test_m3_11_backup_removal import removal as removal  # noqa: PLC0414 - pytest fixture


def prepared(pair: tuple[Removal, Storage]) -> tuple[Removal, Storage, dict[str, object]]:
    item, store = pair
    store.uploads.clear()

    def get(**parameters: str) -> dict[str, object]:
        if parameters["Key"] == store.target.owner_key:
            return store.owner(**parameters)
        assert parameters == {
            "Bucket": store.target.backup_bucket,
            "Key": store.target.prefix + "restic/data/owned",
            "VersionId": "data-version",
        }
        raw = b"opaque retained backup bytes"
        return {"ContentLength": len(raw), "VersionId": "data-version", "Body": io.BytesIO(raw)}

    cast(Mock, item.observer).get_object.side_effect = get
    return item, store, item._observed()


def test_preserves_all_exact_versions_before_any_mutation(
    removal: tuple[Removal, Storage], tmp_path: Path
) -> None:
    tmp_path.chmod(0o700)
    item, store, expected = prepared(removal)
    value = backups.capture(
        item, expected, tmp_path / "copies", maximum_bytes=10000, guard=lambda: None
    )
    assert len(cast(list[object], value["files"])) == 2  # noqa: PLR2004 - exact owner and one data version
    before = {path.name: path.read_bytes() for path in (tmp_path / "copies").iterdir()}
    cast(Mock, item.observer).get_object.side_effect = AssertionError(
        "offline proof did provider GET"
    )
    assert (
        backups.verify(item, expected, tmp_path / "copies", maximum_bytes=10000, guard=lambda: None)
        == value
    )
    assert before == {path.name: path.read_bytes() for path in (tmp_path / "copies").iterdir()}
    assert store.operations == []


@pytest.mark.parametrize(
    "kind", ["multipart", "version", "size", "short", "long", "bound", "changed", "swapped-parent"]
)
def test_incomplete_copy_cannot_authorize_cleanup(
    removal: tuple[Removal, Storage], tmp_path: Path, kind: str
) -> None:
    tmp_path.chmod(0o700)
    item, store, expected = prepared(removal)
    if kind == "multipart":
        store.uploads.add((store.target.prefix + "restic/unfinished", "pending"))
        expected = item._observed()
    original = cast(Mock, item.observer).get_object.side_effect
    output_parent = tmp_path / "destination"
    output_parent.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)

    def get(**parameters: str) -> dict[str, object]:
        assert callable(original)
        response = original(**parameters)
        if parameters["Key"] == store.target.owner_key:
            return cast(dict[str, object], response)
        if kind == "version":
            response["VersionId"] = "another-version"
        elif kind == "size":
            response["ContentLength"] = -1
        elif kind == "short":
            response["Body"] = io.BytesIO(b"short")
        elif kind == "long":
            response["Body"] = io.BytesIO(b"x" * 100)
        elif kind == "changed":
            store.versions[(store.target.prefix + "restic/new", "new")] = "version"
        elif kind == "swapped-parent":
            output_parent.rename(tmp_path / "original-destination")
            output_parent.symlink_to(other, target_is_directory=True)
        return cast(dict[str, object], response)

    cast(Mock, item.observer).get_object.side_effect = get
    with pytest.raises((ValueError, FileNotFoundError)):
        backups.capture(
            item,
            expected,
            output_parent / "copies",
            maximum_bytes=1 if kind == "bound" else 10000,
            guard=lambda: None,
        )
    assert store.operations == []
    assert list(other.iterdir()) == []
    assert not (output_parent / "copies/manifest.json").exists()


def test_independent_reread_detects_changed_retained_bytes(
    removal: tuple[Removal, Storage], tmp_path: Path
) -> None:
    tmp_path.chmod(0o700)
    item, store, expected = prepared(removal)
    output = tmp_path / "copies"
    value = backups.capture(item, expected, output, maximum_bytes=10000, guard=lambda: None)
    row = cast(list[dict[str, object]], value["files"])[0]
    (output / str(row["file"])).write_bytes(b"0" * cast(int, row["size"]))
    with pytest.raises(ValueError, match="independent reread differs"):
        backups.verify(item, expected, output, maximum_bytes=10000, guard=lambda: None)
    assert store.operations == []


def test_empty_object_version_is_preserved_and_independently_verified(
    removal: tuple[Removal, Storage], tmp_path: Path
) -> None:
    tmp_path.chmod(0o700)
    item, store, expected = prepared(removal)
    original = cast(Mock, item.observer).get_object.side_effect

    def get(**parameters: str) -> dict[str, object]:
        assert callable(original)
        response = original(**parameters)
        if parameters["Key"] != store.target.owner_key:
            response.update(ContentLength=0, Body=io.BytesIO(b""))
        return cast(dict[str, object], response)

    cast(Mock, item.observer).get_object.side_effect = get
    output = tmp_path / "empty-version"
    value = backups.capture(item, expected, output, maximum_bytes=10000, guard=lambda: None)
    assert any(row["size"] == 0 for row in cast(list[dict[str, object]], value["files"]))
    cast(Mock, item.observer).get_object.side_effect = AssertionError("unexpected provider call")
    assert backups.verify(item, expected, output, maximum_bytes=10000, guard=lambda: None) == value
    assert store.operations == []
