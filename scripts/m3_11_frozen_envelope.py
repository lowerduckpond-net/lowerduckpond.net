"""Read-only eligibility before an irreversible fixture execution exclusion.

Reject a fixture the narrow later adapters cannot preserve: persistent mounts,
special filesystem entries, unknown version sizes, multipart uploads, excessive
bytes or insufficient private capacity. Recheck capacity again at actual export.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

from lowerduckpond_m3_archive.storage import S3Client

from scripts import m3_11_frozen_actor_export as actors
from scripts import m3_11_frozen_export as export
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_frozen_budget import (
    MAX_ENTRIES,
    MAX_LOCAL_BYTES,
    MAX_REMOTE_BYTES,
    REMOTE_SECONDS,
)
from scripts.m3_11_retirement_files import capacity, digest
from scripts.qualification_fence import registry

if TYPE_CHECKING:
    from scripts.m3_11_frozen_context import NativeFixture


def sizes(client: S3Client, removal: Removal, expected: dict[str, object]) -> int:
    """Read paginated native size metadata; exact version set must match inventory."""
    from scripts.m3_11_frozen_context import require  # noqa: PLC0415

    parameters: dict[str, object] = {
        "Bucket": removal.target.backup_bucket,
        "Prefix": removal.target.prefix,
        "MaxKeys": 1000,
    }
    seen: set[tuple[str, str, str]] = set()
    markers: set[tuple[str, str]] = set()
    total = 0
    while True:
        page = client.list_object_versions(**parameters)
        for kind, field in (("version", "Versions"), ("delete-marker", "DeleteMarkers")):
            for row in cast(list[dict[str, object]], page.get(field, [])):
                key = (kind, row.get("Key"), row.get("VersionId"))
                require(
                    all(isinstance(item, str) for item in key) and key not in seen,
                    "closeout size inventory repeated or malformed a version",
                )
                seen.add(cast(tuple[str, str, str], key))
                if kind == "version":
                    size = row.get("Size")
                    require(type(size) is int and size >= 0, "closeout version size is unavailable")
                    total += cast(int, size)
                require(
                    len(seen) <= MAX_ENTRIES and total <= MAX_REMOTE_BYTES,
                    "closeout backup preservation exceeds supported bounds",
                )
        if page.get("IsTruncated") is False:
            break
        require(page.get("IsTruncated") is True, "closeout size inventory truncation is unknown")
        marker = (page.get("NextKeyMarker"), page.get("NextVersionIdMarker"))
        require(
            all(isinstance(item, str) and item for item in marker) and marker not in markers,
            "closeout size inventory pagination is incomplete",
        )
        markers.add(cast(tuple[str, str], marker))
        parameters.update(KeyMarker=marker[0], VersionIdMarker=marker[1])
    require(
        seen == {tuple(row) for row in cast(list[list[str]], expected["versions"])},
        "closeout size inventory differs from exact owned versions",
    )
    return total


def verify(fixture: NativeFixture) -> dict[str, object]:
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from scripts.m3_11_frozen_context import require  # noqa: PLC0415
    from scripts.m3_11_unattended.model import instant  # noqa: PLC0415

    fixture.owner()
    require(
        all(
            instant(intent.deadline) - datetime.now(UTC) > timedelta(seconds=REMOTE_SECONDS)
            for intent in fixture.manifest.intents
        ),
        "remaining credential life cannot fit the complete remote closeout allowance",
    )
    original = cast(list[dict[str, object]], fixture.fixture["actors"])
    found = json.loads(
        fixture.docker.command("inspect", "--size", *(str(row["id"]) for row in original))
    )
    require(
        isinstance(found, list) and len(found) == len(original),
        "closeout actor size inventory differs",
    )
    total = 0
    for row, expected in zip(found, original, strict=True):
        actors.require_exportable(row, expected)
        size = row.get("SizeRootFs")
        require(type(size) is int and size >= 0, "closeout actor filesystem size is unavailable")
        total += cast(int, size)
    tree = export.Tree(export.Limits(MAX_LOCAL_BYTES, MAX_ENTRIES), fixture.owner).scan(fixture.run)
    total += cast(int, tree["bytes"])
    require(total < MAX_LOCAL_BYTES, "closeout local filesystem evidence exceeds supported bounds")
    removal = Removal(
        fixture.storage.target,
        fixture.storage.binding,
        fixture.storage.owner_version,
        fixture.client("backup"),
        fixture.client("operator"),
        fixture.run / "unused-closeout-preflight",
        lambda: digest(fixture.fixture),
    )
    expected = removal._observed()
    require(not expected["uploads"], "closeout cannot preserve unfinished multipart data")
    backup_bytes = sizes(removal.writer, removal, expected)
    require(
        sizes(removal.observer, removal, expected) == backup_bytes,
        "independent closeout backup sizes disagree",
    )
    output = registry(fixture.run)
    require(output is not None, "closeout requires its existing managed evidence registry")
    capacity(cast(Path, output), MAX_LOCAL_BYTES + MAX_REMOTE_BYTES)
    fixture.owner()
    return {
        "format": "lowerduckpond-m3-11-closeout-envelope-v1",
        "actors_sha256": digest(found),
        "tree_sha256": digest(tree),
        "estimated_local_bytes": total,
        "backup_inventory": expected,
        "backup_bytes": backup_bytes,
        "persistent_mounts": 0,
        "multipart_uploads": 0,
        "provider_mutations": 0,
        "automatic_recovery_established": False,
    }
