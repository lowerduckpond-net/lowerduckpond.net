"""Bind P4 storage observations to exact native archive and Restic resources."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256

from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_contracts import ContractError, decode_json_object
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteStore
from lowerduckpond_static_host_agent.backup_identity import canonical_locator
from lowerduckpond_static_host_agent.host_restore_archives import (
    RestoreArchive,
    verify_restore_archives,
)
from lowerduckpond_static_host_agent.host_restore_paths import private_directory

from scripts.m3_11_backup_discard import inventory as restic_inventory
from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import read
from scripts.m3_12_droplet_native import AdapterInputs

STORAGE_PHASES = frozenset({"functional", "backup-fence", "restore", "fresh-install", "teardown"})


@dataclass(frozen=True)
class StorageTarget:
    role: str
    kind: str
    region: str
    bucket: str
    prefix: str

    @property
    def endpoint(self) -> str:
        return f"https://{self.region}.digitaloceanspaces.com"

    @property
    def repository(self) -> str:
        require(self.kind == "restic", "droplet-storage-repository-kind-invalid")
        return canonical_locator(f"s3:{self.endpoint}/{self.bucket}/{self.prefix}")

    def document(self) -> Document:
        return {
            "role": self.role,
            "kind": self.kind,
            "region": self.region,
            "bucket": self.bucket,
            "prefix": self.prefix,
        }


def storage_target(scope: Document, action: Document, role: str, kind: str) -> StorageTarget:
    require(
        role in action["targets"] and kind in {"restic", "archive"},
        "droplet-storage-scope-changed",
    )
    # Cold restoration consumes the exact original backup and archive resources.
    resource_role = "source" if role == "restore" else role
    location = scope["resources"]["storage"][resource_role][kind]
    return StorageTarget(
        resource_role, kind, location["region"], location["bucket"], location["prefix"]
    )


def _inventory_digest(rows: list[tuple[object, ...]]) -> str:
    checksum = sha256(b"lowerduckpond-m3-12-storage-inventory-v1\n")
    for row in sorted(rows):
        checksum.update(encode(row))
    return checksum.hexdigest()


def observe_storage(
    inputs: AdapterInputs, role: str, kind: str, connect: Callable[[StorageTarget], S3Client]
) -> Document:
    scope, action = inputs.open(STORAGE_PHASES)
    target = storage_target(scope, action, role, kind)
    return inventory_observation(target, connect(target))


def inventory_observation(target: StorageTarget, client: S3Client) -> Document:
    """Read the entire dedicated bucket. An out-of-prefix object remains charged."""
    if target.kind == "archive":
        observed = ArchiveRemoteStore(client, bucket=target.bucket).inventory()
        versions: list[tuple[object, ...]] = [
            ("marker" if row.delete_marker else "version", row.key, row.version_id, row.size)
            for row in observed.versions
        ]
        uploads = [("upload", key, identifier) for key, identifier in observed.multipart_uploads]
        current: list[tuple[object, ...]] = []
    else:
        restic = restic_inventory(client, bucket=target.bucket, prefix="")
        versions = [(row.kind, row.key, row.version_id) for row in restic.versions]
        uploads = [("upload", row.key, row.upload_id) for row in restic.uploads]
        current = [("current", key) for key in restic.current]
    rows: list[tuple[object, ...]] = [*versions, *uploads, *current]
    require(len(set(rows)) == len(rows), "droplet-storage-inventory-duplicates")
    return {
        "format": "lowerduckpond-m3-12-storage-observation-v1",
        "targetSha256": digest(target.document()),
        "inventorySha256": _inventory_digest(rows),
        "versions": len(versions),
        "multipart": len(uploads),
        "current": len(current),
        "outsideNamespace": sum(not str(row[1]).startswith(target.prefix + "/") for row in rows),
        "empty": not rows,
    }


def verify_original_archives(
    inputs: AdapterInputs, archive_raw: bytes, connect: Callable[[StorageTarget], S3Client]
) -> Document:
    """Use the same installed verifier for exact snapshot archive versions."""
    scope, intent = inputs.open(frozenset({"restore"}))
    target = storage_target(scope, intent, "restore", "archive")
    original = intent["prerequisites"]["backup-fence"]
    receipt = read(inputs.attempt.directory, original["file"])
    try:
        document = decode_json_object(archive_raw, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError:
        raise ValidationError("droplet-storage-archive-original-invalid") from None
    require(
        set(document) == {"format", "archives"}
        and document["format"] == "lowerduckpond-m3-12-archive-authority-v1"
        and isinstance(document["archives"], list)
        and encode(document) == archive_raw
        and digest(receipt) == original["sha256"]
        and digest(document) == receipt["evidence"]["archiveInventory"],
        "droplet-storage-archive-original-changed",
    )
    authority = []
    rows = document["archives"]
    assert isinstance(rows, list)  # noqa: S101 - checked above
    for row in rows:
        require(
            isinstance(row, dict)
            and set(row) == {"record", "manifest", "required"}
            and isinstance(row["record"], dict)
            and (row["manifest"] is None or isinstance(row["manifest"], dict))
            and type(row["required"]) is bool,
            "droplet-storage-archive-original-invalid",
        )
        item = RestoreArchive(row["record"], row["manifest"], row["required"])
        item.version(target.bucket)
        authority.append(item)
    workspace = inputs.attempt.directory / "archive-proof"
    private_directory(workspace, owner=os.geteuid())
    return verify_restore_archives(
        ArchiveRemoteStore(connect(target), bucket=target.bucket),
        authority,
        workspace,
        owner=os.geteuid(),
    )
