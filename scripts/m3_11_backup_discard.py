"""Permanently discard selected abandoned M3.11 backup repositories.

Accept run UUIDs or exact m3-11-qualification/<UUID>/ prefixes. Preview by
default; --discard removes all versions, delete markers and multipart uploads.
Stop the selected runs' writers first. This produces no qualification evidence.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from lowerduckpond_m3_archive.storage import (
    ArchiveQualificationError,
    MultipartUpload,
    S3Client,
    VersionEntry,
    assert_versioning_enabled,
    create_client,
    list_current_objects,
    list_multipart_uploads,
    list_versions,
)

from scripts.m3_11_qualification_evidence import uuid7

NAMESPACE = "m3-11-qualification/"
MAX_ENTRIES = 100_000


class DiscardError(ValueError):
    """An operator-facing error with no provider response or credentials."""


def qualification_prefix(value: str) -> str:
    run_id = value
    if value.startswith(NAMESPACE):
        run_id = value.removeprefix(NAMESPACE).removesuffix("/")
    try:
        uuid7(run_id)
    except ValueError as error:
        raise DiscardError(
            "targets must be run UUIDs or exact M3.11 qualification prefixes"
        ) from error
    return f"{NAMESPACE}{run_id}/"


@dataclass(frozen=True)
class Inventory:
    current: frozenset[str]
    versions: frozenset[VersionEntry]
    uploads: frozenset[MultipartUpload]

    def only_owner(self, prefix: str) -> Inventory:
        owner = prefix + "owner.json"
        return Inventory(
            frozenset(key for key in self.current if key == owner),
            frozenset(entry for entry in self.versions if entry.key == owner),
            frozenset(),
        )


EMPTY = Inventory(frozenset(), frozenset(), frozenset())


def inventory(client: S3Client, *, bucket: str, prefix: str) -> Inventory:
    assert_versioning_enabled(client, bucket=bucket)
    current = frozenset(
        list_current_objects(client, bucket=bucket, prefix=prefix, maximum_entries=MAX_ENTRIES)
    )
    versions = frozenset(
        list_versions(client, bucket=bucket, prefix=prefix, maximum_entries=MAX_ENTRIES).entries
    )
    uploads = frozenset(
        list_multipart_uploads(
            client, bucket=bucket, prefix=prefix, maximum_entries=MAX_ENTRIES
        ).uploads
    )
    if not current <= {entry.key for entry in versions if entry.kind == "version"}:
        raise DiscardError("current objects lack exact version identities")
    return Inventory(current, versions, uploads)


def discard(client: S3Client, *, bucket: str, prefix: str, expected: Inventory) -> None:
    if inventory(client, bucket=bucket, prefix=prefix) != expected:
        raise DiscardError("prefix changed since inventory; stop its writers before retrying")
    for upload in sorted(expected.uploads, key=lambda entry: (entry.key, entry.upload_id)):
        client.abort_multipart_upload(Bucket=bucket, Key=upload.key, UploadId=upload.upload_id)
    owner = expected.only_owner(prefix)
    for entry in sorted(
        expected.versions - owner.versions, key=lambda item: (item.key, item.version_id)
    ):
        client.delete_object(Bucket=bucket, Key=entry.key, VersionId=entry.version_id)
    if inventory(client, bucket=bucket, prefix=prefix) != owner:
        raise DiscardError("data remains or changed during deletion; owner marker was retained")
    for entry in sorted(owner.versions, key=lambda item: item.version_id):
        client.delete_object(Bucket=bucket, Key=entry.key, VersionId=entry.version_id)
    if inventory(client, bucket=bucket, prefix=prefix) != EMPTY:
        raise DiscardError("prefix is not empty after deletion; stop its writers before retrying")


def run(client: S3Client, *, bucket: str, targets: Sequence[str], apply: bool) -> None:
    # Validate and inventory every target before the first provider mutation.
    prefixes = tuple(dict.fromkeys(qualification_prefix(value) for value in targets))
    inventories = {prefix: inventory(client, bucket=bucket, prefix=prefix) for prefix in prefixes}
    for prefix, observed in inventories.items():
        versions = sum(entry.kind == "version" for entry in observed.versions)
        markers = len(observed.versions) - versions
        print(
            f"{bucket}/{prefix}: {len(observed.current)} current objects, "
            f"{versions} versions, {markers} delete markers, "
            f"{len(observed.uploads)} unfinished uploads",
            flush=True,
        )
    if not apply:
        print("Preview only. Add --discard to permanently delete these repositories.")
        return
    for prefix, observed in inventories.items():
        discard(client, bucket=bucket, prefix=prefix, expected=observed)
        print(
            f"Removed {bucket}/{prefix}; verified no objects, versions or uploads remain.",
            flush=True,
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="+", help="run UUIDs or full qualification prefixes")
    parser.add_argument("--bucket", default=os.environ.get("SPACES_BACKUP_BUCKET"))
    parser.add_argument("--region", default=os.environ.get("SPACES_REGION"))
    parser.add_argument(
        "--discard", action="store_true", help="permanently delete instead of previewing"
    )
    args = parser.parse_args(argv)
    try:
        # Reject bad targets/configuration before credential use or remote requests.
        prefixes = tuple(qualification_prefix(value) for value in args.targets)
        if (
            not isinstance(args.bucket, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", args.bucket) is None
            or ".." in args.bucket
            or re.fullmatch(r"[0-9.]+", args.bucket) is not None
        ):
            raise DiscardError("set --bucket or SPACES_BACKUP_BUCKET to the backup Space name")
        if (
            not isinstance(args.region, str)
            or re.fullmatch(r"[a-z]{3}[1-9][0-9]?", args.region) is None
        ):
            raise DiscardError("set --region or SPACES_REGION to the Space's region")
        key = os.environ.get("SPACES_ACCESS_KEY_ID", "")
        secret = os.environ.get("SPACES_SECRET_ACCESS_KEY", "")
        if not key or not secret:
            raise DiscardError(
                "set SPACES_ACCESS_KEY_ID and SPACES_SECRET_ACCESS_KEY in the private shell"
            )
        client = create_client(
            access_key_id=key,
            secret_access_key=secret,
            region=args.region,
            endpoint_url=f"https://{args.region}.digitaloceanspaces.com",
        )
        run(client, bucket=args.bucket, targets=prefixes, apply=args.discard)
    except Exception as error:  # Provider exceptions can include sensitive request details.
        message = (
            str(error)
            if isinstance(error, (DiscardError, ArchiveQualificationError))
            else type(error).__name__
        )
        print(f"Backup discard stopped: {message}.", file=sys.stderr)
        print(
            "Any completed deletions remain permanent; rerun the same targets to finish.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
