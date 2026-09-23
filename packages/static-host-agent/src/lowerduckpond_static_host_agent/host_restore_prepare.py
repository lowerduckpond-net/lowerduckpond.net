"""Prepare private, reviewable recovery policy on the secure workstation."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import ssl
import stat
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_fence import FENCE_SCHEMA, require_fence_policy
from lowerduckpond_static_host_agent.host_restore_inputs import (
    INPUT_SCHEMA,
    ISSUER,
    SUBJECTS,
    RestoreInputs,
    machine_id,
)
from lowerduckpond_static_host_agent.host_restore_journal import MAX_RESTORE_BYTES


def read_input(path: Path, *, maximum: int = MAX_RESTORE_BYTES, secret: bool = False) -> bytes:
    if not path.is_absolute():
        raise ValueError("restore preparation paths must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum
            or (secret and stat.S_IMODE(metadata.st_mode) != 0o600)  # noqa: PLR2004
        ):
            raise ValueError("restore preparation input is unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        current = os.fstat(descriptor)
        if len(data) != metadata.st_size or (
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
            raise ValueError("restore preparation input changed")
        return data
    finally:
        os.close(descriptor)


def certificate_digest(raw: bytes) -> str:
    if len(re.findall(rb"-----BEGIN CERTIFICATE-----", raw)) != 1 or b"PRIVATE KEY" in raw:
        raise ValueError("restore origin-pull input must be one public certificate")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))).hexdigest()


def prepare(arguments: argparse.Namespace) -> RestoreInputs:
    fence_raw = read_input(arguments.fence, secret=True)
    fence = decode_json_object(fence_raw)
    artifact = fence.get("artifactDigest")
    if not isinstance(artifact, dict):
        raise ValueError("restore source artifact binding is missing")
    original = [read_input(path, maximum=32 * 1024) for path in arguments.original_ca]
    current = [read_input(path, maximum=32 * 1024) for path in arguments.ca]
    document = {
        "schema": INPUT_SCHEMA,
        "restoreId": fence.get("restoreId"),
        "snapshotId": fence.get("snapshotId"),
        "repositoryBinding": fence.get("repositoryBinding"),
        "originalArtifactSha256": artifact.get("value"),
        "sourceMachineId": fence.get("sourceMachineId"),
        "destinationMachineId": arguments.destination_id,
        "sourceFenceDigest": framed_digest(FENCE_SCHEMA, fence_raw),
        "namespace": decode_json_object(read_input(arguments.namespace, secret=True)),
        "launch": decode_json_object(read_input(arguments.launch, secret=True))
        if arguments.launch is not None
        else None,
        "archiveTarget": {"region": arguments.archive_region, "bucket": arguments.archive_bucket},
        "caddy": {
            "binaryPath": arguments.binary_path,
            "binarySha256": hashlib.sha256(
                read_input(arguments.binary, maximum=128 * 1024 * 1024)
            ).hexdigest(),
            "environmentSha256": hashlib.sha256(
                read_input(arguments.environment, secret=True)
            ).hexdigest(),
            "originPullCaSha256": [certificate_digest(raw) for raw in current],
            "originalOriginPullCaSha256": [certificate_digest(raw) for raw in original],
            "originPullRequired": True,
            "issuer": ISSUER,
            "subjects": list(SUBJECTS),
            "trustBundleSha256": hashlib.sha256(
                read_input(arguments.trust_bundle, maximum=16 * 1024 * 1024)
            ).hexdigest(),
        },
        "publicationEnabled": arguments.publication_enabled,
        "auditRotationEnabled": arguments.audit_rotation_enabled,
    }
    inputs = RestoreInputs.from_bytes(canonical_json_bytes(document))
    require_fence_policy(fence_raw, inputs)
    if not arguments.output.is_absolute():
        raise ValueError("restore preparation output must be absolute")
    # Exclusive creation prevents a changed policy from silently replacing an
    # existing transaction. Output contains no token, key or repository password.
    arguments.output.mkdir(mode=0o700)
    records = {
        "target.json": canonical_json_bytes(inputs.document),
        f"source-fence-{inputs.restore_id}.json": fence_raw,
        **{f"original-origin-pull-ca-{index}.pem": raw for index, raw in enumerate(original)},
    }
    for name, raw in records.items():
        descriptor = os.open(arguments.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    descriptor = os.open(arguments.output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return inputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fence", "namespace", "binary", "environment", "trust-bundle", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--launch", type=Path)
    parser.add_argument("--ca", type=Path, action="append", required=True)
    parser.add_argument("--original-ca", type=Path, action="append", required=True)
    parser.add_argument("--destination-id", type=machine_id, required=True)
    for name in ("archive-region", "archive-bucket", "binary-path"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--publication-enabled", action="store_true")
    parser.add_argument("--audit-rotation-enabled", action="store_true")
    try:
        inputs = prepare(parser.parse_args())
    except Exception:
        print("restore_policy_preparation_unverified")
        return 1
    print("restore_policy_prepared " + inputs.restore_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
