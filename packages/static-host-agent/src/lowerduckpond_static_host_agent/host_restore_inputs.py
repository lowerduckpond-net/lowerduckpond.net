"""Canonical operator-supplied recovery policy, separate from restored authority."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import (
    ContractKind,
    canonical_json_bytes,
    decode_json_object,
    validate_contract,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.backup_identity import (
    BINDING_FORMAT,
    framed_digest,
    require_digest,
)
from lowerduckpond_static_host_agent.caddy_routes import (
    PLATFORM_APEX,
    PLATFORM_WILDCARD,
    TENANT_APEX,
    TENANT_WILDCARD,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    exact_object,
    full_id,
)

INPUT_SCHEMA: Final = "lowerduckpond-host-restore-inputs-v1"
INPUT_ROOT: Final = Path("/etc/lowerduckpond/host-restore")
MACHINE: Final = re.compile(r"[0-9a-f]{32}", re.ASCII)
SUBJECTS: Final = tuple(sorted((PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD)))
ISSUER: Final = "acme-v02.api.letsencrypt.org-directory"
ISSUER_URL: Final = "https://acme-v02.api.letsencrypt.org/directory"
TRUST_BUNDLE: Final = Path("/etc/ssl/certs/ca-certificates.crt")


def machine_id(value: object) -> str:
    if type(value) is not str or MACHINE.fullmatch(value) is None or set(value) == {"0"}:
        raise HostRestoreError("restore machine identity is invalid")
    return value


def local_machine_id(path: Path = Path("/etc/machine-id"), *, owner: int = 0) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or metadata.st_mode & 0o022
            or metadata.st_nlink != 1
            or metadata.st_size != 33  # noqa: PLR2004 - 32 lowercase hex bytes and LF
        ):
            raise HostRestoreError("restore machine identity file is unsafe")
        raw = os.read(descriptor, 34)
        if len(raw) != metadata.st_size or not raw.endswith(b"\n"):
            raise HostRestoreError("restore machine identity file changed")
        return machine_id(raw[:-1].decode("ascii"))
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class RestoreInputs:
    document: dict[str, object]

    @classmethod
    def from_bytes(cls, raw: bytes) -> RestoreInputs:
        value = exact_object(
            decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES),
            {
                "schema",
                "restoreId",
                "snapshotId",
                "repositoryBinding",
                "originalArtifactSha256",
                "sourceMachineId",
                "destinationMachineId",
                "sourceFenceDigest",
                "namespace",
                "launch",
                "archiveTarget",
                "caddy",
                "publicationEnabled",
                "auditRotationEnabled",
            },
        )
        if value["schema"] != INPUT_SCHEMA:
            raise HostRestoreError("restore input schema is unsupported")
        validate_uuid7(value["restoreId"])
        full_id(value["snapshotId"])
        full_id(value["originalArtifactSha256"])
        require_digest(value["repositoryBinding"], BINDING_FORMAT)
        require_digest(value["sourceFenceDigest"], "lowerduckpond-host-restore-source-fence-v1")
        if machine_id(value["sourceMachineId"]) == machine_id(value["destinationMachineId"]):
            raise HostRestoreError("restore destination must be a distinct fenced host")
        namespace = value["namespace"]
        if type(namespace) is not dict:
            raise HostRestoreError("restore namespace is invalid")
        validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
        launch = value["launch"]
        if launch is not None:
            if type(launch) is not dict:
                raise HostRestoreError("restore launch policy is invalid")
            validate_contract(launch, expected_kind=ContractKind.LAUNCH_RECORD)
        for key in ("publicationEnabled", "auditRotationEnabled"):
            if type(value[key]) is not bool:
                raise HostRestoreError("restore activation policy is invalid")
        target = exact_object(value["archiveTarget"], {"region", "bucket"})
        if (
            type(target["region"]) is not str
            or re.fullmatch(r"[a-z]{3}[1-9][0-9]?", target["region"]) is None
            or type(target["bucket"]) is not str
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", target["bucket"]) is None
        ):
            raise HostRestoreError("restore archive target is invalid")
        _validate_caddy(value["caddy"])
        if canonical_json_bytes(value, maximum_bytes=MAX_RESTORE_BYTES) != raw:
            raise HostRestoreError("restore inputs are not canonical")
        return cls(value)

    @classmethod
    def load(cls, root: Path = INPUT_ROOT, *, owner: int = 0) -> RestoreInputs:
        with DurableDirectory.open(
            root, expected_owner=owner, expected_directory_mode=0o700
        ) as directory:
            return cls.from_bytes(
                directory.read_regular(
                    ("target.json",),
                    expected_owner=owner,
                    expected_mode=0o600,
                    maximum_bytes=MAX_RESTORE_BYTES,
                )
            )

    @property
    def digest(self) -> dict[str, str]:
        return framed_digest(
            INPUT_SCHEMA, canonical_json_bytes(self.document, maximum_bytes=MAX_RESTORE_BYTES)
        )

    @property
    def restore_id(self) -> str:
        return validate_uuid7(self.document["restoreId"])

    @property
    def snapshot_id(self) -> str:
        return full_id(self.document["snapshotId"])

    @property
    def caddy(self) -> dict[str, object]:
        return cast(dict[str, object], self.document["caddy"])

    def require_destination(
        self, identity: str, artifact_sha256: str, requested_snapshot: str
    ) -> None:
        if (
            machine_id(identity) != self.document["destinationMachineId"]
            or full_id(artifact_sha256) != self.document["originalArtifactSha256"]
            or full_id(requested_snapshot) != self.snapshot_id
        ):
            raise HostRestoreError("restore_target_input_mismatch")


def _validate_caddy(document: object) -> None:
    value = exact_object(
        document,
        {
            "binaryPath",
            "binarySha256",
            "environmentSha256",
            "originPullCaSha256",
            "originalOriginPullCaSha256",
            "originPullRequired",
            "issuer",
            "subjects",
            "trustBundleSha256",
        },
    )
    binary = value["binaryPath"]
    if (
        type(binary) is not str
        or re.fullmatch(r"/usr/local/lib/lowerduckpond/caddy-[A-Za-z0-9_.-]{1,200}", binary) is None
    ):
        raise HostRestoreError("restore Caddy binary path is invalid")
    for key in ("binarySha256", "environmentSha256", "trustBundleSha256"):
        full_id(value[key])
    for key in ("originPullCaSha256", "originalOriginPullCaSha256"):
        values = value[key]
        if type(values) is not list or not 1 <= len(values) <= 2:  # noqa: PLR2004 - current/next CA
            raise HostRestoreError("restore origin-pull trust is incomplete")
        for digest in values:
            full_id(digest)
    if (
        type(value["originPullRequired"]) is not bool
        or not value["originPullRequired"]
        or value["issuer"] != ISSUER
        or value["subjects"] != list(SUBJECTS)
    ):
        raise HostRestoreError("restore TLS policy cannot weaken production origin trust")


def file_sha256(
    path: Path,
    *,
    owner: int,
    group: int,
    mode: int,
    maximum: int,
) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner
            or metadata.st_gid != group
            or stat.S_IMODE(metadata.st_mode) != mode
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum
        ):
            raise HostRestoreError("restore_trusted_file_unsafe")
        digest = hashlib.sha256()
        count = 0
        while data := os.read(descriptor, min(64 * 1024, maximum + 1 - count)):
            count += len(data)
            if count > maximum:
                raise HostRestoreError("restore_trusted_file_oversized")
            digest.update(data)
        if (
            file_identity(metadata) != file_identity(os.fstat(descriptor))
            or file_identity(metadata) != file_identity(path.stat(follow_symlinks=False))
            or count != metadata.st_size
        ):
            raise HostRestoreError("restore_trusted_file_changed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
