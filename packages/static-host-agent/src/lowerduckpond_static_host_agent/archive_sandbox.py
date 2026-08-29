"""Inert systemd sandbox contract for the future privileged archive worker."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9._-]+", flags=re.ASCII)

ARCHIVE_SANDBOX_STATIC_PROPERTIES: Final[tuple[tuple[str, str], ...]] = (
    ("Type", "exec"),
    ("UMask", "0077"),
    ("MemoryMax", "256M"),
    ("MemorySwapMax", "0"),
    ("TasksMax", "32"),
    ("LimitNOFILE", "1024"),
    ("LimitCPU", "120"),
    ("RuntimeMaxSec", "5min"),
    ("TimeoutStartSec", "5min"),
    ("CPUQuota", "100%"),
    ("PrivateIPC", "true"),
    ("PrivateDevices", "true"),
    ("PrivateNetwork", "true"),
    ("ProtectSystem", "strict"),
    ("TemporaryFileSystem", "/:ro"),
    ("ProtectHome", "true"),
    ("ProtectHostname", "true"),
    ("ProtectClock", "true"),
    ("ProtectKernelTunables", "true"),
    ("ProtectKernelModules", "true"),
    ("ProtectKernelLogs", "true"),
    ("ProtectControlGroups", "true"),
    ("ProtectProc", "invisible"),
    ("ProcSubset", "pid"),
    ("NoNewPrivileges", "true"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("RestrictAddressFamilies", "~AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET"),
    ("RestrictNamespaces", "true"),
    ("RestrictRealtime", "true"),
    ("RestrictSUIDSGID", "true"),
    ("LockPersonality", "true"),
    ("MemoryDenyWriteExecute", "true"),
    ("SystemCallArchitectures", "native"),
    ("SystemCallFilter", "@system-service"),
    ("SystemCallFilter", "~@network-io"),
    (
        "SystemCallFilter",
        "~kill tkill tgkill rt_sigqueueinfo rt_tgsigqueueinfo pidfd_send_signal",
    ),
    (
        "SystemCallFilter",
        "~ptrace process_vm_readv process_vm_writev pidfd_getfd process_madvise process_mrelease",
    ),
    ("SystemCallErrorNumber", "EPERM"),
    ("DevicePolicy", "closed"),
    ("IPAddressDeny", "any"),
    ("TimeoutStopSec", "15s"),
    ("KillMode", "mixed"),
)


class ArchiveSandboxError(ValueError):
    """Archive worker paths cannot be represented by the fixed sandbox contract."""


@dataclass(frozen=True, slots=True)
class ArchiveSandboxPolicy:
    """Exact unit properties for one artifact and one unpublished staging tree."""

    runtime_root: Path
    artifact: Path
    staging_parent: Path
    properties: tuple[tuple[str, str], ...]


def archive_sandbox_policy(
    runtime_root: Path,
    artifact: Path,
    staging_parent: Path,
) -> ArchiveSandboxPolicy:
    """Expose only one runtime, immutable input, and writable unpublished tree."""

    runtime = _validated_existing_path(runtime_root, label="runtime", directory=True)
    artifact_identity = _validated_existing_path(artifact, label="artifact", directory=False)
    staging = _validated_existing_path(staging_parent, label="staging parent", directory=True)
    identities = (runtime, artifact_identity, staging)
    for index, first in enumerate(identities):
        for second in identities[index + 1 :]:
            if _paths_alias_or_overlap(first, second):
                raise ArchiveSandboxError("archive sandbox paths must be disjoint and unaliased")
    properties = (
        *ARCHIVE_SANDBOX_STATIC_PROPERTIES,
        ("BindReadOnlyPaths", str(runtime.path)),
        ("BindReadOnlyPaths", str(artifact_identity.path)),
        ("BindPaths", str(staging.path)),
    )
    return ArchiveSandboxPolicy(
        runtime.path,
        artifact_identity.path,
        staging.path,
        properties,
    )


@dataclass(frozen=True, slots=True)
class _PathIdentity:
    path: Path
    parts: tuple[str, ...]
    inode_chain: tuple[tuple[int, int], ...]


def _validated_existing_path(path: Path, *, label: str, directory: bool) -> _PathIdentity:
    raw = str(path)
    parsed = PurePosixPath(raw)
    if (
        not parsed.is_absolute()
        or raw != str(parsed)
        or raw == "/"
        or any(
            component in {"", ".", ".."} or _SAFE_COMPONENT.fullmatch(component) is None
            for component in parsed.parts[1:]
        )
    ):
        raise ArchiveSandboxError(f"archive sandbox {label} path is not canonical")
    descriptors: list[int] = []
    inode_chain: list[tuple[int, int]] = []
    try:
        descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(descriptor)
        root = os.fstat(descriptor)
        inode_chain.append((root.st_dev, root.st_ino))
        for index, component in enumerate(parsed.parts[1:]):
            final = index == len(parsed.parts[1:]) - 1
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if not final or directory:
                flags |= os.O_DIRECTORY
            descriptor = os.open(component, flags, dir_fd=descriptor)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if stat.S_ISLNK(metadata.st_mode):
                raise ArchiveSandboxError(f"archive sandbox {label} path contains a symbolic link")
            if not final and not stat.S_ISDIR(metadata.st_mode):
                raise ArchiveSandboxError(f"archive sandbox {label} parent is not a directory")
            inode_chain.append((metadata.st_dev, metadata.st_ino))
        final_metadata = os.fstat(descriptors[-1])
        expected_shape = (
            stat.S_ISDIR(final_metadata.st_mode)
            if directory
            else stat.S_ISREG(final_metadata.st_mode)
        )
        if not expected_shape:
            expected = "directory" if directory else "regular file"
            raise ArchiveSandboxError(f"archive sandbox {label} is not a {expected}")
        named = Path(raw).stat(follow_symlinks=False)
        if (named.st_dev, named.st_ino) != inode_chain[-1]:
            raise ArchiveSandboxError(f"archive sandbox {label} changed during validation")
    except OSError as error:
        raise ArchiveSandboxError(f"archive sandbox {label} path is unavailable") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return _PathIdentity(Path(raw), parsed.parts, tuple(inode_chain))


def _paths_alias_or_overlap(first: _PathIdentity, second: _PathIdentity) -> bool:
    if (
        first.path == second.path
        or first.path in second.path.parents
        or second.path in first.path.parents
    ):
        return True
    shared = 0
    for first_part, second_part in zip(first.parts, second.parts, strict=False):
        if first_part != second_part:
            break
        shared += 1
    first_private = set(first.inode_chain[shared:])
    second_private = set(second.inode_chain[shared:])
    return bool(first_private & second_private)
