"""Inert systemd sandbox contract for the future privileged archive worker."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9._-]+", flags=re.ASCII)

ARCHIVE_SANDBOX_STATIC_PROPERTIES: Final[tuple[tuple[str, str], ...]] = (
    ("Type", "oneshot"),
    ("UMask", "0077"),
    ("MemoryMax", "256M"),
    ("MemorySwapMax", "0"),
    ("TasksMax", "32"),
    ("LimitNOFILE", "1024"),
    ("LimitCPU", "120"),
    ("RuntimeMaxSec", "5min"),
    ("CPUQuota", "100%"),
    ("PrivateTmp", "true"),
    ("PrivateDevices", "true"),
    ("PrivateNetwork", "true"),
    ("ProtectSystem", "strict"),
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
    ("RestrictAddressFamilies", "AF_UNIX"),
    ("RestrictNamespaces", "true"),
    ("RestrictRealtime", "true"),
    ("RestrictSUIDSGID", "true"),
    ("LockPersonality", "true"),
    ("MemoryDenyWriteExecute", "true"),
    ("SystemCallArchitectures", "native"),
    ("SystemCallFilter", "@system-service"),
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

    artifact: Path
    staging_parent: Path
    properties: tuple[tuple[str, str], ...]


def archive_sandbox_policy(
    artifact: Path,
    staging_parent: Path,
) -> ArchiveSandboxPolicy:
    """Bind one immutable input and one writable staging parent to the fixed limits."""

    artifact = _validated_absolute_path(artifact, label="artifact")
    staging_parent = _validated_absolute_path(staging_parent, label="staging parent")
    if _contains(artifact, staging_parent) or _contains(staging_parent, artifact):
        raise ArchiveSandboxError("archive sandbox paths must be disjoint")
    properties = (
        *ARCHIVE_SANDBOX_STATIC_PROPERTIES,
        ("ReadOnlyPaths", str(artifact)),
        ("ReadWritePaths", str(staging_parent)),
    )
    return ArchiveSandboxPolicy(artifact, staging_parent, properties)


def _validated_absolute_path(path: Path, *, label: str) -> Path:
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
    return Path(raw)


def _contains(parent: Path, child: Path) -> bool:
    return parent == child or parent in child.parents
