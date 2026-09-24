"""Fixed administrative paths; no restored record can select an installation target."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from lowerduckpond_static_contracts import validate_uuid7

from lowerduckpond_static_host_agent.host_restore_install import RootSwap
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_materialize import MaterializationPaths


def private_directory(path: Path, *, owner: int = 0) -> None:
    """Create only one child under a protected existing parent and sync both."""
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    child = -1
    try:
        metadata = os.fstat(parent)
        if metadata.st_uid != owner or metadata.st_mode & 0o022:
            raise HostRestoreError("restore_workspace_parent_unsafe")
        with suppress(FileExistsError):
            os.mkdir(path.name, 0o700, dir_fd=parent)
        child = os.open(
            path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
        )
        metadata = os.fstat(child)
        if (
            metadata.st_uid != owner
            or metadata.st_gid != owner
            or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004
            or metadata.st_dev != os.fstat(parent).st_dev
        ):
            raise HostRestoreError("restore_workspace_unsafe")
        os.fsync(child)
        os.fsync(parent)
    finally:
        if child >= 0:
            os.close(child)
        os.close(parent)


@dataclass(frozen=True)
class RestorePaths:
    restore_id: str
    caddy_group: int
    # Alternate absolute roots are for component fixtures only. The installed
    # root entrypoint constructs this with defaults and accepts no path options.
    state: Path = Path("/var/lib/lowerduckpond/static")
    content: Path = Path("/srv/lowerduckpond")
    caddy: Path = Path("/etc/caddy")
    recovery: Path = Path("/var/lib/lowerduckpond/recovery")
    cache: Path = Path("/var/cache/lowerduckpond-host-restore")
    owner: int = 0

    def __post_init__(self) -> None:
        validate_uuid7(self.restore_id)
        if any(
            not path.is_absolute()
            for path in (self.state, self.content, self.caddy, self.recovery, self.cache)
        ):
            raise HostRestoreError("restore_paths_must_be_absolute")

    @property
    def swaps(self) -> dict[str, RootSwap]:
        return {
            "state": RootSwap("state", self.state, self.restore_id, 0o700, self.owner),
            "content": RootSwap("content", self.content, self.restore_id, 0o711, self.owner),
            "caddy": RootSwap("caddy", self.caddy, self.restore_id, 0o750, self.caddy_group),
        }

    @property
    def materialization(self) -> MaterializationPaths:
        return MaterializationPaths(
            {
                "state": self.swaps["state"].candidate,
                "content": self.swaps["content"].candidate,
                "recovery": self.recovery.parent / f".restore-{self.restore_id}-recovery",
            },
            self.cache / self.restore_id / "staging",
            self.cache / self.restore_id / "workspace",
        )

    @property
    def archive_workspace(self) -> Path:
        return self.cache / self.restore_id / "archives"

    def prepare_parents(self) -> None:
        for path in (
            self.cache,
            self.cache / self.restore_id,
            self.materialization.workspace,
            self.archive_workspace,
            *(swap.container for swap in self.swaps.values()),
        ):
            private_directory(path, owner=self.owner)
