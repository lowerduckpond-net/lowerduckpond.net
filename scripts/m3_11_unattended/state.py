"""Persistent one-attempt state. Restart can reconcile, never replay qualification."""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.model import LifecycleError, identity, instant, stamp

PHASES = frozenset(
    {"starting", "provisioning", "production-check", "running", "revoking", "finished"}
)
OUTCOMES = frozenset({"passed", "failed", "interrupted", "rehearsal-interrupted"})


def private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not path.is_absolute()
        or path.resolve(strict=True) != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004 - private directory
    ):
        raise LifecycleError("controller storage is not a canonical private directory")


def replace_private(path: Path, value: dict[str, object]) -> None:
    private_directory(path.parent)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pending-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
            temporary.replace(path)
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class RunState:
    directory: Path

    @contextmanager
    def lock(self) -> Iterator[None]:
        private_directory(self.directory)
        descriptor = os.open(
            self.directory / "controller.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def begin(self, binding: dict[str, object]) -> bool:
        """False means this immutable attempt already started and must be reconciled."""
        identity(binding["managed_run_id"])
        path = self.directory / "attempt.json"
        if path.exists() or path.is_symlink():
            value = read_private(path)
            if value.get("binding") != binding:
                raise LifecycleError("controller restart changed the original attempt binding")
            return False
        write_private(
            path,
            {
                "format": "lowerduckpond-m3-11-unattended-attempt-v1",
                "binding": binding,
                "started_at": stamp(datetime.now(UTC)),
            },
        )
        self.update("starting", cleanup="pending")
        return True

    def finish_journey(self, outcome: str, status: int) -> None:
        if outcome not in OUTCOMES or type(status) is not int or not 0 <= status <= 255:  # noqa: PLR2004 - process exit status
            raise LifecycleError("invalid qualification exit outcome")
        if (outcome == "passed") != (status == 0):
            raise LifecycleError("qualification outcome and exit status disagree")
        write_private(
            self.directory / "journey-result.json",
            {
                "format": "lowerduckpond-m3-11-unattended-result-v1",
                "outcome": outcome,
                "status": status,
                "observed_at": stamp(datetime.now(UTC)),
            },
        )

    def interrupted(self) -> None:
        path = self.directory / "journey-result.json"
        if not path.exists():
            self.finish_journey("interrupted", 137)

    def cancel(self) -> None:
        path = self.directory / "cancel.json"
        if not path.exists():
            write_private(path, {"requested_at": stamp(datetime.now(UTC))})

    @property
    def cancelled(self) -> bool:
        return (self.directory / "cancel.json").exists()

    def update(self, phase: str, *, cleanup: str, preserve_verified: bool = False) -> None:
        if phase not in PHASES or cleanup not in {"pending", "verified", "unresolved"}:
            raise LifecycleError("invalid controller progress")
        private_directory(self.directory)
        descriptor = os.open(
            self.directory / "status.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            # A separate short lock serializes watchdog/controller status writes
            # without taking the controller's journey-long execution lock.
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            if (
                preserve_verified
                and (self.directory / "status.json").exists()
                and self.status()["credential_cleanup"] == "verified"
            ):
                return
            replace_private(
                self.directory / "status.json",
                {
                    "format": "lowerduckpond-m3-11-unattended-status-v1",
                    "phase": phase,
                    "credential_cleanup": cleanup,
                    "observed_at": stamp(datetime.now(UTC)),
                },
            )
        finally:
            os.close(descriptor)

    def status(self) -> dict[str, object]:
        progress = fields(
            read_private(self.directory / "status.json"),
            {"format", "phase", "credential_cleanup", "observed_at"},
        )
        if (
            progress["format"] != "lowerduckpond-m3-11-unattended-status-v1"
            or progress["phase"] not in PHASES
            or progress["credential_cleanup"]
            not in {
                "pending",
                "verified",
                "unresolved",
            }
        ):
            raise LifecycleError("controller status is malformed")
        progress["observed_at"] = stamp(instant(progress["observed_at"]))
        result: dict[str, object] = {
            **progress,
            "qualification": "not-finished",
            "closure": "unresolved",
        }
        path = self.directory / "journey-result.json"
        if path.exists():
            journey = fields(read_private(path), {"format", "outcome", "status", "observed_at"})
            if (
                journey["format"] != "lowerduckpond-m3-11-unattended-result-v1"
                or journey["outcome"] not in OUTCOMES
                or type(journey["status"]) is not int
                or not 0 <= journey["status"] <= 255  # noqa: PLR2004 - exit status
                or (journey["outcome"] == "passed") != (journey["status"] == 0)
            ):
                raise LifecycleError("controller qualification result is malformed")
            instant(journey["observed_at"])
            result["qualification"] = journey["outcome"]
            result["exit_status"] = journey["status"]
            if journey["outcome"] == "passed" and progress["credential_cleanup"] == "verified":
                result["closure"] = "complete"
        return result
