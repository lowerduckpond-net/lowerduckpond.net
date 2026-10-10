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
from scripts.m3_11_unattended.model import (
    Credential,
    Intent,
    LeaseManifest,
    LifecycleError,
    digest,
    fingerprint,
    identity,
    instant,
    stamp,
)

PHASES = frozenset(
    {"starting", "provisioning", "production-check", "running", "revoking", "finished"}
)
OUTCOMES = frozenset({"passed", "failed", "interrupted", "rehearsal-interrupted"})


class CleanupLockBusyError(LifecycleError):
    """Another local actor owns credential reconciliation."""


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


@contextmanager
def cleanup_lock(root: Path, *, blocking: bool = True) -> Iterator[None]:
    """Serialize local reconciliation and secret disposal across the shared run spool."""
    private_directory(root)
    private_directory(root.parent)
    # Keep non-attempt files out of the strictly identified run directory.
    descriptor = os.open(
        root.parent / ".credential-cleanup.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600  # noqa: PLR2004 - private lock
            or info.st_nlink != 1
        ):
            raise LifecycleError("cleanup lock has unsafe metadata")
        # Separate from the journey lock: the watchdog must be able to revoke
        # after a deadline while a controller is still finishing diagnostics.
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            raise CleanupLockBusyError("credential reconciliation is already running") from None
        yield
    finally:
        os.close(descriptor)


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

    def stop_attempt(self) -> None:
        path = self.directory / "stop-attempt.json"
        if not path.exists():
            write_private(path, {"requested_at": stamp(datetime.now(UTC))})

    @property
    def stopped(self) -> bool:
        return (self.directory / "stop-attempt.json").exists()

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


@dataclass(frozen=True)
class LeaseState:
    """Private durable facts for one lease; an interrupted issuer is never resumed."""

    directory: Path

    def initialize(self, manifest: LeaseManifest) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(self.directory)
        self.retain("manifest.json", manifest.document())

    def manifest(self) -> LeaseManifest:
        private_directory(self.directory)
        return LeaseManifest.parse(read_private(self.directory / "manifest.json"))

    def retain(self, name: str, value: dict[str, object]) -> None:
        private_directory(self.directory)
        if Path(name).name != name or not name.endswith(".json"):
            raise LifecycleError("lease state path is invalid")
        path = self.directory / name
        if not path.exists() and not path.is_symlink():
            write_private(path, value)
        if read_private(path) != value:
            raise LifecycleError("original lease state cannot be replaced")

    def claim_issuer(self, *, writer_sha256: str) -> None:
        fingerprint(writer_sha256)
        manifest = self.manifest()
        # O_EXCL is the final guard even when two local launchers race. The
        # enclosing controller holds its existing host admission lock as well.
        try:
            write_private(
                self.directory / "issuer.json",
                {
                    "writer_sha256": writer_sha256,
                    "manifest_sha256": manifest.sha256,
                },
            )
        except FileExistsError:
            raise LifecycleError("an existing lease issuer cannot be replayed or adopted") from None

    def require_writer(self, writer_sha256: str) -> None:
        expected = {
            "writer_sha256": fingerprint(writer_sha256),
            "manifest_sha256": self.manifest().sha256,
        }
        if (
            read_private(self.directory / "issuer.json") != expected
            or (self.directory / "issuer-stopped.json").exists()
        ):
            raise LifecycleError("lease issuance writer is not the original active invocation")

    def submitting(self, intent: Intent, *, writer_sha256: str) -> None:
        self.require_writer(writer_sha256)
        if intent not in self.manifest().intents:
            raise LifecycleError("credential submission escaped the lease manifest")
        try:
            write_private(
                self.directory / ("submitting-" + intent.role + ".json"),
                {
                    "intent_sha256": intent.sha256,
                    "writer_sha256": writer_sha256,
                },
            )
        except FileExistsError:
            raise LifecycleError("credential CREATE may already have been submitted") from None

    def remember(self, intent: Intent, identifier: str, secret: str | None) -> None:
        if intent not in self.manifest().intents:
            raise LifecycleError("credential delivery escaped the lease manifest")
        self.retain(
            "created-" + intent.role + ".json",
            {"intent_sha256": intent.sha256, "credential_id": identifier},
        )
        if secret is not None:
            self.retain(
                "credential-" + intent.role + ".json",
                {"intent_sha256": intent.sha256, "identifier": identifier, "secret": secret},
            )

    def credential(self, intent: Intent) -> Credential | None:
        path = self.directory / ("credential-" + intent.role + ".json")
        if not path.exists() and not path.is_symlink():
            return None
        value = fields(read_private(path), {"intent_sha256", "identifier", "secret"})
        if (
            value["intent_sha256"] != intent.sha256
            or not isinstance(value["identifier"], str)
            or not isinstance(value["secret"], str)
            or not value["secret"]
        ):
            raise LifecycleError("retained lease credential differs from its intent")
        return Credential(value["identifier"], value["secret"], {})

    def created(self, intent: Intent) -> dict[str, object] | None:
        path = self.directory / ("created-" + intent.role + ".json")
        if not path.exists() and not path.is_symlink():
            return None
        value = fields(read_private(path), {"intent_sha256", "credential_id"})
        if value["intent_sha256"] != intent.sha256:
            raise LifecycleError("retained credential ID differs from its intent")
        return value

    def finish_issuer(self, *, writer_sha256: str, stopped_at: str) -> dict[str, object]:
        self.require_writer(writer_sha256)
        instant(stopped_at)
        proof: dict[str, object] = {
            "writer_sha256": writer_sha256,
            "stopped_at": stopped_at,
            "retained_roles": sorted(
                intent.role
                for intent in self.manifest().intents
                if self.credential(intent) is not None
            ),
        }
        self.retain("issuer-stopped.json", proof)
        return proof

    @contextmanager
    def use_lock(self) -> Iterator[None]:
        private_directory(self.directory)
        descriptor = os.open(
            self.directory / "runtime-use.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            raise LifecycleError("lease runtime use is already owned") from None
        finally:
            os.close(descriptor)

    def released_use(self, *, attempt_id: str, binding_sha256: str) -> bool:
        use_path = self.directory / ("use-" + identity(attempt_id) + ".json")
        release_path = self.directory / ("released-" + attempt_id + ".json")
        if not use_path.exists() or not release_path.exists():
            return False
        use = fields(read_private(use_path), {"attempt_id", "binding_sha256", "kind"})
        if use["attempt_id"] != attempt_id or use["binding_sha256"] != fingerprint(binding_sha256):
            raise LifecycleError("lease use belongs to another attempt binding")
        proof = fields(read_private(release_path), {"use_sha256", "quiescence"})
        if proof["use_sha256"] != digest(use):
            raise LifecycleError("lease release belongs to another runtime consumer")
        # Reuse the complete proof validator; retain() checks the immutable bytes.
        self.release_use(
            attempt_id=attempt_id,
            quiescence=fields(
                proof["quiescence"], {"host_commands_drained", "containers", "complete"}
            ),
        )
        return True

    def acquire_use(self, *, attempt_id: str, binding_sha256: str, kind: str) -> None:
        """Caller holds use_lock; process exit alone never releases retained fixtures."""
        identity(attempt_id)
        fingerprint(binding_sha256)
        if kind not in {"attempt", "diagnostic"}:
            raise LifecycleError("lease runtime use kind is invalid")
        for path in self.directory.glob("use-*.json"):
            previous = fields(read_private(path), {"attempt_id", "binding_sha256", "kind"})
            release = self.directory / ("released-" + identity(previous["attempt_id"]) + ".json")
            if not release.exists():
                raise LifecycleError("previous lease consumer has not established quiescence")
            proof = fields(read_private(release), {"use_sha256", "quiescence"})
            if proof["use_sha256"] != digest(previous):
                raise LifecycleError("lease release belongs to another runtime consumer")
        write_private(
            self.directory / ("use-" + attempt_id + ".json"),
            {"attempt_id": attempt_id, "binding_sha256": binding_sha256, "kind": kind},
        )

    def release_use(self, *, attempt_id: str, quiescence: dict[str, object]) -> None:
        # This proof is supplied only by the owned host/guest drainer. No timeout
        # or the absence of a local process substitutes for actual guest checks.
        value = fields(quiescence, {"host_commands_drained", "containers", "complete"})
        containers = value["containers"]
        if (
            value["host_commands_drained"] is not True
            or value["complete"] is not True
            or not isinstance(containers, list)
            or not containers
        ):
            raise LifecycleError("lease consumer quiescence is unresolved")
        seen: set[str] = set()
        for raw in containers:
            row = fields(raw, {"id", "name", "image", "owner", "running", "restart_policy"})
            if row["running"] is not False or row["restart_policy"] != "no":
                raise LifecycleError("retained fixture can still execute or restart")
            selected = fingerprint(row["id"])
            if selected in seen:
                raise LifecycleError("quiescence repeats a retained fixture")
            seen.add(selected)
        use = read_private(self.directory / ("use-" + identity(attempt_id) + ".json"))
        self.retain(
            "released-" + attempt_id + ".json", {"use_sha256": digest(use), "quiescence": value}
        )
