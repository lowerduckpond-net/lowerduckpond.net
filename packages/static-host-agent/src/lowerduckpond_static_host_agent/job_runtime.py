"""Fixed-UUID systemd handoff, terminal delivery, and startup reconciliation."""

from __future__ import annotations

import hashlib
import os
import select
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_contracts import (
    MAX_EXPORT_BYTES,
    FrameHeader,
    FrameKind,
    canonical_json_bytes,
    encode_header,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.correlations import CorrelationAdmission
from lowerduckpond_static_host_agent.execution import ExecutionError, JobHandoff
from lowerduckpond_static_host_agent.intake import ArtifactIntake
from lowerduckpond_static_host_agent.issuance import IssuedAuthorization, VerifiedArtifact
from lowerduckpond_static_host_agent.locks import LockMode, StateBusyError
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)

_SYSTEMCTL: Final = Path("/usr/bin/systemctl")
_WORKER_UNIT: Final = "lowerduckpond-static-worker@{job_id}.service"
_HANDOFF_SECONDS: Final = 15.0
_RESULT_TOTAL_SECONDS: Final = 5.0 * 60.0
_RESULT_POLL_SECONDS: Final = 0.05
_RECOVERY_HANDOFF_LIMIT: Final = 2
_WRITE_TOTAL_SECONDS: Final = 20.0 * 60.0
_WRITE_IDLE_SECONDS: Final = 30.0
_CHUNK_BYTES: Final = 64 * 1024
_READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_DIRECTORY_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_EXPORT_MODE: Final = 0o600


class RuntimeBoundaryError(RuntimeError):
    """The opaque handoff or authenticated terminal delivery failed closed."""


class MonotonicClock(Protocol):
    def __call__(self) -> float: ...


class Sleep(Protocol):
    def __call__(self, seconds: float) -> None: ...


class _AuthorizationReceiver(Protocol):
    def receive(
        self,
        *,
        operator_principal: str,
    ) -> IssuedAuthorization: ...


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


class SystemdJobHandoff:
    """Give systemd only one validated root-owned job UUID."""

    def __init__(self, executable: Path = _SYSTEMCTL) -> None:
        if not executable.is_absolute():
            raise ValueError("systemd handoff executable must be absolute")
        self._executable = executable

    def enqueue(self, job_id: str) -> None:
        canonical_id = validate_uuid7(job_id)
        try:
            completed = subprocess.run(  # noqa: S603
                [
                    os.fspath(self._executable),
                    "start",
                    "--no-block",
                    _WORKER_UNIT.format(job_id=canonical_id),
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                cwd="/",
                env={"LANG": "C.UTF-8"},
                timeout=_HANDOFF_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeBoundaryError("authorized job handoff failed") from error
        if completed.returncode != 0:
            raise RuntimeBoundaryError("authorized job handoff failed")


class ResultWaiter:
    """Retrieve one immutable result without exposing authorization directories."""

    def __init__(
        self,
        repository: StateRepository,
        handoff: JobHandoff,
        *,
        clock: MonotonicClock = time.monotonic,
        sleep: Sleep = _sleep,
        total_seconds: float = _RESULT_TOTAL_SECONDS,
    ) -> None:
        if total_seconds <= 0:
            raise ValueError("result deadline must be positive")
        self._repository = repository
        self._handoff = handoff
        self._clock = clock
        self._sleep = sleep
        self._total_seconds = total_seconds

    def retrieve(self, issued: IssuedAuthorization) -> dict[str, object]:
        """Return an existing result or enqueue and await the exact accepted job."""

        result = self._read(issued.job_id)
        if result is None:
            self._handoff.enqueue(issued.job_id)
        deadline = self._clock() + self._total_seconds
        while result is None:
            if self._clock() >= deadline:
                raise RuntimeBoundaryError("authorized job result timed out")
            self._sleep(_RESULT_POLL_SECONDS)
            result = self._read(issued.job_id)
        _validate_result_for_job(issued.document, result)
        return result

    def _read(self, job_id: str) -> dict[str, object] | None:
        try:
            return self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=False,
            ).document
        except FileNotFoundError, StateBusyError:
            return None


class DeadlineWriter:
    """Bound authenticated response writes by idle and total monotonic time."""

    def __init__(
        self,
        file_descriptor: int,
        *,
        clock: MonotonicClock = time.monotonic,
        total_seconds: float = _WRITE_TOTAL_SECONDS,
        idle_seconds: float = _WRITE_IDLE_SECONDS,
    ) -> None:
        if total_seconds <= 0 or idle_seconds <= 0:
            raise ValueError("writer deadlines must be positive")
        self._fd = file_descriptor
        os.set_blocking(self._fd, False)
        self._clock = clock
        self._total_seconds = total_seconds
        self._total_deadline: float | None = None
        self._idle_deadline: float | None = None
        self._idle_seconds = idle_seconds

    def write(self, data: bytes | memoryview) -> None:
        if self._total_deadline is None or self._idle_deadline is None:
            started = self._clock()
            self._total_deadline = started + self._total_seconds
            self._idle_deadline = started + self._idle_seconds
        remaining = memoryview(data)
        while remaining:
            now = self._clock()
            timeout = min(self._total_deadline - now, self._idle_deadline - now)
            if timeout <= 0:
                raise RuntimeBoundaryError("authenticated result delivery timed out")
            _readable, writable, _exceptional = select.select([], [self._fd], [], timeout)
            if self._fd not in writable:
                raise RuntimeBoundaryError("authenticated result delivery timed out")
            try:
                written = os.write(self._fd, remaining)
            except BlockingIOError, InterruptedError:
                continue
            except BrokenPipeError as error:
                raise RuntimeBoundaryError("authenticated result delivery disconnected") from error
            if written <= 0:
                raise RuntimeBoundaryError("authenticated result delivery made no progress")
            remaining = remaining[written:]
            self._idle_deadline = self._clock() + self._idle_seconds


@dataclass(frozen=True, slots=True)
class ReconciliationOutcome:
    repaired_pairs: int
    removed_intake_entries: int
    enqueued_jobs: tuple[str, ...]
    deferred_jobs: int


class StartupReconciler:
    """Recover only bounded committed authority and never intake bytes alone."""

    def __init__(
        self,
        repository: StateRepository,
        intake: ArtifactIntake,
        handoff: JobHandoff,
    ) -> None:
        self._repository = repository
        self._intake = intake
        self._handoff = handoff

    def reconcile(self) -> ReconciliationOutcome:
        repaired_pairs: int | None = None
        queued: list[str] = []
        batch: tuple[str, ...] | None = None

        def load_authority() -> tuple[dict[str, VerifiedArtifact], set[str]]:
            nonlocal batch, repaired_pairs
            repaired = CorrelationAdmission(self._repository).reconcile(blocking=True)
            repaired_pairs = repaired.repaired_records
            active_intent_jobs = self._active_intent_job_ids(repaired.jobs)
            authorized: dict[str, VerifiedArtifact] = {}
            terminal: set[str] = set()
            for stored in repaired.jobs:
                job = stored.document
                job_id = validate_uuid7(job["jobId"])
                correlation_id = _correlation_id(job)
                filename = f"{correlation_id}.artifact"
                result_exists = self._result_exists(job_id)
                artifact = _artifact_binding(job)
                needs_lifecycle_replay = job_id in active_intent_jobs
                if (
                    result_exists or job["phase"] in {"completed", "failed"}
                ) and not needs_lifecycle_replay:
                    terminal.add(filename)
                elif artifact is not None:
                    authorized[filename] = artifact
                if result_exists:
                    if job["phase"] not in {"completed", "failed"} or job_id in active_intent_jobs:
                        queued.append(job_id)
                elif job["phase"] in {"pending", "claimed"}:
                    queued.append(job_id)
                else:
                    raise ExecutionError("terminal authorization job has no immutable result")
            batch = self._repository.select_recovery_batch(
                tuple(queued),
                limit=_RECOVERY_HANDOFF_LIMIT,
                blocking=True,
            )
            return authorized, terminal

        intake = self._intake.reconcile(
            authority=load_authority,
            blocking=True,
        )
        if repaired_pairs is None:  # pragma: no cover - intake always invokes authority
            raise RuntimeBoundaryError("authorization reconciliation did not load authority")
        if batch is None:  # pragma: no cover - intake always invokes authority
            raise RuntimeBoundaryError("authorization reconciliation did not select a batch")
        for job_id in batch:
            self._handoff.enqueue(job_id)
        return ReconciliationOutcome(
            repaired_pairs=repaired_pairs,
            removed_intake_entries=intake.removed_entries,
            enqueued_jobs=tuple(batch),
            deferred_jobs=len(queued) - len(batch),
        )

    def _result_exists(self, job_id: str) -> bool:
        try:
            self._repository.read(
                StateRecordPath.authorization_result(job_id),
                blocking=True,
            )
        except FileNotFoundError:
            return False
        return True

    def _active_intent_job_ids(
        self,
        jobs: tuple[StoredContract, ...],
    ) -> set[str]:
        jobs_by_correlation: dict[str, str] = {}
        for stored in jobs:
            correlation_id = _correlation_id(stored.document)
            if correlation_id in jobs_by_correlation:
                raise ExecutionError("authorization inventory repeats a correlation")
            jobs_by_correlation[correlation_id] = validate_uuid7(stored.document["jobId"])
        active: set[str] = set()
        with self._repository.transaction(
            mode=LockMode.EXCLUSIVE,
            blocking=True,
        ) as transaction:
            for identity in transaction.measure_intent_records().records:
                _path, intent = transaction.read_intent(identity.intent_id)
                provenance = intent.document.get("provenance")
                if (
                    intent.document["kind"] == "ArchiveRetirementIntent"
                    and type(provenance) is dict
                    and provenance.get("kind") == "emergency-administrator"
                ):
                    continue
                correlation_id = validate_uuid7(intent.document["correlationId"])
                try:
                    job_id = jobs_by_correlation[correlation_id]
                except KeyError as error:
                    raise ExecutionError(
                        "active lifecycle intent has no authorization job"
                    ) from error
                active.add(job_id)
        return active


class OperatorSession:
    """Issue, hand off, and return one authenticated terminal response frame."""

    def __init__(
        self,
        adapter: _AuthorizationReceiver,
        waiter: ResultWaiter,
        *,
        state_root: Path,
        expected_owner: int,
        writer: DeadlineWriter,
    ) -> None:
        self._adapter = adapter
        self._waiter = waiter
        self._state_root = state_root
        self._expected_owner = expected_owner
        self._writer = writer

    def run(self, *, operator_principal: str) -> dict[str, object]:
        issued = self._adapter.receive(operator_principal=operator_principal)
        result = self._waiter.retrieve(issued)
        canonical = canonical_json_bytes(result)
        export = _ExportSource.open(
            self._state_root,
            issued.job_id,
            result,
            expected_owner=self._expected_owner,
        )
        try:
            self._writer.write(
                encode_header(
                    FrameHeader(
                        FrameKind.RESPONSE,
                        len(canonical),
                        export.size if export is not None else None,
                    )
                )
            )
            self._writer.write(canonical)
            if export is not None:
                export.write_to(self._writer)
        finally:
            if export is not None:
                export.close()
        return result


@dataclass(slots=True)
class _ExportSource:
    file_descriptor: int
    size: int
    sha256: str
    generation: tuple[int, ...]

    @classmethod
    def open(
        cls,
        state_root: Path,
        job_id: str,
        result: dict[str, object],
        *,
        expected_owner: int,
    ) -> _ExportSource | None:
        binding = result.get("exportBundle")
        if type(binding) is not dict:
            return None
        exports_fd = os.open(state_root / "exports", _DIRECTORY_FLAGS)
        try:
            file_descriptor = os.open(
                f"{validate_uuid7(job_id)}.zip",
                _READ_FLAGS,
                dir_fd=exports_fd,
            )
        finally:
            os.close(exports_fd)
        try:
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != expected_owner
                or stat.S_IMODE(before.st_mode) != _EXPORT_MODE
                or before.st_nlink != 1
                or before.st_size != binding["size"]
                or before.st_size > MAX_EXPORT_BYTES
            ):
                raise RuntimeBoundaryError("authenticated export has unsafe metadata")
            digest = hashlib.sha256()
            while chunk := os.read(file_descriptor, _CHUNK_BYTES):
                digest.update(chunk)
            after = os.fstat(file_descriptor)
            expected_digest = binding["digest"]
            if (
                _generation(before) != _generation(after)
                or type(expected_digest) is not dict
                or digest.hexdigest() != expected_digest["value"]
            ):
                raise RuntimeBoundaryError("authenticated export does not match its result")
            os.lseek(file_descriptor, 0, os.SEEK_SET)
            return cls(
                file_descriptor,
                before.st_size,
                digest.hexdigest(),
                _generation(before),
            )
        except BaseException:
            os.close(file_descriptor)
            raise

    def write_to(self, writer: DeadlineWriter) -> None:
        total = 0
        digest = hashlib.sha256()
        while chunk := os.read(self.file_descriptor, _CHUNK_BYTES):
            writer.write(chunk)
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(self.file_descriptor)
        if (
            _generation(after) != self.generation
            or total != self.size
            or digest.hexdigest() != self.sha256
        ):
            raise RuntimeBoundaryError("authenticated export changed during delivery")

    def close(self) -> None:
        os.close(self.file_descriptor)


def _validate_result_for_job(job: dict[str, object], result: dict[str, object]) -> None:
    request = job["request"]
    provenance = result["provenance"]
    if type(request) is not dict or type(provenance) is not dict:
        raise RuntimeBoundaryError("terminal result binding is malformed")
    tenant_id = _expected_result_tenant(request, result)
    if (
        provenance != {"kind": "authorization-job", "jobId": job["jobId"]}
        or result["correlationId"] != request["correlationId"]
        or result["operation"] != request["operation"]
        or result["tenantId"] != tenant_id
    ):
        raise RuntimeBoundaryError("terminal result does not match its authenticated job")


def _expected_result_tenant(
    request: dict[str, object],
    result: dict[str, object],
) -> object:
    if request["operation"] != "create":
        return request["tenantId"]
    if result["status"] == "failed":
        return None
    try:
        return validate_uuid7(result["tenantId"])
    except (TypeError, ValueError) as error:
        raise RuntimeBoundaryError("successful create result has no generated tenant") from error


def _artifact_binding(job: dict[str, object]) -> VerifiedArtifact | None:
    artifact = job["artifact"]
    if artifact is None:
        return None
    if type(artifact) is not dict:  # pragma: no cover - validated state proves this
        raise RuntimeBoundaryError("authorization artifact binding is malformed")
    size = artifact["size"]
    sha256 = artifact["sha256"]
    if type(size) is not int or type(sha256) is not str:
        raise RuntimeBoundaryError("authorization artifact binding is malformed")
    return VerifiedArtifact(size=size, sha256=sha256)


def _correlation_id(job: dict[str, object]) -> str:
    request = job["request"]
    if type(request) is not dict:  # pragma: no cover - validated state proves this
        raise RuntimeBoundaryError("authorization request is malformed")
    return validate_uuid7(request["correlationId"])


def _generation(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )
