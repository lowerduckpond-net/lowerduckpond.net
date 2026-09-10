"""Authenticated retirement and bounded retention of the single export slot."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, cast

from lowerduckpond_static_contracts import ExportAcknowledgement, validate_uuid7

from lowerduckpond_static_host_agent.export_spool import ExportSpool, ExportSpoolError
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)

EXPORT_RETENTION: Final = timedelta(hours=24)


class ExportDeliveryError(ExportSpoolError):
    """A download or receipt disagrees with durable authenticated authority."""


class ExportDeliveryBoundary(StrEnum):
    RETIREMENT_SYNC = "retirement-sync"
    BUNDLE_REMOVED = "bundle-removed"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ExportDelivery:
    def __init__(
        self,
        repository: StateRepository,
        spool: ExportSpool,
        *,
        now: Callable[[], datetime] = _utc_now,
        hook: Callable[[ExportDeliveryBoundary], None] | None = None,
    ) -> None:
        self._repository = repository
        self._spool = spool
        self._now = now
        self._hook = hook

    @contextmanager
    def download(self, job_id: str, result: dict[str, object]) -> Iterator[float | None]:
        """Keep physical accounting and expiry excluded until the reader closes."""

        with self._spool.locks.acquire(LockName.EXPORT, blocking=True):
            with self._repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
                job, stored_result = self._read(transaction, job_id)
                if stored_result != result:
                    raise ExportDeliveryError("download result changed before delivery")
                available = self._available(transaction, job)
            remaining = (
                max(0.0, (_expires_at(job) - self._now()).total_seconds()) if available else None
            )
            try:
                yield remaining
            finally:
                # The caller closes its descriptor before leaving this context.
                # A transfer reaching the deadline can now release physical space.
                with self._repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
                    current, _result = self._read(transaction, job_id)
                    self._available(transaction, current)

    def acknowledge(
        self, receipt: ExportAcknowledgement, *, operator_principal: str
    ) -> dict[str, object]:
        """Accept a separate EOF-terminated receipt from the original operator."""

        receipt.encode()
        with (
            self._spool.locks.acquire(LockName.EXPORT, blocking=True),
            self._repository.transaction(mode=LockMode.EXCLUSIVE) as transaction,
        ):
            job, result = self._read(transaction, receipt.job_id)
            binding = cast(dict[str, object], result["exportBundle"])
            digest = binding["digest"]
            if (
                job["operatorPrincipal"] != operator_principal
                or type(digest) is not dict
                or digest["value"] != receipt.sha256
                or binding["size"] != receipt.size
            ):
                raise ExportDeliveryError("download acknowledgement does not match its operator")
            if self._available(transaction, job):
                self._retire(transaction, receipt.job_id, reason="acknowledged")
            return result

    def reconcile(self, *, blocking: bool = False) -> None:
        with self._spool.locks.acquire(LockName.EXPORT, blocking=blocking):
            self.reconcile_locked()

    def reconcile_locked(self) -> None:
        """Discard abandoned copies and finish retirement without inventing jobs."""

        self._spool.discard_workspace()
        job_id = self._spool.completed_job_id()
        if job_id is None:
            return
        with self._repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
            job = transaction.read(StateRecordPath.authorization_job(job_id)).document
            # A killed publisher must first finish its ordinary intent and
            # executor validation. The existing recovery queue owns that work.
            if job.get("executionValidated") is not True:
                return
            job, _result = self._read(transaction, job_id)
            self._available(transaction, job)

    def _available(
        self,
        transaction: _StateTransaction,
        job: dict[str, object],
    ) -> bool:
        job_id = validate_uuid7(job["jobId"])
        occupied = self._spool.completed_job_id()
        if job.get("exportDelivery") in {"acknowledged", "expired"}:
            if occupied == job_id:
                self._spool.remove_completed(job_id)
                self._notify(ExportDeliveryBoundary.BUNDLE_REMOVED)
            return False
        if occupied != job_id:
            raise ExportDeliveryError("unretired export has no exact completed slot")
        now = self._now()
        if now.utcoffset() is None:
            raise ExportDeliveryError("export expiry requires an aware root clock")
        if now >= _expires_at(job):
            self._retire(transaction, job_id, reason="expired")
            return False
        return True

    def _retire(self, transaction: _StateTransaction, job_id: str, *, reason: str) -> None:
        transaction.commit_export_retirement(job_id, reason=reason)
        self._notify(ExportDeliveryBoundary.RETIREMENT_SYNC)
        self._spool.remove_completed(job_id)
        self._notify(ExportDeliveryBoundary.BUNDLE_REMOVED)

    @staticmethod
    def _read(
        transaction: _StateTransaction, job_id: str
    ) -> tuple[dict[str, object], dict[str, object]]:
        job = transaction.read(StateRecordPath.authorization_job(job_id)).document
        result = transaction.read(StateRecordPath.authorization_result(job_id)).document
        request = job["request"]
        if (
            type(request) is not dict
            or request["operation"] != "export"
            or job["phase"] != "completed"
            or job.get("executionValidated") is not True
            or result["operation"] != "export"
            or result["status"] != "succeeded"
            or result["correlationId"] != request["correlationId"]
            or result["tenantId"] != request["tenantId"]
            or result["provenance"] != {"kind": "authorization-job", "jobId": job_id}
            or type(result.get("exportBundle")) is not dict
        ):
            raise ExportDeliveryError("download has no validated export authority")
        return job, result

    def _notify(self, boundary: ExportDeliveryBoundary) -> None:
        if self._hook is not None:
            self._hook(boundary)


def _expires_at(job: dict[str, object]) -> datetime:
    return datetime.fromisoformat(str(job["acceptedAt"])) + EXPORT_RETENTION
