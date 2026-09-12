"""Job-bound remote cleanup with durable journal and terminal-state authority."""

from __future__ import annotations

import os
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import ContractError, validate_uuid7

from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, ArchiveRemoteStore
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_REQUEST_BYTES,
    MAX_ARCHIVE_RESPONSE_BYTES,
    ArchiveChannel,
    ArchiveTransportError,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository

ARCHIVE_CLEANUP_SOCKET_PATH: Final = Path("/run/lowerduckpond-archive/cleanup.sock")
_PROTOCOL: Final = "lowerduckpond-archive-cleanup-v1"


def connect_archive_cleanup() -> socket.socket:
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(30.0)
        stream.connect(str(ARCHIVE_CLEANUP_SOCKET_PATH))
        return stream
    except BaseException:
        stream.close()
        raise


class ArchiveCleanupClient:
    """Request cleanup of the sole journal derived independently from one job."""

    def __init__(
        self,
        spool: ExportSpool,
        *,
        connector: Callable[[], socket.socket] = connect_archive_cleanup,
        expected_peer_uid: int = 0,
    ) -> None:
        self._spool = spool
        self._connector = connector
        self._peer = expected_peer_uid

    def purge_construction(self, job_id: str, intent_id: str) -> None:
        """Purge an unbound upload before failure publication, retaining its journal."""
        self._request(job_id, intent_id, operation="purge-construction")

    def finish(self, job_id: str, intent_id: str) -> None:
        """Remove a journal only after independent terminal-state and remote proof."""
        self._request(job_id, intent_id, operation="finish")

    def _request(self, job_id: str, intent_id: str, *, operation: str) -> None:
        canonical_job = validate_uuid7(job_id)
        canonical_intent = validate_uuid7(intent_id)
        lease = self._spool.locks.duplicate_export_descriptor()
        try:
            with ArchiveChannel(
                self._connector(),
                expected_peer_uid=self._peer,
                maximum_receive_bytes=MAX_ARCHIVE_RESPONSE_BYTES,
            ) as channel:
                channel.send(
                    {"protocol": _PROTOCOL, "operation": operation, "jobId": canonical_job},
                    descriptor=lease,
                )
                with channel.receive() as response:
                    if response.descriptor is not None or response.payload != {
                        "status": "cleaned",
                        "operation": operation,
                        "intentId": canonical_intent,
                    }:
                        raise ArchiveRemoteError("archive cleanup did not confirm its journal")
        except (OSError, ContractError, ArchiveTransportError) as error:
            raise ArchiveRemoteError("archive cleanup did not complete") from error
        finally:
            os.close(lease)


def serve_archive_cleanup(  # noqa: PLR0913 - explicit privileged boundaries
    stream: socket.socket,
    repository: StateRepository,
    spool: ExportSpool,
    remote: ArchiveRemoteStore,
    *,
    quarantine: ArchiveQuarantine,
    expected_owner: int = 0,
) -> None:
    """Retain export exclusion through every request, proof, and journal removal."""
    with (
        ArchiveChannel(
            stream,
            expected_peer_uid=expected_owner,
            maximum_receive_bytes=MAX_ARCHIVE_REQUEST_BYTES,
        ) as channel,
        channel.receive() as request,
    ):
        payload = request.payload
        if (
            set(payload) != {"protocol", "operation", "jobId"}
            or payload["protocol"] != _PROTOCOL
            or payload["operation"] not in {"purge-construction", "finish"}
            or request.descriptor is None
        ):
            raise ArchiveRemoteError("archive cleanup requires one job-bound request and lease")
        job_id = validate_uuid7(payload["jobId"])
        operation = payload["operation"]
        with spool.locks.borrow_export_descriptor(request.descriptor):
            intent_id = _cleanup_authority(repository, job_id, operation=operation)
            journal = ArchiveJournal(
                repository,
                spool,
                remote,
                expected_owner=expected_owner,
                quarantine=quarantine.record,
                require_quarantine_empty=quarantine.require_empty,
            )
            if operation == "purge-construction":
                journal.purge_unbound_construction(intent_id)
            else:
                journal.finish(intent_id)
            channel.send({"status": "cleaned", "operation": operation, "intentId": intent_id})


def _cleanup_authority(repository: StateRepository, job_id: str, *, operation: str) -> str:
    with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id)).document
        request = cast(dict[str, object], job["request"])
        identities = transaction.measure_intent_records().records
        if (
            job["jobId"] != job_id
            or job["compatibilityVersion"] != "static-job-v2"
            or request["operation"] not in {"archive", "restore", "delete"}
            or len(identities) != 1
        ):
            raise ArchiveRemoteError("archive cleanup has no sole journal and current job")
        _path, stored = transaction.read_intent(identities[0].intent_id)
        intent = stored.document
        construction = intent["kind"] == "ArchiveConstructionIntent"
        provenance = (
            {"kind": "authorization-job", "jobId": intent.get("jobId")}
            if construction
            else intent.get("provenance")
        )
        if (
            intent["kind"] not in {"ArchiveConstructionIntent", "ArchiveRetirementIntent"}
            or provenance != {"kind": "authorization-job", "jobId": job_id}
            or intent["tenantId"] != request["tenantId"]
            or intent["correlationId"] != request["correlationId"]
            or intent["operatorPrincipal"] != job["operatorPrincipal"]
            or request["operation"] != intent.get("transition", "archive")
            or intent["sourceManifestDigest"]
            != cast(dict[str, object], job["expectedSource"])["manifestDigest"]
        ):
            raise ArchiveRemoteError("archive cleanup journal does not belong to this job")
        if operation == "purge-construction":
            if (
                not construction
                or job["phase"] != "claimed"
                or build_expected_source(transaction, request) != job["expectedSource"]
            ):
                raise ArchiveRemoteError("upload cleanup requires its unchanged claimed source")
            try:
                transaction.read(StateRecordPath.authorization_result(job_id))
            except FileNotFoundError:
                pass
            else:
                raise ArchiveRemoteError("pre-terminal upload cleanup already has a result")
        return validate_uuid7(intent["intentId"])
