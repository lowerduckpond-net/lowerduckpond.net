"""Job-bound archived export across the credential-free worker boundary.

Only the root network service receives an ArchiveRemoteStore. The worker sends
an opaque job and two descriptors, never an object location or SDK operation.
The service streams and hashes bytes; portable ZIP parsing stays in the worker.
"""

from __future__ import annotations

import fcntl
import os
import socket
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Final, cast

from lowerduckpond_static_contracts import ContractError, manifest_digest, validate_uuid7

from lowerduckpond_static_host_agent.archive_bundle import RemoteArchiveBundleSource
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, ArchiveRemoteStore
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_REQUEST_BYTES,
    MAX_ARCHIVE_RESPONSE_BYTES,
    ArchiveChannel,
    ArchiveTransportError,
)
from lowerduckpond_static_host_agent.capacity import CapacityReservation
from lowerduckpond_static_host_agent.durable import (
    DurableDirectory,
    validate_regular_state_file,
)
from lowerduckpond_static_host_agent.export_spool import EXPORT_WORKSPACE_BUNDLE_NAME, ExportSpool
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.portable_bundle import MAXIMUM_PORTABLE_BUNDLE_BYTES
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    _StateTransaction,
)

ARCHIVE_SOCKET_PATH: Final = Path("/run/lowerduckpond-archive/export.sock")
_PROTOCOL: Final = "lowerduckpond-archive-export-v1"


def connect_archive_export() -> socket.socket:
    """Connect only to the fixed private installed endpoint."""

    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(30.0)
        stream.connect(str(ARCHIVE_SOCKET_PATH))
        return stream
    except BaseException:
        stream.close()
        raise


class ArchiveExportClient:
    """Lend spool and exclusion descriptors for one independently authorized read."""

    def __init__(
        self,
        spool: ExportSpool,
        *,
        connector: Callable[[], socket.socket] = connect_archive_export,
        expected_peer_uid: int = 0,
    ) -> None:
        self._spool = spool
        self._connector = connector
        self._peer = expected_peer_uid

    def read_archive(self, job_id: str, record: dict[str, object], destination: BinaryIO) -> None:
        canonical = validate_uuid7(job_id)
        lease = self._spool.locks.duplicate_export_descriptor()
        try:
            with ArchiveChannel(
                self._connector(),
                expected_peer_uid=self._peer,
                maximum_receive_bytes=MAX_ARCHIVE_RESPONSE_BYTES,
            ) as channel:
                channel.send(
                    {"protocol": _PROTOCOL, "operation": "export", "jobId": canonical},
                    descriptor=lease,
                )
                channel.send({"operation": "destination"}, descriptor=destination.fileno())
                with channel.receive() as response:
                    if response.descriptor is not None or response.payload != {
                        "status": "downloaded",
                        "archiveRecord": record,
                    }:
                        raise ArchiveRemoteError("archive service did not confirm the bound record")
        except (OSError, ContractError, ArchiveTransportError) as error:
            raise ArchiveRemoteError("archive service download did not complete") from error
        finally:
            os.close(lease)


def serve_archive_export(
    stream: socket.socket,
    repository: StateRepository,
    spool: ExportSpool,
    remote: ArchiveRemoteStore,
    *,
    expected_owner: int = 0,
) -> None:
    """Serve exactly one read, retaining export exclusion through stream closure.

    A disconnect cannot release a still-running download's lock or descriptor.
    No failure response conveys credentials or provider diagnostics. Installed
    callers handle errors outside this function and log only a fixed category.
    """

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
            or payload["operation"] != "export"
            or request.descriptor is None
        ):
            raise ArchiveRemoteError("archive service requires an export job and lease")
        job_id = validate_uuid7(payload["jobId"])
        with spool.locks.borrow_export_descriptor(request.descriptor):
            with channel.receive() as destination:
                if (
                    destination.payload != {"operation": "destination"}
                    or destination.descriptor is None
                ):
                    raise ArchiveRemoteError("archive service requires one spool destination")
                record = _read_authority(
                    repository,
                    job_id,
                    bucket=remote.bucket,
                    operations=frozenset({"export", "restore"}),
                    allow_retirement=True,
                )
                _download(
                    spool,
                    remote,
                    job_id,
                    record,
                    destination.descriptor,
                    expected_owner=expected_owner,
                )
            channel.send({"status": "downloaded", "archiveRecord": record})


def _read_authority(
    repository: StateRepository,
    job_id: str,
    *,
    bucket: str,
    operations: frozenset[str] = frozenset({"export"}),
    allow_retirement: bool = False,
) -> dict[str, object]:
    with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id)).document
        request = cast(dict[str, object], job["request"])
        expected = cast(dict[str, object], job["expectedSource"])
        if (
            job["jobId"] != job_id
            or job["compatibilityVersion"] != "static-job-v2"
            or job["phase"] != "claimed"
            or job["artifact"] is not None
            or request["operation"] not in operations
            or expected["lifecycle"] != "archived"
            or build_expected_source(transaction, request) != expected
        ):
            raise ArchiveRemoteError("archive download has no current claimed export authority")
        try:
            transaction.read(StateRecordPath.authorization_result(job_id))
        except FileNotFoundError:
            pass
        else:
            raise ArchiveRemoteError("archive download already has a terminal result")
        manifest = transaction.read(StateRecordPath.tenant_desired(request["tenantId"])).document
        spec = cast(dict[str, object], manifest["spec"])
        desired = cast(dict[str, object], spec["desiredDeployment"])
        record = transaction.read(
            StateRecordPath.tenant_archive(request["tenantId"], desired["id"])
        ).document
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(request["tenantId"], desired["id"])
        ).document
        if (
            job["sourceAuthority"] != {"manifest": manifest, "archiveRecord": record}
            or record["bucket"] != bucket
            or record["tenantId"] != request["tenantId"]
            or record["deploymentId"] != desired["id"]
            or record["manifestDigest"] != manifest_digest(manifest).to_dict()
            or record["releaseTreeDigest"] != deployment["releaseTreeDigest"]
        ):
            raise ArchiveRemoteError("archive download record bindings disagree")
        _require_read_journals(transaction, job, record, allow_retirement=allow_retirement)
        return record


def _require_read_journals(
    transaction: _StateTransaction,
    job: dict[str, object],
    archive: dict[str, object],
    *,
    allow_retirement: bool,
) -> None:
    intents = [
        transaction.read_intent(value.intent_id)
        for value in transaction.measure_intent_records().records
    ]
    if not intents:
        return
    request = cast(dict[str, object], job["request"])
    expected = cast(dict[str, object], job["expectedSource"])
    if not allow_retirement or request["operation"] not in {"restore", "delete"}:
        raise ArchiveRemoteError("archive read is blocked by active lifecycle authority")
    retirements = [
        (path, record.document)
        for path, record in intents
        if record.document["kind"] == "ArchiveRetirementIntent"
    ]
    transactions = [
        (path, record.document)
        for path, record in intents
        if record.document["kind"] == "TransactionIntent"
    ]
    if (
        len(retirements) != 1
        or len(transactions) > 1
        or len(intents) != len(retirements) + len(transactions)
    ):
        raise ArchiveRemoteError("archive read has ambiguous retirement authority")
    path, document = retirements[0]
    if (
        path != StateRecordPath.archive_retirement_intent(document["intentId"])
        or document["compatibilityVersion"] != "static-retirement-v2"
        or document["provenance"] != {"kind": "authorization-job", "jobId": job["jobId"]}
        or document["transition"] != request["operation"]
        or document["phase"] != "prepared"
        or document["archiveRecord"] != archive
        or document["tenantId"] != request["tenantId"]
        or document["correlationId"] != request["correlationId"]
        or document["operatorPrincipal"] != job["operatorPrincipal"]
        or document["sourceManifestDigest"] != expected["manifestDigest"]
        or document["archiveRecordDigest"] != expected["archiveRecordDigest"]
    ):
        raise ArchiveRemoteError("archive read retirement authority disagrees")
    if transactions:
        path, document = transactions[0]
        if (
            request["operation"] != "delete"
            or document["operation"] != "delete"
            or path != StateRecordPath.transaction_intent(document["intentId"])
            or document["compatibilityVersion"] != "static-intent-v2"
            or document["tenantId"] != request["tenantId"]
            or document["correlationId"] != request["correlationId"]
            or document["sourceManifest"]
            != cast(dict[str, object], job["sourceAuthority"])["manifest"]
            or document["sourceManifestDigest"] != expected["manifestDigest"]
            or document["candidateManifest"] is not None
            or document["phase"] != "prepared"
        ):
            raise ArchiveRemoteError("archive read transaction is not an unchanged delete source")


def _download(  # noqa: PLR0913 - explicit descriptor and root-owned dependencies
    spool: ExportSpool,
    remote: ArchiveRemoteStore,
    job_id: str,
    record: dict[str, object],
    descriptor: int,
    *,
    expected_owner: int,
) -> None:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    with DurableDirectory.open(
        spool.workspace, expected_owner=expected_owner, expected_directory_mode=0o700
    ) as workspace:
        parent = workspace.duplicate_descriptor()
        try:
            current = os.stat(EXPORT_WORKSPACE_BUNDLE_NAME, dir_fd=parent, follow_symlinks=False)
            supplied = validate_regular_state_file(
                descriptor, expected_owner=expected_owner, expected_mode=0o600
            )
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            if (
                (supplied.st_dev, supplied.st_ino) != (current.st_dev, current.st_ino)
                or supplied.st_size != 0
                or flags & os.O_ACCMODE not in {os.O_WRONLY, os.O_RDWR}
                or flags & os.O_APPEND
                or os.lseek(descriptor, 0, os.SEEK_CUR) != 0
            ):
                raise ArchiveRemoteError("archive destination is not the empty private spool file")
            spool.reserve(CapacityReservation(MAXIMUM_PORTABLE_BUNDLE_BYTES, 0))
            with os.fdopen(os.dup(descriptor), "wb", buffering=0) as output:
                RemoteArchiveBundleSource(remote).read_archive(job_id, record, output)
                os.fsync(output.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)
