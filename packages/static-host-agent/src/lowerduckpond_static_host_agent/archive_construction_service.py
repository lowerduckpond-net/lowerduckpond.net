"""One fresh, job-bound upload session across the worker credential boundary.

The session precedes durable preparation. Reconnecting to a prepared intent
never grants another upload; recovery discovers that key instead. The network
process hashes opaque bytes, leaving portable bundle parsing in the worker.
"""

from __future__ import annotations

import fcntl
import os
import re
import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, cast

from lowerduckpond_static_contracts import (
    ContractError,
    deployment_record_digest,
    manifest_digest,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.archive_journal import (
    ArchiveJournal,
    PreparedArchive,
    VerifiedArchiveUpload,
)
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteError,
    ArchiveRemoteStore,
    RemoteInventory,
    RemoteVersion,
    archive_key,
)
from lowerduckpond_static_host_agent.archive_transport import (
    MAX_ARCHIVE_REQUEST_BYTES,
    MAX_ARCHIVE_RESPONSE_BYTES,
    ArchiveChannel,
    ArchiveTransportError,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, validate_regular_state_file
from lowerduckpond_static_host_agent.export_spool import EXPORT_WORKSPACE_BUNDLE_NAME, ExportSpool
from lowerduckpond_static_host_agent.issuance import build_expected_source
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.repository import (
    StateRecordPath,
    StateRepository,
    StoredContract,
)

ARCHIVE_CONSTRUCTION_SOCKET_PATH: Final = Path("/run/lowerduckpond-archive/construction.sock")
_PROTOCOL: Final = "lowerduckpond-archive-construction-v1"
_MAXIMUM_VERSION_BYTES: Final = 1024


def connect_archive_construction() -> socket.socket:
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(30.0)
        stream.connect(str(ARCHIVE_CONSTRUCTION_SOCKET_PATH))
        return stream
    except BaseException:
        stream.close()
        raise


class ArchiveConstructionSession:
    """One ready session; a failed or completed upload cannot be retried."""

    def __init__(self, channel: ArchiveChannel, *, bucket: str, job_id: str) -> None:
        self.bucket = bucket
        self._channel = channel
        self._job_id = job_id
        self._used = False

    def upload(self, prepared: PreparedArchive, source: BinaryIO) -> VerifiedArchiveUpload:
        if self._used:
            raise ArchiveRemoteError("archive construction session has already been consumed")
        self._used = True
        intent = prepared.construction.document
        if intent["jobId"] != self._job_id or intent["bucket"] != self.bucket:
            raise ArchiveRemoteError("archive construction does not belong to this session")
        try:
            self._channel.send(
                {"operation": "upload", "intentId": intent["intentId"]},
                descriptor=source.fileno(),
            )
            with self._channel.receive() as response:
                revision = prepared.construction.revision
                payload = response.payload
                version = payload.get("versionId")
                if (
                    response.descriptor is not None
                    or not isinstance(version, str)
                    or not version
                    or version == "null"
                    or len(version.encode("utf-8")) > _MAXIMUM_VERSION_BYTES
                    or payload
                    != {
                        "status": "verified",
                        "intentId": intent["intentId"],
                        "preparedRevision": {
                            "kind": revision.contract_kind.value,
                            "byteCount": revision.byte_count,
                            "sha256": revision.sha256,
                        },
                        "versionId": version,
                    }
                ):
                    raise ArchiveRemoteError("archive upload did not confirm the prepared intent")
                return VerifiedArchiveUpload(revision, version)
        except (OSError, ContractError, ArchiveTransportError) as error:
            raise ArchiveRemoteError("archive construction upload did not complete") from error


class ArchiveConstructionClient:
    """Open a session before the worker prepares its durable construction."""

    def __init__(
        self,
        spool: ExportSpool,
        *,
        connector: Callable[[], socket.socket] = connect_archive_construction,
        expected_peer_uid: int = 0,
    ) -> None:
        self._spool = spool
        self._connector = connector
        self._peer = expected_peer_uid

    @contextmanager
    def session(self, job_id: str) -> Iterator[ArchiveConstructionSession]:
        canonical = validate_uuid7(job_id)
        lease = self._spool.locks.duplicate_export_descriptor()
        try:
            with ArchiveChannel(
                self._connector(),
                expected_peer_uid=self._peer,
                maximum_receive_bytes=MAX_ARCHIVE_RESPONSE_BYTES,
            ) as channel:
                channel.send(
                    {"protocol": _PROTOCOL, "operation": "begin", "jobId": canonical},
                    descriptor=lease,
                )
                with channel.receive() as response:
                    bucket = response.payload.get("bucket")
                    if (
                        response.descriptor is not None
                        or not isinstance(bucket, str)
                        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket)
                        or response.payload != {"status": "ready", "bucket": bucket}
                    ):
                        raise ArchiveRemoteError("archive construction session was not admitted")
                    session = ArchiveConstructionSession(channel, bucket=bucket, job_id=canonical)
                yield session
        except (OSError, ContractError, ArchiveTransportError) as error:
            raise ArchiveRemoteError("archive construction session did not complete") from error
        finally:
            os.close(lease)


@dataclass(frozen=True, slots=True)
class _ConstructionAuthority:
    job: StoredContract
    manifest: StoredContract
    deployment: StoredContract


def serve_archive_construction(  # noqa: PLR0913 - explicit private service dependencies
    stream: socket.socket,
    repository: StateRepository,
    spool: ExportSpool,
    remote: ArchiveRemoteStore,
    *,
    quarantine: ArchiveQuarantine,
    expected_owner: int = 0,
) -> None:
    """Accept one new construction; keep exclusion until provider streams close."""
    if quarantine.bucket != remote.bucket:
        raise ArchiveRemoteError("archive construction quarantine belongs to another bucket")
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
            or payload["operation"] != "begin"
            or request.descriptor is None
        ):
            raise ArchiveRemoteError("archive construction requires a fresh job session and lease")
        job_id = validate_uuid7(payload["jobId"])
        with spool.locks.borrow_export_descriptor(request.descriptor):
            quarantine.require_empty()
            authority = _read_authority(repository, job_id, intent_id=None)
            channel.send({"status": "ready", "bucket": remote.bucket})
            with channel.receive() as upload:
                if (
                    set(upload.payload) != {"operation", "intentId"}
                    or upload.payload["operation"] != "upload"
                    or upload.descriptor is None
                ):
                    raise ArchiveRemoteError("archive construction requires one prepared upload")
                intent_id = validate_uuid7(upload.payload["intentId"])
                current = _read_authority(repository, job_id, intent_id=intent_id)
                if (
                    current.job.revision != authority.job.revision
                    or current.manifest.revision != authority.manifest.revision
                    or current.deployment.revision != authority.deployment.revision
                ):
                    raise ArchiveRemoteError("archive construction source changed during session")
                prepared = repository.read(StateRecordPath.archive_construction_intent(intent_id))
                _require_prepared(prepared, authority, bucket=remote.bucket)
                quarantine.require_empty()
                version = _upload(
                    spool,
                    remote,
                    repository,
                    quarantine,
                    prepared,
                    upload.descriptor,
                    expected_owner=expected_owner,
                )
            revision = prepared.revision
            channel.send(
                {
                    "status": "verified",
                    "intentId": intent_id,
                    "preparedRevision": {
                        "kind": revision.contract_kind.value,
                        "byteCount": revision.byte_count,
                        "sha256": revision.sha256,
                    },
                    "versionId": version,
                }
            )


def _read_authority(
    repository: StateRepository, job_id: str, *, intent_id: str | None
) -> _ConstructionAuthority:
    with repository.transaction(mode=LockMode.EXCLUSIVE) as transaction:
        job = transaction.read(StateRecordPath.authorization_job(job_id))
        document = job.document
        request = cast(dict[str, object], document["request"])
        expected = cast(dict[str, object], document["expectedSource"])
        measured = transaction.measure_intent_records()
        if (
            document["jobId"] != job_id
            or document["compatibilityVersion"] != "static-job-v2"
            or document["phase"] != "claimed"
            or document["artifact"] is not None
            or request["operation"] != "archive"
            or expected["lifecycle"] not in {"active", "suspended"}
            or build_expected_source(transaction, request) != expected
            or len(measured.records) != (0 if intent_id is None else 1)
        ):
            raise ArchiveRemoteError("archive construction has no fresh claimed source authority")
        if intent_id is not None:
            transaction.read(StateRecordPath.archive_construction_intent(intent_id))
        try:
            transaction.read(StateRecordPath.authorization_result(job_id))
        except FileNotFoundError:
            pass
        else:
            raise ArchiveRemoteError("archive construction already has a terminal result")
        manifest = transaction.read(StateRecordPath.tenant_desired(request["tenantId"]))
        desired = cast(
            dict[str, object],
            cast(dict[str, object], manifest.document["spec"])["desiredDeployment"],
        )
        deployment = transaction.read(
            StateRecordPath.tenant_deployment(request["tenantId"], desired["id"])
        )
        return _ConstructionAuthority(job, manifest, deployment)


def _require_prepared(
    prepared: StoredContract, authority: _ConstructionAuthority, *, bucket: str
) -> None:
    intent = prepared.document
    job = authority.job.document
    request = cast(dict[str, object], job["request"])
    candidate = deepcopy(authority.manifest.document)
    cast(dict[str, object], candidate["spec"])["desiredState"] = "archived"
    if (
        intent["phase"] != "prepared"
        or intent["versionId"] is not None
        or intent["bucket"] != bucket
        or intent["key"] != archive_key(intent["uploadAttemptId"])
        or intent["jobId"] != job["jobId"]
        or intent["operatorPrincipal"] != job["operatorPrincipal"]
        or intent["tenantId"] != request["tenantId"]
        or intent["correlationId"] != request["correlationId"]
        or intent["sourceManifestDigest"] != manifest_digest(authority.manifest.document).to_dict()
        or intent["candidateManifestDigest"] != manifest_digest(candidate).to_dict()
        or intent["deploymentRecordDigest"]
        != deployment_record_digest(authority.deployment.document).to_dict()
        or intent["releaseTreeDigest"] != authority.deployment.document["releaseTreeDigest"]
    ):
        raise ArchiveRemoteError("prepared construction does not bind the session source")


def _upload(  # noqa: PLR0913, PLR0917 - explicit descriptor and root-owned dependencies
    spool: ExportSpool,
    remote: ArchiveRemoteStore,
    repository: StateRepository,
    quarantine: ArchiveQuarantine,
    prepared: StoredContract,
    descriptor: int,
    *,
    expected_owner: int,
) -> str:
    spool.locks.require_held(LockName.EXPORT, mode=LockMode.EXCLUSIVE, innermost=True)
    intent = prepared.document
    size = cast(int, intent["bundleSize"])
    with DurableDirectory.open(
        spool.workspace, expected_owner=expected_owner, expected_directory_mode=0o700
    ) as workspace:
        parent = workspace.duplicate_descriptor()
        try:
            current = os.stat(EXPORT_WORKSPACE_BUNDLE_NAME, dir_fd=parent, follow_symlinks=False)
            supplied = validate_regular_state_file(
                descriptor, expected_owner=expected_owner, expected_mode=0o600
            )
            if (
                (supplied.st_dev, supplied.st_ino) != (current.st_dev, current.st_ino)
                or supplied.st_size != size
                or fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or os.lseek(descriptor, 0, os.SEEK_CUR) != 0
            ):
                raise ArchiveRemoteError("archive source is not the complete private spool file")
            with os.fdopen(os.dup(descriptor), "rb", buffering=0) as body:
                return _transmit(
                    repository,
                    spool,
                    remote,
                    quarantine,
                    intent,
                    body,
                    expected_owner=expected_owner,
                )
        finally:
            os.close(parent)


def _transmit(  # noqa: PLR0913, PLR0917 - explicit authorization and remote dependencies
    repository: StateRepository,
    spool: ExportSpool,
    remote: ArchiveRemoteStore,
    quarantine: ArchiveQuarantine,
    intent: dict[str, object],
    body: BinaryIO,
    *,
    expected_owner: int,
) -> str:
    journal = ArchiveJournal(
        repository,
        spool,
        remote,
        expected_owner=expected_owner,
        quarantine=quarantine.record,
        require_quarantine_empty=quarantine.require_empty,
    )
    key = cast(str, intent["key"])
    size = cast(int, intent["bundleSize"])
    digest = cast(str, cast(dict[str, object], intent["bundleDigest"])["value"])
    inventory: RemoteInventory | None = None
    try:
        inventory = remote.inventory()
        inventory.require_reservation(journal.bound_versions())
        remote.require_absent(key)
    except Exception:
        quarantine.record(inventory)
        raise
    version: str | None = None
    try:
        version = remote.put_once(key, body, size=size, sha256=digest)
        remote.read_verified(key, version, size=size, sha256=digest)
        return version
    except Exception:
        quarantine.record(
            None
            if version is None
            else RemoteInventory((RemoteVersion(key, version, size, False),), ())
        )
        raise
