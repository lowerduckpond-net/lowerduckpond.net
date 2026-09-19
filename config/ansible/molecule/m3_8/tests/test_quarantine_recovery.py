from __future__ import annotations

import json
from pathlib import Path

import test_archive_lifecycle as archives
import test_lifecycle as support
from lowerduckpond_static_operator.client import OperatorClientError
from testinfra.host import Host


def test_installed_terminal_retry_reopens_only_proven_quarantine(
    host: Host, tmp_path: Path
) -> None:
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._initialize_admission_pacing(host)
    operator, identity, ssh = support._operator_inputs(tmp_path)
    identifiers = support._ids()
    slug = f"m3-quarantine-{next(identifiers).replace('-', '')[-12:]}"

    def submit(operation: str, **fields: object) -> dict[str, object]:
        artifact = fields.pop("artifact", None)
        assert artifact is None or isinstance(artifact, bytes)
        correlation_id = next(identifiers)
        try:
            result = support._submit(
                tmp_path,
                operator,
                identity,
                ssh,
                support._request(operation, correlation_id, **fields),
                artifact=artifact,
            )
        except OperatorClientError as error:
            try:
                diagnostics = archives._worker_diagnostics(host, correlation_id)
            except Exception:  # Diagnostics must preserve the original failure.
                diagnostics = "worker diagnostics unavailable"
            raise AssertionError(f"{error}\nWorker diagnostics: {diagnostics}") from error
        assert result["status"] == "succeeded", result
        return result

    created = submit("create", slug=slug, quotas={"storageMiB": 1, "entries": 10})
    tenant = str(created["tenantId"])
    submit("deploy", tenantId=tenant, artifact=support._deployment_zip(b"quarantine fixture"))
    archived = submit("archive", tenantId=tenant)
    record = archived["archiveRecord"]
    provenance = archived["provenance"]
    assert isinstance(record, dict) and isinstance(provenance, dict)
    script = f"""
import hashlib
import io
import json
import time
from pathlib import Path
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, archive_key
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockName, StateBusyError

def retry(operation, error_type):
    for attempt in range(50):
        try:
            return operation()
        except error_type:
            if attempt == 49:
                raise
            time.sleep(0.1)

record = json.loads({json.dumps(record)!r})
remote = load_archive_configuration().remote_store()
key = archive_key({next(identifiers)!r})
body = b'known disposable unowned fixture'
version = remote.put_once(key, io.BytesIO(body), size=len(body),
                          sha256=hashlib.sha256(body).hexdigest())
try:
    with ExportSpool(Path({support.STATE_ROOT!r}), expected_owner=0) as spool:
        quarantine = ArchiveQuarantine(Path({support.STATE_ROOT!r}), bucket=remote.bucket,
                                       expected_owner=0, locks=spool.locks)
        def record_fixture():
            with spool.locks.acquire(LockName.EXPORT, blocking=True):
                quarantine.record(remote.inventory())
        # Periodic recovery can briefly hold tenant-state while this fixture starts.
        retry(record_fixture, StateBusyError)
        client = ArchiveCleanupClient(spool)
        try:
            client.verify_terminal({provenance["jobId"]!r}, record, mode='retained')
        except ArchiveRemoteError:
            pass
        else:
            raise AssertionError('terminal proof accepted an unresolved quarantine')
        with spool.locks.acquire(LockName.EXPORT, blocking=True):
            assert quarantine.read() is not None
        assert any(item.version_id == version for item in remote.list_versions(exact_key=key))
        # Only this fixture owner knows and removes its independently created object.
        # The installed cleanup service must never infer authority for that deletion.
        remote.client.delete_object(Bucket=remote.bucket, Key=key, VersionId=version)
        assert retry(lambda: client.verify_terminal(
            {provenance["jobId"]!r}, record, mode='retained'), ArchiveRemoteError)
        with spool.locks.acquire(LockName.EXPORT, blocking=True):
            assert quarantine.read() is None
        retained = remote.list_versions(exact_key=record['key'])
        assert len(retained) == 1 and retained[0].version_id == record['versionId']
finally:
    for item in remote.list_versions(exact_key=key):
        assert item.version_id == version, 'fixture key acquired an unexpected version'
        remote.client.delete_object(Bucket=remote.bucket, Key=key, VersionId=version)
"""
    archives._installed_python(host, script)
    restored = submit("restore", tenantId=tenant)
    assert support._lifecycle(restored) == "active"
    assert not archives._remote_versions(host)
