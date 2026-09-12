from __future__ import annotations

import json
from pathlib import Path

import test_archive_lifecycle as archives
import test_lifecycle as support
from testinfra.host import Host


def test_installed_terminal_retry_reopens_only_proven_quarantine(
    host: Host, tmp_path: Path
) -> None:
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._await_persisted_admission_burst(host)
    operator, identity, ssh = support._operator_inputs(tmp_path)
    identifiers = support._ids()
    slug = f"m3-quarantine-{next(identifiers).replace('-', '')[-12:]}"

    def submit(operation: str, **fields: object) -> dict[str, object]:
        artifact = fields.pop("artifact", None)
        assert artifact is None or isinstance(artifact, bytes)
        result = support._submit(
            tmp_path,
            operator,
            identity,
            ssh,
            support._request(operation, next(identifiers), **fields),
            artifact=artifact,
        )
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
from pathlib import Path
from lowerduckpond_static_host_agent.archive_cleanup_service import ArchiveCleanupClient
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError, archive_key
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockName
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
        with spool.locks.acquire(LockName.EXPORT):
            quarantine.record(remote.inventory())
        client = ArchiveCleanupClient(spool)
        try:
            client.verify_terminal({provenance["jobId"]!r}, record, mode='retained')
        except ArchiveRemoteError:
            pass
        else:
            raise AssertionError('terminal proof accepted an unresolved quarantine')
        with spool.locks.acquire(LockName.EXPORT):
            assert quarantine.read() is not None
        assert any(item.version_id == version for item in remote.list_versions(exact_key=key))
        # Only this fixture owner knows and removes its independently created object.
        # The installed cleanup service must never infer authority for that deletion.
        remote.client.delete_object(Bucket=remote.bucket, Key=key, VersionId=version)
        assert client.verify_terminal({provenance["jobId"]!r}, record, mode='retained')
        with spool.locks.acquire(LockName.EXPORT):
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
