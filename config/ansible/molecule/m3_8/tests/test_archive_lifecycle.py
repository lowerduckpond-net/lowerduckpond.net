from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import archive_capture_support as captures
import archive_socket_support as sockets
import pytest
import test_export_import as exports
import test_lifecycle as support
import test_transport_recovery as recovery
from lowerduckpond_static_host_agent.portable_bundle import inspect_portable_bundle
from lowerduckpond_static_operator.client import OperatorClientError
from testinfra.host import Host

_CYCLES = 4
_HISTORY_LIMIT = 3
_CONTENT = b"installed M3.10 versioned archive content\n"


@contextmanager
def _diagnose_submission(host: Host, request: dict[str, object]) -> Iterator[None]:
    try:
        yield
    except OperatorClientError as error:
        try:
            diagnostics = _worker_diagnostics(host, str(request["correlationId"]))
        except Exception:  # Keep the original failure if inspection also fails.
            diagnostics = "worker diagnostics unavailable"
        raise AssertionError(f"{error}\nWorker diagnostics: {diagnostics}") from error


def _installed_python(host: Host, body: str) -> str:
    outcome = host.run("/usr/bin/python3 -I -B -c %s", exports._selected_python(host, body))
    assert outcome.rc == 0, outcome.stderr
    return outcome.stdout


def _worker_diagnostics(host: Host, correlation_id: str) -> str:
    return _installed_python(
        host,
        f"""
import json
import subprocess
from pathlib import Path
from lowerduckpond_static_contracts import validate_uuid7

root = Path({support.STATE_ROOT!r})
correlation = validate_uuid7({correlation_id!r})
binding = json.loads((root / 'authorization/correlations' / (correlation + '.json')).read_bytes())
job_id = validate_uuid7(binding['jobId'])
job = json.loads((root / 'authorization/jobs' / (job_id + '.json')).read_bytes())
result_path = root / 'authorization/results' / (job_id + '.json')
result = json.loads(result_path.read_bytes()) if result_path.exists() else {{}}
unit = subprocess.run(['/usr/bin/systemctl', 'show',
    '--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MemoryPeak,ExecMainStartTimestamp',
    'lowerduckpond-static-worker@' + job_id + '.service'],
    capture_output=True, text=True, timeout=10, check=False)
journal = subprocess.run(['/usr/bin/journalctl', '--no-pager', '--output=short-iso', '--lines=8',
    '--unit=lowerduckpond-archive-cleanup@request.service',
    '--unit=lowerduckpond-archive-export@request.service',
    '--unit=lowerduckpond-archive-construction@request.service',
    '--grep=^archive_(construction|export|cleanup)_service_failed( |$)'],
    capture_output=True, text=True, timeout=10, check=False)
print(json.dumps({{
    'jobId': job_id,
    'operation': job['request']['operation'],
    'phase': job['phase'],
    'executionValidated': job.get('executionValidated'),
    'resultStatus': result.get('status'),
    'resultError': result.get('errorCode'),
    'intents': sorted(path.name for path in (root / 'intents').iterdir())[:8],
    'quarantine': (root / 'platform/archive-quarantine.json').exists(),
    'unitStatus': unit.stdout[:4096],
    'archiveFailureLabels': journal.stdout[:4096],
}}))
""",
    )


def test_installed_tls_storage_credentials_are_mutually_denied(host: Host) -> None:
    _installed_python(
        host,
        """
from botocore.exceptions import ClientError
from botocore.config import Config
from botocore.session import Session

def credential_probe_client(*, access_key_id, secret_access_key):
    # Exercise provider permissions independently of the runtime's SDK allowlist,
    # which deliberately forbids creating or aborting multipart uploads.
    session = Session()
    session.set_config_variable('config_file', '/dev/null')
    session.set_config_variable('credentials_file', '/dev/null')
    return session.create_client('s3', aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key, region_name='ams3',
        endpoint_url='https://ams3.digitaloceanspaces.com',
        verify='/etc/ssl/certs/ca-certificates.crt',
        config=Config(signature_version='s3v4',
            retries={'total_max_attempts': 1, 'mode': 'standard'}, proxies={},
            s3={'addressing_style': 'path'},
            request_checksum_calculation='when_required',
            response_checksum_validation='when_required'))

archive = credential_probe_client(access_key_id='molecule-m3-10-archive',
    secret_access_key='molecule-m3-10-disposable-archive-secret')
backup = credential_probe_client(access_key_id='molecule-m3-10-backup',
    secret_access_key='molecule-m3-10-disposable-backup-secret')
objects = []
uploads = []
try:
    for client, bucket in ((archive, 'molecule-tenant-archives'),
                           (backup, 'molecule-platform-backup')):
        assert client.get_bucket_versioning(Bucket=bucket)['Status'] == 'Enabled'
        version = client.put_object(Bucket=bucket, Key='archives/credential-proof',
                                    Body=b'proof', ContentLength=5)['VersionId']
        objects.append((client, bucket, version))
        upload = client.create_multipart_upload(Bucket=bucket,
            Key='archives/credential-proof')['UploadId']
        uploads.append((client, bucket, 'archives/credential-proof', upload))
        body = client.get_object(Bucket=bucket, Key='archives/credential-proof',
                                 VersionId=version)['Body']
        try:
            assert body.read() == b'proof'
        finally:
            body.close()
    for index, (owner, bucket, version) in enumerate(objects):
        other = backup if index == 0 else archive
        for operation, arguments in (
            ('get_bucket_versioning', {}),
            ('get_object', {'Key': 'archives/credential-proof'}),
            ('get_object', {'Key': 'archives/credential-proof', 'VersionId': version}),
            ('list_objects_v2', {}),
            ('list_object_versions', {}),
            ('list_multipart_uploads', {}),
            ('put_object', {'Key': 'archives/cross-denied', 'Body': b'x', 'ContentLength': 1}),
            ('create_multipart_upload', {'Key': 'archives/cross-denied'}),
            ('delete_object', {'Key': 'archives/credential-proof'}),
            ('delete_object', {'Key': 'archives/credential-proof', 'VersionId': version}),
            ('abort_multipart_upload', {'Key': 'archives/credential-proof',
                                       'UploadId': uploads[index][3]}),
        ):
            try:
                response = getattr(other, operation)(Bucket=bucket, **arguments)
            except ClientError as error:
                assert error.response['ResponseMetadata']['HTTPStatusCode'] == 403
                assert error.response['Error']['Code'] == 'AccessDenied'
            else:
                if operation == 'create_multipart_upload':
                    uploads.append((owner, bucket, arguments['Key'], response['UploadId']))
                if 'Body' in response:
                    response['Body'].close()
                raise AssertionError('cross-bucket access unexpectedly succeeded')
        surviving = owner.list_multipart_uploads(Bucket=bucket,
            Prefix='archives/credential-proof').get('Uploads', [])
        assert len(surviving) == 1 and surviving[0]['UploadId'] == uploads[index][3]
finally:
    for owner, bucket, key, upload in uploads:
        try:
            owner.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload)
        except ClientError as error:
            assert error.response['Error']['Code'] == 'NoSuchUpload'
            assert error.response['ResponseMetadata']['HTTPStatusCode'] == 404
    for owner, bucket, version in objects:
        owner.delete_object(Bucket=bucket, Key='archives/credential-proof', VersionId=version)
for owner, bucket, _ in objects:
    inventory = owner.list_object_versions(Bucket=bucket)
    assert not inventory.get('Versions') and not inventory.get('DeleteMarkers')
    assert not owner.list_multipart_uploads(Bucket=bucket).get('Uploads')
""",
    )


def _remote_versions(host: Host) -> list[dict[str, object]]:
    return json.loads(
        _installed_python(
            host,
            """
import json
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_remote import make_archive_client
config = load_archive_configuration()
client = make_archive_client(region=config.region, access_key_id=config.access_key_id,
    secret_access_key=config.secret_access_key)
page = client.list_object_versions(Bucket=config.bucket)
assert not page.get('IsTruncated') and not page.get('DeleteMarkers')
assert not client.list_multipart_uploads(Bucket=config.bucket).get('Uploads')
print(json.dumps([{'key': item['Key'], 'versionId': item['VersionId']}
                  for item in page.get('Versions', [])]))
""",
        )
    )


def _full_size_source(host: Host) -> dict[str, object]:
    return json.loads(
        _installed_python(
            host,
            f"""
import json
import re
from pathlib import Path
matches = []
for path in Path({support.STATE_ROOT + "/tenants"!r}).glob('*/desired.json'):
    manifest = json.loads(path.read_text())
    if re.fullmatch(r'm3-nine-[0-9a-f]{{12}}', manifest['metadata']['slug']):
        assert manifest['spec']['desiredState'] == 'suspended'
        deployment = manifest['spec']['desiredDeployment']['id']
        release = Path({support.RELEASE_ROOT!r}) / path.parent.name / 'releases' / deployment
        files = [item for item in release.rglob('*') if item.is_file()]
        assert len(files) == {exports._ENTRY_COUNT}
        assert sum(item.stat().st_size for item in files) == {exports._CONTENT_BYTES}
        matches.append(manifest)
assert len(matches) == 1, 'expected the completed full-size M3.9 source fixture'
print(json.dumps(matches[0]))
""",
        )
    )


@pytest.fixture
def controlled_recovery_timer(host: Host) -> Iterator[None]:
    try:
        yield
    finally:
        recovery._start_reconcile_timer(host)


@pytest.mark.usefixtures("controlled_recovery_timer")
def test_installed_archive_export_restore_rearchive_and_delete(host: Host, tmp_path: Path) -> None:
    _exercise_archive_lifecycle(host, tmp_path, full_size_source=True)


def _exercise_archive_lifecycle(  # noqa: PLR0915 - one complete archive lifecycle proof
    host: Host, tmp_path: Path, *, full_size_source: bool
) -> None:
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    operator, identity, ssh = support._operator_inputs(tmp_path)
    identities = support._ids()
    slug = f"m3-archive-{next(identities).replace('-', '')[-12:]}"
    history: list[tuple[dict[str, object], dict[str, object]]] = []

    def submit(operation: str, **fields: object) -> dict[str, object]:
        mode = fields.pop("mode", "ordinary")
        artifact = fields.pop("artifact", None)
        export_path = fields.pop("export_path", None)
        assert artifact is None or isinstance(artifact, bytes)
        assert export_path is None or isinstance(export_path, Path)
        origin = fields.pop("origin", None)
        request = support._request(operation, next(identities), **fields)
        if mode != "ordinary":
            stopped = host.run("systemctl stop lowerduckpond-static-reconcile.timer")
            assert stopped.rc == 0, stopped.stderr
            recovery._await_authorization_quiescent(host)
        if mode in {"capture-active", "capture-archived", "capture-ansible"}:
            result = captures.exercise_capture_exclusion(
                host,
                request,
                archived=mode != "capture-active",
                ansible_overlap=mode == "capture-ansible",
            )
        elif mode == "ansible":
            result = recovery._exercise_ansible_worker_overlap(host, request)
        elif mode == "caddy-fault":
            target_id = str(request["tenantId"])
            snapshot = recovery._TenantSnapshot(
                target_id,
                str(origin),
                support._read_state(host, f"{support.STATE_ROOT}/tenants/{target_id}/desired.json"),
                support._read_state(
                    host, f"{support.STATE_ROOT}/tenants/{target_id}/observed.json"
                ),
                404,
            )
            result = recovery._exercise_caddy_failure_recovery(
                host,
                request,
                assert_rolled_back=lambda: recovery._assert_tenant_snapshot(host, snapshot),
            )
        else:
            with _diagnose_submission(host, request):
                result = support._submit(
                    tmp_path,
                    operator,
                    identity,
                    ssh,
                    request,
                    artifact=artifact,
                    export_path=export_path,
                )
        assert result["status"] == "succeeded", result
        history.append((request, result))
        return result

    created = submit("create", slug=slug, quotas={"storageMiB": 100, "entries": 5000})
    tenant = str(created["tenantId"])
    original_origin = str(created["canonicalOrigin"])
    current = submit("deploy", tenantId=tenant, artifact=support._deployment_zip(_CONTENT))
    deployments = {support._desired_deployment(current)}
    keys: set[str] = set()
    for iteration in range(_CYCLES):
        archived = submit(
            "archive", tenantId=tenant, mode="capture-active" if iteration == 0 else "ordinary"
        )
        assert support._lifecycle(archived) == "archived"
        support._assert_route(host, original_origin, status=404)
        record = archived["archiveRecord"]
        assert isinstance(record, dict)
        assert record["key"] not in keys
        keys.add(str(record["key"]))
        assert _remote_versions(host) == [{"key": record["key"], "versionId": record["versionId"]}]
        if iteration == 0:
            destination = tmp_path / "archived.zip"
            exported = submit("export", tenantId=tenant, export_path=destination)
            assert support._lifecycle(exported) == "archived"
            inspection = inspect_portable_bundle(destination, expected_owner=os.geteuid())
            assert inspection.provenance_manifest == support._manifest(archived)
            assert inspection.content_bytes == len(_CONTENT)
            assert (
                hashlib.sha256(destination.read_bytes()).hexdigest()
                == record["bundleDigest"]["value"]
            )
            target = submit("create", slug=f"{slug}-copy", quotas={"storageMiB": 1, "entries": 10})
            imported = submit(
                "import", tenantId=target["tenantId"], artifact=destination.read_bytes()
            )
            assert imported["tenantId"] != tenant
            assert imported["canonicalOrigin"] == target["canonicalOrigin"]
            assert support._manifest(imported)["spec"]["quotas"] == {"storageMiB": 1, "entries": 10}
            support._assert_route(host, str(imported["canonicalOrigin"]), status=200, body=_CONTENT)
            exports._assert_empty_spool(host)
        restored = submit(
            "restore",
            tenantId=tenant,
            origin=original_origin,
            mode=("caddy-fault", "capture-archived", "ansible", "ordinary")[iteration],
        )
        assert support._lifecycle(restored) == "active"
        if iteration == 0:
            provenance = restored["provenance"]
            assert isinstance(provenance, dict)
            sockets.assert_cleanup_request_queues_through_service_teardown(
                host, str(provenance["jobId"])
            )
        assert restored["canonicalOrigin"] == original_origin
        deployment = support._desired_deployment(restored)
        assert deployment not in deployments
        deployments.add(deployment)
        assert not _remote_versions(host)
        support._assert_route(host, original_origin, status=200, body=_CONTENT)
        entries = host.run("ls -1 %s", f"{support.RELEASE_ROOT}/{tenant}/releases")
        assert entries.rc == 0, entries.stderr
        assert len(entries.stdout.splitlines()) == min(iteration + 2, _HISTORY_LIMIT)
    submit("archive", tenantId=tenant)
    deleted = submit("delete", tenantId=tenant, mode="caddy-fault", origin=original_origin)
    assert "manifest" not in deleted
    assert not _remote_versions(host)
    assert not host.file(f"{support.STATE_ROOT}/tenants/{tenant}").exists
    assert not host.file(f"{support.RELEASE_ROOT}/{tenant}").exists
    support._assert_route(host, original_origin, status=404)
    submit("archive", tenantId=target["tenantId"])
    submit("delete", tenantId=target["tenantId"], mode="capture-ansible")
    assert not _remote_versions(host)
    assert not host.file(f"{support.STATE_ROOT}/tenants/{target['tenantId']}").exists
    if full_size_source:
        large_source = _full_size_source(host)
        large_tenant = str(large_source["metadata"]["id"])
        large_origin = str(large_source["metadata"]["canonicalOrigin"])
        large_archive = submit("archive", tenantId=large_tenant)
        exports._assert_worker_budget(host, large_archive)
        assert support._lifecycle(large_archive) == "archived"
        support._assert_route(host, large_origin, status=404)
        large_restore = submit("restore", tenantId=large_tenant)
        assert (
            support._desired_deployment(large_restore)
            != large_source["spec"]["desiredDeployment"]["id"]
        )
        exports._assert_worker_budget(host, large_restore)
        support._assert_route(host, large_origin, status=200, body=exports._INDEX)
        assert not _remote_versions(host)
    for request, result in history:
        # Export delivery is already acknowledged; historical requests return only results.
        if request["operation"] in {"deploy", "import"}:
            continue
        with _diagnose_submission(host, request):
            replayed = support._submit(tmp_path, operator, identity, ssh, request)
        assert replayed == result
