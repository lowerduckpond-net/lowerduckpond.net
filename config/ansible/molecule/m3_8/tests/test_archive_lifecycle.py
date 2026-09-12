from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator
from pathlib import Path

import archive_capture_support as captures
import pytest
import test_export_import as exports
import test_lifecycle as support
import test_transport_recovery as recovery
from lowerduckpond_static_host_agent.portable_bundle import inspect_portable_bundle
from testinfra.host import Host

_CYCLES = 4
_HISTORY_LIMIT = 3
_CONTENT = b"installed M3.10 versioned archive content\n"


def _installed_python(host: Host, body: str) -> str:
    outcome = host.run("/usr/bin/python3 -I -B -c %s", exports._selected_python(host, body))
    assert outcome.rc == 0, outcome.stderr
    return outcome.stdout


def test_installed_tls_storage_credentials_are_mutually_denied(host: Host) -> None:
    _installed_python(
        host,
        """
from botocore.exceptions import ClientError
from lowerduckpond_static_host_agent.archive_remote import make_archive_client
archive = make_archive_client(region='ams3', access_key_id='molecule-m3-10-archive',
    secret_access_key='molecule-m3-10-disposable-archive-secret')
backup = make_archive_client(region='ams3', access_key_id='molecule-m3-10-backup',
    secret_access_key='molecule-m3-10-disposable-backup-secret')
objects = []
try:
    for client, bucket in ((archive, 'molecule-tenant-archives'),
                           (backup, 'molecule-platform-backup')):
        assert client.get_bucket_versioning(Bucket=bucket)['Status'] == 'Enabled'
        version = client.put_object(Bucket=bucket, Key='archives/credential-proof',
                                    Body=b'proof', ContentLength=5)['VersionId']
        objects.append((client, bucket, version))
        body = client.get_object(Bucket=bucket, Key='archives/credential-proof',
                                 VersionId=version)['Body']
        try:
            assert body.read() == b'proof'
        finally:
            body.close()
    for index, (owner, bucket, version) in enumerate(objects):
        other = backup if index == 0 else archive
        for operation, arguments in (
            ('get_object', {'Key': 'archives/credential-proof', 'VersionId': version}),
            ('list_object_versions', {}),
            ('put_object', {'Key': 'archives/cross-denied', 'Body': b'x', 'ContentLength': 1}),
        ):
            try:
                getattr(other, operation)(Bucket=bucket, **arguments)
            except ClientError as error:
                assert error.response['ResponseMetadata']['HTTPStatusCode'] == 403
            else:
                raise AssertionError('cross-bucket access unexpectedly succeeded')
finally:
    for owner, bucket, version in objects:
        owner.delete_object(Bucket=bucket, Key='archives/credential-proof', VersionId=version)
for owner, bucket, _ in objects:
    inventory = owner.list_object_versions(Bucket=bucket)
    assert not inventory.get('Versions') and not inventory.get('DeleteMarkers')
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


@pytest.fixture
def controlled_recovery_timer(host: Host) -> Iterator[None]:
    try:
        yield
    finally:
        recovery._start_reconcile_timer(host)


@pytest.mark.usefixtures("controlled_recovery_timer")
def test_installed_archive_export_restore_rearchive_and_delete(host: Host, tmp_path: Path) -> None:  # noqa: PLR0915 - one complete lifecycle proof
    support._initialize_namespace(host)
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._await_persisted_admission_burst(host)
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
                b"",
            )
            result = recovery._exercise_caddy_failure_recovery(
                host,
                request,
                assert_rolled_back=lambda: recovery._assert_tenant_snapshot(host, snapshot),
            )
        else:
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
    for request, result in history:
        # Export delivery is already acknowledged; historical requests return only results.
        if request["operation"] in {"deploy", "import"}:
            continue
        assert support._submit(tmp_path, operator, identity, ssh, request) == result
