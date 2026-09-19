"""Independent diagnostic archive case; never complete M3.10 qualification."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import full_size_fixture as full_size
import test_archive_completion as accounting
import test_archive_lifecycle as archives
import test_lifecycle as support
from testinfra.host import Host

from scripts.qualification_case import INSTALLED_FORMAT
from scripts.qualification_context import ARTIFACT_ENV, RUN_ENV, host_name


def test_fresh_full_size_archive_restore(host: Host, tmp_path: Path) -> None:
    assert os.environ.get(RUN_ENV), "this diagnostic case requires a fresh owned local fixture"
    assert os.environ.get("M3_10_ARCHIVE_BACKEND") == "minio"
    assert "M3_10_INSTALLED_REPORT" not in os.environ
    assert host_name() == support.CONTAINER
    assert support._initialize_namespace(host), "the case must start on a fresh host"
    support._ensure_disposable_publication(host)
    support._prepare_edge_probe(host)
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    deployed, expected_digest = full_size.create(
        host, tmp_path, connection, slug=f"m3-full-{uuid.uuid7().hex[-12:]}"
    )
    tenant = str(deployed["tenantId"])
    origin = str(deployed["canonicalOrigin"])
    original_deployment = support._desired_deployment(deployed)
    operator, identity, ssh = connection

    def submit(operation: str) -> dict[str, object]:
        result = support._submit(
            tmp_path,
            operator,
            identity,
            ssh,
            support._request(operation, str(uuid.uuid7()), tenantId=tenant),
        )
        assert result["status"] == "succeeded"
        return result

    suspended = submit("suspend")
    assert support._lifecycle(suspended) == "suspended"
    assert full_size.installed_digest(host, tenant, original_deployment) == expected_digest
    archived = submit("archive")
    assert support._lifecycle(archived) == "archived"
    full_size.assert_worker_budget(host, archived)
    support._assert_route(host, origin, status=404)
    assert len(archives._remote_versions(host)) == 1
    restored = submit("restore")
    assert support._lifecycle(restored) == "active"
    restored_deployment = support._desired_deployment(restored)
    assert restored_deployment != original_deployment
    full_size.assert_worker_budget(host, restored)
    assert full_size.installed_digest(host, tenant, restored_deployment) == expected_digest
    support._assert_route(host, origin, status=200, body=full_size.INDEX)
    assert not archives._remote_versions(host)
    accounting.test_installed_archive_qualification_has_no_unresolved_accounting(host)
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0
    receipt = {
        "format": INSTALLED_FORMAT,
        "run_id": os.environ[RUN_ENV],
        "artifact_sha256": Path(selected.stdout.strip()).name,
        "content_sha256": expected_digest,
        "entries": full_size.ENTRY_COUNT,
        "bytes": full_size.CONTENT_BYTES,
    }
    destination = Path(os.environ[ARTIFACT_ENV]).parent.parent / "case-installed.json"
    with destination.open("x", encoding="ascii") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
