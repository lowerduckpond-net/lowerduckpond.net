"""Native cross-record authority and real SDK transport reject unsafe retirement."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
from botocore.awsrequest import AWSResponse  # type: ignore[import-untyped]
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_static_contracts import manifest_digest, request_digest, result_digest

from scripts import m3_11_frozen_context as c
from scripts import m3_11_frozen_evidence as e
from scripts.m3_11_frozen_frames import frame
from scripts.m3_11_retirement_files import RetirementError
from scripts.m3_11_unattended.model import Credential

B = Path(__file__).resolve().parents[2]
FIX = B / "tests/static-publication/fixtures/accepted"


def load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((FIX / (name + ".json")).read_bytes()))


@pytest.fixture
def evidence_case(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    tmp_path.chmod(0o700)
    manifest = load("site")
    manifest["spec"]["desiredState"] = "archived"
    record = load("archive-record")
    record["manifestDigest"] = manifest_digest(manifest).to_dict()
    record["bucket"] = "example-test-archive"
    result = load("operation-result")
    result.update(operation="archive", manifest=manifest, archiveRecord=record)
    job = load("authorization-job")
    job.update(phase="completed", executionValidated=True)
    job["request"] = {
        "apiVersion": job["apiVersion"],
        "kind": "OperationRequest",
        "operation": "archive",
        "correlationId": record["correlationId"],
        "tenantId": record["tenantId"],
    }
    job["requestDigest"] = request_digest(job["request"]).to_dict()
    correlation = deepcopy(job)
    correlation.update(phase="pending")
    correlation.pop("executionValidated")
    observed = load("tenant-observed-state")
    observed.update(
        observedState="archived",
        activeDeploymentId=None,
        runtimeGenerationId=None,
        desiredManifestDigest=manifest_digest(manifest).to_dict(),
    )
    row = {"archive": record, "desired": manifest, "deployment": load("deployment-record")}
    selected = {
        "bucket": record["bucket"],
        "key": record["key"],
        "version": record["versionId"],
        "size": record["bundleSize"],
        "sha256": record["bundleDigest"]["value"],
    }
    image = {"size": 8 * 1024**3, "sha256": "b" * 64}
    audit_entry = {
        "correlationId": record["correlationId"],
        "operatorPrincipal": job["operatorPrincipal"],
        "tenantId": record["tenantId"],
        "operation": "archive",
        "resultStatus": "succeeded",
        "resultDigest": result_digest(result).to_dict(),
    }

    class Reader:
        def names(self, path: str) -> dict[str, str]:
            return (
                {"namespace.json": "regular"}
                if path == "/static/platform"
                else {"segment-00000000000000000000.jsonl": "regular"}
                if path == "/static/audit"
                else {}
            )

        def read(self, path: str) -> bytes:
            return b"synthetic native-boundary audit fixture\n"

    monkeypatch.setattr(e, "Ext4", lambda path: Reader())
    monkeypatch.setattr(
        e,
        "fingerprint",
        lambda path, maximum: (
            image
            if path.name == "state.ext4"
            else {"size": selected["size"], "sha256": selected["sha256"]}
        ),
    )
    monkeypatch.setattr(e, "inventory", lambda reader, root: [row])

    def contract(reader: object, root: str, path: Any) -> dict[str, Any]:  # noqa: ANN401 - typed native path boundary
        components = path.components
        if components[0] == "tenants":
            return observed
        if components[1] == "correlations":
            return correlation
        if components[1] == "jobs":
            return job
        if components[1] == "results":
            return result
        return {}

    monkeypatch.setattr(e, "contract", contract)
    monkeypatch.setattr(
        e, "DurableDirectory", SimpleNamespace(open=lambda *a, **kw: nullcontext(object()))
    )
    monkeypatch.setattr(e, "inspect_audit_readonly", lambda *a, **kw: "synthetic-chain")
    monkeypatch.setattr(
        e,
        "inspect_audit_correlation",
        lambda *a, **kw: SimpleNamespace(
            state="synthetic-chain", entry=audit_entry, has_later_tenant_state_transition=False
        ),
    )
    monkeypatch.setattr(e, "parser_work_budget", nullcontext)
    monkeypatch.setattr(e, "inspect_portable_bundle", lambda *a, **kw: object())
    monkeypatch.setattr(e, "require_archive_inspection", lambda *a: None)

    def verify() -> dict[str, object]:
        return e.verify(
            selected,
            archive=tmp_path / "archive.zip",
            state_image=tmp_path / "state.ext4",
            image_binding=image,
            scratch=tmp_path,
        )

    return SimpleNamespace(
        verify=verify,
        job=job,
        correlation=correlation,
        result=result,
        observed=observed,
        audit=audit_entry,
    )


def test_native_evidence_linkage_baseline(evidence_case: SimpleNamespace) -> None:
    assert evidence_case.verify()["tenant_job_audit_unchanged"] is True


@pytest.mark.parametrize(
    "kind", ["principal", "result-correlation", "job-operation", "job-tenant", "observed-digest"]
)
def test_native_evidence_rejects_cross_record_drift(
    evidence_case: SimpleNamespace, kind: str
) -> None:
    x = evidence_case
    if kind == "principal":
        x.audit["operatorPrincipal"] = "different@example.test"
    elif kind == "result-correlation":
        x.result["correlationId"] = "0198d17f-6f4a-7000-8000-000000000099"
        x.audit["resultDigest"] = result_digest(x.result).to_dict()
    elif kind == "observed-digest":
        x.observed["desiredManifestDigest"]["value"] = "f" * 64
    else:
        for doc in (x.job, x.correlation):
            if kind == "job-operation":
                doc["request"]["operation"] = "suspend"
            else:
                doc["request"]["tenantId"] = "0198d17f-6f4a-7000-8000-000000000099"
            doc["requestDigest"] = request_digest(doc["request"]).to_dict()
    with pytest.raises((ValueError, RuntimeError)):
        x.verify()


class Raw:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def stream(self, amt: int | None = None, decode_content: bool = False) -> Iterator[bytes]:
        yield self.body

    def read(self, amt: int | None = None) -> bytes:
        return self.body


@pytest.fixture
def wire_case(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    x: Any = c.NativeFixture.__new__(c.NativeFixture)
    x.deliveries = {
        "archive": Credential("synthetic-id", "synthetic-secret", {}),
        "operator": Credential("synthetic-observer", "synthetic-secret-2", {}),
    }
    x.plan = {
        "archive": {
            "bucket": "example-test-archive",
            "key": "archive/example.zip",
            "version": "exact-version",
        }
    }
    x.manifest = SimpleNamespace(
        targets=SimpleNamespace(
            region="nyc3",
            archive_bucket="example-test-archive",
            backup_bucket="example-test-backup",
        )
    )
    x.storage = SimpleNamespace(
        target=SimpleNamespace(backup_bucket="example-test-backup", owner_key="owner/test"),
        owner_version="owner-version",
    )
    x.deletes = x.reads = 0
    state: dict[str, Any] = {
        "expired": False,
        "checks": 0,
        "sends": 0,
        "status": 204,
        "body": b"",
        "headers": {"x-amz-version-id": "exact-version"},
    }

    def owner() -> None:
        state["checks"] += 1
        if state["expired"]:
            raise RetirementError("synthetic proof expired")

    x.owner = owner
    monkeypatch.setattr(c, "require_remaining", lambda n: None)
    client = x.client("archive")

    def send(request: Any) -> AWSResponse:  # noqa: ANN401 - real botocore request
        state["sends"] += 1
        return AWSResponse(request.url, state["status"], state["headers"], Raw(state["body"]))

    monkeypatch.setattr(client._endpoint.http_session, "send", send)

    def delete() -> dict[str, object]:
        return cast(
            dict[str, object],
            client.delete_object(
                Bucket="example-test-archive", Key="archive/example.zip", VersionId="exact-version"
            ),
        )

    return SimpleNamespace(fixture=x, state=state, client=client, delete=delete)


def test_native_client_exact_single_submission(wire_case: SimpleNamespace) -> None:
    x = wire_case
    assert x.delete()["VersionId"] == "exact-version"
    assert x.state["sends"] == x.fixture.deletes == 1
    with pytest.raises(RetirementError):
        x.delete()
    assert x.state["sends"] == 1


def test_native_client_service_failure_never_retries(wire_case: SimpleNamespace) -> None:
    x = wire_case
    x.state.update(
        status=503,
        body=b"<Error><Code>ServiceUnavailable</Code><Message>synthetic</Message></Error>",
    )
    with pytest.raises((ClientError, RetirementError)):
        x.delete()
    assert x.state["sends"] == 1


def test_native_client_blocks_final_expired_owner(wire_case: SimpleNamespace) -> None:
    x = wire_case

    def delay(**kw: object) -> None:
        x.state["expired"] = True

    x.client.meta.events.register_last("before-call.s3.DeleteObject", delay)
    with pytest.raises(RetirementError):
        x.delete()
    assert x.state["sends"] == 0


def test_native_client_wrong_version_no_send(wire_case: SimpleNamespace) -> None:
    x = wire_case
    with pytest.raises(RetirementError):
        x.client.delete_object(
            Bucket="example-test-archive", Key="archive/example.zip", VersionId="different"
        )
    assert x.state["sends"] == x.fixture.deletes == 0


def test_native_client_redirect_cannot_repeat(wire_case: SimpleNamespace) -> None:
    x = wire_case
    x.state.update(
        status=301,
        headers={"x-amz-bucket-region": "ams3"},
        body=b"<Error><Code>PermanentRedirect</Code><Message>synthetic</Message></Error>",
    )
    with pytest.raises((ClientError, RetirementError)):
        x.delete()
    assert x.state["sends"] == 1


def test_native_client_rechecks_after_signing(wire_case: SimpleNamespace) -> None:
    x = wire_case

    def delay(**kw: object) -> None:
        x.state["expired"] = True

    x.client.meta.events.register_last("before-sign.s3.DeleteObject", delay)
    with pytest.raises(RetirementError):
        x.delete()
    assert x.state["sends"] == 0


def test_signed_delete_rechecks_whole_post_effect_allowance(
    wire_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.m3_11_unattended import storage_admission  # noqa: PLC0415

    x, clock = wire_case, [0.0]
    monkeypatch.setattr(storage_admission, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(storage_admission, "_deadline", 3000.0)
    monkeypatch.setattr(c, "require_remaining", storage_admission.require_remaining)

    def delay(**kwargs: object) -> None:
        clock[0] = 700.0

    x.client.meta.events.register_last("before-sign.s3.DeleteObject", delay)
    with pytest.raises(RuntimeError):
        x.delete()
    assert x.state["sends"] == 0
    assert x.fixture.deletes == 1  # Reserved identity remains consumed despite no wire effect.


def test_get_reconciliation_does_not_require_new_delete_allowance(
    wire_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.m3_11_unattended import storage_admission  # noqa: PLC0415

    x = wire_case
    monkeypatch.setattr(storage_admission, "time", SimpleNamespace(monotonic=lambda: 700.0))
    monkeypatch.setattr(storage_admission, "_deadline", 3000.0)
    monkeypatch.setattr(c, "require_remaining", storage_admission.require_remaining)
    result = x.client.get_bucket_versioning(Bucket="example-test-archive")
    assert result["ResponseMetadata"]["HTTPStatusCode"] == x.state["status"]
    assert x.state["sends"] == 1 and x.fixture.deletes == 0


def test_partial_frame_cannot_extend_one_deadline() -> None:
    read, write = os.pipe()
    try:
        os.write(write, b'{"partial":')
        with os.fdopen(read, "rb", buffering=0) as stream, pytest.raises(TimeoutError):
            frame(stream, deadline=time.monotonic() + 0.05)
    finally:
        os.close(write)


def test_complete_frames_do_not_consume_following_frame() -> None:
    read, write = os.pipe()
    try:
        os.write(write, b'{"one":1}\n{"two":2}\n')
        with os.fdopen(read, "rb", buffering=0) as stream:
            deadline = time.monotonic() + 60
            assert frame(stream, deadline=deadline) == {"one": 1}
            assert frame(stream, deadline=deadline) == {"two": 2}
    finally:
        os.close(write)


def synthetic_environment(root: Path) -> dict[str, str]:
    from scripts.qualification_context import (  # noqa: PLC0415 - consumer-boundary fixture
        ARTIFACT_ENV,
        resource_names,
    )

    return {
        **resource_names("0198d17f6f4a70008000000000000001"),
        ARTIFACT_ENV: str(root / "fixture/static-host-agent.tar"),
    }


@pytest.mark.parametrize("copied", [False, True])
def test_active_run_and_child_action_block_retirement_until_both_finish(
    tmp_path: Path, copied: bool
) -> None:
    from scripts.m3_11_retirement_files import record  # noqa: PLC0415
    from scripts.qualification_context import run_lease  # noqa: PLC0415
    from scripts.qualification_disposition import DIRECTORY, ORIGIN  # noqa: PLC0415
    from scripts.qualification_mutation import ownership  # noqa: PLC0415

    tmp_path.chmod(0o700)
    root = tmp_path / "original"
    root.mkdir(mode=0o700)
    (root / "run.lock").touch(mode=0o600)
    workspace = root
    if copied:
        (root / "diagnostics").mkdir(mode=0o700)
        workspace = root / "diagnostics/workspace"
        workspace.mkdir(mode=0o700)
        (workspace / "run.lock").touch(mode=0o600)
        marker: dict[str, object] = {
            "format": "lowerduckpond-m3-11-debug-v1",
            "original_run": str(root),
            "qualification_authority": "none",
            "original_files": {},
        }
        record(root / ORIGIN, marker)
        record(workspace / ORIGIN, marker)
    with run_lease(workspace):
        with ownership(workspace), pytest.raises(BlockingIOError), ownership(root, exclusive=True):
            pytest.fail("retirement overlapped an active parent/child mutation")
        with pytest.raises(BlockingIOError), ownership(root, exclusive=True):
            pytest.fail("retirement overlapped the still-active parent")
    with ownership(root, exclusive=True):
        (root / DIRECTORY).mkdir(mode=0o700)
    with pytest.raises(ValueError, match="permanently"), run_lease(workspace):
        pytest.fail("completed retirement did not fence a later consumer")


@pytest.mark.parametrize("operation", ["command", "phase", "start", "converge", "fault"])
@pytest.mark.parametrize("retired", [False, True])
def test_consumer_action_holds_shared_lock_through_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
    operation: str,
    retired: bool,
) -> None:
    restore_fixture = installed_module("restore_fixture")
    from scripts import qualification_case, qualification_restore  # noqa: PLC0415
    from scripts.qualification_disposition import DIRECTORY  # noqa: PLC0415
    from scripts.qualification_mutation import ownership  # noqa: PLC0415

    tmp_path.chmod(0o700)
    root = tmp_path / "original"
    root.mkdir(mode=0o700)
    environment = synthetic_environment(root)
    calls: list[str] = []

    def effect(*args: object, **kwargs: object) -> bytes:
        with pytest.raises(BlockingIOError), ownership(root, exclusive=True):
            pytest.fail("retirement acquired ownership while a consumer was mutating")
        calls.append(operation)
        return b"synthetic"

    fixture: Any = restore_fixture.Fixture.__new__(restore_fixture.Fixture)
    fixture.environment = environment
    fixture.root, fixture.inventory = root, root / "inventory.json"
    fixture.destination = SimpleNamespace(run=lambda *a, **kw: (effect(), SimpleNamespace(rc=0))[1])
    fixture.acme = object()
    monkeypatch.setattr(qualification_restore, "bounded_command", effect)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: (effect(), SimpleNamespace(returncode=0))[1],
    )
    monkeypatch.setattr(restore_fixture.shutil, "which", lambda name: "/synthetic/uv")
    monkeypatch.setattr(
        restore_fixture.restore_convergence, "run", lambda *a, **kw: (effect(), 0)[1]
    )
    monkeypatch.setattr(restore_fixture, "checked", effect)

    def invoke() -> None:
        if operation == "command":
            qualification_restore.command(environment, "docker", "start", "synthetic")
        elif operation == "phase":
            qualification_case.phase(root, environment, "/synthetic/uv", "synthetic")
        elif operation == "converge":
            fixture.converge(succeeds=True)
        elif operation == "fault":
            fixture.fault("synthetic")
        else:
            fixture.start()

    if retired:
        (root / DIRECTORY).mkdir(mode=0o700)
        with pytest.raises(ValueError, match="permanently"):
            invoke()
        assert not calls
    else:
        invoke()
        assert calls == [operation]
        with ownership(root, exclusive=True):
            pass


@pytest.mark.parametrize("retired", [False, True])
def test_direct_directory_disposal_serializes_with_retirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired: bool
) -> None:
    from scripts import m3_11_debug_closeout as closeout  # noqa: PLC0415
    from scripts.m3_11_combined_inputs import FORMAT, _environment  # noqa: PLC0415
    from scripts.m3_11_retirement_files import record  # noqa: PLC0415
    from scripts.qualification_disposition import DIRECTORY  # noqa: PLC0415
    from scripts.qualification_mutation import ownership  # noqa: PLC0415

    tmp_path.chmod(0o700)
    root = tmp_path / "original"
    root.mkdir(mode=0o700)
    identity = "0198d17f-6f4a-7000-8000-000000000001"
    fixture: dict[str, object] = {
        "format": FORMAT,
        "run_id": identity,
        "environment": _environment(root, identity, "unix:///synthetic"),
    }
    record(root / "fixture.json", fixture)
    record(
        closeout.disposal_receipt(root),
        {
            "format": closeout.DISPOSAL_FORMAT,
            "directory": str(root),
            "device": root.stat().st_dev,
            "inode": root.stat().st_ino,
            "fixture": fixture,
        },
    )
    removed: list[Path] = []
    original = shutil.rmtree

    def remove(path: Path) -> None:
        with pytest.raises(BlockingIOError), ownership(root, exclusive=True):
            pytest.fail("retirement overlapped directory disposal")
        removed.append(path)
        original(path)

    monkeypatch.setattr(shutil, "rmtree", remove)
    if retired:
        (root / DIRECTORY).mkdir(mode=0o700)
        with pytest.raises(ValueError, match="permanently"):
            closeout.finish_directory(root, apply=True)
        assert not removed and root.is_dir() and closeout.disposal_receipt(root).is_file()
    else:
        closeout.finish_directory(root, apply=True)
        assert removed == [root] and not root.exists()
