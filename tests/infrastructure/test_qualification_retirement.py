from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_static_contracts import (
    archive_record_digest,
    canonical_json_bytes,
    manifest_digest,
    result_digest,
)
from lowerduckpond_static_host_agent.audit import DEFAULT_AUDIT_LIMITS, AuditError
from lowerduckpond_static_host_agent.job_runtime import RuntimeBoundaryError
from lowerduckpond_static_host_agent.locks import LockManager, StateBusyError

from scripts import qualification_local as local
from scripts import qualification_retirement as retirement
from scripts import qualification_retirement_probe as probe
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, HOST_ENV, run_lease

HOST_ID = "a" * 64
ARCHIVE_ID = "b" * 64
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("DOCKER_HOST", "unix:///owned/docker.sock")
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")
    local.create_environment(tmp_path)
    with run_lease(tmp_path, create=True):
        pass
    (tmp_path / "case-containers.json").write_text(
        json.dumps({HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID})
    )
    return tmp_path


def test_retirement_uses_only_bound_ids_after_two_fresh_local_checks(
    owned: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[str] = []
    historical = owned / "failure.json"
    historical.write_bytes(b"original failure remains unchanged\n")
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/docker")

    def containers(environment: dict[str, str]) -> dict[str, str]:
        events.append("identity")
        return {HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID}

    def accounting(environment: dict[str, str], host_id: str) -> str:
        assert host_id == HOST_ID
        events.append("local")
        return "quiescent-installed"

    def storage(environment: dict[str, str], archive_id: str) -> None:
        assert archive_id == ARCHIVE_ID
        events.append("remote")

    def execute(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        events.append(f"{command[1]}:{command[-1]}")
        assert command[0] == "/usr/bin/docker"
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(retirement, "owned_containers", containers)
    monkeypatch.setattr(retirement, "local_proof", accounting)
    monkeypatch.setattr(retirement, "independent_storage_absence", storage)
    monkeypatch.setattr(subprocess, "run", execute)
    destination = retirement.retire(owned)
    assert events == [
        "identity",
        "local",
        "remote",
        "identity",
        "local",
        f"stop:{HOST_ID}",
        f"rm:{HOST_ID}",
        f"stop:{ARCHIVE_ID}",
        f"rm:{ARCHIVE_ID}",
    ]
    assert json.loads(destination.read_text())["authority"] == "diagnostic-only"
    assert historical.read_bytes() == b"original failure remains unchanged\n"


@pytest.mark.parametrize("failure", ["identity", "local", "remote", "replacement", "changed"])
def test_failed_or_changing_proofs_never_mutate_containers(
    owned: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    identities = [{HOST_ENV: HOST_ID, ARCHIVE_ENV: ARCHIVE_ID}] * 2
    if failure in {"identity", "replacement"}:
        identities[0 if failure == "identity" else 1] = {
            HOST_ENV: "c" * 64,
            ARCHIVE_ENV: ARCHIVE_ID,
        }
    monkeypatch.setattr(retirement, "owned_containers", Mock(side_effect=identities))
    accounting = (
        Mock(side_effect=ValueError("unknown"))
        if failure == "local"
        else Mock(
            side_effect=[
                "quiescent-installed",
                "empty-before-installation" if failure == "changed" else "quiescent-installed",
            ]
        )
    )
    monkeypatch.setattr(retirement, "local_proof", accounting)
    monkeypatch.setattr(
        retirement,
        "independent_storage_absence",
        Mock(side_effect=ValueError("unknown") if failure == "remote" else None),
    )
    mutation = Mock()
    monkeypatch.setattr(subprocess, "run", mutation)
    with pytest.raises(ValueError):
        retirement.retire(owned)
    mutation.assert_not_called()
    assert not (owned / "retirement.json").exists()


def test_active_run_cannot_be_retired(owned: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    inspection = Mock()
    monkeypatch.setattr(retirement, "environment_for", inspection)
    with run_lease(owned), pytest.raises(BlockingIOError):
        retirement.retire(owned)
    inspection.assert_not_called()


def test_environment_uses_original_endpoint_and_discards_live_inputs(
    owned: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in (
        "SPACES_SECRET_ACCESS_KEY",
        "CLOUDFLARE_API_TOKEN",
        "M3_8_ARCHIVE_SECRET",
        "M3_10_INSTALLED_REPORT",
    ):
        monkeypatch.setenv(key, "private-canary")
    monkeypatch.setenv("DOCKER_CONTEXT", "other-daemon")
    monkeypatch.setenv("DOCKER_HOST", "unix:///other/docker.sock")
    environment = retirement.environment_for(owned)
    assert "private-canary" not in environment.values()
    assert "DOCKER_CONTEXT" not in environment
    assert environment["DOCKER_HOST"] == "unix:///owned/docker.sock"
    assert environment["M3_10_ARCHIVE_BACKEND"] == "minio"
    manifest = json.loads((owned / "fixture.json").read_text())
    manifest["environment"][HOST_ENV] = "lowerduckpond-ubuntu-2604"
    (owned / "fixture.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        retirement.environment_for(owned)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "empty", "oversize"])
def test_retained_artifact_must_be_a_bounded_regular_file(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "artifact"
    if kind == "symlink":
        path.symlink_to("/dev/zero")
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "directory":
        path.mkdir()
    else:
        with path.open("wb") as stream:
            stream.truncate(retirement.MAX_ARTIFACT_BYTES + 1 if kind == "oversize" else 0)
    with pytest.raises((OSError, ValueError)):
        retirement.artifact_digest(path)


def test_selected_artifact_must_match_retained_bytes(
    owned: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = retirement.environment_for(owned)
    artifact = Path(environment[ARTIFACT_ENV])
    artifact.write_bytes(b"selected fixture artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setattr(
        retirement,
        "bounded_command",
        lambda *args, **kwargs: json.dumps(
            {"state": "quiescent-installed", "artifact_sha256": digest}
        ).encode(),
    )
    assert retirement.local_proof(environment, HOST_ID) == "quiescent-installed"
    artifact.write_bytes(b"different artifact")
    with pytest.raises(ValueError, match="differs"):
        retirement.local_proof(environment, HOST_ID)


@pytest.fixture
def installed(tmp_path: Path) -> tuple[Path, Path, Path]:
    state, caddy, sites = (tmp_path / name for name in ("state", "caddy", "sites"))
    for path in [
        *(state / name for name in (*probe.PENDING, "tenants", "platform")),
        *(state / "authorization" / name for name in ("jobs", "results", "correlations")),
        caddy / "intents",
        sites / ".staging",
    ]:
        path.mkdir(parents=True)
    (state / "locks").mkdir()
    with LockManager.initialize(state / "locks", expected_owner=os.geteuid()):
        pass
    fixture = ROOT / "tests/static-publication/fixtures/accepted"
    job = json.loads((fixture / "authorization-job.json").read_text())
    job.update(
        compatibilityVersion="static-job-v2",
        executionValidated=True,
        sourceAuthority=None,
        phase="completed",
    )
    result = json.loads((fixture / "operation-result.json").read_text())
    binding = {**job, "phase": "pending", "executionValidated": False}
    for kind, name, value in (
        ("jobs", job["jobId"], job),
        ("results", job["jobId"], result),
        ("correlations", job["request"]["correlationId"], binding),
    ):
        (state / "authorization" / kind / f"{name}.json").write_text(json.dumps(value))
    return state, caddy, sites


def test_terminal_validated_accounting_passes(installed: tuple[Path, Path, Path]) -> None:
    probe.installed(*installed, owner=os.geteuid())


@pytest.fixture(params=(False, True), ids=("local", "archived"))
def administrator_result(
    installed: tuple[Path, Path, Path], request: pytest.FixtureRequest
) -> tuple[Path, Path]:
    state, _, _ = installed
    for directory in (state, *(p for p in state.rglob("*") if p.is_dir())):
        directory.chmod(0o700)
    (state / "audit").mkdir(mode=0o700)
    correlation = "0198d17f-6f4a-7000-8000-000000000077"
    tenant = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2199"
    result = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {
            "kind": "emergency-administrator",
            "operatorPrincipal": "ldp-admin",
            "reason": "Installed administrator recovery",
        },
        "operation": "delete",
        "status": "succeeded",
        "correlationId": correlation,
        "tenantId": tenant,
        "canonicalOrigin": f"t-{tenant.replace('-', '')}.lowerduckpond.com",
    }
    path = state / "authorization/results" / f"{correlation}.json"
    path.write_bytes(canonical_json_bytes(result))
    path.chmod(0o600)
    audit = json.loads(
        (ROOT / "tests/static-publication/fixtures/accepted/audit-entry.json").read_text()
    )
    audit.update(
        operation="delete",
        operatorPrincipal="ldp-admin",
        tenantId=tenant,
        correlationId=correlation,
        resultDigest=result_digest(result).to_dict(),
        deletionEvidence={
            "mode": "emergency",
            "releasedSlugs": ["removed-tenant"],
            "archiveRecordDigest": None,
            "bucket": None,
            "key": None,
            "versionId": None,
            "emergencyReason": "Installed administrator recovery",
        },
    )
    if request.param:
        archive = json.loads(
            (ROOT / "tests/static-publication/fixtures/accepted/archive-record.json").read_text()
        )
        archive.update(tenantId=tenant, bucket="fixture-archives")
        audit["deletionEvidence"].update(
            mode="emergency-archived",
            archiveRecordDigest=archive_record_digest(archive).to_dict(),
            bucket=archive["bucket"],
            key=archive["key"],
            versionId=archive["versionId"],
        )
    segment = state / "audit/segment-00000000000000000000.jsonl"
    segment.write_bytes(canonical_json_bytes(audit))
    segment.chmod(0o600)
    return path, segment


@pytest.mark.parametrize(
    "drift",
    [
        "none",
        "missing-audit",
        "digest",
        "principal",
        "reason",
        "tenant",
        "ordinary-orphan",
        "name",
        "remaining-tenant",
        "ordinary-correlation",
        "publication",
        "chain",
    ],
)
def test_administrator_deletion_requires_exact_audited_authority_without_mutation(
    installed: tuple[Path, Path, Path], administrator_result: tuple[Path, Path], drift: str
) -> None:
    state, _, _ = installed
    path, segment = administrator_result
    result = json.loads(path.read_text())
    audit = json.loads(segment.read_text())
    changes: dict[str, tuple[tuple[str, ...], object]] = {
        "digest": (("resultDigest", "value"), "f" * 64),
        "principal": (("operatorPrincipal",), "different-admin"),
        "reason": (("deletionEvidence", "emergencyReason"), "different reason"),
        "tenant": (("tenantId",), "0191e2c4-8f7a-7c3b-8d1e-5f62047a2188"),
        "chain": (("sequence",), 1),
    }
    if drift == "missing-audit":
        segment.unlink()
    elif drift in changes:
        fields, value = changes[drift]
        selected = audit
        for field in fields[:-1]:
            selected = selected[field]
        selected[fields[-1]] = value
        segment.write_bytes(canonical_json_bytes(audit))
    elif drift == "ordinary-orphan":
        result["provenance"] = json.loads(
            (ROOT / "tests/static-publication/fixtures/accepted/operation-result.json").read_text()
        )["provenance"]
        path.write_bytes(canonical_json_bytes(result))
    elif drift == "name":
        path.rename(path.with_name("0198d17f-6f4a-7000-8000-000000000088.json"))
    elif drift == "remaining-tenant":
        (state / "tenants" / result["tenantId"]).mkdir()
    elif drift == "ordinary-correlation":
        (state / "authorization/correlations" / path.name).write_text("{}")
    elif drift == "publication":
        temporary = segment.with_name(".ldp-state-" + "a" * 32)
        temporary.write_bytes(b"unfinished publication must remain intact\n")
        temporary.chmod(0o600)
    before = {p: p.read_bytes() for p in state.rglob("*") if p.is_file()}
    if drift == "none":
        probe.installed(*installed, owner=os.geteuid())
    else:
        with pytest.raises((ValueError, AuditError)):
            probe.installed(*installed, owner=os.geteuid())
    assert {p: p.read_bytes() for p in state.rglob("*") if p.is_file()} == before


def test_administrator_audit_has_a_total_byte_bound_before_reading_segments(
    installed: tuple[Path, Path, Path], administrator_result: tuple[Path, Path]
) -> None:
    _, segment = administrator_result
    size = DEFAULT_AUDIT_LIMITS.maximum_segment_bytes
    count = DEFAULT_AUDIT_LIMITS.maximum_administrator_bytes // size + 1
    for number in range(count):
        path = segment.with_name(f"segment-{number:020d}.jsonl")
        with path.open("wb") as stream:
            stream.truncate(size)
        path.chmod(0o600)
    with pytest.raises(ValueError, match="byte bound"):
        probe.installed(*installed, owner=os.geteuid())


@pytest.mark.parametrize("condition", ["active", "archived", "stale-observation", "archive-record"])
def test_retirement_requires_settled_tenants_without_archive_obligations(
    installed: tuple[Path, Path, Path], condition: str
) -> None:
    state, _, _ = installed
    fixtures = ROOT / "tests/static-publication/fixtures/accepted"
    desired = json.loads((fixtures / "site.json").read_text())
    observed = json.loads((fixtures / "tenant-observed-state.json").read_text())
    if condition == "archived":
        desired["spec"]["desiredState"] = "archived"
    if condition != "stale-observation":
        observed["desiredManifestDigest"] = manifest_digest(desired).to_dict()
    tenant = state / "tenants" / desired["metadata"]["id"]
    (tenant / "archives").mkdir(parents=True)
    (tenant / "desired.json").write_text(json.dumps(desired))
    (tenant / "observed.json").write_text(json.dumps(observed))
    if condition == "archive-record":
        (tenant / "archives/retained.json").write_text("{}")
    if condition == "active":
        probe.installed(*installed, owner=os.geteuid())
    else:
        with pytest.raises(ValueError):
            probe.installed(*installed, owner=os.geteuid())


@pytest.mark.parametrize(
    "issue",
    [
        "pending",
        "unvalidated",
        "result-mismatch",
        "orphan",
        "quarantine",
        "intake",
        "binding",
        "busy",
    ],
)
def test_unfinished_or_inconsistent_accounting_blocks_retirement(
    installed: tuple[Path, Path, Path], issue: str
) -> None:
    state, _, _ = installed
    if issue == "busy":
        with (state / "locks/publication.lock").open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with pytest.raises(StateBusyError):
                probe.installed(*installed, owner=os.geteuid())
        return
    if issue in {"pending", "unvalidated"}:
        path = next((state / "authorization/jobs").iterdir())
        value = json.loads(path.read_text())
        value["phase" if issue == "pending" else "executionValidated"] = (
            "pending" if issue == "pending" else False
        )
        path.write_text(json.dumps(value))
    elif issue == "result-mismatch":
        path = next((state / "authorization/results").iterdir())
        value = json.loads(path.read_text())
        value["provenance"]["jobId"] = "0198d17f-6f4a-7000-8000-000000000099"
        path.write_text(json.dumps(value))
    elif issue == "orphan":
        (state / "authorization/results/orphan.json").write_text("{}")
    elif issue == "binding":
        next((state / "authorization/correlations").iterdir()).unlink()
    else:
        (
            state
            / ("platform/archive-quarantine.json" if issue == "quarantine" else "intake/pending")
        ).touch()
    with pytest.raises((ValueError, RuntimeBoundaryError)):
        probe.installed(*installed, owner=os.geteuid())


def test_uninstalled_proof_rejects_retained_state_and_symlink_ancestors(tmp_path: Path) -> None:
    state, caddy, sites = (tmp_path / name for name in ("state", "caddy", "sites"))
    probe.uninstalled(state, caddy, sites)
    (state / "intents").mkdir(parents=True)
    (state / "intents/pending").touch()
    with pytest.raises(ValueError):
        probe.uninstalled(state, caddy, sites)
    (state / "intents/pending").unlink()
    (state / "intents").rmdir()
    (state / "intents").symlink_to(tmp_path)
    with pytest.raises(ValueError):
        probe.uninstalled(state, caddy, sites)


@pytest.mark.parametrize("output", [None, b'{"status":"error"}', b'{"key":"retained-bucket"}'])
def test_uninstalled_storage_must_be_completely_empty(
    monkeypatch: pytest.MonkeyPatch, output: bytes | None
) -> None:
    monkeypatch.setattr(retirement, "bounded_command", lambda *args, **kwargs: output)
    with pytest.raises(ValueError):
        retirement.uninstalled_storage_absence({}, ARCHIVE_ID)
