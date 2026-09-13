from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, manifest_digest, result_digest
from lowerduckpond_static_host_agent import LockManager, StateRepository

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/static-publication/fixtures/accepted"
ARTIFACT = "c" * 64
SOURCE = "0" * 40
TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"


def executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\nset -euo pipefail\n" + body + "\n")
    path.chmod(0o755)


@pytest.fixture
def completed_host(tmp_path: Path) -> Path:
    install = tmp_path / "opt/lowerduckpond/static-host-agent"
    (install / ARTIFACT / "site-packages").mkdir(parents=True)
    (install / "current").symlink_to(ARTIFACT)
    state = tmp_path / "var/lib/lowerduckpond/static"
    for name in (
        "",
        "platform",
        "tenants",
        "authorization",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
        "audit",
        "locks",
        "intents",
        "exports",
        "intake",
        f"tenants/{TENANT}",
        f"tenants/{TENANT}/archives",
        f"tenants/{TENANT}/deployments",
    ):
        directory = state / name
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    LockManager.initialize(state / "locks", expected_owner=os.geteuid()).close()
    # Real canonical authorization history and a real hash-chained audit segment
    # must remain byte-identical through this read-only host gate.
    job = json.loads((FIXTURES / "authorization-job.json").read_text())
    correlation = state / "authorization/correlations" / (job["request"]["correlationId"] + ".json")
    correlation.write_bytes(canonical_json_bytes(job))
    correlation.chmod(0o600)
    result = state / "authorization/results" / (job["jobId"] + ".json")
    result.write_bytes(
        canonical_json_bytes(json.loads((FIXTURES / "operation-result.json").read_text()))
    )
    result.chmod(0o600)
    manifest = json.loads(result.read_text())["manifest"]
    desired = state / "tenants" / TENANT / "desired.json"
    desired.write_bytes(canonical_json_bytes(manifest))
    desired.chmod(0o600)
    job["phase"] = "completed"
    record = state / "authorization/jobs" / (job["jobId"] + ".json")
    record.write_bytes(canonical_json_bytes(job))
    record.chmod(0o600)
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        audit = json.loads((FIXTURES / "audit-entry.json").read_text())
        audit["resultDigest"] = result_digest(json.loads(result.read_text())).to_dict()
        repository.append_audit(audit)
    for name in ("srv/lowerduckpond/sites/.staging", "etc/caddy/intents"):
        directory = tmp_path / name
        directory.mkdir(parents=True)
        directory.chmod(0o700)
    executable(
        tmp_path / "usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact",
        "[[ ${1##*/} == " + ARTIFACT + " ]]",
    )
    executable(
        tmp_path / "usr/local/libexec/lowerduckpond/check-caddy-generation",
        "function check() { echo current; }\n"
        "check \\\n    --authoritative-check \\\n    --origin-pull-required \\\n    fixture",
    )
    executable(tmp_path / "bin/systemctl", "exit 0")
    source = (ROOT / "scripts/m3-10-completed-host-preflight").read_text()
    for prefix in ("/opt/", "/etc/", "/var/", "/srv/", "/usr/local/"):
        source = source.replace(prefix, str(tmp_path) + prefix)
    source = source.replace("/usr/bin/python3", sys.executable)
    source = source.replace("== 0:", f"== {os.geteuid()}:")
    source = source.replace("expected_owner=0", f"expected_owner={os.geteuid()}")
    (tmp_path / "probe").write_text(source)
    return tmp_path


def gate(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - private copied program and local fixture state
        ["/bin/bash", str(tree / "probe"), ARTIFACT, "completed-host", SOURCE],
        env={"PATH": str(tree / "bin") + ":" + os.environ["PATH"]},
        capture_output=True,
        text=True,
        check=False,
    )


def test_completed_host_preserves_nonempty_authorization_tenant_and_audit_state(
    completed_host: Path,
) -> None:
    state = completed_host / "var/lib/lowerduckpond/static"
    before = {path: path.read_bytes() for path in state.rglob("*") if path.is_file()}
    result = gate(completed_host)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "format": "lowerduckpond-m3-10-archive-authority-v1",
        "sourceRevision": SOURCE,
        "artifactSha256": ARTIFACT,
        "archives": [],
    }
    assert {path: path.read_bytes() for path in state.rglob("*") if path.is_file()} == before
    assert (state / "tenants" / TENANT).is_dir()


@pytest.mark.parametrize("drift", ["none", "missing", "digest", "reason", "principal"])
def test_completed_host_preserves_administrator_results_without_an_ordinary_job(
    completed_host: Path,
    drift: str,
) -> None:
    correlation = "0198d17f-6f4a-7000-8000-000000000077"
    deleted_tenant = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2199"
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
        "tenantId": deleted_tenant,
        "canonicalOrigin": "t-0191e2c48f7a7c3b8d1e5f62047a2199.lowerduckpond.com",
    }
    authorization = completed_host / "var/lib/lowerduckpond/static/authorization"
    path = authorization / "results" / (correlation + ".json")
    path.write_bytes(canonical_json_bytes(result))
    path.chmod(0o600)
    with StateRepository(authorization.parent, expected_owner=os.geteuid()) as repository:
        previous = repository.inspect_audit()
        audit = json.loads((FIXTURES / "audit-entry.json").read_text())
        audit.update(
            sequence=previous.entry_count,
            previousEntryDigest=previous.terminal_digest,
            operatorPrincipal="ldp-admin",
            operation="delete",
            tenantId=deleted_tenant,
            correlationId=correlation,
            resultDigest=result_digest(result).to_dict(),
        )
        audit["deletionEvidence"] = {
            "mode": "emergency",
            "releasedSlugs": ["removed-tenant"],
            "archiveRecordDigest": None,
            "bucket": None,
            "key": None,
            "versionId": None,
            "emergencyReason": "Installed administrator recovery",
        }
        repository.append_audit(audit, administrator=True)
    segment = next((authorization.parent / "audit").iterdir())
    if drift != "none":
        first_entry = segment.read_bytes().splitlines(keepends=True)[0]
        if drift == "digest":
            audit["resultDigest"]["value"] = "f" * 64
        elif drift == "reason":
            audit["deletionEvidence"]["emergencyReason"] = "different reason"
        elif drift == "principal":
            audit["operatorPrincipal"] = "different-admin"
        segment.write_bytes(
            first_entry + (b"" if drift == "missing" else canonical_json_bytes(audit))
        )
    before = segment.read_bytes()
    outcome = gate(completed_host)
    assert (outcome.returncode == 0) is (drift == "none"), outcome.stderr
    assert segment.read_bytes() == before
    assert path.read_bytes() == canonical_json_bytes(result)
    assert not (authorization / "jobs" / (correlation + ".json")).exists()


@pytest.mark.parametrize(
    "path",
    [
        "var/lib/lowerduckpond/static/intents/pending.json",
        "var/lib/lowerduckpond/static/intake/pending.zip",
        "var/lib/lowerduckpond/static/exports/pending.zip",
        "var/lib/lowerduckpond/static/platform/archive-quarantine.json",
        "srv/lowerduckpond/sites/.staging/pending",
        "etc/caddy/intents/start.json",
    ],
)
def test_completed_host_refuses_transient_work_without_cleaning_it(
    completed_host: Path,
    path: str,
) -> None:
    pending = completed_host / path
    pending.write_text("retain for investigation\n")
    assert gate(completed_host).returncode != 0
    assert pending.read_text() == "retain for investigation\n"


@pytest.mark.parametrize(
    "drift",
    [
        "artifact",
        "artifact-verifier",
        "checker-mode",
        "checker-owner-mode",
        "checker-failure",
        "audit",
        "authorization",
        "active-worker",
        "queued-work",
        "query-failure",
        "caddy-inactive",
    ],
)
def test_completed_host_rejects_drift_or_unprovable_quiescence(
    completed_host: Path,
    drift: str,
) -> None:
    libexec = completed_host / "usr/local/libexec/lowerduckpond"
    checker = libexec / "check-caddy-generation"
    if drift == "artifact":
        current = completed_host / "opt/lowerduckpond/static-host-agent/current"
        current.unlink()
        current.symlink_to("d" * 64)
    elif drift == "artifact-verifier":
        executable(libexec / "verify-static-host-agent-artifact", "exit 1")
    elif drift == "checker-mode":
        checker.write_text(checker.read_text().replace("--authoritative-check", "--check"))
    elif drift == "checker-owner-mode":
        checker.chmod(0o777)
    elif drift == "checker-failure":
        checker.write_text(checker.read_text().replace("echo current", "echo pending"))
    elif drift in {"audit", "authorization"}:
        directory = completed_host / "var/lib/lowerduckpond/static" / drift
        record = next(path for path in directory.rglob("*") if path.is_file())
        record.write_text("invalid permanent history\n")
    else:
        executable(
            completed_host / "bin/systemctl",
            {
                "active-worker": "if [[ $1 == list-units ]]; then echo active-worker; fi",
                "queued-work": (
                    "if [[ $1 == list-jobs ]]; then "
                    'echo "1 lowerduckpond-static-reconcile.service start running"; fi'
                ),
                "query-failure": "if [[ $1 == list-jobs ]]; then exit 1; fi",
                "caddy-inactive": "if [[ $1 == is-active ]]; then exit 1; fi",
            }[drift],
        )
    assert gate(completed_host).returncode != 0


@pytest.mark.parametrize(
    "directory",
    ["authorization/jobs", "authorization/results", "authorization/correlations", "audit"],
)
def test_completed_host_does_not_retire_abandoned_publication_files(
    completed_host: Path, directory: str
) -> None:
    temporary = completed_host / "var/lib/lowerduckpond/static" / directory / ".publish-incomplete"
    temporary.write_bytes(b"retain interrupted publication")
    temporary.chmod(0o600)
    assert gate(completed_host).returncode != 0
    assert temporary.read_bytes() == b"retain interrupted publication"


@pytest.mark.parametrize(
    "state",
    [
        "pending",
        "claimed",
        "pending-with-result",
        "claimed-with-result",
        "terminal-without-result",
        "failed-with-success",
        "unchecked-v2",
        "missing-job",
        "missing-correlation",
        "changed-correlation",
        "foreign-result",
    ],
)
def test_completed_host_rejects_jobs_that_startup_would_queue_or_repair(
    completed_host: Path, state: str
) -> None:
    root = completed_host / "var/lib/lowerduckpond/static/authorization"
    job_path = next((root / "jobs").iterdir())
    result_path = next((root / "results").iterdir())
    correlation_path = next((root / "correlations").iterdir())
    job = json.loads(job_path.read_text())
    if state.startswith(("pending", "claimed")):
        job["phase"] = state.split("-", maxsplit=1)[0]
        job_path.write_bytes(canonical_json_bytes(job))
        if not state.endswith("with-result"):
            result_path.unlink()
    elif state == "terminal-without-result":
        result_path.unlink()
    elif state == "failed-with-success":
        job["phase"] = "failed"
        job_path.write_bytes(canonical_json_bytes(job))
    elif state == "unchecked-v2":
        job.update(
            compatibilityVersion="static-job-v2", executionValidated=False, sourceAuthority=None
        )
        job_path.write_bytes(canonical_json_bytes(job))
    elif state == "missing-job":
        job_path.unlink()
    elif state == "missing-correlation":
        correlation_path.unlink()
    elif state == "changed-correlation":
        correlation = json.loads(correlation_path.read_text())
        correlation["operatorPrincipal"] = "different@example.test"
        correlation_path.write_bytes(canonical_json_bytes(correlation))
    else:
        result = json.loads(result_path.read_text())
        result["correlationId"] = "0198d17f-6f4a-7000-8000-000000000099"
        result_path.write_bytes(canonical_json_bytes(result))
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert gate(completed_host).returncode != 0
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == before


def archived_tenant(tree: Path) -> tuple[Path, dict[str, object]]:
    tenant = tree / "var/lib/lowerduckpond/static/tenants" / TENANT
    manifest = json.loads((FIXTURES / "site.json").read_text())
    deployment = json.loads((FIXTURES / "deployment-record.json").read_text())
    record = json.loads((FIXTURES / "archive-record.json").read_text())
    manifest["spec"]["desiredState"] = "archived"
    manifest["spec"]["desiredDeployment"] = {
        "id": deployment["id"],
        "archiveSha256": deployment["archiveSha256"],
    }
    record["manifestDigest"] = manifest_digest(manifest).to_dict()
    record["releaseTreeDigest"] = deployment["releaseTreeDigest"]
    archive_path = tenant / "archives" / (record["deploymentId"] + ".json")
    for path, document in (
        (tenant / "desired.json", manifest),
        (tenant / "deployments" / (deployment["id"] + ".json"), deployment),
        (archive_path, record),
    ):
        path.write_bytes(canonical_json_bytes(document))
        path.chmod(0o600)
    return archive_path, record


def test_completed_host_emits_only_validated_retained_archive_authority(
    completed_host: Path,
) -> None:
    _path, record = archived_tenant(completed_host)
    result = gate(completed_host)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "format": "lowerduckpond-m3-10-archive-authority-v1",
        "sourceRevision": SOURCE,
        "artifactSha256": ARTIFACT,
        "archives": [record],
    }


@pytest.mark.parametrize(
    "drift",
    [
        "manifest-binding",
        "release-binding",
        "missing",
        "extra",
        "interrupted",
        "live-tenant",
    ],
)
def test_completed_host_refuses_unbound_or_incomplete_archive_records(
    completed_host: Path, drift: str
) -> None:
    path, record = archived_tenant(completed_host)
    if drift in {"manifest-binding", "release-binding"}:
        field = "manifestDigest" if drift == "manifest-binding" else "releaseTreeDigest"
        changed = json.loads(path.read_text())
        changed[field]["value"] = "f" * 64
        path.write_bytes(canonical_json_bytes(changed))
    elif drift == "missing":
        path.unlink()
    elif drift == "extra":
        (path.parent / "extra.json").write_bytes(canonical_json_bytes(record))
    elif drift == "interrupted":
        path.rename(path.parent / ".publish-incomplete")
    else:
        desired = path.parent.parent / "desired.json"
        manifest = json.loads(desired.read_text())
        manifest["spec"]["desiredState"] = "active"
        desired.write_bytes(canonical_json_bytes(manifest))
    before = {p: p.read_bytes() for p in path.parent.rglob("*") if p.is_file()}
    assert gate(completed_host).returncode != 0
    assert {p: p.read_bytes() for p in path.parent.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize(
    "drift", ["missing", "digest", "status", "principal", "tenant", "correlation"]
)
def test_completed_host_binds_each_terminal_result_to_its_audit(
    completed_host: Path, drift: str
) -> None:
    directory = completed_host / "var/lib/lowerduckpond/static/audit"
    path = next(directory.iterdir())
    if drift == "missing":
        path.unlink()
    else:
        audit = json.loads(path.read_text())
        if drift == "digest":
            audit["resultDigest"]["value"] = "f" * 64
        elif drift == "status":
            audit["resultStatus"] = "failed"
        elif drift == "principal":
            audit["operatorPrincipal"] = "different@example.test"
        else:
            audit["tenantId" if drift == "tenant" else "correlationId"] = (
                "0198d17f-6f4a-7000-8000-000000000099"
            )
        path.write_bytes(canonical_json_bytes(audit))
    before = {p: p.read_bytes() for p in directory.iterdir()}
    assert gate(completed_host).returncode != 0
    assert {p: p.read_bytes() for p in directory.iterdir()} == before


@pytest.mark.parametrize(
    "version,audited", [("static-job-v1", False), ("static-job-v2", False), ("static-job-v2", True)]
)
def test_completed_host_preserves_only_the_legacy_failed_job_audit_exception(
    completed_host: Path, version: str, audited: bool
) -> None:
    state = completed_host / "var/lib/lowerduckpond/static"
    job_path = next((state / "authorization/jobs").iterdir())
    job = json.loads(job_path.read_text())
    job["phase"] = "failed"
    job["compatibilityVersion"] = version
    if version == "static-job-v2":
        job.update(executionValidated=True, sourceAuthority=None)
    job_path.write_bytes(canonical_json_bytes(job))
    correlation_path = next((state / "authorization/correlations").iterdir())
    correlation_path.write_bytes(canonical_json_bytes(job))
    result = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationResult",
        "provenance": {"kind": "authorization-job", "jobId": job["jobId"]},
        "correlationId": job["request"]["correlationId"],
        "operation": "create",
        "status": "failed",
        "errorCode": "not_implemented",
        "tenantId": None,
    }
    result_path = next((state / "authorization/results").iterdir())
    result_path.write_bytes(canonical_json_bytes(result))
    audit_path = next((state / "audit").iterdir())
    audit = json.loads(audit_path.read_text())
    audit_path.unlink()
    if audited:
        audit.update(
            resultDigest=result_digest(result).to_dict(), resultStatus="failed", tenantId=None
        )
        with StateRepository(state, expected_owner=os.geteuid()) as repository:
            repository.append_audit(audit)
    outcome = gate(completed_host)
    assert (outcome.returncode == 0) is (audited or version == "static-job-v1"), outcome.stderr
