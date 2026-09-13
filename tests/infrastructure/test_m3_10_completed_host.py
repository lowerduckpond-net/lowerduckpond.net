from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import LockManager, StateRepository

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/static-publication/fixtures/accepted"
ARTIFACT = "c" * 64
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
    ):
        directory = state / name
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
    LockManager.initialize(state / "locks", expected_owner=os.geteuid()).close()
    # Real canonical authorization history and a real hash-chained audit segment
    # must remain byte-identical through this read-only host gate.
    job = json.loads((FIXTURES / "authorization-job.json").read_text())
    record = state / "authorization/jobs" / (job["jobId"] + ".json")
    record.write_bytes(canonical_json_bytes(job))
    record.chmod(0o600)
    with StateRepository(state, expected_owner=os.geteuid()) as repository:
        repository.append_audit(json.loads((FIXTURES / "audit-entry.json").read_text()))
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
        ["/bin/bash", str(tree / "probe"), ARTIFACT, "completed-host"],
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
    assert {path: path.read_bytes() for path in state.rglob("*") if path.is_file()} == before
    assert (state / "tenants" / TENANT).is_dir()


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
