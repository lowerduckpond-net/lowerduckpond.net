import os
import subprocess
from pathlib import Path

import pytest

WORKFLOW_PATH = Path(".github/workflows/infrastructure.yml")
ARCHIVE_QUALIFICATION_PATH = Path("scripts/m3-archive-qualification")
ARCHIVE_PREFLIGHT_INVOCATION_COUNT = 2
HOST_STATE_REFERENCE_COUNT = 8
READ_ONLY_LOCKFILE_WORKFLOW_COUNT = 3


def test_apply_installs_and_directly_invokes_the_locked_archive_preflight() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "uv sync --frozen --no-dev --package lowerduckpond-m3-archive" in workflow
    assert (
        workflow.count(".venv/bin/ldp-m3-archive preflight") == ARCHIVE_PREFLIGHT_INVOCATION_COUNT
    )
    assert "uv run --frozen ldp-m3-archive" not in workflow


def test_ordinary_plan_retains_the_deployed_public_edge_phase() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "inputs.public_edge_phase == 'none' && 'direct'" not in workflow
    assert "tofu output -raw edge_rollout_phase" in workflow
    assert "Cannot infer the deployed edge phase from legacy state." in workflow
    assert 'echo "TF_VAR_edge_rollout_phase=${phase}" >> "${GITHUB_ENV}"' in workflow
    assert "resolved_public_edge_phase" in workflow


def test_edge_transitions_require_the_exact_reviewed_host_state() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "origin_pull_host_state:" in workflow
    assert "enforced) expected_host_state=required" in workflow
    assert "direct) expected_host_state=staged" in workflow
    assert "*) expected_host_state=unconfirmed" in workflow
    assert workflow.count("origin_pull_host_state") >= HOST_STATE_REFERENCE_COUNT


def test_operational_initialization_keeps_provider_locks_read_only() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    archive_qualification = ARCHIVE_QUALIFICATION_PATH.read_text(encoding="utf-8")

    assert workflow.count("-lockfile=readonly") == READ_ONLY_LOCKFILE_WORKFLOW_COUNT
    assert "-lockfile=readonly" in archive_qualification


@pytest.mark.parametrize(
    "wrapper", [ARCHIVE_QUALIFICATION_PATH, Path("scripts/configure-production")]
)
def test_operational_wrapper_disables_tracing_before_reading_initial_secret_inputs(
    wrapper: Path,
) -> None:
    canary = "qualification-trace-fixture"
    environment = {
        "PATH": os.environ["PATH"],
        "M3_ARCHIVE_QUALIFICATION_EVIDENCE_ROOT": "/unused-qualification-evidence",
    }
    for name in (
        "ADMIN_SOURCE_CIDRS_JSON",
        "ANSIBLE_PRIVATE_KEY_FILE",
        "CADDY_CLOUDFLARE_API_TOKEN",
        "CADDY_ORIGIN_PULL_CA_PATHS_JSON",
        "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED",
        "OPENTOFU_ENCRYPTION_PASSPHRASE",
        "OPENTOFU_STATE_ACCESS_KEY_ID",
        "OPENTOFU_STATE_SECRET_ACCESS_KEY",
        "OPENTOFU_STATE_BUCKET",
        "RESTIC_PASSWORD",
    ):
        environment[name] = canary
    # Deliberately omit SPACES_REGION: stop at the input guard before tool or
    # provider access, even when tracing was requested by the calling shell.
    outcome = subprocess.run(  # noqa: S603 - fixed wrapper with non-secret fixture input
        ["/usr/bin/bash", "-x", str(wrapper.resolve())],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert outcome.returncode == 2  # noqa: PLR2004 - documented input-guard exit status
    assert "Required environment variable SPACES_REGION is not set." in outcome.stderr
    assert canary not in outcome.stdout + outcome.stderr
