from pathlib import Path

WORKFLOW_PATH = Path(".github/workflows/infrastructure.yml")
ARCHIVE_PREFLIGHT_INVOCATION_COUNT = 2
HOST_STATE_REFERENCE_COUNT = 8


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
