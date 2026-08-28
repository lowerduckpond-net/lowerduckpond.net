from pathlib import Path

WORKFLOW_PATH = Path(".github/workflows/infrastructure.yml")
ARCHIVE_PREFLIGHT_INVOCATION_COUNT = 2


def test_apply_installs_and_directly_invokes_the_locked_archive_preflight() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "uv sync --frozen --no-dev --package lowerduckpond-m3-archive" in workflow
    assert (
        workflow.count(".venv/bin/ldp-m3-archive preflight") == ARCHIVE_PREFLIGHT_INVOCATION_COUNT
    )
    assert "uv run --frozen ldp-m3-archive" not in workflow
