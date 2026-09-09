from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[2]
SELECTOR = (REPOSITORY_ROOT / "scripts/m3-8-ci-required").resolve()
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/ci.yml"
GIT = shutil.which("git")
assert GIT is not None
SELECTED_STEP_COUNT = 2


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(  # noqa: S603 -- fixed test-only Git invocation.
        [GIT, "-C", os.fspath(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit_file(repository: Path, relative_path: str, content: str) -> str:
    path = repository / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    git(repository, "add", relative_path)
    git(repository, "commit", "--quiet", "--message", f"change {relative_path}")
    return git(repository, "rev-parse", "HEAD")


def select(repository: Path, base: str, head: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- reviewed repository helper.
        [os.fspath(SELECTOR), base, head],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    git(tmp_path, "init", "--quiet")
    git(tmp_path, "config", "user.email", "ci-selection@example.test")
    git(tmp_path, "config", "user.name", "CI selection test")
    base = commit_file(tmp_path, "README.md", "baseline\n")
    return tmp_path, base


@pytest.mark.parametrize(
    "relative_path",
    [
        ".github/workflows/ci.yml",
        ".python-version",
        "config/ansible/roles/caddy/tasks/main.yml",
        "justfile",
        "mise.lock",
        "mise.toml",
        "packages/static-host-agent/src/example.py",
        "platform/versions.yml",
        "pyproject.toml",
        "schemas/static-publication/v1alpha1/example.json",
        "scripts/build-static-host-agent",
        "scripts/m3-8-ci-required",
        "tools/static-operator/src/example.py",
        "uv.lock",
    ],
)
def test_selector_requires_installed_host_changes(
    repository: tuple[Path, str], relative_path: str
) -> None:
    path, base = repository
    head = commit_file(path, relative_path, "changed\n")

    result = select(path, base, head)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "true\n"


@pytest.mark.parametrize(
    "relative_path",
    [
        "docs/operations/example.md",
        "infra/opentofu/example.tf",
        "scripts/preflight-m3-dark-host-production",
        "tests/infrastructure/test_example.py",
    ],
)
def test_selector_skips_unrelated_changes(repository: tuple[Path, str], relative_path: str) -> None:
    path, base = repository
    head = commit_file(path, relative_path, "changed\n")

    result = select(path, base, head)

    assert result.returncode == 0, result.stderr
    assert result.stdout == "false\n"


def test_selector_runs_when_a_revision_is_unavailable(repository: tuple[Path, str]) -> None:
    path, head = repository

    result = select(path, "0" * 40, head)

    assert result.returncode == 0
    assert result.stdout == "true\n"
    assert "could not resolve" in result.stderr


def test_ci_keeps_the_required_check_while_selecting_expensive_steps() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "fetch-depth: 0" in workflow
    assert "required=$(scripts/m3-8-ci-required" in workflow
    assert workflow.count("if: steps.selection.outputs.required == 'true'") == SELECTED_STEP_COUNT
    assert "if: steps.selection.outputs.required != 'true'" in workflow
    assert "needs: [ansible-static, ansible-m3-8]" in workflow
    assert 'test "$M3_8_RESULT" = success' in workflow
    assert 'cron: "23 4 * * 1"' in workflow
