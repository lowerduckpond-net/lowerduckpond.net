from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[3] / "scripts/set-m3-origin-pull-generation"
INVALID_ASSIGNMENT_EXIT = 65
MISSING_FILE_EXIT = 66
PRIVATE_FILE_MODE = 0o600


def _run(path: Path, generation: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["M3_QUALIFICATION_TFVARS_PATH"] = str(path)
    return subprocess.run(  # noqa: S603 - fixed repository script and test-owned path.
        [SCRIPT, generation],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )


def test_selector_changes_only_the_exact_assignment(tmp_path: Path) -> None:
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(
        'unrelated = "secret-placeholder"\n'
        'origin_pull_generation = "primary" # reviewed selection\n',
        encoding="utf-8",
    )
    tfvars.chmod(PRIVATE_FILE_MODE)

    result = _run(tfvars, "replacement")

    assert result.returncode == 0
    assert result.stdout == "M3.0 origin-pull generation selected: replacement\n"
    assert tfvars.read_text(encoding="utf-8") == (
        'unrelated = "secret-placeholder"\n'
        'origin_pull_generation = "replacement" # reviewed selection\n'
    )
    assert tfvars.stat().st_mode & 0o777 == PRIVATE_FILE_MODE


@pytest.mark.parametrize(
    "content",
    (
        'unrelated = "primary"\n',
        'origin_pull_generation = "invalid"\n',
        'origin_pull_generation = "primary"\norigin_pull_generation = "replacement"\n',
    ),
)
def test_selector_refuses_a_missing_or_ambiguous_assignment(tmp_path: Path, content: str) -> None:
    tfvars = tmp_path / "terraform.tfvars"
    tfvars.write_text(content, encoding="utf-8")

    result = _run(tfvars, "replacement")

    assert result.returncode == INVALID_ASSIGNMENT_EXIT
    assert tfvars.read_text(encoding="utf-8") == content


def test_selector_refuses_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.tfvars"
    target.write_text('origin_pull_generation = "primary"\n', encoding="utf-8")
    link = tmp_path / "terraform.tfvars"
    link.symlink_to(target)

    result = _run(link, "replacement")

    assert result.returncode == MISSING_FILE_EXIT
    assert target.read_text(encoding="utf-8") == 'origin_pull_generation = "primary"\n'
