"""Read Molecule's captured Ansible output independently of terminal rendering."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Mapping


def plain_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Keep nested Ansible diagnostics unwrapped even in a colored parent shell."""
    return {
        **environment,
        "NO_COLOR": "1",
        "PY_COLORS": "0",
        "ANSIBLE_FORCE_COLOR": "0",
        "ANSIBLE_NOCOLOR": "1",
    }


def plain_output(result: subprocess.CompletedProcess[str]) -> str:
    # Molecule can send its entire bordered command output to stderr. Preserve
    # a line boundary between streams so their last/first lines cannot combine.
    output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.stdout + "\n" + result.stderr)
    return re.sub(r"(?m)^[ \t]*│ ?", "", output)


def assert_reapply_result(
    result: subprocess.CompletedProcess[str],
    *,
    container: str,
    expected_changes: int = 0,
) -> None:
    output = plain_output(result)
    assert result.returncode == 0, output
    recap = re.compile(
        rf"^{re.escape(container)}[ \t]+:[ \t]+ok=\d+[ \t]+changed=(\d+)[ \t]+",
        re.MULTILINE,
    )
    assert recap.findall(output) == [str(expected_changes)], output
