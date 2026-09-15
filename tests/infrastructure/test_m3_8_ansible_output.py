from __future__ import annotations

import os
import subprocess
import sys

import pytest

from config.ansible.molecule.m3_8.tests.ansible_output import (
    assert_reapply_result,
    plain_environment,
    plain_output,
)

CONTAINER = "lowerduckpond-ubuntu-2604"
RECAP = f"{CONTAINER} : ok=241 changed=1 unreachable=0 failed=0 skipped=77 rescued=0 ignored=0\n"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
@pytest.mark.parametrize("bordered", [False, True])
def test_reapply_accepts_the_host_recap_on_either_stream(stream: str, bordered: bool) -> None:
    output = RECAP
    if bordered:
        output = "  \x1b[2m│\x1b[0m \x1b[33m" + output.rstrip() + "\x1b[0m\n"
    result = subprocess.CompletedProcess(
        ["molecule", "converge"],
        0,
        stdout=output if stream == "stdout" else "",
        stderr=output if stream == "stderr" else "",
    )
    assert_reapply_result(result, container=CONTAINER, expected_changes=1)


@pytest.mark.parametrize(
    ("returncode", "output", "expected_changes"),
    [
        (1, RECAP, 1),
        (0, "", 1),
        (0, "m3_8 : actions=4 successful=1 failed=0\n", 1),
        (0, RECAP.replace(CONTAINER, "other-host"), 1),
        (0, RECAP, 0),
        (0, RECAP.replace("changed=1", "changed=10"), 1),
        (0, RECAP + RECAP.replace("changed=1", "changed=0"), 1),
        (0, RECAP + RECAP, 1),
        (0, RECAP.replace("ok=241 changed=", "ok=241\nchanged="), 1),
    ],
)
def test_reapply_rejects_failure_or_missing_ambiguous_or_wrong_recap(
    returncode: int, output: str, expected_changes: int
) -> None:
    result = subprocess.CompletedProcess(["molecule", "converge"], returncode, "", output)
    with pytest.raises(AssertionError):
        assert_reapply_result(result, container=CONTAINER, expected_changes=expected_changes)


@pytest.mark.parametrize("changes", [0, 1, 2])
def test_reapply_requires_each_exact_expected_change_count(changes: int) -> None:
    result = subprocess.CompletedProcess(
        ["molecule", "converge"], 0, RECAP.replace("changed=1", f"changed={changes}"), ""
    )
    assert_reapply_result(result, container=CONTAINER, expected_changes=changes)


@pytest.mark.parametrize(
    "message",
    [
        "refusing to alter staged inputs without a tenant-capable generation migration",
        "refusing to mutate an admitted request path",
        "refusing to disable static publication",
    ],
)
def test_expected_refusal_diagnostics_are_visible_on_stderr(message: str) -> None:
    result = subprocess.CompletedProcess(
        ["molecule", "converge"], 2, "controller output", f"\x1b[31m{message}\x1b[0m\n"
    )
    assert message in plain_output(result)
    assert plain_output(result).startswith("controller output\n")
    assert result.returncode == 2  # noqa: PLR2004 - preserve Ansible's failure status


def test_plain_child_environment_overrides_parent_colors_without_mutating_it() -> None:
    parent = {"TERM": "xterm-256color", "PY_COLORS": "1", "ANSIBLE_FORCE_COLOR": "1"}
    child = plain_environment(parent)
    assert child["TERM"] == "xterm-256color"
    assert child["NO_COLOR"] == "1"
    assert child["PY_COLORS"] == child["ANSIBLE_FORCE_COLOR"] == "0"
    assert child["ANSIBLE_NOCOLOR"] == "1"
    assert parent == {"TERM": "xterm-256color", "PY_COLORS": "1", "ANSIBLE_FORCE_COLOR": "1"}


def test_real_molecule_capture_keeps_recap_intact_with_a_colored_narrow_parent() -> None:
    # Exercise the pinned renderer without running Ansible or touching a host.
    command = f"""from pathlib import Path
import sys
from molecule.app import App
result = App(Path.cwd()).run_command(
    [sys.executable, '-c', {f"print({RECAP!r})"!r}], command_borders=True)
raise SystemExit(result.returncode)
"""
    environment = plain_environment(
        {
            **os.environ,
            "TERM": "xterm-256color",
            "PY_COLORS": "1",
            "ANSIBLE_FORCE_COLOR": "1",
            "COLUMNS": "40",
        }
    )
    result = subprocess.run(  # noqa: S603 - pinned local renderer, synthetic recap only
        [sys.executable, "-c", command],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert_reapply_result(result, container=CONTAINER, expected_changes=1)
    assert "\x1b" not in result.stdout + result.stderr
    assert "│" not in result.stdout + result.stderr
