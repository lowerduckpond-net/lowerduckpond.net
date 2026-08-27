from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[3] / "scripts/m3-qualification"
EXPECTED_FRAGMENT_ORDER = (
    "libraries",
    "edge-primary",
    "edge-replacement",
    "edge-rollback",
    "edge-forward",
    "edge-retired-primary",
    "edge-final",
    "host",
    "domains",
    "browser",
    "assembled",
)


def test_status_passes_fragments_in_executable_workflow_order(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "session.json").write_text("placeholder\n", encoding="utf-8")
    capture = tmp_path / "arguments"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$M3_TEST_ARGUMENT_CAPTURE"
""",
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["M3_QUALIFICATION_EVIDENCE_DIR"] = str(evidence)
    environment["M3_TEST_ARGUMENT_CAPTURE"] = str(capture)

    result = subprocess.run(  # noqa: S603 - fixed repository script with test-owned PATH.
        (SCRIPT, "status"),
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 0
    arguments = capture.read_text(encoding="utf-8").splitlines()
    fragments = tuple(
        arguments[index + 1] for index, argument in enumerate(arguments) if argument == "--fragment"
    )
    assert tuple(fragment.partition("=")[0] for fragment in fragments) == EXPECTED_FRAGMENT_ORDER
