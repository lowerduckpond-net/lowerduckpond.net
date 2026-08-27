from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[3] / "scripts/m3-qualification"
SOURCE_REVISION = "0" * 40


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)


def test_host_action_fails_when_a_successful_report_cannot_be_retrieved(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "git",
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" status --porcelain --untracked-files=normal "* ]]; then
  exit 0
fi
if [[ " $* " == *" rev-parse HEAD "* ]]; then
  echo {SOURCE_REVISION}
  exit 0
fi
exit 1
""",
    )
    _write_executable(
        fake_bin / "tofu",
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"droplet_id":"123","droplet_urn":"do:droplet:123","ipv4_address":"192.0.2.1"}'
""",
    )
    _write_executable(
        fake_bin / "uv",
        f"""#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" session-value "* ]]; then
  case "${{!#}}" in
    run_id) echo 0198d17f-6f4a-7000-8000-000000000001 ;;
    source_revision) echo {SOURCE_REVISION} ;;
    droplet_id) echo 123 ;;
    droplet_urn) echo do:droplet:123 ;;
    ipv4_address) echo 192.0.2.1 ;;
    *) exit 1 ;;
  esac
  exit 0
fi
cat >/dev/null
""",
    )
    _write_executable(
        fake_bin / "ssh",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" sudo cat -- /run/lowerduckpond-m3-qualification/host-report.json "* ]]; then
  exit 1
fi
if [[ " $* " == *" sudo cat -- /var/lib/lowerduckpond-m3/converged-session "* ]]; then
  echo convergence-marker
fi
""",
    )
    evidence = tmp_path / "evidence"
    environment = dict(os.environ)
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["M3_QUALIFICATION_EVIDENCE_DIR"] = str(evidence)

    result = subprocess.run(  # noqa: S603 - fixed repository script with test-owned PATH.
        (SCRIPT, "host", "replacement"),
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 1
    assert "host probe did not produce a sanitized report" in result.stderr
    assert not (evidence / "host.json").exists()
    assert not tuple(evidence.glob(".host.json.*"))
