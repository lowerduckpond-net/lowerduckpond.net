from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[3] / "scripts/m3-qualification"


def test_live_browser_action_requires_the_pinned_endpoint(tmp_path: Path) -> None:
    environment = dict(os.environ)
    environment.pop("M3_QUALIFICATION_PLAYWRIGHT_WS_ENDPOINT", None)
    environment["M3_QUALIFICATION_EVIDENCE_DIR"] = str(tmp_path / "evidence")

    result = subprocess.run(  # noqa: S603 - fixed repository script.
        (SCRIPT, "browser"),
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode != 0
    assert "live browser qualification requires the pinned Playwright endpoint" in result.stderr
    assert not (tmp_path / "evidence/browser.json").exists()
