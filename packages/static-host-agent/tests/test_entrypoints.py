from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import entrypoints

_DISABLED_STATUS = 78


def test_disabled_operator_checks_the_gate_before_opening_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    gate = tmp_path / "publication-gate"
    gate.write_text(
        "#!/bin/sh\nprintf 'publication_disabled\\n' >&2\nexit 78\n",
        encoding="utf-8",
    )
    gate.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PUBLICATION_GATE", gate)
    monkeypatch.setattr(entrypoints, "_STATE_ROOT", tmp_path / "absent-state")

    status = entrypoints.operator_main(["--principal", "operator@example.test"])

    assert status == _DISABLED_STATUS
    assert capfd.readouterr().err == "publication_disabled\n"
