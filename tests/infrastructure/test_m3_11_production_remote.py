"""The root dispatcher refuses unleased backup access and masks private failures."""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

from scripts import m3_11_production_backup as backup
from scripts import m3_11_production_lease as lease
from scripts import m3_11_production_remote as remote


@pytest.mark.parametrize("fault", ["uid", "cgroup", "lease", "input", "candidate", "none"])
def test_backup_requires_tracked_live_action_and_never_exposes_private_errors(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(os, "geteuid", lambda: 1 if fault == "uid" else 0)
    monkeypatch.setattr(sys, "argv", ["helper.pyz", "backup", "a" * 64])
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda *args, **kwargs: (
            "0::/other\n" if fault == "cgroup" else f"0::/system.slice/{remote.UNIT}\n"
        ),
    )
    output, errors = io.BytesIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(output))
    monkeypatch.setattr(sys, "stderr", errors)
    monkeypatch.setattr(
        sys, "stdin", io.TextIOWrapper(io.BytesIO(b"extra" if fault == "input" else b""))
    )

    def require(path: Path, *, owner: int, token: str) -> None:
        assert path == remote.LEASE and owner == 0 and token == "a" * 64
        if fault == "lease":
            raise ValueError("missing original action lease")
        calls.append("lease")

    def candidate() -> bytes:
        calls.append("candidate")
        if fault == "candidate":
            raise RuntimeError("fake-private-provider-response-must-not-escape")
        return b'{"original":"proof"}\n'

    monkeypatch.setattr(lease, "require_action", require)
    monkeypatch.setattr(backup, "verify", candidate)
    assert remote.main() == (0 if fault == "none" else 1)
    assert output.getvalue() == (b'{"original":"proof"}\n' if fault == "none" else b"")
    assert errors.getvalue() == ("" if fault == "none" else "production_action_failed\n")
    assert ("candidate" in calls) == (fault in {"candidate", "none"})
