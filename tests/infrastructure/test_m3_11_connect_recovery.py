"""Rollback projects all cleanup generations without reviving old issuance."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import connect_recovery as recovery
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_lease_configuration import document


def test_cleanup_only_rollback_preserves_exact_policy_generations_and_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = document()
    source, destination = tmp_path / "controller.json", tmp_path / "cleanup.json"
    write_private(source, original)
    before = source.read_bytes()
    monkeypatch.setattr(
        sys, "argv", ["recovery", "--configuration", str(source), "--output", str(destination)]
    )
    assert recovery.main() == 0
    result = LeaseConfiguration.load(destination)
    assert read_private(destination) == LeaseConfiguration.parse(original).document(
        cleanup_only=True
    )
    with pytest.raises(LifecycleError, match="cleanup-only"):
        result.require_issuance(now=datetime.now(UTC))
    assert source.read_bytes() == before
    with pytest.raises(SystemExit):
        recovery.main()
    assert source.read_bytes() == before
