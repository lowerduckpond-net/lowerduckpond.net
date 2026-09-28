"""Diagnostic mutation stays bound to the original local fixture and archive target."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_debug_fixture as debug
from scripts import qualification_restore as owned
from scripts.m3_11_combined_inputs import allocate
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.qualification_context import HOST_ENV, RESOURCE_ENV, RUN_ENV


@pytest.mark.parametrize(
    "fault", ["none", "destination", "source", "acme", "stopped", "archive", "source-gate"]
)
def test_changed_identity_target_or_source_fence_refuses_continuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    for name in (
        *RESOURCE_ENV,
        "DOCKER_CONTEXT",
        "MOLECULE_EPHEMERAL_DIRECTORY",
        "M3_10_INSTALLED_REPORT",
    ):
        monkeypatch.delenv(name, raising=False)
    environment = allocate(tmp_path, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
    monkeypatch.setenv("SPACES_REGION", "ams3")
    monkeypatch.setenv("SPACES_ARCHIVE_BUCKET", "changed" if fault == "archive" else "original")
    write_private(tmp_path / "diagnostic-origin.json", {"qualification_authority": "none"})
    monkeypatch.setattr(debug, "require_original_unchanged", Mock())
    (tmp_path / "restore").mkdir(mode=0o700)
    actual: dict[str, dict[str, object]] = {}
    context: dict[str, object] = {}
    for kind in ("source", "destination", "acme"):
        value: dict[str, object] = {
            "id": kind,
            "name": environment[HOST_ENV] + kind,
            "image": "original-image",
            "owner": environment[RUN_ENV],
        }
        context[kind + "_fixture_sha256"] = hashlib.sha256(canonical_bytes(value)).hexdigest()
        write_private(tmp_path / "restore" / (kind + ".json"), value)
        actual[kind] = {**value, "running": fault != "stopped"}
        if kind == fault:
            actual[kind]["image"] = "replacement-image"
    write_private(tmp_path / "combined-context.json", context)
    monkeypatch.setattr(owned, "inspect", lambda env, identity: actual[identity])
    fence = Mock(side_effect=ValueError("source changed") if fault == "source-gate" else None)
    monkeypatch.setattr(owned, "source_fenced", fence)
    storage = Mock(target=Mock(region="ams3", archive_bucket="original"))
    monkeypatch.setattr(LiveStorage, "load", Mock(return_value=storage))
    if fault == "none":
        saved, bound = debug.inputs(tmp_path)
        assert saved["DOCKER_HOST"] == environment["DOCKER_HOST"]
        assert bound is storage
        fence.assert_called_once_with(saved)
    else:
        with pytest.raises(ValueError):
            debug.inputs(tmp_path)
        if fault != "source-gate":
            fence.assert_not_called()
