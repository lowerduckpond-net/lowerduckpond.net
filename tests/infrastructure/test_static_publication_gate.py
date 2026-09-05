from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

GATE = (
    Path(__file__).parents[2]
    / "config/ansible/roles/static_host_agent/files/static-publication-gate"
)
JOB_ID = "0198d17f-6f4a-7000-8000-000000000001"


def _load_gate() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("static_publication_gate", str(GATE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "arguments",
    [
        ["job-issuance"],
        ["caddy-generation", "1"],
        ["worker", JOB_ID],
    ],
)
def test_enabled_gate_accepts_only_fixed_publication_commands(
    arguments: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _load_gate()
    monkeypatch.setattr(gate, "publication_enabled", lambda: True)
    monkeypatch.setattr(sys, "argv", [str(GATE), *arguments])

    gate.main()


def test_disabled_gate_retains_empty_generation_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = _load_gate()
    monkeypatch.setattr(gate, "publication_enabled", lambda: False)
    monkeypatch.setattr(sys, "argv", [str(GATE), "caddy-generation", "0"])

    gate.main()


@pytest.mark.parametrize(
    "enabled,arguments,status,message",
    [
        (False, ["job-issuance"], 78, "publication_disabled"),
        (False, ["worker", JOB_ID], 78, "publication_disabled"),
        (
            True,
            ["worker", "not-a-job"],
            64,
            "invalid static publication gate invocation",
        ),
        (
            True,
            ["caddy-generation", "0x1"],
            64,
            "invalid static publication gate invocation",
        ),
    ],
)
def test_gate_rejects_disabled_or_malformed_commands(  # noqa: PLR0913,PLR0917
    enabled: bool,
    arguments: list[str],
    status: int,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gate = _load_gate()
    monkeypatch.setattr(gate, "publication_enabled", lambda: enabled)
    monkeypatch.setattr(sys, "argv", [str(GATE), *arguments])

    with pytest.raises(SystemExit, match=str(status)):
        gate.main()

    assert capsys.readouterr().err.strip() == message
