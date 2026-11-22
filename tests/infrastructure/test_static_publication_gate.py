from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

GATE = (
    Path(__file__).parents[2]
    / "config/ansible/roles/static_host_agent/files/static-publication-gate"
)
JOB_ID = "0198d17f-6f4a-7000-8000-000000000001"


def _load_gate(*, ordinary: bool = True) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("static_publication_gate", str(GATE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    if ordinary:
        module.require_restore_admission = lambda: None
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


def test_recovery_gate_precedes_even_the_empty_generation_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    gate = _load_gate(ordinary=False)

    def closed(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert command == ["/usr/local/libexec/lowerduckpond/host-restore-gate", "--ordinary"]
        return subprocess.CompletedProcess(command, 78)

    def must_not_read_configuration() -> bool:
        pytest.fail("unfinished recovery reached ordinary publication configuration")

    monkeypatch.setattr(gate.subprocess, "run", closed)
    monkeypatch.setattr(gate, "publication_enabled", must_not_read_configuration)
    monkeypatch.setattr(sys, "argv", [str(GATE), "caddy-generation", "0"])
    with pytest.raises(SystemExit, match="78"):
        gate.main()
    assert capsys.readouterr().err.strip() == "host_restore_pending"


def test_successor_launch_check_does_not_write_into_the_selected_artifact(tmp_path: Path) -> None:
    installation = tmp_path / "site-packages"
    package = installation / "lowerduckpond_static_host_agent"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "droplet_enrollment.py").write_text('PUBLICATION_VIEW = "droplet-publication"\n')
    (package / "platform_launch.py").write_text(
        "def verify_launch(state, authority):\n"
        "    return 'verified-launch'\n"
        "def require_local_launch_binding(authority, receipt, *, disposable):\n"
        "    assert receipt == 'verified-launch'\n"
    )
    (package / "successor_rollback.py").write_text(
        "def require_unfenced_publication(authority):\n    assert authority.is_dir()\n"
    )

    subprocess.run(  # noqa: S603 - real gate in a fresh isolated interpreter and owned test paths
        [
            sys.executable,
            "-I",
            "-c",
            "from pathlib import Path; from runpy import run_path; import sys; "
            "gate = run_path(sys.argv[1])['main']; fixture = Path(sys.argv[2]); "
            "gate.__globals__.update(INSTALLATION=fixture / 'site-packages', "
            "STATE=fixture, SUCCESSOR=fixture, publication_enabled=lambda: True, "
            "require_restore_admission=lambda: None); "
            "sys.argv = [sys.argv[1], 'job-issuance']; gate()",
            str(GATE),
            str(tmp_path),
        ],
        check=True,
    )

    assert not list(installation.rglob("__pycache__"))
