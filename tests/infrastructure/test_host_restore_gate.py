from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.host_restore_gate import restore_admission
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

GATE = Path(__file__).parents[2] / "config/ansible/roles/host_recovery/files/host-restore-gate"


def _load() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("installed_restore_gate", str(GATE))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("gate", ["installed", "package"])
@pytest.mark.parametrize(
    "damage", [None, "name", "mode", "symlink", "hardlink", "directory", "overflow", "orphan"]
)
def test_uninitialized_gate_accepts_only_bounded_private_unpublished_files(
    gate: str, damage: str | None, tmp_path: Path
) -> None:
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    temporary = root / (".ldp-state-" + "a" * 32)
    temporary.write_bytes(b"unpublished bytes")
    temporary.chmod(0o600)
    lock = root / "host-restore.lock"
    lock.touch(mode=0o600)
    if damage == "name":
        temporary.rename(root / ".ldp-state-invalid")
    elif damage == "mode":
        temporary.chmod(0o644)
    elif damage == "symlink":
        temporary.unlink()
        temporary.symlink_to(lock)
    elif damage == "hardlink":
        (tmp_path / "alias").hardlink_to(temporary)
    elif damage == "directory":
        temporary.unlink()
        temporary.mkdir(mode=0o600)
    elif damage == "overflow":
        for number in range(64):
            (root / f".ldp-state-{number:032x}").touch(mode=0o600)
    elif damage == "orphan":
        (root / "completed.json").write_text("{}")

    def admitted() -> bool:
        if gate == "package":
            return restore_admission(root, owner=os.geteuid())
        _load().require_uninitialized_directory(root, owner=os.geteuid())
        return True

    if damage is None:
        assert admitted()
        assert temporary.read_bytes() == b"unpublished bytes"
    else:
        with pytest.raises((ValueError, StatePathError, HostRestoreError)):
            admitted()


@pytest.mark.parametrize("argument", ["--ordinary", "--boot", "--caddy"])
def test_absent_recovery_marker_needs_no_artifact_or_external_command(
    argument: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load()
    monkeypatch.setattr(module, "ROOT", tmp_path / "absent")
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [str(GATE), argument])
    monkeypatch.setattr(
        module, "close_firewall", lambda: pytest.fail("ordinary boot closed ingress")
    )
    monkeypatch.setattr(
        module, "acquire_selection", lambda: pytest.fail("ordinary boot imported an artifact")
    )
    assert module.main() == 0


@pytest.mark.parametrize("argument", ["--ordinary", "--boot", "--caddy"])
def test_unsafe_root_fails_closed_and_boot_installs_firewall_before_failure(
    argument: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load()
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    monkeypatch.setattr(module, "ROOT", unsafe)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [str(GATE), argument])
    calls: list[str] = []
    monkeypatch.setattr(module, "close_firewall", lambda: calls.append("closed"))
    assert module.main() == 78  # noqa: PLR2004
    assert calls == (["closed"] if argument == "--boot" else [])


def test_admission_dropins_bind_private_restore_provenance_into_isolated_workers() -> None:
    template = (GATE.parents[1] / "templates/restore-admission.conf.j2").read_text()
    assert "BindReadOnlyPaths=/var/lib/lowerduckpond/recovery" in template
    assert "ExecStartPre=!/usr/local/libexec/lowerduckpond/host-restore-gate" in template
    assert "ConditionPathExists=!/var/lib/lowerduckpond/recovery/restore-gate.json" in template
    firewall = (GATE.parent / "restore-firewall.conf").read_text()
    assert "ExecStop=\n" in firewall
    ordinary = (GATE.parents[2] / "firewall/templates/lowerduckpond.nft.j2").read_text()
    assert "flush ruleset" not in ordinary
    assert "destroy table inet lowerduckpond" in ordinary


@pytest.mark.parametrize("argument", ["--ordinary", "--boot", "--caddy"])
def test_orphaned_restore_provenance_closes_ingress_without_importing_artifact(
    argument: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load()
    root = tmp_path / "recovery"
    root.mkdir(mode=0o700)
    (root / "runtime-mapping.json").write_text("{}")
    original = Path.lstat

    def metadata(path: Path) -> os.stat_result:
        value = original(path)
        if path == root:
            fields = list(value)
            fields[4] = fields[5] = 0
            return os.stat_result(fields)
        return value

    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(module, "ROOT", root)
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [str(GATE), argument])
    calls: list[str] = []
    monkeypatch.setattr(module, "close_firewall", lambda: calls.append("closed"))
    monkeypatch.setattr(
        module,
        "acquire_selection",
        lambda: pytest.fail("missing restore journal imported an artifact"),
    )
    assert module.main() == 78  # noqa: PLR2004
    assert calls == (["closed"] if argument == "--boot" else [])
