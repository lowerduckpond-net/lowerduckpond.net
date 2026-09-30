"""Retained execution uses real fixture helpers without manufacturing passing receipts."""

from __future__ import annotations

import hashlib
import importlib
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore

from scripts import m3_11_debug_public as public
from scripts import m3_11_debug_stages as stages
from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_private_inputs import write_private


def test_restore_reattaches_instead_of_rebuilding_and_clears_only_controlled_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Mock()
    fixture.status.return_value = {"phase": "installed"}
    fixture.destination.run.return_value.rc = 0
    scenarios = Mock()
    monkeypatch.setattr(stages, "require_inherited", Mock())
    monkeypatch.setattr(stages, "attach", Mock(return_value=fixture))
    monkeypatch.setattr(stages, "history", Mock(return_value={}))
    monkeypatch.setattr(importlib, "import_module", Mock(return_value=scenarios))
    assert stages.run(tmp_path, tmp_path, "restore") == {"restore": "complete"}
    scenarios.gate_closed.assert_called_once_with(fixture)
    fixture.destination.run.assert_called_once_with(
        "systemctl stop lowerduckpond-host-restore.service"
    )
    fixture.fault.assert_called_once_with("none")
    fixture.start.assert_called_once_with()
    fixture.wait.assert_called_once_with({"complete"})
    assert not list(tmp_path.glob("*.json"))


def test_recorded_repair_runs_in_original_destination_and_refuses_changed_script(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = Mock(destination_id="original-destination")
    fixture.command.return_value = b"diagnostic output\n"
    script = b"print('branch repair')\n"
    path = tmp_path / "repair.py"
    path.write_bytes(script)
    path.chmod(0o600)
    write_private(
        tmp_path / "controller.json", {"repair_sha256": hashlib.sha256(script).hexdigest()}
    )
    monkeypatch.setattr(stages, "require_inherited", Mock())
    monkeypatch.setattr(stages, "attach", Mock(return_value=fixture))
    module = Mock(_selected_python=lambda host, body: body)
    monkeypatch.setattr(importlib, "import_module", Mock(return_value=module))
    assert stages.run(tmp_path, tmp_path, "repair")["qualification_authority"] == "none"
    arguments = fixture.command.call_args.args
    assert arguments[:3] == ("docker", "exec", "original-destination")
    assert "270s" in arguments
    path.write_bytes(b"print('changed')\n")
    fixture.command.reset_mock()
    with pytest.raises(ValueError, match="captured branch script"):
        stages.run(tmp_path, tmp_path, "repair")
    fixture.command.assert_not_called()


@pytest.mark.parametrize("warm", [False, True])
@pytest.mark.parametrize("retire_stale_dns", [False, True])
def test_public_continuation_reaches_accounting_without_relabeling_warm_issuance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, warm: bool, retire_stale_dns: bool
) -> None:
    dependency = tmp_path / "roots.pem"
    dependency.write_bytes(b"original roots")
    dependency.chmod(0o600)
    recovery = Mock(
        context_sha256="a" * 64,
        context={"caddy_binary_sha256": "b" * 64},
        names={"nonce": str(uuid.uuid7())},
        original={"roots.pem": dependency},
        token="secret",  # noqa: S106 - private-output canary
    )
    recovery.witness.observed_zones = {"zone-a", "zone-b"}
    recovery.witness.sample.return_value.record_count = 1
    results = iter([False, True]) if not warm else iter([True])

    def call(action: str, **arguments: object) -> dict[str, object]:
        if action == "diagnostic_prepare":
            return {"cold": not warm}
        if action == "ready":
            return {"ready": next(results), "tls": {"public": True}}
        return {"retained": "account"}

    recovery.call.side_effect = call
    retirement = Mock(return_value={"retired_records": 4})
    monkeypatch.setattr(stages, "retire_dns", retirement)
    monkeypatch.setattr(
        importlib,
        "import_module",
        Mock(return_value=Mock(PublicRecovery=Mock(return_value=recovery))),
    )
    fixture = Mock(target={"auditRotationEnabled": True})
    result = stages.public_recovery(tmp_path, fixture, retire_stale_dns=retire_stale_dns)
    if retire_stale_dns:
        retirement.assert_called_once_with(recovery.witness, recovery.call)
    else:
        retirement.assert_not_called()
    assert result["cold"] is not warm
    assert result["interrupted"] is not warm
    assert fixture.reboot.call_count == (0 if warm else 1)
    if warm:
        recovery.drain_issuance.assert_not_called()
    else:
        recovery.drain_issuance.assert_called_once_with(diagnostic=True)
    assert recovery.call.call_args_list[-1].args == ("diagnostic_finish",)
    assert not (tmp_path / "public-ca.json").exists()
    assert not (tmp_path / "combined.json").exists()


def test_public_failure_stops_issuance_and_never_opens_ingress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    recovery = Mock(
        context={"caddy_binary_sha256": "b" * 64}, names={"nonce": "nonce"}, original={}
    )

    def call(action: str, **kwargs: object) -> dict[str, object]:
        if action == "ready":
            raise ValueError("invalid TLS")
        return {"cold": False}

    recovery.call.side_effect = call
    monkeypatch.setattr(
        importlib,
        "import_module",
        Mock(return_value=Mock(PublicRecovery=Mock(return_value=recovery))),
    )
    with pytest.raises(ValueError, match="invalid TLS"):
        stages.public_recovery(tmp_path, Mock())
    assert recovery.call.call_args_list[-1].args == ("diagnostic_stop_failed",)
    assert all(call.args[0] != "diagnostic_finish" for call in recovery.call.call_args_list)


@pytest.mark.parametrize("mismatch", ["tls", "journal"])
def test_diagnostic_finish_cannot_open_ingress_with_invalid_evidence(
    monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    monkeypatch.setattr(probe, "_guard", Mock(return_value={"journal_sha256": "original"}))
    monkeypatch.setattr(probe, "_closed", Mock())
    monkeypatch.setattr(probe, "_tls", Mock(return_value={"identity": mismatch}))
    monkeypatch.setattr(probe, "_journal", Mock(return_value="wrong"))
    monkeypatch.setattr(RestoreStore, "locked", Mock(return_value=MockLease()))
    opened = Mock()
    monkeypatch.setattr(public, "open_gate", opened)
    with pytest.raises(ValueError, match="TLS or restore identity"):
        public.diagnostic_finish("a" * 64, {"identity": "journal"}, audit_rotation=True)
    opened.assert_not_called()


class MockLease:
    def __enter__(self) -> Mock:
        return Mock()

    def __exit__(self, *args: object) -> None:
        pass


def test_diagnostic_failure_repeats_quiescence_without_replacing_original_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(policy, "INPUTS", tmp_path)
    original = b'{"context_sha256":"original"}\n'
    failed = tmp_path / "failed.json"
    failed.write_bytes(original)
    before = failed.stat()
    stop = Mock()
    monkeypatch.setattr(probe, "_stop_failed", stop)
    record = Mock(side_effect=AssertionError("must preserve original evidence"))
    monkeypatch.setattr(probe, "_record", record)
    for _ in range(2):
        assert public.diagnostic_stop_failed("original") == {
            "stopped": True,
            "qualification_authority": "none",
        }
    assert stop.call_count == 2  # noqa: PLR2004 - both failures must stop the issuer
    record.assert_not_called()
    assert failed.read_bytes() == original
    assert (failed.stat().st_ino, failed.stat().st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    stop.side_effect = ValueError("changed context")
    with pytest.raises(ValueError, match="changed context"):
        public.diagnostic_stop_failed("changed")


@pytest.mark.parametrize("diagnostic", [False, True])
@pytest.mark.parametrize(
    "action", ["diagnostic_start", "diagnostic_retire_dns", "diagnostic_stop_failed"]
)
def test_diagnostic_actions_exist_only_in_explicit_debug_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
    diagnostic: bool,
    action: str,
) -> None:
    module = installed_module("public_ca_recovery")
    run_id, nonce = str(uuid.uuid7()), str(uuid.uuid7())
    write_private(
        tmp_path / "combined-context.json",
        {"run_id": run_id, "subject_set_sha256": evidence.subject_digest(nonce)},
    )
    write_private(
        tmp_path / "combined-names.json",
        {
            "format": evidence.NAMES_FORMAT,
            "run_id": run_id,
            "nonce": nonce,
            "subjects": list(evidence.subjects(nonce)),
        },
    )
    monkeypatch.setattr(module.PublicRecovery, "_identity", Mock())
    monkeypatch.setattr(module, "require_original", Mock(return_value={}))
    monkeypatch.setattr(module.DnsWitness, "begin", Mock())
    monkeypatch.setattr(module, "_selected_python", lambda host, body: body)
    storage = Mock(target=Mock(run_id=run_id), environment={"CADDY_CLOUDFLARE_API_TOKEN": "secret"})
    fixture = Mock(live_storage=storage)
    recovery = module.PublicRecovery(fixture, storage, tmp_path, diagnostic=diagnostic)
    # Invoke with missing arguments: dispatch must resolve the name only in the
    # diagnostic program, without performing a guest mutation on this controller.
    result = subprocess.run(  # noqa: S603 - missing required arguments prevent execution
        [sys.executable, "-c", recovery.program],
        input=evidence.canonical_bytes({"action": action}),
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert (b"TypeError" if diagnostic else b"KeyError") in result.stderr


@pytest.mark.parametrize("action", ["ready", "diagnostic_retire_dns"])
def test_only_dns_retirement_gets_a_private_mount_namespace(
    installed_module: Callable[[str], ModuleType], action: str
) -> None:
    module = installed_module("public_ca_recovery")
    recovery = module.PublicRecovery.__new__(module.PublicRecovery)
    recovery._identity = Mock()
    recovery._remaining = Mock(return_value=180)
    recovery.fixture = Mock(destination_id="owned-destination")
    recovery.fixture.command.return_value = b"{}"
    recovery.program = "pass"
    recovery.context_sha256 = "a" * 64
    assert recovery.call(action) == {}
    arguments = recovery.fixture.command.call_args.args
    assert arguments[:4] == ("docker", "exec", "--interactive", "owned-destination")
    if action == "diagnostic_retire_dns":
        assert arguments[4:9] == ("/usr/bin/unshare", "--mount", "--propagation", "private", "--")
    else:
        assert arguments[4] == "/usr/bin/python3"
