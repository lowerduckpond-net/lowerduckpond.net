"""Public dependency proof must preserve the real gate and original inputs."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_private_inputs import write_private

BINARY = "/usr/local/lib/lowerduckpond/caddy-2.11.4-xcaddy-0.4.7-cloudflare-0.2.4"
CONTEXT = "a" * 64


def test_disposable_configuration_cannot_fall_back_to_a_private_or_staging_issuer() -> None:
    nonce = str(uuid.uuid7())
    assert policy.disposable_subjects(nonce) == evidence.subjects(nonce)
    config = json.loads(policy.configuration(nonce))
    tls = config["apps"]["tls"]
    assert tls["certificates"]["automate"] == list(evidence.subjects(nonce))
    issuers = tls["automation"]["policies"][0]["issuers"]
    assert len(issuers) == 1
    assert issuers[0]["ca"] == issuers[0]["test_ca"] == evidence.ISSUER
    assert issuers[0]["challenges"]["http"]["disabled"]
    assert issuers[0]["challenges"]["tls-alpn"]["disabled"]
    assert config["storage"]["root"] != "/var/lib/caddy"
    assert config["admin"]["disabled"]


@pytest.mark.parametrize("nonce", [str(uuid.uuid4()), "nonce", "../../caddy", ""])
def test_public_subjects_cannot_be_selected_by_the_caller(nonce: str) -> None:
    with pytest.raises(ValueError):
        policy.configuration(nonce)


@pytest.mark.parametrize(
    "binary", ["/usr/local/bin/caddy", BINARY + "\nExecStart=/bin/sh", BINARY + " --resume"]
)
def test_service_rejects_mutable_binary_and_unit_injection(binary: str) -> None:
    with pytest.raises(ValueError):
        policy.service(binary)


def test_service_preserves_restore_admission_and_isolates_go_public_roots() -> None:
    unit = policy.service(BINARY).decode()
    assert "host-restore-gate --caddy" in unit
    assert "Requires=lowerduckpond-restore-gate.service" in unit
    assert f"Environment=SSL_CERT_FILE={policy.INPUTS}/roots.pem" in unit
    assert f"Environment=SSL_CERT_DIR={policy.INPUTS}/empty-roots" in unit
    assert f"BindReadOnlyPaths={policy.INPUTS}/hosts:/etc/hosts" in unit
    assert f"BindReadOnlyPaths={policy.INPUTS}/resolv.conf:/etc/resolv.conf" in unit
    assert "[Install]" not in unit
    assert "Restart=no" in unit


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "writable", "large", "fifo"])
def test_private_probe_inputs_refuse_unsafe_files(tmp_path: Path, fault: str) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"original")
    if fault == "symlink":
        path.rename(tmp_path / "target")
        path.symlink_to(tmp_path / "target")
    elif fault == "hardlink":
        os.link(path, tmp_path / "other")
    elif fault == "writable":
        path.chmod(0o666)
    elif fault == "fifo":
        path.unlink()
        os.mkfifo(path)
    with pytest.raises((ValueError, OSError)):
        probe._read(path, owner=os.getuid(), maximum=1 if fault == "large" else 100)


@pytest.fixture
def actions(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    events: list[str] = []
    monkeypatch.setattr(probe, "_guard", Mock(return_value={"journal_sha256": "journal"}))
    monkeypatch.setattr(probe, "_closed", lambda: events.append("closed"))
    monkeypatch.setattr(probe, "_document", Mock(return_value={}))

    def record(name: str, value: object) -> dict[str, object]:
        events.append(name)
        return {"value": value}

    def systemctl(*args: str) -> bytes:
        events.append("systemctl " + " ".join(args))
        return b""

    monkeypatch.setattr(probe, "_record", record)
    monkeypatch.setattr(probe, "_systemctl", systemctl)
    return events


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(),
        HostRestoreError("restore_tls_peer_unavailable"),
        HostRestoreError("restore_tls_peer_unverified"),
        HostRestoreError("restore_tls_subjects_unavailable"),
    ],
)
def test_only_coordinator_readiness_errors_are_recoverable(
    actions: list[str], monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(probe, "_tls", Mock(side_effect=error))
    assert probe.ready(CONTEXT) == {"ready": False}
    assert actions == ["closed"]


@pytest.mark.parametrize(
    "error",
    [
        HostRestoreError("restore_tls_key_mismatch"),
        HostRestoreError("restore_tls_storage_changed"),
        HostRestoreError("restore_tls_chain_or_validity_invalid"),
        PermissionError(),
    ],
)
def test_invalid_or_changed_public_evidence_is_terminal(
    actions: list[str], monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(probe, "_tls", Mock(side_effect=error))
    with pytest.raises(type(error)):
        probe.ready(CONTEXT)
    assert actions == ["closed"]


def test_completed_issuance_cannot_be_relabeled_as_interrupted(
    actions: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "_tls", Mock(return_value={"certificates": ["all four"]}))
    with pytest.raises(ValueError, match="already completed"):
        probe.interrupt(CONTEXT)
    assert actions == ["closed"]


def test_interruption_requires_retained_actual_account(
    actions: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "_tls", Mock(side_effect=FileNotFoundError()))
    monkeypatch.setattr(probe, "_inventory", Mock(return_value={"certificate.crt": "digest"}))
    with pytest.raises(ValueError, match="actual ACME account"):
        probe.interrupt(CONTEXT)
    assert "interrupting" in actions
    assert "systemctl stop " + policy.UNIT in actions
    assert "interrupted" not in actions


@pytest.mark.parametrize("fault", ["same-pid", "changed-storage"])
def test_reboot_requires_new_pid_one_and_identical_stopped_storage(
    actions: list[str], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(
        probe,
        "_document",
        Mock(
            return_value={
                "pid_one": Path("/proc/1/stat").read_text().split()[21]
                if fault == "same-pid"
                else "old",
                "storage": {"acme/account.key": "original"},
            }
        ),
    )
    monkeypatch.setattr(
        probe,
        "_inventory",
        Mock(
            return_value={
                "acme/account.key": "changed" if fault == "changed-storage" else "original"
            }
        ),
    )
    with pytest.raises(ValueError, match="preserve the stopped"):
        probe.rebooted(CONTEXT)
    assert "rebooted" not in actions


def test_resume_refuses_storage_changed_after_reboot_observation(
    actions: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(probe, "_document", Mock(return_value={"storage": {"key": "old"}}))
    monkeypatch.setattr(probe, "_inventory", Mock(return_value={"key": "new"}))
    with pytest.raises(ValueError, match="before resume"):
        probe.start(CONTEXT, resume=True)
    assert actions == ["closed"]


@pytest.mark.parametrize("fault", ["tls-failure", "different-tls", "different-journal", "none"])
def test_public_ingress_requires_fresh_matching_tls_under_original_restore_lease(
    actions: list[str], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    class Lease:
        def __enter__(self) -> Mock:
            actions.append("lock")
            return Mock(immutable=lambda *args: actions.append("intent"))

        def __exit__(self, *args: object) -> None:
            actions.append("unlock")

    monkeypatch.setattr(RestoreStore, "locked", lambda *args: Lease())
    monkeypatch.setattr(
        probe,
        "_tls",
        Mock(
            side_effect=HostRestoreError("invalid") if fault == "tls-failure" else None,
            return_value={"leaf": "changed" if fault == "different-tls" else "original"},
        ),
    )
    monkeypatch.setattr(
        probe,
        "_journal",
        Mock(return_value="changed" if fault == "different-journal" else "journal"),
    )
    monkeypatch.setattr(probe, "ingress_record", Mock(return_value=b"bound intent"))
    monkeypatch.setattr(probe, "open_gate", lambda store: actions.append("admission"))
    monkeypatch.setattr(probe, "finish_public_ingress", lambda store: actions.append("ingress"))
    monkeypatch.setattr(probe, "restore_admission", Mock(return_value=True))
    if fault != "none":
        with pytest.raises((ValueError, HostRestoreError)):
            probe.open_verified(CONTEXT, {"leaf": "original"})
        assert actions == ["closed", "lock", "unlock"]
    else:
        probe.open_verified(CONTEXT, {"leaf": "original"})
        assert actions == [
            "closed",
            "lock",
            "verified",
            "intent",
            "admission",
            "ingress",
            "unlock",
            "opened",
        ]


@dataclass
class Controller:
    run: Callable[[], tuple[dict[str, object], dict[str, object]]]
    call: Mock
    fixture: Mock
    peer: Mock
    witness: Mock
    directory: Path
    expire: Callable[[], None]


@pytest.fixture
def controller(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Controller:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "config/ansible/molecule/m3_8/tests"))
    module = importlib.import_module("public_ca_recovery")
    value = object.__new__(module.PublicRecovery)
    value.deadline = module.time.monotonic() + 100
    value.fixture = Mock(binary=BINARY, target={"auditRotationEnabled": False})
    value.directory = tmp_path
    value.context_sha256 = CONTEXT
    value.context = {"caddy_binary_sha256": "b" * 64}
    value.names = {"nonce": str(uuid.uuid7())}
    value.token = "0" * 40
    public_inputs = tmp_path / "public-inputs"
    public_inputs.mkdir(mode=0o700)
    for name in ("roots.pem", "hosts", "resolv.conf", "original.json"):
        path = public_inputs / name
        path.write_bytes(b"original fixture input")
        path.chmod(0o600)
    value.original = {name: public_inputs / name for name in ("roots.pem", "hosts", "resolv.conf")}
    value.witness = Mock()
    value.witness.sample.return_value = Mock(record_count=1, sha256="c" * 64)
    value.witness.require_absent.return_value = Mock(sha256="d" * 64)
    value._identity = Mock()
    value.peer = Mock()
    value._wait = Mock()
    monkeypatch.setattr(module, "gate_closed", Mock())

    def call(action: str, **arguments: object) -> dict[str, object]:
        if action != "stop_failed":
            value._remaining()
        if action == "ready":
            return {"ready": True, "tls": {"issuer": policy.ISSUER_STORAGE, "certificates": []}}
        return {"action": action}

    value.call = Mock(side_effect=call)
    return Controller(
        value.run,
        value.call,
        value.fixture,
        value.peer,
        value.witness,
        tmp_path,
        lambda: setattr(value, "deadline", 0),
    )


def test_public_controller_keeps_interruption_and_reboot_before_verification(
    controller: Controller,
) -> None:
    public_ca, _ = controller.run()
    assert [call.args[0] for call in controller.call.call_args_list] == [
        "install",
        "start",
        "interrupt",
        "rebooted",
        "start",
        "ready",
        "open_verified",
        "restore_native",
    ]
    assert controller.fixture.reboot.call_count == 1
    assert controller.call.call_args_list[4].kwargs == {"resume": True}
    assert [call.kwargs["opened"] for call in controller.peer.call_args_list] == [
        False,
        False,
        False,
        True,
    ]
    controller.witness.require_both_zones_observed.assert_called_once()
    controller.witness.require_absent.assert_called_once_with("cleanup")
    assert public_ca["trust"] == "system-public-roots"
    assert (controller.directory / "public-ca.json").exists()


@pytest.mark.parametrize(
    "fault", ["unobserved-interruption", "one-zone", "dns-leftover", "reboot-timeout"]
)
def test_public_controller_never_opens_or_emits_proof_after_failed_dependency_checks(
    controller: Controller, fault: str
) -> None:
    if fault == "unobserved-interruption":
        controller.witness.sample.return_value.record_count = 0
    elif fault == "one-zone":
        controller.witness.require_both_zones_observed.side_effect = ValueError("one zone")
    elif fault == "dns-leftover":
        controller.witness.require_absent.side_effect = ValueError("challenge remains")
    else:
        controller.fixture.reboot.side_effect = controller.expire
    with pytest.raises((ValueError, TimeoutError)):
        controller.run()
    assert "open_verified" not in [call.args[0] for call in controller.call.call_args_list]
    assert controller.call.call_args_list[-1].args == ("stop_failed",)
    assert not (controller.directory / "public-ca.json").exists()


def test_installed_dispatch_loads_real_helpers_without_credentials_in_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "config/ansible/molecule/m3_8/tests"))
    module = importlib.import_module("public_ca_recovery")
    run_id, nonce = str(uuid.uuid7()), str(uuid.uuid7())
    context: dict[str, object] = {
        "run_id": run_id,
        "subject_set_sha256": evidence.subject_digest(nonce),
    }
    write_private(tmp_path / "combined-context.json", context)
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
    token = uuid.uuid4().hex + "-private-canary"
    storage = Mock(target=Mock(run_id=run_id), environment={"CADDY_CLOUDFLARE_API_TOKEN": token})
    fixture = Mock(live_storage=storage)
    recovery = module.PublicRecovery(fixture, storage, tmp_path)
    assert token not in recovery.program
    result = subprocess.run(  # noqa: S603 - exact fixture helpers; unknown action performs no mutation
        [sys.executable, "-c", recovery.program],
        input=b'{"action":"unsupported"}',
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode != 0
    assert b"KeyError: 'unsupported'" in result.stderr
    assert token.encode() not in result.stderr + result.stdout
