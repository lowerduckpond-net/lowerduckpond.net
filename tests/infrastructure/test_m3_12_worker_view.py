"""Receipt and service-manager checks for the isolated installed worker witness."""

import json
import os
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import droplet_enrollment, host_restore_gate, installed_routing
from lowerduckpond_static_host_agent.host_restore_inputs import local_machine_id
from lowerduckpond_static_host_agent.platform_launch import (
    require_local_launch_binding,
    verify_launch,
)

from scripts import check_m3_12_worker_view as controller
from scripts import m3_12_droplet_observe as observe

GUEST = controller.ROOT / "config/ansible/molecule/m3_8/m3_12_worker_view.py"
MANAGER_QUERY = ("show", "--property=SystemState", "--value")


def test_prepared_restore_requires_the_workers_owned_boot_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guest = runpy.run_path(str(GUEST))
    create_launch = guest["create_launch"]
    state = tmp_path / "state"
    root = tmp_path / "authority"
    view = root / droplet_enrollment.PUBLICATION_VIEW
    recovery = tmp_path / "recovery"
    caddy = tmp_path / "caddy"
    ssh = tmp_path / "ssh"
    for directory in (state, recovery, caddy, ssh):
        directory.mkdir(mode=0o700)
    machine = tmp_path / "machine"
    machine.write_bytes(b"b" * 32 + b"\n")
    system = tmp_path / "uuid"
    system.write_bytes(b"22222222-3333-4444-5555-666666666666\n")
    boot = tmp_path / "current-boot"
    boot.write_bytes(b"22222222-3333-4444-5555-666666666666\n")
    artifact = tmp_path / ("a" * 64)
    artifact.mkdir()
    selected = tmp_path / "current"
    selected.symlink_to(artifact)
    owner = os.geteuid()
    key = ssh / "ssh_host_ed25519_key.pub"
    create_launch.__globals__.update(
        STATE=state,
        ROOT=root,
        VIEW=view,
        RECOVERY=recovery,
        CADDY=caddy,
        HOST_KEY=key,
        local_machine_id=lambda **_: local_machine_id(machine, owner=owner),
    )
    monkeypatch.setattr(observe, "MACHINE_ID", machine)
    monkeypatch.setattr(observe, "SYSTEM_UUID", system)
    monkeypatch.setattr(observe, "HOST_KEY", key)
    monkeypatch.setattr(observe, "BOOT_ID", boot)
    monkeypatch.setattr(observe, "SELECTION", selected)
    monkeypatch.setattr(droplet_enrollment, "DOCKER_MARKER", tmp_path / "not-docker")
    monkeypatch.setattr(host_restore_gate, "RECOVERY_ROOT", recovery)
    monkeypatch.setattr(installed_routing, "AUTHORITY", view)
    monkeypatch.setattr(installed_routing, "CADDY_ROOT", caddy)
    real_projection = installed_routing.installed_projection
    monkeypatch.setattr(
        installed_routing,
        "installed_projection",
        lambda **kwargs: real_projection(**kwargs, group=os.getegid()),
    )
    create_launch(artifact.name, owner=owner)
    source = verify_launch(state, view, owner=owner)
    guest["prepare_completed_restore"](artifact.name, owner=owner, caddy_group=os.getegid())
    assert verify_launch(state, view, owner=owner) == source

    worker_boot = tmp_path / "worker-boot"
    with pytest.raises(FileNotFoundError):
        require_local_launch_binding(
            view, source, disposable=False, owner=owner, boot_path=worker_boot
        )
    worker_boot.write_bytes(b"11111111-3333-4444-5555-666666666666\n")
    with pytest.raises(FileNotFoundError):
        require_local_launch_binding(
            view, source, disposable=False, owner=owner, boot_path=worker_boot
        )
    worker_boot.write_bytes(boot.read_bytes())
    worker_boot.chmod(0o440)
    require_local_launch_binding(view, source, disposable=False, owner=owner, boot_path=worker_boot)


@pytest.mark.parametrize(
    ("expected", "mode", "message"),
    [
        (0, "entered", None),
        (78, "entered", None),
        (0, "without-execution", "did not prove exit 0"),
        (0, "skipped-gate", "did not prove exit 0"),
        (0, "stale-receipt", "did not prove exit 0"),
        (78, "wrong-denial", "did not prove exit 78"),
        (0, "bus-error", "Failed to connect to system scope bus via local transport"),
        (0, "unready", "worker not ready"),
    ],
)
def test_worker_requires_fresh_systemd_execution(
    tmp_path: Path, expected: int, mode: str, message: str | None
) -> None:
    run_worker = runpy.run_path(str(GUEST))["run_worker"]
    unit = run_worker.__globals__["UNIT"]
    root = tmp_path / "worker-view-witness"
    hook = tmp_path / "stop.py"
    hook.write_text(controller.STOP_SOURCE.replace(controller.WITNESS, str(root)))
    calls: list[tuple[str, ...]] = []

    def systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        command = ["/usr/bin/systemctl", *arguments]
        if arguments == MANAGER_QUERY:
            return subprocess.CompletedProcess(
                command, 0, "starting\n" if mode == "unready" else "degraded\n", ""
            )
        if arguments[0] == "show":
            # systemd returns this default after a condition skip or unit GC.
            return subprocess.CompletedProcess(
                command, 0, "LoadState=loaded\nActiveState=inactive\nExecMainStatus=0\n", ""
            )
        assert arguments == ("start", unit)
        if mode == "bus-error":
            return subprocess.CompletedProcess(
                command, 1, "", "Failed to connect to system scope bus via local transport"
            )
        if mode != "without-execution":
            if mode != "skipped-gate":
                (root / "entered").write_text((root / "request").read_text())
            if expected != 0:
                category = (
                    "host_restore_pending"
                    if mode == "wrong-denial"
                    else "launch_authority_unavailable"
                )
                (root / "stderr").write_text(f"{category}\n")
            subprocess.run(  # noqa: S603 - isolated real stop hook and synthetic environment
                [sys.executable, "-I", "-B", str(hook)],
                check=True,
                env={
                    **os.environ,
                    "INVOCATION_ID": "a" * 32,
                    "SERVICE_RESULT": "success" if expected == 0 else "exit-code",
                    "EXIT_CODE": "exited",
                    "EXIT_STATUS": str(expected),
                },
            )
            if mode == "stale-receipt":
                path = root / "receipt.json"
                receipt = json.loads(path.read_text())
                receipt["request"] = "different request"
                path.write_text(json.dumps(receipt))
        return subprocess.CompletedProcess(command, 0, "", "")

    run_worker.__globals__.update(STATE=tmp_path, systemctl=systemctl)
    if message is None:
        run_worker(expected)
    else:
        with pytest.raises(ValueError, match=message) as error:
            run_worker(expected)
        if mode == "bus-error":
            assert f"/usr/bin/systemctl start {unit} exit=1" in str(error.value)
            assert "stdout='degraded'" in str(error.value)
            assert "ActiveState=inactive" in str(error.value)
            assert "ExecMainStatus=0" in str(error.value)
    assert calls[0] == MANAGER_QUERY
    assert (("start", unit) in calls) == (mode != "unready")


def test_guest_socket_does_not_prove_manager_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        if arguments[0] == "inspect":
            return subprocess.CompletedProcess(list(arguments), 0, "running 0", "")
        if arguments[2] == "/usr/bin/test":
            return subprocess.CompletedProcess(list(arguments), 0, "", "")
        assert not check
        assert arguments[2:] == ("/usr/bin/systemctl", *MANAGER_QUERY)
        return subprocess.CompletedProcess(list(arguments), 1, "", "manager connection lost")

    monkeypatch.setattr(controller, "docker", docker)
    with pytest.raises(
        ValueError,
        match=r"/usr/bin/systemctl show --property=SystemState --value exit=1.*connection lost",
    ):
        controller.wait_for_systemd("owned-guest")
