"""Run the P2 witness through the owned installed guest's native transport."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from independent_fixture import require_owned_fixture
from testinfra.host import Host

from scripts.m3_12_contracts import decode
from scripts.m3_12_diagnostic_store import ROOT, Attempt, publish
from scripts.m3_12_diagnostic_transport import GUEST_FILE, read_guest
from scripts.m3_12_diagnostics import Step, child_environment, collect, execute, status
from scripts.qualification_case import owned_containers
from scripts.qualification_context import HOST_ENV
from scripts.qualification_probe import bounded_command

CANARY = b"M3-12-SYNTHETIC-PRIVATE-TRANSPORT-WITNESS"
WITNESS = Path(__file__).with_name("m3_12_guest_witness.py")
SETUP_FAILURE = 7


def playbook(
    attempt: Attempt,
    directory: Path,
    host_id: str,
    mode: str,
) -> tuple[tuple[str, ...], str]:
    invocation = attempt.directory.name
    remote = f"{GUEST_FILE}/{invocation}"
    unit = f"ldp-diagnostic-{invocation}.service"
    paths = (
        ROOT / "scripts/m3_12_diagnostic_store.py",
        ROOT / "scripts/m3_12_diagnostic_guest.py",
        WITNESS,
    )
    setup: list[dict[str, object]] = [
        {
            "ansible.builtin.file": {
                "path": f"{remote}/scripts",
                "state": "directory",
                "mode": "0700",
            }
        },
        *(
            {
                "ansible.builtin.copy": {
                    "src": str(path),
                    "dest": f"{remote}/scripts/{path.name}",
                    "mode": "0600",
                }
            }
            for path in paths
        ),
    ]
    service = [
        "systemd-run",
        "--quiet",
        "--collect",
        "--unit",
        unit,
        "--property",
        "StandardOutput=null",
        "--property",
        "StandardError=null",
        *(["--property", "Type=notify"] if mode == "hold" else ["--wait"]),
        "/usr/bin/python3",
        "-I",
        "-B",
        f"{remote}/scripts/{WITNESS.name}",
        attempt.directory.parent.name,
        invocation,
        mode,
    ]
    inventory = directory / f"{mode}-inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        "owned": {
                            "ansible_connection": "community.docker.docker",
                            "ansible_host": host_id,
                            "ansible_python_interpreter": "/usr/bin/python3",
                        }
                    }
                },
            }
        )
    )
    tasks = directory / f"{mode}.json"
    tasks.write_text(
        json.dumps(
            [
                {
                    "name": "Exercise root-owned native diagnostic transport",
                    "hosts": "owned",
                    "gather_facts": False,
                    "no_log": True,
                    "tasks": [*setup, {"ansible.builtin.command": {"argv": service}}],
                }
            ]
        )
    )
    program = shutil.which("ansible-playbook")
    if program is None:
        raise AssertionError("Pinned Ansible is unavailable.")
    return (program, "-i", str(inventory), str(tasks)), unit


def verify_no_canary(root: Path) -> None:
    for artifact in root.rglob("*"):
        if artifact.is_file() and CANARY in artifact.read_bytes():
            raise AssertionError("The fixture canary crossed a private capture boundary.")


def disconnect_observer(attempt: Attempt, arguments: tuple[str, ...]) -> None:
    code = """
import signal
import subprocess
import sys
from pathlib import Path
from scripts.m3_12_diagnostic_store import Attempt, clock

attempt = Attempt(Path(sys.argv[1]))
with attempt.lock("controller.lock"):
    attempt.append("bootstrap", "ansible", clock())
    action = subprocess.run(sys.argv[2:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if action.returncode:
        sys.exit(action.returncode)
    print("submitted", flush=True)
    signal.pause()
"""
    with subprocess.Popen(  # noqa: S603 - fixed witness caller on the owned guest
        [sys.executable, "-c", code, str(attempt.directory), *arguments],
        env=child_environment(attempt),
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as observer:
        try:
            assert observer.stdout is not None
            assert observer.stdout.readline() == b"submitted\n", "Guest setup did not complete."
        finally:
            if observer.poll() is None:
                observer.kill()


def test_m3_12_installed_diagnostic_boundaries(
    host: Host,
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    require_owned_fixture()
    assert host.backend.NAME == "docker"
    environment = dict(os.environ)
    host_id = owned_containers(environment)[HOST_ENV]
    journal = tmp_path / "attempts"
    setup = Attempt.allocate(journal)
    command = (
        "import pathlib, os, sys;"
        "assert (pathlib.Path(os.environ['LDP_M3_12_ATTEMPT'])/'0000000000.json').is_file();"
        f"print({CANARY!r});print({CANARY!r}, file=sys.stderr);sys.exit({SETUP_FAILURE})"
    )
    assert (
        execute(
            setup,
            (Step("dependencies", "controller", "dependencies", (sys.executable, "-c", command)),),
        )
        == SETUP_FAILURE
    )
    assert status(setup)["process"] == {"exit": SETUP_FAILURE}
    collect(setup)
    assert (
        decode((setup.directory / "summary.json").read_bytes(), "diagnostic-summary")["category"]
        == "dependencies"
    )

    failed = Attempt.allocate(journal)
    arguments, _ = playbook(failed, tmp_path, host_id, "failure")
    result = execute(failed, (Step("bootstrap", "ansible", "process", arguments),))
    assert result != 0
    native = read_guest(failed, environment, host_id, "result")
    assert [item["type"] for item in native["failures"][0]["causes"]] == ["unexpected", "timeout"]
    journal_events = [failed.record(name) for name in failed.names()]
    assert any(
        event["operation"] == "ansible"
        and event["stage"] == "preparation"
        and event["terminalEvidence"] == "recorded"
        for event in journal_events
    ), "Ansible did not emit its terminal checkpoint."

    # Force collection to refuse a conflicting export without replacing original exit evidence.
    publish(failed.directory, "summary.json", {"format": "synthetic-conflicting-summary"})
    try:
        collect(failed)
    except ValueError:
        pass
    else:
        raise AssertionError("Conflicting collection succeeded.")
    assert status(failed)["process"] == {"exit": result}
    assert any(
        item["role"] == "collection"
        for name in failed.names()
        for item in failed.record(name)["failures"]
    )

    lost = Attempt.allocate(journal)
    arguments, unit = playbook(lost, tmp_path, host_id, "hold")
    try:
        disconnect_observer(lost, arguments)
        # The invoking observer was killed. The native unit remains active.
        assert (
            bounded_command(
                [
                    "docker",
                    "exec",
                    host_id,
                    "systemctl",
                    "show",
                    "--property=ActiveState",
                    "--value",
                    unit,
                ],
                environment=environment,
            )
            == b"active\n"
        )
        native = read_guest(lost, environment, host_id, "start")
        assert native["terminalEvidence"] == "missing"
        assert status(lost)["uncertainWork"] is True
        assert status(lost)["result"] == "unknown"
    finally:
        stopped = bounded_command(
            ["docker", "exec", host_id, "systemctl", "stop", unit],
            environment=environment,
        )

    assert stopped == b"", "The witness unit did not stop."

    verify_no_canary(journal)
    capture = capfd.readouterr()
    if CANARY.decode() in capture.out or CANARY.decode() in capture.err:
        raise AssertionError("The fixture canary reached the console.")
    events = Path(environment["LDP_QUALIFICATION_TIMING_EVENTS"])
    publish(
        events.parent,
        "m3-12-installed-diagnostic-proof.json",
        {
            "format": "lowerduckpond-m3-12-installed-diagnostic-proof-v1",
            "setup": "original-exit-retained",
            "systemd": "cause-chain-transferred",
            "observer": "unknown-while-guest-active",
            "collection": "secondary-failure-retained",
            "secretExclusion": "checked",
        },
    )
