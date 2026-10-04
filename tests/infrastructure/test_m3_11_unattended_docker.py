"""Opt-in, credential-free lifecycle proof on the actual qualification Docker host."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from scripts.m3_11_unattended import docker as docker_module
from scripts.m3_11_unattended.docker import OWNER, Docker, helper_volume
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_unattended_delivery import delivery_configuration

# The controller runs the real durable state and lifecycle engine with only the
# existing local provider double. No bootstrap file, live API or runner is loaded.
CONTROLLER = """
import dataclasses, json, os, signal, time, uuid
from pathlib import Path
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.state import RunState
from tests.infrastructure.test_m3_11_unattended_lifecycle import Case
os.umask(0o077)
root = Path('/smoke')
root.chmod(0o700)
run = root / 'attempt'
run.mkdir(mode=0o700, exist_ok=True)
case = Case(root / 'journal')
state = RunState(run)
binding = {'managed_run_id':case.run_id}
if (run/'attempt.json').exists():
    binding = read_private(run/'attempt.json')['binding']
with state.lock():
    if state.begin(binding):
        intent, credential = case.create()
        write_private(root/'provider.json', case.provider.items)
        write_private(root/'credential.json', {'intent': intent.document(),
            'id':credential.identifier,'secret':credential.secret})
        write_private(root/'retained-failure.json', {'private':'never-export-this-smoke-canary'})
        write_private(root/'creates.json', {'count':case.provider.creates})
        state.update('running', cleanup='pending')
    else:
        state.interrupted()
        case.lifecycle.request_revocation(binding['managed_run_id'])
        state.update('revoking', cleanup='pending')
    while True:
        if (root/'crash').exists():
            (root/'crash').unlink()
            os.kill(os.getpid(), signal.SIGKILL)
        if (root/'cleanup.json').exists():
            state.update('finished', cleanup='verified')
        time.sleep(0.2)
"""

CLEANER = """
import dataclasses, os
from pathlib import Path
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.model import Credential
from scripts.m3_11_unattended.lifecycle import intents
from tests.infrastructure.test_m3_11_unattended_lifecycle import Case
os.umask(0o077)
root = Path('/smoke')
case = Case(root/'journal')
case.provider.items = read_private(root/'provider.json')
secret = read_private(root/'credential.json')
intent = intents(case.journal)[0]
result = case.lifecycle.sweep({intent.sha256: Credential(secret['id'],secret['secret'],{})})
assert len(result) == 1 and result[0].status == 'verified'
assert result[0].negative_authentication == 'denied'
assert not case.provider.items
write_private(root/'cleanup.json', {'results':[dataclasses.asdict(value) for value in result]})
"""


def wait_for(docker: Docker, name: str, path: str) -> None:
    end = time.monotonic() + 45
    while time.monotonic() < end:
        try:
            docker.command("exec", name, "test", "-f", path, timeout=5)
            return
        except RuntimeError:
            time.sleep(0.5)
    pytest.fail("detached smoke did not reach its bounded checkpoint")


@pytest.mark.skipif(
    not os.environ.get("LDP_M3_11_DOCKER_SMOKE_IMAGE"),
    reason="explicit prepared Docker image required",
)
def test_admission_reservation_is_atomic_on_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate the smoke from any concurrently running qualification launcher.
    monkeypatch.setattr(docker_module, "ADMISSION", "ldp-m311-smoke-admission-" + uuid.uuid4().hex)
    first, second = Docker(), Docker()
    image = os.environ["LDP_M3_11_DOCKER_SMOKE_IMAGE"]
    with docker_module.admission(first, image=image):
        with pytest.raises(LifecycleError), docker_module.admission(second, image=image):
            pytest.fail("a second client acquired the same daemon reservation")
        held = first.owned(docker_module.ADMISSION)
        assert held["State"]["Status"] == "created"  # type: ignore[index]
    with docker_module.admission(second, image=image):
        assert first.owned(docker_module.ADMISSION)["Id"] != held["Id"]


@pytest.mark.skipif(
    not os.environ.get("LDP_M3_11_DOCKER_SMOKE_REVISION"),
    reason="explicit prepared Docker host required",
)
def test_workspace_config_is_readable_by_container_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = Docker()
    source = os.environ["LDP_M3_11_DOCKER_SMOKE_REVISION"]
    image = os.environ["LDP_M3_11_DOCKER_SMOKE_IMAGE"]
    config = tmp_path / "controller.json"
    delivery_configuration(config)
    mounts: list[str] = []
    for constant, destination in (
        ("EVIDENCE_VOLUME", "/evidence"),
        ("CONFIG_VOLUME", "/configuration"),
        ("CLEANUP_VOLUME", "/cleanup"),
    ):
        volume = "ldp-m311-smoke-delivery-" + uuid.uuid4().hex
        monkeypatch.setattr(docker_module, constant, volume)
        docker.volume(volume)
        mounts += ["--mount", f"type=volume,source={volume},target={destination},readonly"]
    docker_module.initialize_run(
        docker, image=image, request=b"{}\n", run_id=str(uuid.uuid7()), config=config
    )
    # Load through the production validators with networking disabled. No real
    # credentials or provider access are involved. The previous Docker copy
    # retained UID 1000 and failed this load in the root controller.
    program = """
import os, sys
from pathlib import Path
from scripts.m3_11_unattended.config import Configuration, cleanup_configuration
assert os.geteuid() != int(sys.argv[1]), 'exercise distinct workspace/container owners'
config = Configuration.load(Path('/configuration/controller.json'))
targets, vault, cleanup = cleanup_configuration(Path('/cleanup/cleanup.json'))
assert (targets, vault, cleanup) == (config.targets, config.journal_vault, config.cleanup)
print('private configuration accepted by container; cleanup authority remains separate')
"""
    output = docker.command(
        "run",
        "--rm",
        "--network",
        "none",
        "--label",
        OWNER + "=true",
        "--mount",
        f"type=volume,source={helper_volume(source)},target=/opt/lifecycle,readonly",
        *mounts,
        image,
        "uv",
        "run",
        "--no-sync",
        "--frozen",
        "python",
        "-c",
        program,
        str(os.geteuid()),
    )
    assert (
        output
        == b"private configuration accepted by container; cleanup authority remains separate\n"
    )
    # Retain isolated fake-input volumes; never touch real controller volumes.


@pytest.mark.skipif(
    not os.environ.get("LDP_M3_11_DOCKER_SMOKE_REVISION"),
    reason="explicit prepared Docker host required",
)
def test_detachment_published_port_death_restart_and_independent_cleanup(tmp_path: Path) -> None:
    docker = Docker()
    source = os.environ["LDP_M3_11_DOCKER_SMOKE_REVISION"]
    image = os.environ["LDP_M3_11_DOCKER_SMOKE_IMAGE"]
    nonce = uuid.uuid4().hex
    controller, guest, cleaner = (
        "ldp-m311-smoke-" + role + "-" + nonce for role in ("controller", "guest", "cleaner")
    )
    volume = "ldp-m311-smoke-" + nonce
    docker.volume(volume)
    mounts = [
        "--mount",
        f"type=volume,source={helper_volume(source)},target=/opt/lifecycle,readonly",
        "--mount",
        f"type=volume,source={volume},target=/smoke",
    ]
    controllers: list[str] = []
    try:
        docker.command(
            "run",
            "--detach",
            "--name",
            guest,
            "--label",
            OWNER + "=true",
            "--publish",
            "127.0.0.1::18080",
            "--workdir",
            "/opt/qualification-tools",
            image,
            "python3",
            "-m",
            "http.server",
            "18080",
        )
        controllers.append(guest)
        # The short launcher exits. Its detached daemon-side controller persists.
        completed = subprocess.run(  # noqa: S603 - fixed local smoke, no credential input
            [
                docker.executable,
                "run",
                "--detach",
                "--restart",
                "unless-stopped",
                "--name",
                controller,
                "--label",
                OWNER + "=true",
                "--network",
                "host",
                *mounts,
                image,
                "uv",
                "run",
                "--no-sync",
                "--frozen",
                "python",
                "-c",
                CONTROLLER,
            ],
            env=docker.environment,
            capture_output=True,
            timeout=60,
            check=True,
        )
        assert completed.returncode == 0
        controllers.append(controller)
        wait_for(docker, controller, "/smoke/creates.json")
        port = docker.command("port", guest, "18080/tcp").decode().strip().split(":")[-1]
        docker.command(
            "exec",
            controller,
            "python3",
            "-c",
            "import socket,sys; "
            "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),5); s.close()",
            port,
        )
        initial = docker.owned(controller)
        docker.command("exec", controller, "touch", "/smoke/crash")
        end = time.monotonic() + 45
        while docker.owned(controller).get("RestartCount") == 0 and time.monotonic() < end:
            time.sleep(0.5)
        wait_for(docker, controller, "/smoke/attempt/journey-result.json")
        docker.command(
            "run",
            "--name",
            cleaner,
            "--label",
            OWNER + "=true",
            "--network",
            "none",
            *mounts,
            image,
            "uv",
            "run",
            "--no-sync",
            "--frozen",
            "python",
            "-c",
            CLEANER,
        )
        controllers.append(cleaner)
        wait_for(docker, controller, "/smoke/cleanup.json")
        assert json.loads(docker.command("exec", controller, "cat", "/smoke/creates.json")) == {
            "count": 1
        }
        outcome = json.loads(
            docker.command("exec", controller, "cat", "/smoke/attempt/journey-result.json")
        )
        assert outcome["outcome"] == "interrupted"
        assert (
            "never-export-this-smoke-canary"
            in docker.command("exec", controller, "cat", "/smoke/retained-failure.json").decode()
        )
        final = docker.owned(controller)
        assert final.get("RestartCount") != initial.get("RestartCount")
        receipt = {
            "source": source,
            "image": image,
            "volume": volume,
            "docker_host": docker.info(),
            "terminal_exit": "survived",
            "published_loopback": "reachable",
            "controller_death": "interrupted",
            "restart": "reconciled-without-replay",
            "independent_cleanup": "verified-local-double",
            "private_evidence": "retained",
            "workspace_agent_exit": "not-tested",
            "coder_rebuild": "not-tested",
        }
        output = Path(
            os.environ.get("LDP_M3_11_DOCKER_SMOKE_RECEIPT", str(tmp_path / "receipt.json"))
        )
        output.write_text(json.dumps(receipt, sort_keys=True) + "\n")
    finally:
        for name in reversed(controllers):
            docker.remove_controller(name)
        # Preserve the private smoke volume; never prune the daemon.
