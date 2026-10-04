"""Concurrent launchers must reserve the daemon before creating any run state."""

from __future__ import annotations

import dataclasses
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_unattended import __main__ as cli
from scripts.m3_11_unattended import approval, docker
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.model import LifecycleError, stamp

from .test_m3_11_unattended_controller import DAEMON, configuration


class Daemon:
    def __init__(self) -> None:
        self.mutex = threading.Lock()
        self.reserved = False
        self.controllers: list[str] = []

    def info(self) -> dict[str, str]:
        return DAEMON

    def command(self, *arguments: str) -> bytes:
        with self.mutex:
            if arguments[0] == "create":
                assert arguments[arguments.index("--name") + 1] == docker.ADMISSION
                if self.reserved:
                    raise LifecycleError("name is already reserved")
                self.reserved = True
                return b"a" * 64
            assert arguments[0] == "ps" and self.reserved
            return "\n".join(self.controllers).encode()

    def remove_controller(self, selected: str) -> None:
        with self.mutex:
            assert selected == "a" * 64 and self.reserved
            self.reserved = False


def test_concurrent_starts_fail_before_initialization_and_cannot_queue_an_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    daemon = Daemon()
    config = configuration()
    source = "e" * 40
    now = datetime.now(UTC)
    approved = {
        "format": approval.FORMAT,
        "prepared": {
            "source_revision": source,
            "helper_revision": source,
            "controller_image": "sha256:" + "b" * 64,
            "artifact_sha256": "c" * 64,
            "daemon": DAEMON,
        },
        "targets": dataclasses.asdict(config.targets),
        "qualification_inputs_sha256": "d" * 64,
        "modes": ["rehearsal"],
        "approved_at": stamp(now - timedelta(seconds=1)),
        "expires_at": stamp(now + timedelta(hours=1)),
        "credential_lifetime_hours": 14,
        "approval_reference": "concurrency fixture",
    }
    monkeypatch.setattr(cli, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(cli, "fingerprint", lambda *_args: "d" * 64)
    monkeypatch.setattr(Configuration, "load", lambda _path: config)
    entered, release = threading.Event(), threading.Event()
    requests: list[dict[str, object]] = []

    def initialize(_docker: docker.Docker, **arguments: object) -> None:
        assert daemon.reserved
        request = arguments["request"]
        assert isinstance(request, bytes)
        requests.append(json.loads(request))
        entered.set()
        assert release.wait(timeout=10)

    def launch(_docker: docker.Docker, **arguments: object) -> None:
        assert daemon.reserved
        daemon.controllers.append(docker.controller_name(str(arguments["run_id"])))

    monkeypatch.setattr(cli, "initialize_run", initialize)
    monkeypatch.setattr(cli, "launch", launch)
    monkeypatch.setattr(cli, "operate", lambda *_args: b'{"status":{"phase":"starting"}}')

    def start() -> str:
        return cli.start(
            cast(docker.Docker, daemon),
            approved=approved,
            config=tmp_path / "unused.json",
            source=source,
            mode="rehearsal",
            daemon_socket=docker.SOCKET,
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(start)
        try:
            assert entered.wait(timeout=10)
            with pytest.raises(LifecycleError, match="reserved"):
                start()
            assert len(requests) == 1
        finally:
            release.set()
        run_id = first.result(timeout=10)
    assert requests[0]["daemon"] == DAEMON
    assert daemon.controllers == [docker.controller_name(run_id)]
    assert not daemon.reserved
    # Once the reservation is released, the active controller still blocks a
    # new launcher; no rejected invocation can resume later on its own.
    with pytest.raises(LifecycleError, match="active attempt"):
        start()
    assert len(requests) == 1
    assert not daemon.reserved


def test_failed_launcher_releases_its_own_admission_reservation() -> None:
    daemon = Daemon()
    with (
        pytest.raises(LifecycleError, match="delivery failed"),
        docker.admission(cast(docker.Docker, daemon), image="sha256:" + "b" * 64),
    ):
        raise LifecycleError("delivery failed")
    assert not daemon.reserved
