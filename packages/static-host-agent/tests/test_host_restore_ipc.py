from __future__ import annotations

import fcntl
import os
import socket
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import host_restore_ipc as ipc
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_ipc import (
    REPLY_SCHEMA,
    receive_message,
    request_archive,
    require_lease,
    require_request,
    send_message,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    LOCK,
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import begin


@pytest.mark.parametrize("fault", ["none", "request", "reply", "phase"])
def test_root_socket_transfers_real_continuously_held_leases(  # noqa: PLR0915 - real fork and lease boundaries
    root: Path, journal: RestoreJournal, tmp_path: Path, fault: str
) -> None:
    selected = tmp_path / "selection.lock"
    selected.touch(mode=0o600)
    descriptor = os.open(selected, os.O_RDONLY | os.O_CLOEXEC)
    fcntl.flock(descriptor, fcntl.LOCK_SH)
    address = tmp_path / "archive.sock"
    child = -1
    try:
        with RestoreStore.locked(root, owner=os.geteuid()) as store:
            begin(store, journal)
            assert store.lease_descriptor is not None

            @contextmanager
            def start(action: str) -> Iterator[None]:
                nonlocal child
                child = os.fork()
                if child != 0:
                    try:
                        yield
                    finally:
                        _, status = os.waitpid(child, 0)
                        child = -1
                        assert os.waitstatus_to_exitcode(status) == 0
                    return
                # Model a separate systemd process, which has neither inherited
                # descriptor. Only SCM_RIGHTS grants these shared open-file leases.
                os.close(descriptor)
                assert store.lease_descriptor is not None
                os.close(store.lease_descriptor)
                with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as stream:
                    stream.settimeout(10)
                    stream.connect(str(address))
                    request, received = receive_message(stream, descriptor_count=2)
                    try:
                        require_lease(root / LOCK, received[0], exclusive=True, owner=os.geteuid())
                        require_lease(selected, received[1], exclusive=False, owner=os.geteuid())
                        with (
                            pytest.raises(BlockingIOError),
                            RestoreStore.locked(root, owner=os.geteuid()),
                        ):
                            pass
                        with DurableDirectory.open(
                            root, expected_owner=os.geteuid(), expected_directory_mode=0o700
                        ) as directory:
                            if fault == "request":
                                request["restoreId"] = "0198d17f-6f4a-7000-8000-000000000002"
                            if fault in {"request", "phase"}:
                                with pytest.raises(HostRestoreError):
                                    require_request(
                                        request,
                                        RestoreStore(directory, os.geteuid()),
                                        journal.bindings["originalArtifact"]["value"],
                                        installed=fault == "phase",
                                    )
                            else:
                                assert (
                                    require_request(
                                        request,
                                        RestoreStore(directory, os.geteuid()),
                                        journal.bindings["originalArtifact"]["value"],
                                        installed=False,
                                    )
                                    == action
                                )
                        send_message(
                            stream,
                            {
                                "schema": REPLY_SCHEMA,
                                "nonce": "0" * 32 if fault == "reply" else request["nonce"],
                                "verified": fault == "none",
                                "evidence": {"proved": True},
                            },
                        )
                    finally:
                        for received_descriptor in received:
                            os.close(received_descriptor)
                os._exit(0)

            if fault == "none":
                assert request_archive(
                    store,
                    descriptor,
                    journal.bindings["originalArtifact"]["value"],
                    "verify",
                    recovery=root,
                    path=address,
                    selection=selected,
                    start=start,
                ) == {"proved": True}
            else:
                with pytest.raises(HostRestoreError, match="helper_unverified"):
                    request_archive(
                        store,
                        descriptor,
                        journal.bindings["originalArtifact"]["value"],
                        "verify",
                        recovery=root,
                        path=address,
                        selection=selected,
                        start=start,
                    )
            assert child == -1
            require_lease(root / LOCK, store.lease_descriptor, exclusive=True, owner=os.geteuid())
            assert not address.exists()
    finally:
        os.close(descriptor)
        if child > 0:
            os.kill(child, 9)
            os.waitpid(child, 0)


def test_unheld_or_replaced_lease_and_unsolicited_descriptors_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "lease"
    path.touch(mode=0o600)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        with pytest.raises(HostRestoreError, match="lease_missing"):
            require_lease(path, descriptor, exclusive=True, owner=os.geteuid())
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        with sender, receiver:
            send_message(sender, {"proof": True}, (descriptor,))
            with pytest.raises(HostRestoreError, match="message_invalid"):
                receive_message(receiver, descriptor_count=0)
            sender.send(canonical_json_bytes({"proof": True}).rstrip(b"\n"))
            with pytest.raises(HostRestoreError, match="noncanonical"):
                receive_message(receiver, descriptor_count=0)
        path.rename(path.with_name("prior"))
        path.touch(mode=0o600)
        with pytest.raises(HostRestoreError, match="lease_unsafe"):
            require_lease(path, descriptor, exclusive=True, owner=os.geteuid())
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("outcome", ["success", "failure", "timeout"])
def test_service_completion_after_reply_is_required_and_client_is_reaped(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    original = subprocess.Popen
    clients: list[subprocess.Popen[bytes]] = []

    def start(command: tuple[str, ...], **kwargs: object) -> subprocess.Popen[bytes]:
        assert command == (
            "/usr/bin/systemctl",
            "start",
            "lowerduckpond-host-restore-archive-private.service",
        )
        # A real child models the start job which outlives the archive reply.
        # Native installed tests exercise the actual oneshot service.
        status = 1 if outcome == "failure" else 0
        code = f"import sys; sys.stdin.buffer.read(1); raise SystemExit({status})"
        process = original(
            (sys.executable, "-I", "-c", code),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        clients.append(process)
        if outcome == "timeout":
            wait = process.wait

            def shortened_wait(timeout: float | None = None) -> int:
                return wait(timeout=0.01 if timeout is not None else timeout)

            monkeypatch.setattr(process, "wait", shortened_wait)
        return process

    monkeypatch.setattr(subprocess, "Popen", start)

    def request() -> None:
        with ipc._archive_service("verify"):
            assert clients[0].poll() is None  # Reply received while start job is pending.
            if outcome != "timeout":
                assert clients[0].stdin is not None
                clients[0].stdin.write(b"x")
                clients[0].stdin.flush()

    if outcome == "success":
        request()
        assert clients[0].returncode == 0
    else:
        category = "start_failed" if outcome == "failure" else "completion_deadline"
        with pytest.raises(HostRestoreError, match=category):
            request()
        assert clients[0].returncode != 0
    assert clients[0].poll() is not None
