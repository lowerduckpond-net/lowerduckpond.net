from __future__ import annotations

import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from config.ansible.molecule.m3_8 import prepare_archive_storage as archive
from config.ansible.molecule.m3_8.prepare_archive_storage import _certificates


def test_readiness_reports_changing_causes_without_process_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = iter(
        [
            subprocess.CompletedProcess([], 1, b"", b"connection refused secret-in-stderr"),
            subprocess.CompletedProcess(
                [], 2, b"secret-in-stdout", b"certificate signed by unknown authority"
            ),
        ]
    )
    monkeypatch.setattr(archive, "_READY_ATTEMPTS", 2)
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: next(results))
    monkeypatch.setattr(time, "sleep", lambda _: None)
    with pytest.raises(RuntimeError) as error:
        archive._wait_for_archive(["docker", "exec", "fixture", "mc"])
    message = str(error.value)
    assert "first: exit=1, cause=connection refused" in message
    assert "last: exit=2, cause=untrusted certificate" in message
    assert "secret-in-stderr" not in message
    assert "secret-in-stdout" not in message
    assert archive._ROOT_SECRET not in message


def test_readiness_accepts_later_success(monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter(
        [
            subprocess.CompletedProcess([], 1, b"", b"connection refused"),
            subprocess.CompletedProcess([], 0, b"", b""),
        ]
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: next(results))
    monkeypatch.setattr(time, "sleep", lambda _: None)
    archive._wait_for_archive(["mc"])


def test_readiness_timeout_hides_command_and_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired([archive._ROOT_SECRET], 10, stderr=b"secret-in-stderr")

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="readiness probe timed out") as error:
        archive._wait_for_archive(["mc"])
    assert archive._ROOT_SECRET not in str(error.value)
    assert error.value.__suppress_context__


def test_disposable_archive_chain_passes_strict_tls_without_replacing_existing_certificates(
    tmp_path: Path,
) -> None:
    root = tmp_path / "certificates"
    _certificates(root)
    original = {path.name: path.read_bytes() for path in root.iterdir()}
    _certificates(root)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == original
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(root / "public.crt", root / "private.key")
    client_context = ssl.create_default_context(cafile=str(root / "ca.crt"))
    client_context.verify_flags |= ssl.VERIFY_X509_STRICT
    with socket.socket() as listener:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve() -> None:
            connection, _ = listener.accept()
            connection.settimeout(5)
            with server_context.wrap_socket(connection, server_side=True) as stream:
                assert stream.recv(1) == b"?"
                stream.sendall(b"!")

        with ThreadPoolExecutor(max_workers=1) as executor:
            serving = executor.submit(serve)
            with (
                socket.create_connection(listener.getsockname(), timeout=5) as connection,
                client_context.wrap_socket(
                    connection, server_hostname="ams3.digitaloceanspaces.com"
                ) as stream,
            ):
                stream.sendall(b"?")
                assert stream.recv(1) == b"!"
            serving.result(timeout=5)
