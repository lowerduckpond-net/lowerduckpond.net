from __future__ import annotations

import os
import socket
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import archive_entrypoint


@pytest.fixture(params=["export", "construction", "cleanup"])
def entrypoint(request: pytest.FixtureRequest) -> Callable[[list[str]], int]:
    if request.param == "export":
        return archive_entrypoint.archive_export_main
    if request.param == "cleanup":
        return archive_entrypoint.archive_cleanup_main
    return archive_entrypoint.archive_construction_main


@pytest.mark.parametrize("arguments", [["--credentials", "/untrusted/secret"], ["job"], ["export"]])
def test_archive_entrypoint_has_no_caller_selected_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    entrypoint: Callable[[list[str]], int],
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        archive_entrypoint,
        "load_archive_configuration",
        lambda: pytest.fail("must not load credentials"),
    )
    assert entrypoint(arguments) == 64  # noqa: PLR2004 - EX_USAGE
    assert capsys.readouterr().err == "invalid_archive_service_invocation\n"


def test_archive_entrypoint_requires_root(
    monkeypatch: pytest.MonkeyPatch, entrypoint: Callable[[list[str]], int]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        archive_entrypoint,
        "load_archive_configuration",
        lambda: pytest.fail("must not load credentials"),
    )
    assert entrypoint([]) == 64  # noqa: PLR2004 - EX_USAGE


def test_archive_entrypoint_never_logs_provider_or_credential_exception_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    entrypoint: Callable[[list[str]], int],
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(archive_entrypoint, "_accept_connection", lambda: nullcontext(object()))
    monkeypatch.setattr(
        archive_entrypoint, "StateRepository", lambda *_args, **_kwargs: nullcontext(object())
    )
    monkeypatch.setattr(
        archive_entrypoint, "ExportSpool", lambda *_args, **_kwargs: nullcontext(object())
    )

    def unavailable() -> None:
        raise RuntimeError("sensitive provider request diagnostic")

    monkeypatch.setattr(archive_entrypoint, "load_archive_configuration", unavailable)
    assert entrypoint([]) == 1
    operation = entrypoint.__name__.removeprefix("archive_").removesuffix("_main")
    assert capsys.readouterr().err == f"archive_{operation}_service_failed\n"


def test_each_activation_accepts_only_one_connection_and_preserves_the_queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    duplicate = os.dup
    with (
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as first,
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second,
    ):
        address = str(tmp_path / "s")
        listener.bind(address)
        listener.listen(1)
        monkeypatch.setattr(os, "dup", lambda _descriptor: duplicate(listener.fileno()))
        first.connect(address)
        second.connect(address)
        first.sendall(b"first")
        second.sendall(b"second")
        with archive_entrypoint._accept_connection() as stream:
            assert stream.recv(16) == b"first"
            stream.sendall(b"one")
        assert first.recv(16) == b"one"
        assert first.recv(16) == b""
        second.settimeout(0.01)
        with pytest.raises(TimeoutError):
            second.recv(16)
        # The listener remains usable by the next service invocation, including
        # the already queued connection; closing the first stream cannot flush it.
        with archive_entrypoint._accept_connection() as stream:
            assert stream.recv(16) == b"second"
            stream.sendall(b"two")
        assert second.recv(16) == b"two"
        assert listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1


def test_connected_stdin_is_rejected_before_loading_archive_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    entrypoint: Callable[[list[str]], int],
) -> None:
    duplicate = os.dup
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        archive_entrypoint,
        "load_archive_configuration",
        lambda: pytest.fail("must validate the activation socket before loading credentials"),
    )
    first, second = socket.socketpair()
    with first, second:
        monkeypatch.setattr(os, "dup", lambda _descriptor: duplicate(first.fileno()))
        assert entrypoint([]) == 1
    operation = entrypoint.__name__.removeprefix("archive_").removesuffix("_main")
    assert capsys.readouterr().err == f"archive_{operation}_service_failed\n"


@pytest.mark.parametrize(
    ("family", "kind"),
    [(socket.AF_INET, socket.SOCK_STREAM), (socket.AF_UNIX, socket.SOCK_DGRAM)],
)
def test_activation_rejects_other_socket_families_and_datagrams(
    monkeypatch: pytest.MonkeyPatch, family: int, kind: int
) -> None:
    duplicate = os.dup
    with socket.socket(family, kind) as source:
        monkeypatch.setattr(os, "dup", lambda _descriptor: duplicate(source.fileno()))
        with (
            pytest.raises(ValueError, match="listening Unix stream"),
            archive_entrypoint._accept_connection(),
        ):
            pytest.fail("unsupported activation socket was accepted")


def test_activation_wait_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    duplicate = os.dup
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(tmp_path / "s"))
        listener.listen(1)
        monkeypatch.setattr(os, "dup", lambda _descriptor: duplicate(listener.fileno()))
        monkeypatch.setattr(archive_entrypoint, "_ACCEPT_TIMEOUT", 0.01)
        with pytest.raises(TimeoutError), archive_entrypoint._accept_connection():
            pytest.fail("activation without a waiting client was accepted")
