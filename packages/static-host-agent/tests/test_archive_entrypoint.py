from __future__ import annotations

import os
import socket
from contextlib import nullcontext

import pytest
from lowerduckpond_static_host_agent import archive_entrypoint


@pytest.mark.parametrize("arguments", [["--credentials", "/untrusted/secret"], ["job"], ["export"]])
def test_archive_entrypoint_has_no_caller_selected_inputs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], arguments: list[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        archive_entrypoint,
        "load_archive_configuration",
        lambda: pytest.fail("must not load credentials"),
    )
    assert archive_entrypoint.archive_export_main(arguments) == 64  # noqa: PLR2004 - EX_USAGE
    assert capsys.readouterr().err == "invalid_archive_service_invocation\n"


def test_archive_entrypoint_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        archive_entrypoint,
        "load_archive_configuration",
        lambda: pytest.fail("must not load credentials"),
    )
    assert archive_entrypoint.archive_export_main([]) == 64  # noqa: PLR2004 - EX_USAGE


def test_archive_entrypoint_never_logs_provider_or_credential_exception_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "dup", lambda _descriptor: 0)
    monkeypatch.setattr(socket, "socket", lambda **_kwargs: nullcontext(object()))
    monkeypatch.setattr(
        archive_entrypoint, "StateRepository", lambda *_args, **_kwargs: nullcontext(object())
    )
    monkeypatch.setattr(
        archive_entrypoint, "ExportSpool", lambda *_args, **_kwargs: nullcontext(object())
    )

    def unavailable() -> None:
        raise RuntimeError("sensitive provider request diagnostic")

    monkeypatch.setattr(archive_entrypoint, "load_archive_configuration", unavailable)
    assert archive_entrypoint.archive_export_main([]) == 1
    assert capsys.readouterr().err == "archive_export_service_failed\n"
