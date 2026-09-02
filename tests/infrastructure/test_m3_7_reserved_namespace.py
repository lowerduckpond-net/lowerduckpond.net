from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from lowerduckpond_m3_qualification.reserved_namespace import (
    BLOCKED_RESERVED_PATHS,
    PROVIDER_TRACE_PATH,
    NamespaceResponse,
    ReservedNamespaceError,
)

from scripts import check_m3_7_reserved_namespace as production_check


def test_production_request_carries_the_journal_correlation_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "m3-7-reserved-0123456789abcdef0123456789abcdef"
    observed: list[tuple[str, str, dict[str, str]]] = []

    class Response:
        status = 403

        @staticmethod
        def read(limit: int) -> bytes:
            assert limit == production_check.MAXIMUM_RESPONSE_BYTES + 1
            return b"blocked"

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return [("Server", "cloudflare")]

    class Connection:
        def __init__(self, hostname: str, *, timeout: int) -> None:
            assert hostname == "lowerduckpond.net"
            assert timeout == production_check.HTTP_TIMEOUT_SECONDS

        @staticmethod
        def request(method: str, path: str, *, headers: dict[str, str]) -> None:
            observed.append((method, path, headers))

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(production_check.http.client, "HTTPSConnection", Connection)

    response = production_check._request("lowerduckpond.net", "/cdn-cgi", marker)

    assert response.status == Response.status
    assert observed == [
        (
            "GET",
            f"/cdn-cgi?ldp_m3_reserved_probe={marker}",
            {
                "Cache-Control": "no-cache",
                "User-Agent": "lowerduckpond-m3-production-acceptance/1",
            },
        )
    ]


def test_production_check_uses_both_exact_apex_hostnames() -> None:
    marker = "m3-7-reserved-0123456789abcdef0123456789abcdef"
    observed: list[tuple[str, str, str]] = []
    journal_markers: list[str] = []
    delays: list[float] = []

    def request(hostname: str, path: str, request_marker: str) -> NamespaceResponse:
        observed.append((hostname, path, request_marker))
        if path == PROVIDER_TRACE_PATH:
            return NamespaceResponse(
                status=200,
                fields={"server": "cloudflare", "content-type": "text/plain"},
                content=b"fl=test\ncolo=DFW\n",
            )
        return NamespaceResponse(status=403, fields={}, content=b"blocked")

    production_check.run(
        request=request,
        origin_was_reached=lambda request_marker: journal_markers.append(request_marker) or False,
        marker=marker,
        settle=delays.append,
    )

    assert observed == [
        (hostname, path, marker)
        for hostname in production_check.PRODUCTION_HOSTNAMES
        for path in (*BLOCKED_RESERVED_PATHS, PROVIDER_TRACE_PATH)
    ]
    assert journal_markers == [marker]
    assert delays == [production_check.JOURNAL_SETTLE_SECONDS]


def test_production_check_fails_when_a_probe_reaches_caddy() -> None:
    marker = "m3-7-reserved-fedcba9876543210fedcba9876543210"

    def request(hostname: str, path: str, request_marker: str) -> NamespaceResponse:
        assert request_marker == marker
        if path == PROVIDER_TRACE_PATH:
            return NamespaceResponse(
                status=200,
                fields={"server": "cloudflare", "content-type": "text/plain"},
                content=b"fl=test\ncolo=DFW\n",
            )
        return NamespaceResponse(status=403, fields={}, content=b"blocked")

    with pytest.raises(ReservedNamespaceError, match="reached production Caddy"):
        production_check.run(
            request=request,
            origin_was_reached=lambda request_marker: request_marker == marker,
            marker=marker,
            settle=lambda _: None,
        )


def test_origin_probe_uses_the_pinned_production_ssh_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = "m3-7-reserved-0123456789abcdef0123456789abcdef"
    private_key = tmp_path / "production-key"
    private_key.touch(mode=0o600)
    monkeypatch.setenv("ANSIBLE_PRIVATE_KEY_FILE", str(private_key))
    monkeypatch.setenv("PRODUCTION_ORIGIN_IPV4", "8.8.8.8")
    observed: list[tuple[str, ...]] = []

    def run(
        command: tuple[str, ...],
        *,
        check: bool,
        capture_output: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        observed.append(command)
        assert not check
        assert capture_output
        assert timeout == production_check.SSH_TIMEOUT_SECONDS
        return subprocess.CompletedProcess(command, 1, stdout=b"", stderr=b"")

    monkeypatch.setattr(production_check.subprocess, "run", run)

    assert not production_check._origin_was_reached(marker)
    assert observed == [
        (
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "HostKeyAlias=lowerduckpond.net",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-i",
            str(private_key),
            "ldp-admin@8.8.8.8",
            "sudo",
            "--non-interactive",
            "/usr/bin/journalctl",
            "--unit=caddy.service",
            "--since=-2min",
            "--lines=32",
            "--no-pager",
            "--output=cat",
            f"--grep={marker}",
        )
    ]


def test_origin_probe_fails_closed_when_the_journal_contains_the_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = "m3-7-reserved-0123456789abcdef0123456789abcdef"
    private_key = tmp_path / "production-key"
    private_key.touch(mode=0o600)
    monkeypatch.setenv("ANSIBLE_PRIVATE_KEY_FILE", str(private_key))
    monkeypatch.setenv("PRODUCTION_ORIGIN_IPV4", "8.8.8.8")
    monkeypatch.setattr(
        production_check.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout=f'{{"request":{{"uri":"/?{marker}"}}}}\n'.encode(), stderr=b""
        ),
    )

    assert production_check._origin_was_reached(marker)


def test_origin_probe_rejects_a_journal_or_transport_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = "m3-7-reserved-0123456789abcdef0123456789abcdef"
    private_key = tmp_path / "production-key"
    private_key.touch(mode=0o600)
    monkeypatch.setenv("ANSIBLE_PRIVATE_KEY_FILE", str(private_key))
    monkeypatch.setenv("PRODUCTION_ORIGIN_IPV4", "8.8.8.8")
    monkeypatch.setattr(
        production_check.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, stdout=b"", stderr=b"journal read failed\n"
        ),
    )

    with pytest.raises(ReservedNamespaceError, match="journal read failed"):
        production_check._origin_was_reached(marker)
