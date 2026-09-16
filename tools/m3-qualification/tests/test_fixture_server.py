from __future__ import annotations

import http.client
import socket
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer

import pytest
from lowerduckpond_m3_qualification.fixture_server import (
    PLATFORM_ORIGIN,
    QualificationRequestHandler,
)

OK_STATUS = 200
BAD_REQUEST_STATUS = 400
HOSTILE_COOKIE_COUNT = 2


@pytest.fixture
def fixture_server() -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), QualificationRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_fixture_reports_state_without_echoing_it(fixture_server: ThreadingHTTPServer) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", fixture_server.server_port, timeout=5)
    try:
        connection.request(
            "GET",
            "/probe",
            headers={"Cookie": "private=value", "Sec-Fetch-Site": "cross-site"},
        )
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()

    assert response.status == OK_STATUS
    assert response.getheader("Access-Control-Allow-Origin") == PLATFORM_ORIGIN
    assert response.getheader("Access-Control-Allow-Credentials") == "true"
    assert response.getheader("X-M3-Upstream-Saw-State") == "true"
    assert response.getheader("X-M3-Sec-Fetch-Site") == "cross-site"
    assert len(response.getheaders()) > 1
    cookies = [value for key, value in response.getheaders() if key == "Set-Cookie"]
    assert len(cookies) == HOSTILE_COOKIE_COUNT
    assert b"private" not in body
    assert b"value" not in body


@pytest.mark.parametrize("fetch_site", [None, "none", "same-origin", "same-site", "cross-site"])
def test_fixture_preserves_supported_fetch_metadata(
    fixture_server: ThreadingHTTPServer, fetch_site: str | None
) -> None:
    connection = http.client.HTTPConnection("127.0.0.1", fixture_server.server_port, timeout=5)
    try:
        fields = {} if fetch_site is None else {"Sec-Fetch-Site": fetch_site}
        connection.request("GET", "/probe", headers=fields)
        response = connection.getresponse()
        response.read()
    finally:
        connection.close()

    assert response.status == OK_STATUS
    assert response.getheader("X-M3-Sec-Fetch-Site") == (fetch_site or "none")


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"unrecognized-private-value",
        b"cross-site, same-origin",
        b"cross-site\x00private-value",
        b"cross-site\r\n X-M3-Injected: private-value",
        b"cross-site\n\tX-M3-Injected: private-value",
    ],
)
def test_fixture_rejects_unrecognized_or_folded_fetch_metadata(
    fixture_server: ThreadingHTTPServer, value: bytes
) -> None:
    # Raw HTTP reaches the server parser without the client's newline guard.
    with socket.create_connection(("127.0.0.1", fixture_server.server_port), timeout=5) as stream:
        stream.sendall(
            b"GET /probe HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Site: "
            + value
            + b"\r\nConnection: close\r\n\r\n"
        )
        with http.client.HTTPResponse(stream) as response:
            response.begin()
            body = response.read()
            assert response.status == BAD_REQUEST_STATUS
            assert response.getheader("X-M3-Sec-Fetch-Site") is None
            assert response.getheader("X-M3-Injected") is None
            assert all("private-value" not in item for _, item in response.getheaders())
            assert b"private-value" not in body
