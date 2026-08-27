from __future__ import annotations

import http.client
import threading
from http.server import ThreadingHTTPServer

from lowerduckpond_m3_qualification.fixture_server import (
    PLATFORM_ORIGIN,
    QualificationRequestHandler,
)

OK_STATUS = 200
HOSTILE_COOKIE_COUNT = 2


def test_fixture_reports_state_without_echoing_it() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), QualificationRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        connection.request(
            "GET",
            "/probe",
            headers={"Cookie": "private=value", "Sec-Fetch-Site": "cross-site"},
        )
        response = connection.getresponse()
        body = response.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

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
