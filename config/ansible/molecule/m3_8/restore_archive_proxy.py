"""Owned negative fixture: deny or corrupt one real exact-version S3 download.

Only the destination's connection is redirected here. Lists pass through to
MinIO, both TLS legs verify the fixture's original CA, and writes are refused.
No credential or request bytes are logged. The production helper is unchanged.
"""

from __future__ import annotations

import http.client
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path("/root/restore-archive")
LIMIT = 120 * 1024 * 1024
CHUNK = 1024 * 1024
LOCK = threading.Lock()


def fault_for(path: str, policy: dict[str, object]) -> str:
    parsed = urlsplit(path)
    exact = unquote(parsed.path) == f"/{policy['bucket']}/{policy['key']}" and parse_qs(
        parsed.query
    ) == {"versionId": [policy["versionId"]]}
    fault = policy["fault"]
    if fault not in {"deny", "corrupt"}:
        raise ValueError("unknown archive fixture fault")
    return str(fault) if exact else "none"


def damage(chunk: bytes, *, fault: str, first: bool) -> bytes:
    if fault == "corrupt" and first and chunk:
        return bytes([chunk[0] ^ 1]) + chunk[1:]
    return chunk


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:
        if self.headers.get("Host") != "ams3.digitaloceanspaces.com":
            self.send_error(421)
            return
        with LOCK:
            policy = json.loads((ROOT / "fault.json").read_bytes())
            fault = fault_for(self.path, policy)
            if fault != "none":
                # This receipt proves that the installed process reached the
                # exact version, rather than failing at unrelated setup.
                (ROOT / "observed").write_text(fault)
        if fault == "deny":
            body = (
                b"<Error><Code>AccessDenied</Code><Message>Owned fixture denial</Message></Error>"
            )
            self.send_response(403)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        connection = http.client.HTTPSConnection(
            "ams3.digitaloceanspaces.com",
            context=ssl.create_default_context(cafile=str(ROOT / "ca.crt")),
            timeout=30,
        )
        try:
            connection.request("GET", self.path, headers=dict(self.headers))
            response = connection.getresponse()
            if fault == "corrupt" and response.status != 200:  # noqa: PLR2004 - HTTP
                raise ValueError("corruption requires a successful real version download")
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding"}:
                    self.send_header(key, value)
            self.end_headers()
            total = 0
            while chunk := response.read(CHUNK):
                first = total == 0
                total += len(chunk)
                if total > LIMIT:
                    raise ValueError("fixture response exceeds archive limit")
                self.wfile.write(damage(chunk, fault=fault, first=first))
            if fault == "corrupt":
                with LOCK:
                    (ROOT / "observed").write_text("corrupt-downloaded")
        finally:
            connection.close()


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)  # noqa: S104 - owned container
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(ROOT / "public.crt"), str(ROOT / "private.key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
