"""Disposable Cloudflare adapter and TLS proxy in front of pinned Pebble.

Runs only inside the run-owned fixture. Pebble performs the ACME protocol and
real DNS-01 validation; this adapter never signs certificates or approves an
authorization. No HTTP-01/TLS-ALPN listener or validation bypass is enabled.
"""

from __future__ import annotations

import http.client
import json
import ssl
import subprocess
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path("/root/restore-acme")
ZONES = {"lowerduckpond.com": "1" * 32, "lowerduckpond.net": "2" * 32}
TOKEN = "0" * 40
MAX_BODY = 256 * 1024
MAX_TXT = 128
RECORD_PARTS = 5
CONTROL_PORT = 8056


class State:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, str | int]] = {}
        self.created = 0
        self.deleted = 0
        self.acme_requests = 0
        self.denied_dns = 0
        self.denied_acme = 0
        self.fault = "none"
        self.lock = threading.Lock()

    def dns(self, action: str, body: dict[str, str]) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", 8055, timeout=10)
        try:
            connection.request("POST", action, json.dumps(body))
            response = connection.getresponse()
            response.read(MAX_BODY)
            if response.status != HTTPStatus.OK:
                raise ValueError("controlled DNS update failed")
        finally:
            connection.close()

    def synchronize(self, name: str) -> None:
        self.dns("/clear-txt", {"host": name + "."})
        for record in self.records.values():
            if record["name"] == name:
                self.dns("/set-txt", {"host": name + ".", "value": str(record["content"])})

    def cloudflare(self, method: str, path: str, body: bytes) -> object:
        parsed = urlsplit(path)
        parts = parsed.path.strip("/").split("/")
        query = parse_qs(parsed.query)
        if parts == ["client", "v4", "zones"] and method == "GET":
            return [
                {"id": identity, "name": name, "status": "active"}
                for name, identity in ZONES.items()
                if query.get("name", [name]) == [name]
            ]
        if (
            len(parts) not in (5, 6)
            or parts[:3] != ["client", "v4", "zones"]
            or parts[3] not in ZONES.values()
            or parts[4] != "dns_records"
        ):
            raise ValueError("unsupported fixture DNS request")
        zone = next(name for name, identity in ZONES.items() if identity == parts[3])
        if method == "GET":
            return [
                record
                for record in self.records.values()
                if record["zone_id"] == parts[3]
                and query.get("name", [record["name"]]) == [record["name"]]
                and query.get("type", [record["type"]]) == [record["type"]]
            ]
        if method == "POST" and len(parts) == RECORD_PARTS:
            value = json.loads(body)
            if (
                value.get("type") != "TXT"
                or value.get("name", "").rstrip(".") != f"_acme-challenge.{zone}"
                or not isinstance(value.get("content"), str)
                or not 1 <= len(value["content"]) <= MAX_TXT
            ):
                raise ValueError("request is outside the disposable DNS-01 scope")
            self.created += 1
            identity = f"{self.created:032x}"
            record = {
                "id": identity,
                "zone_id": parts[3],
                "zone_name": zone,
                "type": "TXT",
                "name": f"_acme-challenge.{zone}",
                "content": value["content"],
                "ttl": 120,
            }
            self.records[identity] = record
            self.synchronize(str(record["name"]))
            return record
        if method == "DELETE" and len(parts) == RECORD_PARTS + 1:
            record = self.records[parts[5]]
            if record["zone_id"] != parts[3]:
                raise ValueError("DNS record belongs to another zone")
            del self.records[parts[5]]
            self.synchronize(str(record["name"]))
            self.deleted += 1
            return {"id": parts[5]}
        raise ValueError("unsupported fixture DNS method")


STATE = State()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # The native Pebble logs are retained privately. Do not log JWS/TXT data.
        return

    def reply(self, status: int, value: object) -> None:
        body = json.dumps(value, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def dispatch(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= MAX_BODY:
            self.reply(413, {})
            return
        body = self.rfile.read(length)
        with STATE.lock:
            if self.server.server_port == CONTROL_PORT:
                if self.command == "POST" and self.path == "/fault":
                    fault = json.loads(body)["fault"]
                    if fault not in {"none", "dns", "acme"}:
                        raise ValueError("invalid fixture fault")
                    STATE.fault = fault
                self.reply(
                    200,
                    {
                        "fault": STATE.fault,
                        "created": STATE.created,
                        "deleted": STATE.deleted,
                        "remaining": len(STATE.records),
                        "acmeRequests": STATE.acme_requests,
                        "deniedDns": STATE.denied_dns,
                        "deniedAcme": STATE.denied_acme,
                    },
                )
                return
            host = self.headers.get("Host")
            if host == "api.cloudflare.com":
                if STATE.fault == "dns" or self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    STATE.denied_dns += 1
                    self.reply(403, {"success": False, "errors": [{"code": 10000}]})
                    return
                value = STATE.cloudflare(self.command, self.path, body)
                self.reply(
                    200,
                    {
                        "success": True,
                        "errors": [],
                        "messages": [],
                        "result": value,
                        "result_info": {"page": 1, "total_pages": 1, "per_page": 100},
                    },
                )
                return
            if host != "acme-v02.api.letsencrypt.org":
                self.reply(421, {})
                return
            if STATE.fault == "acme":
                STATE.denied_acme += 1
                self.reply(503, {"type": "urn:ietf:params:acme:error:serverInternal"})
                return
            STATE.acme_requests += 1
        context = ssl.create_default_context(cafile=str(ROOT / "proxy-ca.crt"))
        # The upstream leaf includes localhost; the proxy still verifies it.
        connection = http.client.HTTPSConnection("localhost", 14000, context=context, timeout=20)
        try:
            connection.request(
                self.command,
                "/dir" if self.path == "/directory" else self.path,
                body,
                {
                    "Host": host,
                    "Content-Type": self.headers.get("Content-Type", ""),
                    "X-Forwarded-Proto": "https",
                },
            )
            response = connection.getresponse()
            data = response.read(MAX_BODY + 1)
            if len(data) > MAX_BODY:
                raise ValueError("oversized fixture ACME response")
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {"connection", "transfer-encoding", "content-length"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        finally:
            connection.close()

    def do_GET(self) -> None:
        self.dispatch()

    def do_HEAD(self) -> None:
        self.dispatch()

    def do_POST(self) -> None:
        self.dispatch()

    def do_DELETE(self) -> None:
        self.dispatch()


def main() -> None:
    sys.path.insert(0, str(ROOT))
    from restore_dns_server import serve  # noqa: PLC0415 - fixture-local module

    serve((ROOT / "address").read_text().strip())
    processes = []
    try:
        for name, args in (
            (
                "pebble-challtestsrv",
                [
                    "-http01",
                    "",
                    "-https01",
                    "",
                    "-tlsalpn01",
                    "",
                    "-defaultIPv4",
                    "127.0.0.1",
                    "-defaultIPv6",
                    "",
                ],
            ),
            ("pebble", ["-config", str(ROOT / "pebble.json"), "-dnsserver", "127.0.0.1:8054"]),
        ):
            with (ROOT / f"{name}.log").open("xb") as log:
                processes.append(
                    subprocess.Popen(  # noqa: S603 - fixed pinned fixture binaries
                        [str(ROOT / name), *args],
                        stdout=log,
                        stderr=log,
                        env={"PATH": "/usr/bin:/bin", "PEBBLE_VA_NOSLEEP": "1"},
                    )
                )
        control = ThreadingHTTPServer(("127.0.0.1", 8056), Handler)
        threading.Thread(target=control.serve_forever, daemon=True).start()
        server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)  # noqa: S104 - isolated fixture
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(ROOT / "proxy.crt"), str(ROOT / "proxy.key"))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            process.wait(timeout=10)


if __name__ == "__main__":
    main()
