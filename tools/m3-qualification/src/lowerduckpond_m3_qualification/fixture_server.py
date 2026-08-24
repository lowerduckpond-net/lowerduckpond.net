"""Loopback-only hostile upstream for the live Caddy qualification fixture."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

PLATFORM_ORIGIN: Final = "https://m3-qualification.lowerduckpond.net"


class QualificationRequestHandler(BaseHTTPRequestHandler):
    """Return bounded state observations and an intentionally unsafe response."""

    server_version = "LowerDuckPondQualification/1"
    sys_version = ""

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/probe":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        state_received = bool(self.headers.get("Cookie"))
        fetch_site = self.headers.get("Sec-Fetch-Site", "none")
        body = b"lowerduckpond-m3-cookie-independent-body\n"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", PLATFORM_ORIGIN)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Expose-Headers", "X-M3-Sec-Fetch-Site")
        self.send_header("Vary", "Origin")
        self.send_header("X-M3-Upstream-Saw-State", str(state_received).lower())
        self.send_header("X-M3-Sec-Fetch-Site", fetch_site)
        self.send_header(
            "Set-Cookie",
            "ldp_m3_upstream=must-be-removed; Domain=lowerduckpond.com; Path=/; Secure",
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string: str, *args: object) -> None:
        del format_string, args


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", default=18080, type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    server = ThreadingHTTPServer((arguments.bind, arguments.port), QualificationRequestHandler)
    print(json.dumps({"event": "ready", "port": arguments.port}), flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
