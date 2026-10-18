"""Bounded diagnostic facts, never exception payloads or provider-controlled text."""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
import urllib.error
from dataclasses import dataclass, field

MAX_CHAIN = 8
MAX_CONNECTIONS = 8
MAX_CODE = 65535
# Exact types keep dynamically named subclasses out of diagnostics.
EXCEPTIONS = {
    ExceptionGroup: "ExceptionGroup",
    BaseExceptionGroup: "BaseExceptionGroup",
    OSError: "OSError",
    TimeoutError: "TimeoutError",
    ConnectionError: "ConnectionError",
    ConnectionResetError: "ConnectionResetError",
    ConnectionRefusedError: "ConnectionRefusedError",
    ConnectionAbortedError: "ConnectionAbortedError",
    BrokenPipeError: "BrokenPipeError",
    socket.gaierror: "gaierror",
    socket.herror: "herror",
    ssl.SSLError: "SSLError",
    ssl.SSLCertVerificationError: "SSLCertVerificationError",
    ssl.SSLEOFError: "SSLEOFError",
    ssl.SSLZeroReturnError: "SSLZeroReturnError",
    urllib.error.URLError: "URLError",
    urllib.error.HTTPError: "HTTPError",
    http.client.RemoteDisconnected: "RemoteDisconnected",
    http.client.IncompleteRead: "IncompleteRead",
    http.client.BadStatusLine: "BadStatusLine",
    http.client.HTTPException: "HTTPException",
    UnicodeDecodeError: "UnicodeDecodeError",
    json.JSONDecodeError: "JSONDecodeError",
}


def exception_chain(error: BaseException | None) -> dict[str, object]:
    """Keep reason/cause/context relationships without copying strings or locals."""
    pending: list[tuple[BaseException, str, int | None]] = (
        [(error, "root", None)] if error is not None else []
    )
    seen: set[int] = set()
    nodes: list[dict[str, object]] = []
    repeated = False
    truncated = False
    while pending and len(nodes) < MAX_CHAIN:
        current, relation, parent = pending.pop(0)
        if id(current) in seen:
            repeated = True
            continue
        seen.add(id(current))
        node: dict[str, object] = {
            "type": EXCEPTIONS.get(type(current), "unknown"),
            "relation": relation,
            "parent": parent,
        }
        # Never coerce provider/exception attributes: even their __str__ can leak.
        for name in ("errno", "verify_code"):
            code = getattr(current, name, None) if type(current) in EXCEPTIONS else None
            if type(code) is int and -MAX_CODE <= code <= MAX_CODE:
                node[name] = code
        index = len(nodes)
        nodes.append(node)
        if type(current) in {ExceptionGroup, BaseExceptionGroup}:
            assert isinstance(current, BaseExceptionGroup)  # noqa: S101 - exact types above
            truncated |= len(current.exceptions) > MAX_CHAIN
            pending.extend((child, "member", index) for child in current.exceptions[:MAX_CHAIN])
        reason = current.reason if type(current) is urllib.error.URLError else None
        for linked, relationship in (
            (reason, "reason"),
            (current.__cause__, "cause"),
            (current.__context__, "context"),
        ):
            if isinstance(linked, BaseException):
                pending.append((linked, relationship, index))
    return {"nodes": nodes, "truncated": truncated or bool(pending), "repeated": repeated}


@dataclass
class ReadDiagnostic:
    socket_timeout_seconds: int
    # Resolve the clock at capture, including when tests supply a synthetic clock.
    started: float = field(default_factory=lambda: time.monotonic())  # noqa: PLW0108
    stage: str = "open"
    http_status: int | None = None
    response_bytes: int | None = None
    connections: list[dict[str, object]] = field(default_factory=list)
    connection_count: int = 0

    def connection(self, *, tunnel: bool) -> dict[str, object]:
        self.connection_count += 1
        value: dict[str, object] = {
            "sequence": self.connection_count,
            "target": "proxy" if tunnel else "origin",
            "stage": "resolve-connect",
            # A successful connection does not expose previous candidate failures.
            "failed_candidates": None,
        }
        if len(self.connections) == MAX_CONNECTIONS:
            # Keep the first observations and the latest, potentially failed, hop.
            self.connections[-1] = value
        else:
            self.connections.append(value)
        return value

    def status(self, value: object) -> None:
        # HTTP status is the only retained header metadata. No header values,
        # request IDs, reason phrases, redirects or response bodies are copied.
        if type(value) is int and 100 <= value <= 599:  # noqa: PLR2004 - HTTP range
            self.http_status = value

    def document(self, error: BaseException | None = None) -> dict[str, object]:
        return {
            "format": "lowerduckpond-cloudflare-read-diagnostic-v1",
            "stage": self.stage,
            "elapsed_seconds": round(max(0, time.monotonic() - self.started), 6),
            "attempt": 1,
            "socket_timeout_seconds": self.socket_timeout_seconds,
            "http_status": self.http_status,
            "response_bytes": self.response_bytes,
            "exception_chain": exception_chain(error),
            "connections": self.connections,
            "connection_count": self.connection_count,
            "connections_truncated": self.connection_count > MAX_CONNECTIONS,
        }
