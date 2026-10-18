"""Request-local connection diagnostics using the ordinary urllib HTTPS path.

No address, hostname, exception message, URL, header or body is retained here.
The standard resolver/address order, proxy selection, TLS context and socket
timeouts are preserved. This performs no application retry or extra probe.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.request
from functools import partial
from typing import cast

from scripts.cloudflare_read_diagnostics import ReadDiagnostic, exception_chain


class _HTTPSConnection(http.client.HTTPSConnection):
    # These stdlib hooks are not included in typeshed's public interface.
    _tunnel_host: str | None

    def __init__(
        self,
        host: str,
        *,
        timeout: float,
        context: ssl.SSLContext | None,
        diagnostic: ReadDiagnostic,
    ) -> None:
        super().__init__(host, timeout=timeout, context=context)
        self._diagnostic = diagnostic
        self._observation: dict[str, object] = {}
        self._create_connection = self._connect_socket

    def _connect_socket(
        self, address: tuple[str, int], timeout: float, source_address: tuple[str, int] | None
    ) -> socket.socket:
        started = time.monotonic()
        try:
            # The default path discards all but the last address-level OSError.
            # Keep safe group facts, then re-raise that same last error so urllib
            # still closes the connection and wraps it in URLError as before.
            connected = socket.create_connection(address, timeout, source_address, all_errors=True)
            # TCP_NODELAY setup and TLS wrapping still follow in the stdlib.
            self._observation["stage"] = "after-tcp-connect"
            return connected
        except ExceptionGroup as error:
            self._observation["failed_candidates"] = len(error.exceptions)
            self._observation["candidate_errors"] = exception_chain(error)
            raise error.exceptions[-1] from None
        finally:
            self._observation["resolve_connect_elapsed_seconds"] = round(
                max(0, time.monotonic() - started), 6
            )

    def _tunnel(self) -> None:
        self._observation["stage"] = "proxy-tunnel"
        super()._tunnel()  # type: ignore[misc]  # stdlib private connection hook
        self._observation["stage"] = "after-proxy-tunnel"

    def connect(self) -> None:
        self._observation = self._diagnostic.connection(tunnel=bool(self._tunnel_host))
        started = time.monotonic()
        try:
            super().connect()
            self._observation["stage"] = "connected"
        except (OSError, http.client.HTTPException) as error:
            self._observation["exception_chain"] = exception_chain(error)
            raise
        finally:
            self._observation["elapsed_seconds"] = round(max(0, time.monotonic() - started), 6)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    _context: ssl.SSLContext | None

    def __init__(self, diagnostic: ReadDiagnostic) -> None:
        super().__init__()
        self._diagnostic = diagnostic

    def https_open(self, request: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            partial(_HTTPSConnection, diagnostic=self._diagnostic),
            request,
            context=self._context,
        )


def open_request(
    request: urllib.request.Request, *, timeout: int, diagnostic: ReadDiagnostic
) -> http.client.HTTPResponse:
    # build_opener keeps the default environment ProxyHandler and TLS trust.
    # Never install a global opener or monkeypatch global socket/http classes.
    opener = urllib.request.build_opener(_HTTPSHandler(diagnostic))
    return cast(http.client.HTTPResponse, opener.open(request, timeout=timeout))
