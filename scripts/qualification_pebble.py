"""Bounded, checksum-pinned downloads for the disposable DNS-01 ACME fixture."""

from __future__ import annotations

import hashlib
import time
from http import HTTPStatus
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

PINNED = {
    "pebble": "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed",
    "pebble-challtestsrv": "e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92",
}
MAXIMUM_BYTES = 32 * 1024 * 1024
ATTEMPTS = 3
RETRYABLE = {
    HTTPStatus.REQUEST_TIMEOUT,
    HTTPStatus.TOO_MANY_REQUESTS,
    HTTPStatus.INTERNAL_SERVER_ERROR,
    HTTPStatus.BAD_GATEWAY,
    HTTPStatus.SERVICE_UNAVAILABLE,
    HTTPStatus.GATEWAY_TIMEOUT,
}


def download(name: str) -> bytes:
    """Retry transient release-host failures without accepting unverified bytes."""
    digest = PINNED[name]
    url = (
        f"https://github.com/letsencrypt/pebble/releases/download/v2.10.1/{name}-linux-amd64.tar.gz"
    )
    for attempt in range(ATTEMPTS):
        try:
            with urlopen(url, timeout=30) as response:
                data: bytes = response.read(MAXIMUM_BYTES + 1)
        except HTTPError as error:
            error.close()
            if error.code not in RETRYABLE or attempt == ATTEMPTS - 1:
                raise
        except URLError, TimeoutError, ConnectionError, IncompleteRead:
            if attempt == ATTEMPTS - 1:
                raise
        else:
            if len(data) > MAXIMUM_BYTES or hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("Pebble release archive failed checksum verification")
            return data
        time.sleep(2**attempt)
    raise AssertionError("Pebble download retry loop exhausted")  # pragma: no cover
