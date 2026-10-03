"""Release-host outages may retry; corrupt or permanent responses must fail."""

from __future__ import annotations

import hashlib
import time
from email.message import Message
from http.client import IncompleteRead
from io import BytesIO
from urllib.error import HTTPError, URLError

import pytest

from scripts import qualification_pebble as pebble


def unavailable(code: int = 503) -> HTTPError:
    return HTTPError("https://example.invalid/release", code, "unavailable", Message(), BytesIO())


@pytest.mark.parametrize(
    "error",
    [unavailable(), URLError("temporary DNS failure"), TimeoutError(), IncompleteRead(b"x")],
)
def test_transient_download_failure_retries_pinned_release(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    data = b"verified fixture archive"
    monkeypatch.setitem(pebble.PINNED, "pebble", hashlib.sha256(data).hexdigest())
    calls: list[tuple[str, int]] = []
    delays: list[float] = []

    def open_release(url: str, *, timeout: int) -> BytesIO:
        calls.append((url, timeout))
        if len(calls) == 1:
            raise error
        return BytesIO(data)

    monkeypatch.setattr(pebble, "urlopen", open_release)
    monkeypatch.setattr(time, "sleep", delays.append)
    assert pebble.download("pebble") == data
    assert (
        calls
        == [
            (
                "https://github.com/letsencrypt/pebble/releases/download/v2.10.1/pebble-linux-amd64.tar.gz",
                30,
            )
        ]
        * 2
    )
    assert delays == [1]


@pytest.mark.parametrize("code, attempts", [(503, 3), (404, 1), (403, 1)])
def test_download_failure_is_bounded(
    monkeypatch: pytest.MonkeyPatch, code: int, attempts: int
) -> None:
    errors: list[HTTPError] = []
    delays: list[float] = []

    def open_release(url: str, *, timeout: int) -> BytesIO:
        error = unavailable(code)
        errors.append(error)
        raise error

    monkeypatch.setattr(pebble, "urlopen", open_release)
    monkeypatch.setattr(time, "sleep", delays.append)
    with pytest.raises(HTTPError) as failure:
        pebble.download("pebble")
    assert failure.value.code == code
    assert len(errors) == attempts
    assert all(error.closed for error in errors)
    assert delays == [1, 2][: attempts - 1]


@pytest.mark.parametrize("oversized", [False, True])
def test_unverified_download_never_retries(
    monkeypatch: pytest.MonkeyPatch, oversized: bool
) -> None:
    data = b"untrusted bytes"
    if oversized:
        monkeypatch.setattr(pebble, "MAXIMUM_BYTES", len(data) - 1)
        monkeypatch.setitem(pebble.PINNED, "pebble", hashlib.sha256(data).hexdigest())
    responses: list[BytesIO] = []

    def open_release(url: str, *, timeout: int) -> BytesIO:
        response = BytesIO(data)
        responses.append(response)
        return response

    monkeypatch.setattr(pebble, "urlopen", open_release)
    with pytest.raises(ValueError, match="checksum verification"):
        pebble.download("pebble")
    assert len(responses) == 1
    assert responses[0].closed
