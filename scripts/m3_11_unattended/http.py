"""Bounded provider requests with fixed origins and no credential-bearing errors."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final, override

from scripts.m3_11_unattended.model import LifecycleError

ORIGINS: Final = frozenset({"https://api.digitalocean.com", "https://api.cloudflare.com/client/v4"})
MAX_BYTES: Final = 2 * 1024 * 1024
TIMEOUT: Final = 30


class NoRedirect(urllib.request.HTTPRedirectHandler):
    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        raise LifecycleError("provider redirect rejected")


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, object]


class Api:
    def __init__(self, origin: str, token: str) -> None:
        if origin not in ORIGINS or not token or any(char.isspace() for char in token):
            raise LifecycleError("invalid provider bootstrap input")
        self.origin, self._token = origin, token

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if (
            method not in {"GET", "POST", "DELETE"}
            or not path.startswith("/")
            or ".." in path
            or "#" in path
        ):
            raise LifecycleError("provider request escaped its fixed API")
        request = urllib.request.Request(  # noqa: S310 - allowlisted HTTPS origin
            self.origin + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method=method,
        )
        try:
            with urllib.request.build_opener(NoRedirect()).open(
                request, timeout=TIMEOUT
            ) as response:
                status, raw = response.status, response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as error:
            # Error bodies can reflect names or authentication inputs. Discard them.
            status = error.code
            error.close()
            if status not in {HTTPStatus.NOT_FOUND, HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN}:
                raise LifecycleError(
                    "provider request failed; outcome remains unresolved"
                ) from None
            return Response(status, {})
        except OSError, urllib.error.URLError:
            raise LifecycleError("provider request failed; outcome remains unresolved") from None
        if status == HTTPStatus.NO_CONTENT and not raw:
            return Response(status, {})
        if len(raw) > MAX_BYTES:
            raise LifecycleError("provider response exceeds its bound")
        try:
            value = json.loads(raw)
        except ValueError, UnicodeError:
            raise LifecycleError("provider response is invalid") from None
        if not isinstance(value, dict):
            raise LifecycleError("provider response is invalid")
        return Response(status, value)


def collection(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise LifecycleError("provider inventory is malformed")
    return value
