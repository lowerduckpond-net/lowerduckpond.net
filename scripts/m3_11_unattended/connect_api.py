"""Bounded Connect I/O; a local-cache read never constitutes journal durability."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import urlsplit

from scripts.m3_11_unattended.http import NoRedirect
from scripts.m3_11_unattended.journal import _note_content
from scripts.m3_11_unattended.model import LifecycleError

MAX_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 30
IDENTITY = re.compile(r"[a-z0-9]{26}")


def origin(value: str, *, local_cleanup: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise LifecycleError("Connect origin is invalid") from None
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(ord(char) < 33 or ord(char) > 126 for char in value)  # noqa: PLR2004 - URL ASCII bounds
        or port == 0
        or (
            parsed.scheme != "https"
            and not (
                local_cleanup
                and parsed.scheme == "http"
                and parsed.hostname == "127.0.0.1"
                and port
            )
        )
    ):
        raise LifecycleError("Connect needs verified HTTPS or explicit local cleanup loopback")
    return value.rstrip("/")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = dict(pairs)
    if len(value) != len(pairs):
        raise LifecycleError("Connect returned ambiguous JSON")
    return value


@dataclass(frozen=True)
class Response:
    status: int
    body: object


class Connect:
    def __init__(self, url: str, token: str, *, local_cleanup: bool = False) -> None:
        self.url = origin(url, local_cleanup=local_cleanup)
        if len(token) > 65536 or re.fullmatch(r"[A-Za-z0-9_.-]+", token) is None:  # noqa: PLR2004
            raise LifecycleError("Connect client credential is unavailable")
        self._token = token
        self.credential_sha256 = hashlib.sha256(token.encode()).hexdigest()
        # The configured origin is the delivery boundary. Ambient proxies must
        # not receive this credential, and redirects cannot change its origin.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if (
            re.fullmatch(r"/v1/vaults(?:/[a-z0-9]{26}(?:/items(?:/[a-z0-9]{26})?)?)?", path) is None
            or method not in {"GET", "POST"}
            or (method == "POST" and not (path.endswith("/items") and isinstance(body, dict)))
            or (method == "GET" and body is not None)
        ):
            raise LifecycleError("Connect request escaped its bounded API")
        payload = None if body is None else json.dumps(body).encode()
        if payload is not None and len(payload) > MAX_BYTES:
            raise LifecycleError("Connect request exceeds its bound")
        request = urllib.request.Request(  # noqa: S310 - checked HTTPS or explicit loopback origin
            self.url + path,
            data=payload,
            method=method,
            headers={
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                status, raw = response.status, response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()  # Reflected credentials and server diagnostics are never exported.
            if status in {HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND}:
                return Response(status, None)
            raise LifecycleError("Connect operation failed; outcome remains unresolved") from None
        except OSError, urllib.error.URLError:
            raise LifecycleError("Connect operation failed; outcome remains unresolved") from None
        if len(raw) > MAX_BYTES:
            raise LifecycleError("Connect response exceeds its bound")
        try:
            value = json.loads(raw, object_pairs_hook=_object)
        except ValueError, UnicodeError:
            raise LifecycleError("Connect response is invalid") from None
        if not isinstance(value, dict | list):
            raise LifecycleError("Connect response has an unexpected shape")
        return Response(status, value)

    @staticmethod
    def _identity(value: str) -> str:
        if IDENTITY.fullmatch(value) is None:
            raise LifecycleError("Connect operations need immutable vault and item identities")
        return value

    def vaults(self) -> list[dict[str, object]]:
        response = self.request("GET", "/v1/vaults")
        value = response.body
        if (
            response.status != HTTPStatus.OK
            or not isinstance(value, list)
            or any(
                not isinstance(vault, dict)
                or not isinstance(vault.get("id"), str)
                or IDENTITY.fullmatch(vault["id"]) is None
                for vault in value
            )
        ):
            raise LifecycleError("Connect vault visibility could not be verified")
        if len({vault["id"] for vault in value}) != len(value):
            raise LifecycleError("Connect vault visibility is ambiguous")
        return value

    def item(self, vault: str, item: str) -> dict[str, object]:
        path = f"/v1/vaults/{self._identity(vault)}/items/{self._identity(item)}"
        response = self.request("GET", path)
        value = response.body
        if (
            response.status != HTTPStatus.OK
            or not isinstance(value, dict)
            or value.get("id") != item
            or not isinstance(value.get("vault"), dict)
            or value["vault"].get("id") != vault
        ):
            raise LifecycleError("Connect item identity could not be verified")
        return value

    def read(self, reference: str) -> str:
        match = re.fullmatch(
            r"op://([a-z0-9]{26})/([a-z0-9]{26})/([A-Za-z0-9_-]+)(?:/([A-Za-z0-9_-]+))?", reference
        )
        if match is None:
            raise LifecycleError("Connect reference needs immutable vault and item identities")
        item = self.item(match[1], match[2])
        section, selected = (match[3], match[4]) if match[4] else (None, match[3])
        fields = item.get("fields")
        if selected == "notesPlain" and section is None:
            value = _note_content(fields)
        else:
            if not isinstance(fields, list) or any(
                not isinstance(field, dict)
                or (field.get("section") is not None and not isinstance(field["section"], dict))
                for field in fields
            ):
                raise LifecycleError("Connect item fields are unavailable")
            section_id = None
            if section is not None:
                sections = item.get("sections")
                if not isinstance(sections, list):
                    raise LifecycleError("Connect item section is unavailable")
                matches = [
                    entry
                    for entry in sections
                    if isinstance(entry, dict) and section in (entry.get("id"), entry.get("label"))
                ]
                if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
                    raise LifecycleError("Connect item section is ambiguous")
                section_id = matches[0]["id"]
            matches = [
                field
                for field in fields
                if selected in (field.get("id"), field.get("label"))
                and (field.get("section") or {}).get("id") == section_id
            ]
            if len(matches) != 1 or not isinstance(matches[0].get("value"), str):
                raise LifecycleError("Connect item field is unavailable or ambiguous")
            value = matches[0]["value"]
        if not 1 <= len(value.encode()) <= 65536:  # noqa: PLR2004 - existing field bound
            raise LifecycleError("Connect field exceeds its input bound")
        return str(value)
