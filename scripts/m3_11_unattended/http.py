"""Bounded provider requests with fixed origins and no credential-bearing errors."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Final, override

from scripts.m3_11_unattended.model import LifecycleError, Targets

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
        self.credential_sha256 = hashlib.sha256(token.encode()).hexdigest()

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if (
            method not in {"GET", "POST", "DELETE"}
            or not path.startswith("/")
            or ".." in path
            or "#" in path
        ):
            raise LifecycleError("provider request escaped its fixed API")
        return self._request(method, path, body)

    def audit_policy_update(
        self, *, candidate: dict[str, object], body: dict[str, object]
    ) -> Response:
        from scripts.m3_11_unattended.audit_policy_recovery import (  # noqa: PLC0415
            body as normalized,
        )
        from scripts.m3_11_unattended.audit_policy_recovery import (  # noqa: PLC0415
            candidate as approved_candidate,
        )

        approved = approved_candidate(candidate)
        if self.origin != "https://api.cloudflare.com/client/v4" or body not in (
            normalized(approved["before"]),
            normalized(approved["candidate_after"]),
        ):
            raise LifecycleError("audit policy update escaped its exact approved bodies")
        return self._request(
            "PUT", f"/accounts/{approved['account_id']}/tokens/{approved['credential_id']}", body
        )

    def cleanup_expiry_update(
        self, *, plan: dict[str, object], targets: Targets, expected: str, provider: str
    ) -> Response:
        from scripts.m3_11_unattended.cleanup_expiry import approved_update  # noqa: PLC0415

        if self.origin != "https://api.cloudflare.com/client/v4":
            raise LifecycleError("cleanup expiry update requires the fixed Cloudflare API")
        path, body = approved_update(
            plan,
            targets=targets,
            expected=expected,
            provider=provider,
            authority_sha256=self.credential_sha256,
        )
        return self._request("PUT", path, body)

    def _request(self, method: str, path: str, body: dict[str, object] | None) -> Response:
        try:
            result = subprocess.run(  # noqa: S603 - fixed helper; bearer/body only in private pipes
                [sys.executable, "-m", __name__, "--exchange"],
                input=json.dumps(
                    {
                        "origin": self.origin,
                        "token": self._token,
                        "method": method,
                        "path": path,
                        "body": body,
                    }
                ).encode(),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PYTHONDONTWRITEBYTECODE": "1"},
                cwd=Path(__file__).resolve().parents[2],
                timeout=TIMEOUT,
                check=False,
            )
        except OSError, subprocess.SubprocessError:
            # Includes the whole exchange: DNS, TLS, headers, trickling body and
            # decoding. A killed CREATE remains uncertain and is never replayed.
            raise LifecycleError("provider request failed; outcome remains unresolved") from None
        if result.returncode or len(result.stdout) > MAX_BYTES + 1024:
            raise LifecycleError("provider request failed; outcome remains unresolved")
        try:
            value = json.loads(result.stdout)
        except ValueError, UnicodeError:
            raise LifecycleError("provider response is invalid") from None
        if (
            not isinstance(value, dict)
            or set(value) != {"status", "body"}
            or type(value["status"]) is not int
            or not isinstance(value["body"], dict)
        ):
            raise LifecycleError("provider response is invalid")
        return Response(value["status"], value["body"])

    def _exchange(self, method: str, path: str, body: dict[str, object] | None) -> Response:
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
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(
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


if __name__ == "__main__":
    if sys.argv[1:] != ["--exchange"]:
        raise SystemExit(2)
    try:
        selected = json.loads(sys.stdin.buffer.read(MAX_BYTES + 1024))
        response = Api(selected["origin"], selected["token"])._exchange(
            selected["method"], selected["path"], selected["body"]
        )
        output = json.dumps(
            {"status": response.status, "body": response.body}, ensure_ascii=False
        ).encode()
        if len(output) > MAX_BYTES + 1024:
            raise SystemExit(1)
        sys.stdout.buffer.write(output)
    except Exception:  # Child boundary must suppress credential-bearing diagnostics.
        raise SystemExit(1) from None
