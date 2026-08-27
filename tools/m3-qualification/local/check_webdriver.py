"""Independently smoke-test the static cookie boundary in a stock browser."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from collections.abc import Sequence
from http import HTTPStatus
from urllib.parse import urlsplit

ALIAS_ORIGIN = "https://alias.ldp-tenant.test"
CANONICAL_ORIGIN = "https://t-0198d17f6f4a70008000000000000001.ldp-tenant.test"
CANONICAL_ROOT_BODY = "lowerduckpond-m3-canonical-root"
HOSTILE_NAMES = frozenset({"ldp_m3_upstream", "__Host-ldp_m3_upstream_host"})


class WebDriverError(RuntimeError):
    """A fixed local WebDriver contract failed."""


def _request(endpoint: str, method: str, path: str, payload: object | None = None) -> object:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - caller validates exact loopback HTTP.
        f"{endpoint}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            value = json.load(response).get("value")
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise WebDriverError("WebDriver request failed") from error
    if isinstance(value, dict) and "error" in value:
        raise WebDriverError("WebDriver returned an error")
    return value


def run(endpoint: str, browser_name: str) -> None:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
        raise WebDriverError("WebDriver endpoint is not loopback")
    value = _request(
        endpoint,
        "POST",
        "/session",
        {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": browser_name,
                    "acceptInsecureCerts": True,
                }
            }
        },
    )
    if not isinstance(value, dict) or not isinstance(value.get("sessionId"), str):
        raise WebDriverError("WebDriver session response is invalid")
    session_id = value["sessionId"]
    root = f"/session/{session_id}"
    try:
        _request(endpoint, "POST", f"{root}/url", {"url": f"{ALIAS_ORIGIN}/static"})
        _request(
            endpoint,
            "POST",
            f"{root}/cookie",
            {
                "cookie": {
                    "name": "ldp_m3_parent",
                    "value": "ldp-m3-canary-not-sensitive",
                    "domain": ".ldp-tenant.test",
                    "path": "/",
                    "secure": True,
                }
            },
        )
        _request(endpoint, "POST", f"{root}/url", {"url": ALIAS_ORIGIN})
        current_url = _request(endpoint, "GET", f"{root}/url")
        canonical_root_body = _request(
            endpoint,
            "POST",
            f"{root}/execute/sync",
            {"script": "return document.body.textContent;", "args": []},
        )
        if current_url != f"{CANONICAL_ORIGIN}/" or canonical_root_body != CANONICAL_ROOT_BODY:
            raise WebDriverError("alias redirect contract failed")
        _request(endpoint, "POST", f"{root}/url", {"url": f"{CANONICAL_ORIGIN}/probe"})
        cookies = _request(endpoint, "GET", f"{root}/cookie")
        if not isinstance(cookies, list) or any(
            isinstance(cookie, dict) and cookie.get("name") in HOSTILE_NAMES for cookie in cookies
        ):
            raise WebDriverError("hostile response state reached the browser jar")
        observation = _request(
            endpoint,
            "POST",
            f"{root}/execute/async",
            {
                "script": """
                    const done = arguments[arguments.length - 1];
                    fetch('/probe', {credentials: 'include'})
                      .then((response) => done({
                        status: response.status,
                        upstream: response.headers.get('x-m3-upstream-saw-state'),
                        incoming: response.headers.get('x-m3-incoming-state')
                      }))
                      .catch(() => done({failed: true}));
                """,
                "args": [],
            },
        )
        if (
            not isinstance(observation, dict)
            or observation.get("status") != HTTPStatus.OK
            or observation.get("upstream") != "false"
            or observation.get("incoming") not in {None, ""}
            or observation.get("failed") is True
        ):
            raise WebDriverError("request state removal contract failed")
    finally:
        _request(endpoint, "DELETE", root)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--browser", required=True, choices=("chrome", "firefox"))
    arguments = parser.parse_args(argv)
    try:
        run(arguments.endpoint, arguments.browser)
    except WebDriverError as error:
        print(f"{arguments.browser}: FAIL ({error})")
        return 1
    print(f"{arguments.browser}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
