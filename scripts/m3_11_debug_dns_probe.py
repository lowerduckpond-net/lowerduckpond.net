"""Explicit diagnostic cleanup inside the stopped, owned public issuer fixture."""

from __future__ import annotations

import http.client
import json
import re
import ssl
import time
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.host_restore_process import require_command

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe

API_HOST = "api.cloudflare.com"
FIELDS = {"id", "name", "type", "content"}
MAX_RECORDS = 8


def records(value: object, nonce: str) -> list[dict[str, str]]:
    names = {
        "_acme-challenge." + subject.removeprefix("*.")
        for subject in policy.disposable_subjects(nonce)
    }
    if not isinstance(value, list) or not 0 < len(value) <= MAX_RECORDS:
        raise ValueError("diagnostic DNS retirement requires bounded exact records")
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != FIELDS | {"zone_id"}:
            raise ValueError("diagnostic DNS retirement record is malformed")
        if (
            any(not isinstance(v, str) for v in item.values())
            or any(re.fullmatch(r"[0-9a-f]{32}", item[key]) is None for key in ("id", "zone_id"))
            or item["name"] not in names
            or item["type"] != "TXT"
            or re.fullmatch(r'(?:[A-Za-z0-9_-]{43}|"[A-Za-z0-9_-]{43}")', item["content"]) is None
        ):
            raise ValueError("diagnostic DNS retirement record is foreign or malformed")
        result.append(cast("dict[str, str]", item))
    if len({(r["zone_id"], r["id"]) for r in result}) != len(result):
        raise ValueError("diagnostic DNS retirement repeats a record")
    return result


def _request(method: str, path: str, token: str, deadline: float) -> object:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("diagnostic DNS retirement deadline elapsed")
    connection = http.client.HTTPSConnection(
        API_HOST,
        timeout=min(10, remaining),
        context=ssl.create_default_context(cafile=policy.INPUTS / "roots.pem"),
    )
    try:
        connection.request(
            method, "/client/v4" + path, headers={"Authorization": "Bearer " + token}
        )
        response = connection.getresponse()
        raw = response.read(policy.MAXIMUM_BYTES + 1)
        if response.status != 200 or len(raw) > policy.MAXIMUM_BYTES:  # noqa: PLR2004 - provider success status
            raise ValueError("diagnostic DNS retirement provider request failed")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("success") is not True or "result" not in value:
            raise ValueError("diagnostic DNS retirement provider response is malformed")
        return value["result"]
    except OSError, http.client.HTTPException, UnicodeError, json.JSONDecodeError:
        raise ValueError("diagnostic DNS retirement provider request failed") from None
    finally:
        connection.close()


def _clean_dependencies() -> None:
    if Path("/proc/self/ns/mnt").stat().st_ino == Path("/proc/1/ns/mnt").stat().st_ino:
        raise ValueError("diagnostic DNS retirement requires a private mount namespace")
    for name in ("hosts", "resolv.conf"):
        require_command(
            ("/usr/bin/mount", "--bind", str(policy.INPUTS / name), "/etc/" + name),
            failure="diagnostic_dns_clean_resolver_failed",
            timeout=10,
        )


def retire(context_sha256: str, expected: object) -> dict[str, object]:
    marker = probe._guard(context_sha256)
    probe._closed()
    probe._inactive(policy.UNIT)
    probe._tls(marker)  # Cleanup is only for an already-issued diagnostic continuation.
    wanted = records(expected, str(marker["nonce"]))
    _clean_dependencies()
    raw = probe._read(policy.INPUTS / "environment")
    prefix = b"CLOUDFLARE_API_TOKEN="
    if not raw.startswith(prefix) or not raw.endswith(b"\n"):
        raise ValueError("diagnostic DNS retirement credential file is malformed")
    token = raw[len(prefix) : -1].decode("ascii")
    if policy.credential_environment(token) != raw:
        raise ValueError("diagnostic DNS retirement credential file changed")
    deadline = time.monotonic() + 120
    zones = {r["zone_id"]: r["name"].split(".", 2)[2] for r in wanted}
    if len(set(zones.values())) != len(zones):
        raise ValueError("diagnostic DNS retirement zone identities are ambiguous")
    for zone_id, domain in zones.items():
        zone = _request("GET", "/zones/" + zone_id, token, deadline)
        if not isinstance(zone, dict) or zone.get("id") != zone_id or zone.get("name") != domain:
            raise ValueError("diagnostic DNS retirement zone identity changed")
    # Preflight every exact record before the first deletion. Never select by name alone.
    for item in wanted:
        current = _request(
            "GET", f"/zones/{item['zone_id']}/dns_records/{item['id']}", token, deadline
        )
        if not isinstance(current, dict) or {key: current.get(key) for key in FIELDS} != {
            key: item[key] for key in FIELDS
        }:
            raise ValueError("diagnostic DNS retirement record changed")
    for item in wanted:
        probe._inactive(policy.UNIT)
        result = _request(
            "DELETE", f"/zones/{item['zone_id']}/dns_records/{item['id']}", token, deadline
        )
        if not isinstance(result, dict) or result.get("id") != item["id"]:
            raise ValueError("diagnostic DNS retirement deletion was not confirmed")
    return {"retired_records": len(wanted), "qualification_authority": "none"}
