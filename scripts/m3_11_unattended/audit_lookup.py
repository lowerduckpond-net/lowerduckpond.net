"""Preparatory, read-only audit diagnostic. No creation, deletion or closure API.

Live use needs separate Account Settings Read authorization. A positive result
is a candidate for ownership verification; absence never discharges an intent.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable
from http import HTTPStatus
from typing import Protocol
from urllib.parse import urlencode, urlsplit

from scripts.m3_11_unattended.http import Response, collection
from scripts.m3_11_unattended.model import Intent, LifecycleError, digest, instant

MAX_PAGES = 10
PAGE_SIZE = 100
SECONDS = 180
MAX_ID = 128
MAX_CURSOR = 4096
HEX_ID = re.compile(r"[0-9a-f]{32}")


class Reader(Protocol):
    def request(
        self, method: str, path: str, body: dict[str, object] | None = None
    ) -> Response: ...


def collect(  # noqa: PLR0912, PLR0913 - bounded pagination with explicit retention
    reader: Reader,
    *,
    account: str,
    since: str,
    before: str,
    retain: Callable[[int, dict[str, object]], None],
    clock: Callable[[], float] = time.monotonic,
) -> list[dict[str, object]]:
    """Use a fixed interval, bounded GETs, and fail on partial/changed pagination.

    The caller must enforce the outer 180-second process limit as well. The
    repository Api additionally bounds each complete exchange at 30 seconds.
    Every raw page goes to the caller's private evidence store before parsing.
    """
    if HEX_ID.fullmatch(account) is None or instant(since) >= instant(before):
        raise LifecycleError("invalid bounded audit target")
    until = clock() + SECONDS
    cursor = None
    seen_cursors: set[str] = set()
    seen_records: set[str] = set()
    records: list[dict[str, object]] = []
    for page in range(MAX_PAGES):
        if clock() >= until:
            raise LifecycleError("audit observation deadline elapsed")
        query = {"since": since, "before": before, "direction": "asc", "limit": PAGE_SIZE}
        if cursor is not None:
            query["cursor"] = cursor
        response = reader.request("GET", f"/accounts/{account}/logs/audit?" + urlencode(query))
        retain(page, response.body)
        if clock() >= until:
            raise LifecycleError("audit observation deadline elapsed")
        body = response.body
        if response.status != HTTPStatus.OK or body.get("success") is not True:
            raise LifecycleError("audit request was not authenticated and acknowledged")
        values = collection(body.get("result"))
        info = body.get("result_info")
        if not isinstance(info, dict) or len(values) > PAGE_SIZE:
            raise LifecycleError("audit pagination is invalid")
        count = info.get("count")
        if (
            type(count) is not int
            and not (isinstance(count, str) and re.fullmatch(r"[0-9]{1,3}", count))
        ) or int(count) != len(values):
            raise LifecycleError("audit page count changed")
        for row in values:
            key = row.get("id")
            action = row.get("action")
            if not isinstance(key, str) or not 1 <= len(key) <= MAX_ID or key in seen_records:
                raise LifecycleError("audit inventory is ambiguous")
            if not isinstance(action, dict) or not instant(since) <= instant(
                action.get("time")
            ) < instant(before):
                raise LifecycleError("audit record escaped its fixed interval")
            seen_records.add(key)
        records.extend(values)
        cursor = info.get("cursor")
        if cursor in (None, ""):
            return records
        if (
            not isinstance(cursor, str)
            or not 1 <= len(cursor) <= MAX_CURSOR
            or cursor in seen_cursors
        ):
            raise LifecycleError("audit pagination cursor repeated or invalid")
        seen_cursors.add(cursor)
    raise LifecycleError("audit observation page bound reached")


def _object(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def analyze(
    records: list[dict[str, object]], intent: Intent, *, parent_id: str
) -> dict[str, object]:
    """Export hashes and fixed booleans only; never provider text or token values.

    V2 actor.token_id identifies the caller, not the new credential. A matching
    resource/response ID remains a lead, requiring separate native readback and
    exact ownership checks. A failed event is not proof of no side effect.
    """
    if HEX_ID.fullmatch(parent_id) is None or intent.provider != "cloudflare-user":
        raise LifecycleError("invalid audit identity binding")
    leads = []
    for row in records:
        raw, action, actor, resource, account = (
            _object(row.get(k)) for k in ("raw", "action", "actor", "resource", "account")
        )
        request, response = _object(resource.get("request")), _object(resource.get("response"))
        response_result = _object(response.get("result"))
        uri = raw.get("uri")
        try:
            path = urlsplit(uri).path if isinstance(uri, str) else None
        except ValueError:
            raise LifecycleError("audit record URI is malformed") from None
        if path not in {"/user/tokens", "/client/v4/user/tokens"} or raw.get("method") != "POST":
            continue
        exact_name = any(v.get("name") == intent.name for v in (request, response, response_result))
        parent_match = actor.get("token_id") == parent_id
        if not exact_name and not parent_match:
            continue
        native_time = action.get("time")
        try:
            in_creation_window = (
                instant(intent.requested_at)
                <= instant(native_time)
                <= instant(intent.create_before)
            )
        except LifecycleError:
            in_creation_window = False
        supplied_ids = [
            value
            for value in (resource.get("id"), response.get("id"), response_result.get("id"))
            if value is not None
        ]
        identities_agree = (
            bool(supplied_ids)
            and all(isinstance(value, str) and HEX_ID.fullmatch(value) for value in supplied_ids)
            and len(set(supplied_ids)) == 1
        )
        candidates = {
            value
            for value in (resource.get("id"), response.get("id"), response_result.get("id"))
            if isinstance(value, str)
            and HEX_ID.fullmatch(value)
            and value != parent_id
            and value not in intent.baseline_ids
        }
        user_match = actor.get("id") == intent.targets.user_id
        account_match = account.get("id") == intent.targets.account_id
        status_code = raw.get("status_code")
        success = (
            action.get("result") == "success"
            and type(status_code) is int
            and HTTPStatus.OK <= status_code < HTTPStatus.MULTIPLE_CHOICES
        )
        leads.append(
            {
                "record_sha256": digest(row),
                "exact_name": exact_name,
                "parent_identity_matches": parent_match,
                "user_identity_matches": user_match,
                "account_identity_matches": account_match,
                "within_creation_window": in_creation_window,
                "provider_reports_success": success,
                "supplied_child_identities_agree": identities_agree,
                "candidate_id_sha256": sorted(_hash(value) for value in candidates),
                "candidate_for_native_ownership_checks": all(
                    (
                        exact_name,
                        parent_match,
                        user_match,
                        account_match,
                        in_creation_window,
                        success,
                        identities_agree,
                        len(candidates) == 1,
                    )
                ),
            }
        )
    return {
        "format": "lowerduckpond-m3-11-audit-diagnostic-v1",
        "run_id": intent.run_id,
        "intent_sha256": intent.sha256,
        "observed_records": len(records),
        "records_sha256": digest(records),
        "leads": leads,
        "provider_mutations": 0,
        "authorizes_closure": False,
        "limitation": (
            "Audit absence or failure is inconclusive. Positive IDs require "
            "independent native ownership/removal verification."
        ),
    }
