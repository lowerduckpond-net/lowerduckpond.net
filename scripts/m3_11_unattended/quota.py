"""Observe 1Password capacity before creating obligations; reserve nothing implicitly."""

from __future__ import annotations

import json

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.journal import OnePassword
from scripts.m3_11_unattended.model import LifecycleError

# A ten-hour journey, fourteen-hour child deadline, hourly independent actors,
# creation/readback and terminal cleanup, with spare calls for reconciliation.
# Cold controller/independent journal reads add their actual retained item count.
BASE_REQUEST_HEADROOM = 360
TOKEN_READ_HEADROOM = 100
TOKEN_WRITE_HEADROOM = 40


def limits(op: OnePassword) -> dict[tuple[str, str], int]:
    value = json.loads(op.command("service-account", "ratelimit", "--format", "json"))
    if not isinstance(value, list) or len(value) != 3:  # noqa: PLR2004 - native quota categories
        raise LifecycleError("1Password request capacity is unavailable")
    remaining: dict[tuple[str, str], int] = {}
    expected = {("token", "read"), ("token", "write"), ("account", "read_write")}
    for entry in value:
        record = fields(entry, {"type", "action", "limit", "used", "remaining", "reset"})
        kind, action = record["type"], record["action"]
        if not isinstance(kind, str) or not isinstance(action, str):
            raise LifecycleError("1Password request capacity is invalid")
        key = (kind, action)
        if key not in expected or key in remaining:
            raise LifecycleError("1Password request capacity is ambiguous")
        numbers: dict[str, int] = {}
        for name in ("limit", "used", "remaining", "reset"):
            number = record[name]
            if type(number) is not int or number < 0:
                raise LifecycleError("1Password request capacity is invalid")
            numbers[name] = number
        if numbers["used"] + numbers["remaining"] != numbers["limit"]:
            raise LifecycleError("1Password request capacity is invalid")
        remaining[key] = numbers["remaining"]
    return remaining


def require_capacity(provision: OnePassword, cleanup: OnePassword, *, records: int) -> None:
    """Headroom is an observation, not a reservation against unrelated account use.

    Never skip a revocation because quota is low. This gate applies only before
    new provisioning; unavailable journal access always leaves cleanup unresolved.
    """
    for op in (provision, cleanup):
        available = limits(op)
        if (
            available[("account", "read_write")] < BASE_REQUEST_HEADROOM + 2 * records
            or available[("token", "read")] < TOKEN_READ_HEADROOM + records
            or available[("token", "write")] < TOKEN_WRITE_HEADROOM
        ):
            raise LifecycleError("1Password capacity is insufficient for qualification and cleanup")
