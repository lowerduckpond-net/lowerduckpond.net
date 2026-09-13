"""Workstation-only Page Rules reads through Cloudflare's user-token API."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Final

from scripts.check_m3_7_production_edge import CloudflareClient, ProductionEdgePreflightError

_MAXIMUM_REMAINING: Final = timedelta(days=90)
_ZONE_COUNT: Final = 2


def _timestamp(value: object) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed
        except ValueError:
            pass
    raise ProductionEdgePreflightError("the Page Rules user token has invalid validity metadata")


class PageRulesClient:
    """Verify a temporary user token and restrict it to the two reviewed inventories."""

    def __init__(
        self, client: CloudflareClient, *, zone_ids: frozenset[str], now: datetime
    ) -> None:
        if len(zone_ids) != _ZONE_COUNT or any(
            re.fullmatch(r"[0-9a-f]{32}", zone) is None for zone in zone_ids
        ):
            raise ProductionEdgePreflightError("the Page Rules user token needs two exact zones")
        self._client = client
        self._paths = frozenset(f"/zones/{zone}/pagerules" for zone in zone_ids)
        verification = client.get("/user/tokens/verify")
        if (
            not isinstance(verification, dict)
            or verification.get("status") != "active"
            or not isinstance(verification.get("id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", verification["id"]) is None
        ):
            raise ProductionEdgePreflightError("the Page Rules user token did not verify as active")
        expires = _timestamp(verification.get("expires_on"))
        if not now < expires <= now + _MAXIMUM_REMAINING:
            raise ProductionEdgePreflightError(
                "the Page Rules user token must expire within 90 days"
            )
        not_before = verification.get("not_before")
        if not_before not in (None, "") and _timestamp(not_before) > now:
            raise ProductionEdgePreflightError("the Page Rules user token is not valid yet")

    def get(self, path: str) -> object:
        if path not in self._paths:
            raise ProductionEdgePreflightError("the Page Rules user token escaped its read scope")
        return self._client.get(path)
