"""Read-only credential gate before a fresh, complete M3.11 qualification."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime

from scripts.check_m3_7_production_edge import (
    CloudflareClient,
    ProductionEdgePreflightError,
    _require_zone_identity,
)
from scripts.check_m3_10_provider import (
    GateError,
    check_caddy_token,
    page_rules_client,
    required,
)
from scripts.qualification_budget import MINIMUM_TOKEN_REMAINING


def check(environment: Mapping[str, str], *, now: datetime) -> None:
    page_rules_client(environment, now=now, minimum_remaining=MINIMUM_TOKEN_REMAINING)
    caddy = CloudflareClient(required(environment, "CADDY_CLOUDFLARE_API_TOKEN"))
    account_id = _require_zone_identity(
        caddy, required(environment, "CLOUDFLARE_ZONE_ID"), "lowerduckpond.net"
    )
    check_caddy_token(
        environment,
        account_id=account_id,
        now=now,
        minimum_audit_remaining=MINIMUM_TOKEN_REMAINING,
    )


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise GateError("qualification token preflight accepts no arguments")
        check(os.environ, now=datetime.now(UTC))
    except (RuntimeError, ValueError, OSError) as error:
        message = (
            str(error)
            if isinstance(error, (GateError, ProductionEdgePreflightError))
            else type(error).__name__
        )
        print(f"M3.11 qualification token preflight failed: {message}.", file=sys.stderr)
        return 1
    hours = MINIMUM_TOKEN_REMAINING.total_seconds() / 3600
    print(f"M3.11 qualification tokens have at least {hours:g} hours remaining from now.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
