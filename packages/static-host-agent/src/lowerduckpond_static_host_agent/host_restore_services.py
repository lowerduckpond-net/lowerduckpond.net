"""Fixed systemd admission and quiescence boundaries for administrative recovery."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_process import require_command

SCHEDULES_READY: Final = Path("/run/lowerduckpond-host-restore/schedules-ready")

ORDINARY_ACTIVATORS: Final = (
    "lowerduckpond-static-reconcile.timer",
    "lowerduckpond-static-emergency-reconcile.timer",
    "lowerduckpond-archive-export.socket",
    "lowerduckpond-archive-construction.socket",
    "lowerduckpond-archive-cleanup.socket",
    "lowerduckpond-backup.timer",
    "lowerduckpond-backup-maintenance.timer",
    "lowerduckpond-audit-verify.timer",
    "lowerduckpond-audit-rotate.timer",
    "lowerduckpond-health.timer",
)
ORDINARY_SERVICES: Final = (
    "caddy-recovery.service",
    "lowerduckpond-static-reconcile.service",
    "lowerduckpond-static-emergency-reconcile.service",
    "lowerduckpond-backup.service",
    "lowerduckpond-backup-maintenance.service",
    "lowerduckpond-backup-identity.service",
    "lowerduckpond-audit-initialize.service",
    "lowerduckpond-audit-verify.service",
    "lowerduckpond-audit-rotate.service",
    # Its read-only audit proof holds tenant-state SH. Drain it before root
    # replacement and nonblocking verification, just like scheduled mutation.
    "lowerduckpond-health.service",
)
TEMPLATES: Final = (
    "lowerduckpond-static-worker@.service",
    "lowerduckpond-archive-export@.service",
    "lowerduckpond-archive-construction@.service",
    "lowerduckpond-archive-cleanup@.service",
)
_PATTERNS: Final = (
    "caddy.service",
    *ORDINARY_ACTIVATORS,
    *ORDINARY_SERVICES,
    *(name.replace("@.", "@*.") for name in TEMPLATES),
)
_INSTANCE: Final = re.compile(
    r"lowerduckpond-(?:static-worker@[0-9a-f-]{36}|archive-(?:export|construction|cleanup)@request)\.service",
    re.ASCII,
)


def _units() -> dict[str, str]:
    raw = require_command(
        (
            "/usr/bin/systemctl",
            "list-units",
            "--all",
            "--no-pager",
            "--no-legend",
            "--plain",
            *_PATTERNS,
        ),
        failure="restore_service_inventory_unavailable",
    )
    rows: dict[str, str] = {}
    for line in raw.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) < 4:  # noqa: PLR2004 - unit,load,active,substate then description
            raise HostRestoreError("restore_service_inventory_invalid")
        name, _loaded, active, _substate = fields[:4]
        if (
            name in rows
            or (name not in _PATTERNS and _INSTANCE.fullmatch(name) is None)
            or active
            not in {
                "active",
                "reloading",
                "inactive",
                "failed",
                "activating",
                "deactivating",
                "maintenance",
                "refreshing",
            }
        ):
            raise HostRestoreError("restore_service_inventory_invalid")
        rows[name] = active
    return rows


def close_public_ingress() -> None:
    require_command(
        ("/usr/sbin/nft", "--file", "/usr/local/share/lowerduckpond/restore-gate.nft"),
        failure="restore_firewall_unavailable",
    )


def quiesce_host(*, caddy: bool = True) -> tuple[str, ...]:
    """The already durable gate prevents new command and unit admission.

    Runtime masks supplement permanent root admission drop-ins. The latter are
    required even when a locally installed /etc unit takes precedence over a
    runtime mask, and recreate closed admission after a reboot.
    """
    # A completed restore may have left this volatile admission token. A new
    # closed transaction never inherits permission to start its activators.
    SCHEDULES_READY.unlink(missing_ok=True)
    names = [*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES]
    if caddy:
        names.append("caddy.service")
    require_command(
        ("/usr/bin/systemctl", "mask", "--runtime", *names),
        failure="restore_service_mask_failed",
    )
    units = _units()
    stopping = tuple(name for name in units if caddy or name != "caddy.service")
    if stopping:
        require_command(
            ("/usr/bin/systemctl", "stop", *stopping),
            failure="restore_service_stop_failed",
            timeout=30,
        )
    require_quiescent(caddy=caddy)
    return tuple(sorted(names))


def require_quiescent(*, caddy: bool = True) -> None:
    units = _units()
    if any(
        status not in {"inactive", "failed"}
        for name, status in units.items()
        if caddy or name != "caddy.service"
    ):
        raise HostRestoreError("restore_services_not_quiescent")


def start_caddy() -> None:
    # Never reset failed state/attempt counters. An exhausted start remains an
    # operator-visible failure of this same journaled restore transaction.
    require_command(
        ("/usr/bin/systemctl", "unmask", "--runtime", "caddy.service"),
        failure="restore_caddy_unmask_failed",
    )
    require_command(
        ("/usr/bin/systemctl", "start", "caddy.service"),
        failure="restore_caddy_start_failed",
        timeout=120,
    )


def caddy_failed() -> bool:
    # Result can retain an earlier exit-code failure when systemd rejects
    # a subsequent attempt at the rate limit. Read the service state instead.
    result = require_command(
        ("/usr/bin/systemctl", "show", "--property=ActiveState", "--value", "caddy.service"),
        failure="restore_caddy_start_state_unavailable",
    )
    return result.strip() == b"failed"


def reset_caddy_start_limit() -> None:
    require_command(
        ("/usr/bin/systemctl", "reset-failed", "caddy.service"),
        failure="restore_caddy_start_reset_failed",
    )


def public_gate_present() -> bool:
    """Inspect the current kernel gate without clearing it or parsing stderr."""
    raw = require_command(
        ("/usr/sbin/nft", "--json", "list", "tables"),
        failure="restore_firewall_readback_failed",
    )
    try:
        response = json.loads(raw)
    except ValueError:
        raise HostRestoreError("restore_firewall_inventory_invalid") from None
    rows = response.get("nftables") if isinstance(response, dict) else None
    if not isinstance(rows, list):
        raise HostRestoreError("restore_firewall_inventory_invalid")
    tables = set()
    for row in rows:
        if not isinstance(row, dict) or len(row) != 1:
            raise HostRestoreError("restore_firewall_inventory_invalid")
        if "metainfo" in row:
            continue
        table = row.get("table")
        if not isinstance(table, dict) or not all(
            isinstance(table.get(key), str) for key in ("family", "name")
        ):
            raise HostRestoreError("restore_firewall_inventory_invalid")
        tables.add((table["family"], table["name"]))
    return ("inet", "lowerduckpond_restore") in tables


def remove_public_gate() -> None:
    require_command(
        ("/usr/sbin/nft", "destroy", "table", "inet", "lowerduckpond_restore"),
        failure="restore_firewall_open_failed",
    )


def restore_schedules(*, audit_rotation: bool) -> None:
    names = (*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES)
    require_command(
        ("/usr/bin/systemctl", "unmask", "--runtime", *names),
        failure="restore_service_unmask_failed",
    )
    timers = tuple(
        name
        for name in ORDINARY_ACTIVATORS
        if name != "lowerduckpond-audit-rotate.timer" or audit_rotation
    )
    require_command(
        ("/usr/bin/systemctl", "enable", "caddy.service", *timers),
        failure="restore_schedule_enable_failed",
    )
    if not audit_rotation:
        require_command(
            ("/usr/bin/systemctl", "disable", "lowerduckpond-audit-rotate.timer"),
            failure="restore_rotation_disable_failed",
        )
    require_command(
        ("/usr/bin/systemctl", "start", *timers),
        failure="restore_schedule_start_failed",
    )
