"""Project failed audit initialization on the leased installed guest."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
from hashlib import sha256
from pathlib import Path

UNIT = "lowerduckpond-audit-initialize.service"
SOURCE = "config/ansible/roles/backup/tasks/main.yml"
SELECTION = "/opt/lowerduckpond/static-host-agent/current/site-packages"
MARKER = "enabled-repeat-audit-observer.json"
PROTECTION = Path("/var/lib/lowerduckpond/static/audit/archive/protection-status.json")
PROPERTIES = (
    "LoadState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "ExecMainStartTimestampMonotonic",
    "ExecMainExitTimestampMonotonic",
)
RESULTS = frozenset(
    {
        "success",
        "exit-code",
        "signal",
        "core-dump",
        "timeout",
        "oom-kill",
        "resources",
        "start-limit-hit",
        "watchdog",
        "protocol",
    }
)
CATEGORIES = frozenset(
    {
        "verified",
        "rotation-pending",
        "resource-exhaustion",
        "index-corruption",
        "archive-unavailable",
        "protection",
    }
)
UNAVAILABLE: dict[str, object] = {"observation": "unavailable"}
MAX_STATUS = 255


def unit_failure(
    raw: str,
    since_ns: int,
    protection: tuple[int, str] | None,
    offset: tuple[int, int],
) -> dict[str, object]:
    fields = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if fields.keys() != set(PROPERTIES) or fields["LoadState"] != "loaded":
        return (
            {"observation": "unloaded"} if fields.get("LoadState") == "not-found" else UNAVAILABLE
        )
    if any(re.fullmatch(r"[0-9]{1,20}", fields[key]) is None for key in PROPERTIES[2:]):
        return UNAVAILABLE
    code, status, start, end = (int(fields[key]) for key in PROPERTIES[2:])
    result = fields["Result"]
    if (result, code, status, start, end) == ("success", 0, 0, 0, 0):
        # systemd can unload a completed oneshot and then show default properties.
        return {"observation": "unloaded"}
    if not since_ns <= start * 1000 <= end * 1000 or result == "success":
        return {"observation": "unattributed"}
    if result not in RESULTS or code not in {0, 1, 2, 3} or not 0 <= status <= MAX_STATUS:
        return UNAVAILABLE
    evidence: dict[str, object] = {
        "observation": "correlated",
        "Result": result,
        "ExecMainCode": code,
        "ExecMainStatus": status,
    }
    if protection is not None:
        modified, category = protection
        earliest_offset, latest_offset = offset
        # A status write within this invocation is fresh evidence. Other audit
        # units also write status, so this is the observed category at the time.
        if (
            start * 1000 + latest_offset <= modified <= end * 1000 + earliest_offset
            and category in CATEGORIES
        ):
            evidence["protectionCategory"] = category
    return evidence


def validated(value: object) -> dict[str, object]:
    """Rebuild the published projection from a closed, typed guest response."""
    if not isinstance(value, dict):
        return UNAVAILABLE
    state = value.get("observation")
    if state in ("unavailable", "unloaded", "unattributed"):
        return {"observation": state}
    result, code, status = (value.get(key) for key in PROPERTIES[1:4])
    if (
        state != "correlated"
        or not isinstance(result, str)
        or result not in RESULTS - {"success"}
        or type(code) is not int
        or code not in {0, 1, 2, 3}
        or type(status) is not int
        or not 0 <= status <= MAX_STATUS
    ):
        return UNAVAILABLE
    report = {
        "observation": "correlated",
        "Result": result,
        "ExecMainCode": code,
        "ExecMainStatus": status,
    }
    category = value.get("protectionCategory")
    if isinstance(category, str) and category in CATEGORIES:
        report["protectionCategory"] = category
    return report


def status_file() -> tuple[int, str] | None:
    from lowerduckpond_static_host_agent.audit_archive_journal import (  # noqa: PLC0415
        MAX_STATUS_BYTES,
        decode_protection_status,
    )

    descriptor = os.open(PROTECTION, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004 - protected status
            or not 0 < metadata.st_size <= MAX_STATUS_BYTES
        ):
            return None
        record = source.read(MAX_STATUS_BYTES + 1)
        if os.fstat(source.fileno()).st_mtime_ns != metadata.st_mtime_ns:
            return None
    category = decode_protection_status(record)["category"]
    return (metadata.st_mtime_ns, category) if isinstance(category, str) else None


def wall_offset() -> tuple[int, int]:
    before = time.monotonic_ns()
    wall = time.time_ns()
    return wall - time.monotonic_ns(), wall - before


def guest_observation() -> dict[str, object]:
    from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError  # noqa: PLC0415

    from scripts.m3_12_installed_root import ROOT, private  # noqa: PLC0415

    mark = json.loads(private(ROOT / MARKER))
    if mark["boot"] != Path("/proc/sys/kernel/random/boot_id").read_text():
        return UNAVAILABLE
    result = subprocess.run(  # noqa: S603 - fixed unit and property names
        ["/usr/bin/systemctl", "show", UNIT, "--property=" + ",".join(PROPERTIES)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode:
        return UNAVAILABLE
    try:
        protection = status_file()
    except OSError, ValueError, BackupIdentityError:
        protection = None
    lower, upper = wall_offset()
    # Use the outer sampled realtime offsets to narrow the candidate status
    # window if the offset changed between the marker and this read.
    return unit_failure(
        result.stdout,
        mark["monotonic"],
        protection,
        (min(lower, mark["lower"]), max(upper, mark["upper"])),
    )


def guest_mark() -> None:
    from lowerduckpond_static_host_agent.durable import DurableDirectory  # noqa: PLC0415

    from scripts.m3_12_installed_root import ROOT, canonical  # noqa: PLC0415

    lower, upper = wall_offset()
    value = {
        "boot": Path("/proc/sys/kernel/random/boot_id").read_text(),
        "monotonic": time.monotonic_ns(),
        "lower": lower,
        "upper": upper,
    }
    with DurableDirectory.open(ROOT, expected_owner=0, expected_directory_mode=0o700) as root:
        root.create_immutable((MARKER,), canonical(value))


def main(mode: str, token: str) -> int:
    sys.path.insert(0, SELECTION)
    try:
        from scripts.m3_12_installed_root import (  # noqa: PLC0415
            ROOT,
            canonical,
            lease_check,
            private,
        )

        lease_check(token)
        if private(ROOT / "enabled-repeat.started") != canonical(
            {"lease": sha256(token.encode()).hexdigest(), "stage": "enabled-repeat"}
        ):
            return 1
        if mode == "mark":
            guest_mark()
        elif mode == "collect":
            print(json.dumps(guest_observation(), sort_keys=True))
        else:
            return 1
    except Exception:
        # This optional observation must never emit guest errors or replace the apply result.
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
