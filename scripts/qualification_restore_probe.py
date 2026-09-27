"""Bounded read-only reconstruction labels; no restored data or credentials leave."""

from __future__ import annotations

import json
import re
import signal
import subprocess
from pathlib import Path

PHASES = {
    "prepared",
    "restored",
    "validated",
    "reconciled",
    "runtime-prepared",
    "installed",
    "verified",
    "complete",
    "not-started",
    "unknown",
}
STATES = {"active", "inactive", "failed", "activating", "deactivating", "unknown"}
UNITS = (
    "lowerduckpond-host-restore.service",
    "lowerduckpond-host-restore-archive-private.service",
    "lowerduckpond-host-restore-archive-installed.service",
    "caddy.service",
    "caddy-recovery.service",
)
RESULTS = {"success", "exit-code", "signal", "timeout", "resources", "oom-kill", "start-limit-hit"}
VERIFICATION_STEPS = {
    "installed-roots",
    "installed-audit",
    "installed-archives",
    "installed-state",
    "runtime-selection",
    "caddy-start",
    "running-runtime",
    "tls",
    "runtime-recheck",
}


def failed_step(invocation: str) -> str:
    """Only a fixed marker from this coordinator invocation may leave the host."""
    if re.fullmatch(r"[0-9a-f]{32}", invocation) is None:
        return "unknown"
    pattern = "^host_restore_step_failed step=(" + "|".join(sorted(VERIFICATION_STEPS)) + ")$"
    try:
        result = subprocess.run(  # noqa: S603 - fixed units, allowlisted ID and bounded labels
            [
                "/usr/bin/journalctl",
                "--quiet",
                "--no-pager",
                "--output=cat",
                "--lines=1",
                "--unit=" + UNITS[0],
                "_SYSTEMD_INVOCATION_ID=" + invocation,
                "--grep=" + pattern,
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        match = re.fullmatch(pattern, result.stdout.strip()) if result.returncode == 0 else None
        return match[1] if match else "unknown"
    except Exception:
        return "unknown"


def observe() -> dict[str, object]:
    signal.alarm(15)
    phase = "not-started"
    try:
        with Path("/var/lib/lowerduckpond/recovery/host-restore.json").open("rb") as stream:
            journal = json.loads(stream.read(256 * 1024 + 1))
        phase = journal.get("phase", "unknown")
    except FileNotFoundError:
        pass
    except Exception:
        phase = "unknown"
    result = subprocess.run(  # noqa: S603 - one bounded query for the fixed service set
        [
            "/usr/bin/systemctl",
            "show",
            "--property=Id,LoadState,ActiveState,Result,ExecMainStatus,InvocationID",
            *UNITS,
        ],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    rows = {}
    for block in result.stdout.strip().split("\n\n"):
        value = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        if value.get("Id") in UNITS and value.get("LoadState") == "loaded":
            rows[value["Id"]] = value
    units = {}
    for unit in UNITS:
        value = rows.get(unit, {})
        units[unit] = {
            "state": value.get("ActiveState") if value.get("ActiveState") in STATES else "unknown",
            "result": value.get("Result") if value.get("Result") in RESULTS else "unknown",
            "exit_status": int(value["ExecMainStatus"])
            if re.fullmatch(r"[0-9]{1,3}", value.get("ExecMainStatus", ""))
            else "unknown",
        }
    return {
        "phase": phase if phase in PHASES else "unknown",
        "gate_present": Path("/var/lib/lowerduckpond/recovery/restore-gate.json").exists(),
        "units": units,
        "failed_step": failed_step(rows.get(UNITS[0], {}).get("InvocationID", ""))
        if units[UNITS[0]]["state"] == "failed"
        else "unknown",
    }


if __name__ == "__main__":
    print(json.dumps(observe(), sort_keys=True))
