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
UNITS = ("lowerduckpond-host-restore.service", "caddy.service")
RESULTS = {"success", "exit-code", "signal", "timeout", "resources", "oom-kill", "start-limit-hit"}


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
    units = {}
    for unit in UNITS:
        result = subprocess.run(  # noqa: S603 - fixed read-only local observations
            ["/usr/bin/systemctl", "show", "--property=ActiveState,Result,ExecMainStatus", unit],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        value = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
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
    }


if __name__ == "__main__":
    print(json.dumps(observe(), sort_keys=True))
