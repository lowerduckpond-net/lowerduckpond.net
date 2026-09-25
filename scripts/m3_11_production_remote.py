"""Run leased rollout actions inside one descendant-tracking systemd unit."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from scripts import m3_11_production_gate as gate
from scripts import m3_11_production_lease as lease
from scripts import m3_11_production_records as records

ROOT = Path("/run/lowerduckpond-m3-11")
LEASE = ROOT / "lease"
UNIT = "lowerduckpond-m3-11-action.service"
CGROUP = Path("/sys/fs/cgroup/system.slice") / UNIT


def drain() -> None:
    """Stop the old action and prove that its detached descendants are gone."""
    result = subprocess.run(  # noqa: S603 - fixed local administrative command
        ["/usr/bin/systemctl", "stop", UNIT], capture_output=True, timeout=20, check=False
    )
    state = subprocess.run(  # noqa: S603 - fixed local read-only command
        ["/usr/bin/systemctl", "show", UNIT, "--property=LoadState", "--value"],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if result.returncode and state.stdout != b"not-found\n":
        raise ValueError("production action could not be stopped")
    try:
        events = (CGROUP / "cgroup.events").read_text(encoding="ascii")
    except FileNotFoundError:
        return
    if "populated 0" not in events.splitlines():
        raise ValueError("production action descendants remain")


def main() -> int:
    try:
        if os.geteuid() != 0:
            raise ValueError("production action requires root")
        arguments = sys.argv[1:]
        if arguments == ["owner"]:
            LEASE.mkdir(mode=0o700, exist_ok=True)
            with lease.controller(LEASE, owner=0, drain=drain) as token:
                print(token, flush=True)
                # SSH channel closure releases the owner. No command or token
                # refresh is accepted on this separate control connection.
                if sys.stdin.buffer.read(8) not in {b"", b"release\n"}:
                    raise ValueError("invalid production owner control message")
            return 0
        if Path("/proc/self/cgroup").read_text(encoding="ascii") != f"0::/system.slice/{UNIT}\n":
            raise ValueError("production action is outside its tracked unit")
        if len(arguments) == 2 and arguments[0] == "gate":  # noqa: PLR2004 - operation and token
            lease.require_action(LEASE, owner=0, token=arguments[1])
            gate.require(records.ROOT, sys.stdin.buffer.read(gate.MAX_BYTES + 1), owner=0)
            return 0
        if len(arguments) >= 3 and arguments[0] == "journal":  # noqa: PLR2004 - token and operation
            # This child runs under the outer action's still-held lease. Taking
            # another action lock here would conflict with that same owner.
            lease.require_action(LEASE, owner=0, token=arguments[1])
            raw = sys.stdin.buffer.read(records.MAX_RECORD_BYTES + 1)
            result = records.operate(records.ROOT, arguments[2:], raw, owner=0)
            sys.stdout.buffer.write(result)
            return 0
        if len(arguments) != 3 or arguments[0] != "action":  # noqa: PLR2004 - fixed wire arguments
            raise ValueError("invalid production action invocation")
        with lease.action(LEASE, owner=0, token=arguments[1]):
            # The trusted Ansible/controller command is a single shell argument;
            # stdin/stdout remain byte streams, including piped file transfers.
            return subprocess.call(  # noqa: S603 - qualified controller command under live lease
                ["/bin/sh", "-c", arguments[2]]
            )
    except OSError, ValueError, subprocess.SubprocessError:
        print("production_action_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
