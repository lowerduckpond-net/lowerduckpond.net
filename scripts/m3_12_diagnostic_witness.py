"""Finish the installed P2 witness on its original fixture before teardown."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

from scripts.m3_12_contracts import decode
from scripts.m3_12_diagnostic_store import ROOT, Attempt, projection, publish
from scripts.m3_12_diagnostic_transport import (
    RETAINED_ATTEMPTS,
    RETAINED_FIXTURE,
    bound_host,
    guest_owner,
)
from scripts.m3_12_diagnostics import child_environment, status
from scripts.qualification_context import run_lease
from scripts.qualification_probe import bounded_command

CANARY = b"M3-12-SYNTHETIC-PRIVATE-TRANSPORT-WITNESS"


def prove_retained_collection(fixture: Path) -> None:
    (receipt,) = (fixture / RETAINED_ATTEMPTS).glob(f"*/*/{RETAINED_FIXTURE}")
    attempt = Attempt(receipt.parent)
    just = shutil.which("just")
    if just is None:
        raise ValueError("Installed diagnostic witness requires just")

    # Prove the real public recipe can acquire and use the original run lease.
    # The previously killed submitting observer must still have no terminal.
    start = time.monotonic_ns()
    collection = subprocess.run(  # noqa: S603 - exact, owned diagnostic read
        [just, "m3-12", "collect", str(attempt.directory), "--guest", "start"],
        env=child_environment(attempt),
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    elapsed_ms = (time.monotonic_ns() - start) // 1_000_000
    with run_lease(fixture):
        environment, host = bound_host(fixture)
        guest_owner(attempt, environment, host)
        unit = f"ldp-diagnostic-{attempt.directory.name}.service"
        running = bounded_command(
            [
                "docker",
                "exec",
                host,
                "systemctl",
                "show",
                "--property=ActiveState",
                "--value",
                unit,
            ],
            environment=environment,
            timeout=None,
        )
        stopped = bounded_command(
            ["docker", "exec", host, "systemctl", "stop", unit],
            environment=environment,
            timeout=None,
        )

    if (
        running != b"active\n"
        or stopped != b""
        or collection.returncode
        or CANARY in collection.stdout
        or CANARY in collection.stderr
    ):
        raise ValueError("Public installed guest collection or witness unit cleanup failed")
    native = attempt.record("guest-start.json")
    if (
        decode(collection.stdout, "diagnostic-summary") != projection(native)
        or native["terminalEvidence"] != "missing"
        or status(attempt)["result"] != "unknown"
        or status(attempt)["uncertainWork"] is not True
        or (attempt.directory / "original.json").exists()
    ):
        raise ValueError("Retained observation changed the interrupted outcome")
    for file in attempt.directory.glob("*.json"):
        if CANARY in file.read_bytes():
            raise ValueError("The fixture canary crossed a private capture boundary.")
    publish(
        fixture,
        "m3-12-installed-diagnostic-proof.json",
        {
            "format": "lowerduckpond-m3-12-installed-diagnostic-proof-v2",
            "setup": "original-exit-retained",
            "systemd": "cause-chain-transferred",
            "observer": "unknown-while-guest-active",
            "collection": "secondary-failure-retained",
            "secretExclusion": "checked",
            "publicCollector": "original-binding-and-lease-verified",
            "publicCollectionMs": elapsed_ms,
        },
    )
