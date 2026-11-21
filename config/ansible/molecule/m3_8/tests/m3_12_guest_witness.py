"""Synthetic errors emitted only inside the installed diagnostic witness."""

from __future__ import annotations

import os
import signal
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.m3_12_diagnostic_guest import observe

CANARY = "M3-12-SYNTHETIC-PRIVATE-TRANSPORT-WITNESS"


def fail() -> None:
    print(CANARY, flush=True)
    print(CANARY, file=sys.stderr, flush=True)
    try:
        raise TimeoutError(CANARY)
    except TimeoutError as error:
        raise RuntimeError(CANARY) from error


def hold() -> None:
    address = os.environ["NOTIFY_SOCKET"]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.connect("\0" + address[1:] if address.startswith("@") else address)
        channel.sendall(b"READY=1")
    signal.pause()


if __name__ == "__main__":
    run, invocation, mode = sys.argv[1:]
    raise SystemExit(observe(run, invocation, {"failure": fail, "hold": hold}[mode]))
