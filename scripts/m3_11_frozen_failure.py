"""Fixed retirement phase and native types, never exception text or request data."""

from __future__ import annotations

import time
from pathlib import Path

from scripts.m3_11_retirement_files import RetirementError
from scripts.m3_11_unattended.model import LifecycleError
from scripts.provider_preflight_diagnostics import exception_facts

SOURCES = frozenset(
    {
        "m3_11_frozen_retirement.py",
        "m3_11_frozen_context.py",
        "m3_11_frozen_entry.py",
        "m3_11_frozen_client.py",
        "m3_11_frozen_driver.py",
        "m3_11_frozen_frames.py",
    }
)


def document(error: BaseException, *, started: float) -> dict[str, object]:
    facts = exception_facts(error)
    types: dict[type[BaseException], str] = {
        RetirementError: "RetirementError",
        LifecycleError: "LifecycleError",
    }
    native_type = types.get(type(error))
    source = None
    trace = error.__traceback__
    while trace is not None:
        name = Path(trace.tb_frame.f_code.co_filename).name
        if name in SOURCES:
            source = {"file": "scripts/" + name, "line": trace.tb_lineno}
        trace = trace.tb_next
    return {
        "format": "lowerduckpond-frozen-retirement-failure-v1",
        "phase": "frozen-retirement",
        "native_exception_type": native_type,
        "exception_chain": facts,
        "source": source,
        "elapsed_seconds": max(0.0, time.monotonic() - started),
        "no_replay": True,
    }
