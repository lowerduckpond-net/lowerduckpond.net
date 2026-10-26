"""Fixed retirement phase and native types, never exception text or request data."""

from __future__ import annotations

import time
from pathlib import Path

from scripts.m3_11_retirement_files import RetirementError
from scripts.m3_11_unattended.model import LifecycleError
from scripts.provider_preflight_diagnostics import exception_facts

MAX_ATTEMPTS = 10000

SOURCES = frozenset(
    {
        "m3_11_frozen_retirement.py",
        "m3_11_frozen_context.py",
        "m3_11_frozen_entry.py",
        "m3_11_frozen_client.py",
        "m3_11_frozen_driver.py",
        "m3_11_frozen_frames.py",
        "m3_11_frozen_stage_entry.py",
        "m3_11_frozen_stage_receipt.py",
        "m3_11_frozen_stage.py",
        "m3_11_frozen_remote.py",
        "m3_11_frozen_remote_proof.py",
        "m3_11_frozen_disposal.py",
        "m3_11_frozen_residual.py",
        "m3_11_frozen_export.py",
        "m3_11_frozen_actor_export.py",
        "m3_11_frozen_backups.py",
        "m3_11_frozen_collect.py",
        "m3_11_frozen_terminal.py",
        "m3_11_frozen_terminal_bundle.py",
        "m3_11_frozen_github.py",
        "m3_11_frozen_envelope.py",
        "m3_11_frozen_capture_resume.py",
        "m3_11_frozen_certificate.py",
        "m3_11_frozen_refresh.py",
        "m3_11_frozen_validate.py",
    }
)


def document(
    error: BaseException,
    *,
    started: float,
    phase: str = "frozen-retirement",
    attempt_count: int = 1,
) -> dict[str, object]:
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
        "phase": phase
        if phase
        in {
            "frozen-retirement",
            "execute",
            "reconcile",
            "remote-cleanup",
            "remote-continue",
            "remote-observe",
            "local-disposal",
            "local-continue",
            "local-observe",
            "terminal-snapshot",
            "terminal-github-get",
            "terminal-capture",
        }
        else "unclassified",
        "attempt_count": attempt_count
        if type(attempt_count) is int and 0 < attempt_count <= MAX_ATTEMPTS
        else None,
        "native_exception_type": native_type,
        "exception_chain": facts,
        "source": source,
        "elapsed_seconds": max(0.0, time.monotonic() - started),
        "no_replay": True,
    }
