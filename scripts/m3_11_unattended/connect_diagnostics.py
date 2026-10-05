"""Closed failure diagnostics: static source locations, never exception contents."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

from scripts.m3_11_unattended.model import LifecycleError

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "scripts/m3_11_private_inputs.py",
    "scripts/m3_11_qualification_evidence.py",
    "scripts/production_qualification_inputs.py",
    "scripts/check_m3_7_production_edge.py",
    *(
        "scripts/m3_11_unattended/" + name + ".py"
        for name in (
            "connect_action",
            "connect_admission",
            "connect_api",
            "connect_auth",
            "connect_checkpoint",
            "connect_configuration",
            "connect_genesis",
            "connect_host",
            "connect_journal",
            "connect_ledger",
            "github_checkpoint",
            "config",
            "cloudflare",
            "spaces",
            "http",
            "journal",
            "lifecycle",
            "model",
            "cleanup",
        )
    ),
)


def failure(error: Exception) -> dict[str, object]:
    category = "unexpected"
    for classes, label in (
        ((LifecycleError,), "lifecycle"),
        ((ValueError, KeyError, TypeError), "input"),
        ((OSError,), "io"),
        ((subprocess.SubprocessError,), "subprocess"),
    ):
        if isinstance(error, classes):
            category = label
            break
    value: dict[str, object] = {"category": category, "origin": None}
    try:
        paths = {str((ROOT / name).resolve()): name for name in SOURCES}
        frame = error.__traceback__
        while frame is not None:
            code, line = frame.tb_frame.f_code, frame.tb_lineno
            path = paths.get(code.co_filename)
            if path is not None:
                # Names come from the pinned source's AST, never an arbitrary
                # exception class, dynamically compiled filename or function.
                tree = ast.parse((ROOT / path).read_text())
                matches = [
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == code.co_name
                    and node.end_lineno is not None
                    and node.lineno <= line <= node.end_lineno
                ]
                if len(matches) == 1:
                    value["origin"] = {"path": path, "function": matches[0].name, "line": line}
            frame = frame.tb_next
    except Exception:
        # A broken diagnostic must not change cleanup's unresolved outcome.
        value["origin"] = None
    return value
