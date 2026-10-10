"""Closed failure diagnostics: static source locations, never exception contents."""

from __future__ import annotations

import ast
import subprocess
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.connect_api import ConnectExchangeError, exchange_diagnostic
from scripts.m3_11_unattended.model import LifecycleError

ROOT = Path(__file__).resolve().parents[2]
MAX_RELATED_FAILURES = 4
SOURCES = (
    "scripts/m3_11_private_inputs.py",
    "scripts/m3_11_qualification_evidence.py",
    "scripts/production_qualification_inputs.py",
    "scripts/check_m3_7_production_edge.py",
    "scripts/check_m3_10_provider.py",
    *(
        "scripts/m3_11_unattended/" + name + ".py"
        for name in (
            "connect_action",
            "connect_admission",
            "connect_api",
            "connect_auth",
            "connect_checkpoint",
            "connect_recovery",
            "connect_configuration",
            "connect_control",
            "connect_genesis",
            "connect_host",
            "connect_journal",
            "connect_ledger",
            "connect_provisioning",
            "creation_outcome",
            "github_checkpoint",
            "config",
            "cloudflare",
            "spaces",
            "http",
            "journal",
            "lifecycle",
            "model",
            "cleanup",
            "worker",
            "state",
            "production",
            "inputs",
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
    if (
        isinstance(error, subprocess.CalledProcessError)
        and type(error.returncode) is int
        and -128 <= error.returncode <= 255  # noqa: PLR2004 - bounded process status
    ):
        value["exit_status"] = error.returncode
    if isinstance(error, ConnectExchangeError):
        with suppress(RuntimeError, ValueError, TypeError, KeyError):
            value["exchange"] = exchange_diagnostic(error.exchange)
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


def failure_chain(
    error: Exception, *, describe: Callable[[Exception], dict[str, object]] = failure
) -> dict[str, object]:
    """Retain bounded transport causes using the same closed fields as the primary error."""
    value: dict[str, object] = {"failure": describe(error)}
    related: list[dict[str, object]] = []
    seen = {id(error)}
    secondary = error.__cause__ or error.__context__
    while (
        isinstance(secondary, Exception)
        and id(secondary) not in seen
        and len(related) < MAX_RELATED_FAILURES
    ):
        seen.add(id(secondary))
        related.append(describe(secondary))
        secondary = secondary.__cause__ or secondary.__context__
    if related:
        value["related_failures"] = related
    return value


def retain_failure(path: Path, *, binding: dict[str, object], stage: str, error: Exception) -> None:
    """A failed diagnostic can never prevent revocation or replace earlier evidence."""
    try:
        if not path.exists():
            value: dict[str, object] = {
                "binding": binding,
                "stage": stage,
                **failure_chain(error),
            }
            write_private(path, value)
    except Exception:
        return  # Exception text can contain secrets; failure never blocks cleanup.


def verified_failure(  # noqa: PLR0912 - closed optional diagnostic fields
    raw: object, *, binding: dict[str, object], stages: frozenset[str]
) -> dict[str, object]:
    names = {"binding", "stage", "failure"}
    if isinstance(raw, dict) and "related_failures" in raw:
        names.add("related_failures")
    value = fields(raw, names)
    if "related_failures" in value:
        related = value["related_failures"]
        if not isinstance(related, list) or not 1 <= len(related) <= MAX_RELATED_FAILURES:
            raise LifecycleError("related failure diagnostics exceed their bound")
        for detail in related:
            verified_failure(
                {"binding": value["binding"], "stage": value["stage"], "failure": detail},
                binding=binding,
                stages=stages,
            )
    if (
        value["binding"] != binding
        or not isinstance(value["stage"], str)
        or value["stage"] not in stages
    ):
        raise LifecycleError("failure diagnostic differs from its bound attempt")
    detail_fields = {"category", "origin"}
    if isinstance(value["failure"], dict) and "exchange" in value["failure"]:
        detail_fields.add("exchange")
    if isinstance(value["failure"], dict) and "exit_status" in value["failure"]:
        detail_fields.add("exit_status")
    detail = fields(value["failure"], detail_fields)
    if "exit_status" in detail and (
        detail["category"] != "subprocess"
        or type(detail["exit_status"]) is not int
        or not -128 <= detail["exit_status"] <= 255  # noqa: PLR2004 - bounded process status
    ):
        raise LifecycleError("failure diagnostic process status is invalid")
    if "exchange" in detail:
        exchange_diagnostic(detail["exchange"])
    if not isinstance(detail["category"], str) or detail["category"] not in {
        "lifecycle",
        "input",
        "io",
        "subprocess",
        "unexpected",
    }:
        raise LifecycleError("failure diagnostic category is invalid")
    if detail["origin"] is not None:
        origin = fields(detail["origin"], {"path", "function", "line"})
        path, function, line = origin["path"], origin["function"], origin["line"]
        if path not in SOURCES or not isinstance(path, str) or type(line) is not int:
            raise LifecycleError("failure diagnostic source is invalid")
        matches = [
            node
            for node in ast.walk(ast.parse((ROOT / path).read_text()))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function
            and node.end_lineno is not None
            and node.lineno <= line <= node.end_lineno
        ]
        if len(matches) != 1:
            raise LifecycleError("failure diagnostic location is not in the pinned source")
    return value
