"""Secret-free failures for the selected public-CA guest helper, never raw stderr.

The guest transports failures as observations so the bounded command may keep
discarding stderr. Every controller consumer must unwrap them before accepting
an observation. Neither exception text, arguments, notes, locals nor source
lines cross this boundary; only fixed labels and selected-module line numbers do.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

KEY = "public_probe_failure"
FORMAT = "lowerduckpond-public-probe-failure-v1"
MAX_FRAMES = 8
MAX_LINE = 10000
ACTIONS = frozenset(
    {
        "install",
        "start",
        "ready",
        "suspend",
        "interrupt",
        "rebooted",
        "open_verified",
        "restore_native",
        "stop_failed",
        "install_isolated",
        "observe_prepared",
        "diagnostic_prepare",
        "diagnostic_start",
        "diagnostic_interrupt",
        "diagnostic_open",
        "diagnostic_finish",
        "diagnostic_retire_dns",
        "diagnostic_stop_failed",
        "diagnostic_suspend",
    }
)
MODULES = frozenset(
    {
        "m3_11_public_probe.py",
        "m3_11_public_caddy.py",
        "m3_11_debug_public.py",
        "m3_11_debug_dns_probe.py",
    }
)
TYPES = frozenset(
    {
        "ValueError",
        "HostRestoreError",
        "FileNotFoundError",
        "PermissionError",
        "TimeoutError",
        "ConnectionError",
        "OSError",
        "KeyError",
        "TypeError",
        "AssertionError",
        "AttributeError",
        "unknown",
    }
)
# Only exact, literal assertions from the selected helper. Similar text and
# exceptions carrying filenames, HTTP bodies or credentials remain unclassified.
REASONS = {
    "retained public probe predates controlled issuance suspension": "suspension-input-changed",
    "public issuance already completed before its interruption": "issuance-already-complete",
    "public probe admin socket is not private to the owned issuer": "admin-socket-unsafe",
    "public probe issuance suspension was not confirmed": "admin-response-unverified",
    "public probe still has active issuance configuration": "issuance-still-active",
    "isolated public DNS mode is unset or malformed": "isolation-network-unset",
    "public probe action is unsupported": "unsupported-action",
}
TLS_ERRORS = frozenset(
    {
        "restore_tls_peer_unverified",
        "restore_tls_peer_unavailable",
        "restore_tls_storage_unsafe",
        "restore_tls_certificate_invalid",
        "restore_tls_key_mismatch",
        "restore_tls_policy_invalid",
        "restore_tls_trust_unsafe",
        "restore_tls_storage_limit",
        "restore_tls_chain_or_validity_invalid",
        "restore_tls_storage_changed",
        "restore_tls_trust_changed",
        "restore_tls_subjects_unavailable",
    }
)
CODES = frozenset({*REASONS.values(), *TLS_ERRORS, "unclassified"})


class ProbeError(ValueError):
    """A validated failure observation; never usable as a successful guest result."""

    def __init__(self, receipt: dict[str, object]) -> None:
        self.receipt = receipt
        super().__init__(f"public probe {receipt['action']} failed: {receipt['code']}")


def failure(
    action: object, error: Exception, *, context_sha256: object = None
) -> dict[str, object]:
    """Construct labels without stringifying an exception or its chained errors."""
    name = type(error).__name__
    reason = "unclassified"
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        reason = REASONS.get(error.args[0], "unclassified")
    if (
        type(error) is HostRestoreError
        and len(error.args) == 1
        and type(error.args[0]) is str
        and error.args[0] in TLS_ERRORS
    ):
        reason = error.args[0]
    frames: list[dict[str, object]] = []
    frame = error.__traceback__
    while frame is not None:
        filename = frame.tb_frame.f_code.co_filename
        if filename in MODULES and 0 < frame.tb_lineno <= MAX_LINE:
            frames.append({"module": filename, "line": frame.tb_lineno})
        frame = frame.tb_next
    return {
        KEY: {
            "format": FORMAT,
            "action": action if type(action) is str and action in ACTIONS else "unknown",
            "context_sha256": context_sha256
            if type(context_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", context_sha256)
            else None,
            "code": reason,
            "error_type": name if name in TYPES else "unknown",
            "frames": frames[-MAX_FRAMES:],
        }
    }


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate public observation field")
        result[key] = value
    return result


def observation(raw: bytes, *, action: str, context_sha256: str | None = None) -> dict[str, object]:
    """Fail closed on typed errors, mismatched actions or malformed envelopes."""
    if action not in ACTIONS:
        raise ValueError("public probe action is unsupported")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs)
    except ValueError, UnicodeError:
        raise ValueError("public probe observation is malformed") from None
    if not isinstance(result, dict):
        raise ValueError("public probe did not return an observation")
    if KEY not in result:
        return cast(dict[str, object], result)
    receipt = result[KEY]
    if (
        set(result) != {KEY}
        or not isinstance(receipt, dict)
        or set(receipt) != {"format", "action", "context_sha256", "code", "error_type", "frames"}
        or receipt["format"] != FORMAT
        or receipt["action"] != action
        or receipt["context_sha256"] != context_sha256
        or type(receipt["code"]) is not str
        or receipt["code"] not in CODES
        or type(receipt["error_type"]) is not str
        or receipt["error_type"] not in TYPES
    ):
        raise ValueError("public probe failure observation is malformed")
    frames = receipt["frames"]
    if not isinstance(frames, list) or len(frames) > MAX_FRAMES:
        raise ValueError("public probe failure coordinates are malformed")
    for frame in frames:
        if (
            not isinstance(frame, dict)
            or set(frame) != {"module", "line"}
            or type(frame["module"]) is not str
            or frame["module"] not in MODULES
            or type(frame["line"]) is not int
            or not 0 < frame["line"] <= MAX_LINE
        ):
            raise ValueError("public probe failure coordinates are malformed")
    raise ProbeError(cast(dict[str, object], receipt))


def retained_failures(directory: Path) -> dict[str, object]:
    """Summarize fixed isolated receipt paths after cleanup, without blocking it.

    This telemetry grants no cleanup or recovery authority. Damaged diagnostic
    metadata yields fixed unavailable labels, never raw bytes or an exception.
    """
    from scripts.m3_11_private_inputs import read_private  # noqa: PLC0415 - host-only reader
    from scripts.m3_11_unattended.model import digest  # noqa: PLC0415

    failures: dict[str, object] = {}
    unavailable: list[str] = []
    context: str | None = None
    context_available = True
    try:
        context = digest(read_private(directory / "isolation-context.json"))
    except FileNotFoundError:
        pass
    except Exception:
        context_available = False
    for action in sorted(ACTIONS):
        path = directory / f"public-probe-failure-{action}.json"
        try:
            if not path.exists() and not path.is_symlink():
                continue
            if not context_available:
                unavailable.append(action)
                continue
            raw = read_private(path, maximum=8192)
            observation(json.dumps({KEY: raw}).encode(), action=action, context_sha256=context)
        except ProbeError as error:
            failures[action] = error.receipt
        except Exception:
            unavailable.append(action)
    return {
        "format": "lowerduckpond-public-probe-diagnostics-v1",
        "failures": failures,
        "unavailable_actions": unavailable,
        "context_available": context_available,
    }
