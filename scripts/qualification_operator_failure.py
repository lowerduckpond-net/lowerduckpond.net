"""Fixed transport failure labels; never publish SSH stderr or request values."""

from __future__ import annotations

import math
import re

UNKNOWN = "unknown"
MAX_MESSAGE_BYTES = 8192
MAX_SOURCE_LINE = 100000
MAX_HANDOFF_NUMBER = 1000000
EXACT = {
    "operator transport timed out": "client-timeout",
    "operator response ended before its declared result": "truncated-result",
    "operator response contains trailing bytes": "trailing-response",
    "operator transport stopped accepting input": "input-stopped",
    "operator transport closed input before the request completed": "input-closed",
    **{
        "operator transport failed: " + message: reason
        for message, reason in (
            ("authorized job handoff failed", "job-handoff-failed"),
            ("authorized job completion timed out", "job-completion-timeout"),
            ("authorized job lifecycle validation timed out", "job-validation-timeout"),
            ("authorized job completed without a durable result", "job-result-absent"),
            ("authorized job result changed during completion", "job-result-changed"),
            ("authorized job result disagrees with lifecycle authority", "job-authority-mismatch"),
            ("authorized job completed with incomplete lifecycle authority", "job-incomplete"),
            ("authenticated result delivery timed out", "host-delivery-timeout"),
            ("authenticated result delivery disconnected", "host-delivery-disconnected"),
            ("static_operator_failed:OSError", "host-os-error"),
            ("static_operator_failed:ValueError", "host-value-error"),
        )
    },
    **{
        f"operator transport failed: {name}.lock is busy": "host-lock-busy"
        for name in ("intake", "export", "publication", "tenant-state")
    },
}
PATTERNS = (
    (
        r"operator transport failed: ssh: connect to host [^\n]+ port [0-9]+: Connection refused",
        "ssh-refused",
    ),
    (
        r"operator transport failed: ssh: connect to host [^\n]+ port [0-9]+: Connection timed out",
        "ssh-connect-timeout",
    ),
    (r"operator transport failed: [^\n]*Permission denied \(publickey\)\.", "ssh-authentication"),
    (r"operator transport failed: ssh_status_[0-9]{1,3}", "ssh-exit-status"),
)
HANDOFF_REASONS = {
    "subprocess-timeout": "job-handoff-timeout",
    "os-error": "job-handoff-os-error",
    "systemctl-exit": "job-systemctl-exit",
}
HANDOFF = re.compile(
    r"operator transport failed: authorized job handoff failed: "
    r"phase=(enqueue|completion-wait) reason=(subprocess-timeout|os-error|systemctl-exit) "
    r"attempt=(1) elapsed_seconds=([0-9]{1,6}\.[0-9]{3}) "
    r"budget_seconds=([0-9]{1,6}\.[0-9]{3}) "
    r"(exception=TimeoutExpired|exception=OSError errno=-?[0-9]{1,6}|exit_status=-?[0-9]{1,6})"
)
REASONS = frozenset(
    (*EXACT.values(), *(reason for _, reason in PATTERNS), *HANDOFF_REASONS.values())
)
FUNCTIONS = frozenset(
    {
        "submit",
        "acknowledge_export",
        "_start_ssh",
        "write",
        "read_exact",
        "_wait",
        "wait",
        "timeout",
        "require_output_eof",
        "_receive_export",
        "_copy_artifact",
    }
)


def reason(message: str) -> str:
    if len(message) > MAX_MESSAGE_BYTES:
        return UNKNOWN
    if message in EXACT:
        return EXACT[message]
    if detail := handoff(message):
        return HANDOFF_REASONS[str(detail["cause"])]
    return next((label for pattern, label in PATTERNS if re.fullmatch(pattern, message)), UNKNOWN)


def sanitize(value: object) -> dict[str, object]:
    source = value if isinstance(value, dict) else {}
    line = source.get("client_line")
    detail, function = source.get("reason"), source.get("client_function")
    result: dict[str, object] = {
        "reason": detail if isinstance(detail, str) and detail in REASONS else UNKNOWN,
        "client_function": (
            function if isinstance(function, str) and function in FUNCTIONS else UNKNOWN
        ),
        "client_line": line if type(line) is int and 1 <= line <= MAX_SOURCE_LINE else UNKNOWN,
    }

    if safe := _safe_handoff(source.get("handoff")):
        result["handoff"] = safe
    return result


def handoff(message: str) -> dict[str, object]:
    """Accept only the fixed server diagnostic grammar, never arbitrary stderr."""
    match = HANDOFF.fullmatch(message) if len(message) <= MAX_MESSAGE_BYTES else None
    if match is None:
        return {}
    phase, cause, attempt, elapsed, budget, suffix = match.groups()
    value: dict[str, object] = {
        "phase": phase,
        "cause": cause,
        "attempt": int(attempt),
        "elapsed_seconds": float(elapsed),
        "budget_seconds": float(budget),
    }
    for field in suffix.split():
        key, _, selected = field.partition("=")
        value[key] = selected
    for key in ("errno", "exit_status"):
        if key in value:
            value[key] = int(str(value[key]))
    return _safe_handoff(value)


def _safe_handoff(value: object) -> dict[str, object]:  # noqa: PLR0911 - fail-closed fields
    if not isinstance(value, dict):
        return {}
    if value.get("phase") not in ("enqueue", "completion-wait") or value.get("attempt") != 1:
        return {}
    if type(value.get("attempt")) is not int:
        return {}
    for key in ("elapsed_seconds", "budget_seconds"):
        number = value.get(key)
        if (
            not isinstance(number, (int, float))
            or isinstance(number, bool)
            or not 0 <= number < MAX_HANDOFF_NUMBER
            or not math.isfinite(number)
        ):
            return {}
    cause = value.get("cause")
    suffixes: dict[str, dict[str, object]] = {
        "subprocess-timeout": {"exception": "TimeoutExpired"},
        "os-error": {"exception": "OSError", "errno": value.get("errno")},
        "systemctl-exit": {"exit_status": value.get("exit_status")},
    }
    suffix = suffixes.get(cause if isinstance(cause, str) else "")
    if suffix is None or any(value.get(key) != expected for key, expected in suffix.items()):
        return {}
    for key in ("errno", "exit_status"):
        if key in suffix:
            number = suffix[key]
            if (
                not isinstance(number, int)
                or isinstance(number, bool)
                or not -MAX_HANDOFF_NUMBER < number < MAX_HANDOFF_NUMBER
            ):
                return {}
    return {
        **{
            key: value[key]
            for key in ("phase", "cause", "attempt", "elapsed_seconds", "budget_seconds")
        },
        **suffix,
    }
