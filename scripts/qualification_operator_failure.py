"""Fixed transport failure labels; never publish SSH stderr or request values."""

from __future__ import annotations

import re

UNKNOWN = "unknown"
MAX_MESSAGE_BYTES = 8192
MAX_SOURCE_LINE = 100000
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
REASONS = frozenset((*EXACT.values(), *(reason for _, reason in PATTERNS)))
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
    return next((label for pattern, label in PATTERNS if re.fullmatch(pattern, message)), UNKNOWN)


def sanitize(value: object) -> dict[str, object]:
    source = value if isinstance(value, dict) else {}
    line = source.get("client_line")
    detail, function = source.get("reason"), source.get("client_function")
    return {
        "reason": detail if isinstance(detail, str) and detail in REASONS else UNKNOWN,
        "client_function": (
            function if isinstance(function, str) and function in FUNCTIONS else UNKNOWN
        ),
        "client_line": line if type(line) is int and 1 <= line <= MAX_SOURCE_LINE else UNKNOWN,
    }
