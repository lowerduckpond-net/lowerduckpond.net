"""Bounded semantic validation shared by native and controller Ansible recap readers."""

from __future__ import annotations

import json
from typing import cast

from scripts import m3_11_production_journal as journal

COUNTERS = frozenset({"ok", "changed", "failures", "unreachable", "skipped", "rescued", "ignored"})
MAX_RECEIPT_BYTES = 4096


def validate_recap(
    raw: bytes, context: str, *, idempotent: bool, expected_host: str
) -> dict[str, int]:
    if not 0 < len(raw) <= MAX_RECEIPT_BYTES:
        raise ValueError("production playbook recap size is unsafe")
    value = json.loads(raw)
    if (
        type(value) is not dict
        or set(value) != {"format", "context_sha256", "hosts"}
        or value["format"] != "lowerduckpond-m3-11-playbook-recap-v1"
        or value["context_sha256"] != context
        or type(value["hosts"]) is not dict
        or set(value["hosts"]) != {expected_host}
        or journal.canonical(value) != raw
    ):
        raise ValueError("production playbook did not report exactly its intended host and inputs")
    counters = value["hosts"][expected_host]
    if (
        type(counters) is not dict
        or set(counters) != COUNTERS
        or any(type(count) is not int or count < 0 for count in counters.values())
        or not counters["ok"]
        or any(counters[name] for name in ("failures", "unreachable", "rescued", "ignored"))
        or (idempotent and counters["changed"])
    ):
        raise ValueError("production playbook failed or its second pass was not idempotent")
    return cast(dict[str, int], counters)
