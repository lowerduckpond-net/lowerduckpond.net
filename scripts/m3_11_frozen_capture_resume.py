"""Explicit read-only preservation continuation, retaining every partial byte.

Never used after any removal submission. Completed copies are fully reread;
incomplete copies move to a new immutable sibling before a fresh GET/export.
No failed or partial evidence is overwritten or deleted.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from pathlib import Path

from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts import m3_11_frozen_export as files
from scripts.m3_11_retirement_files import RetirementError, directory, record, sync


def capture(  # noqa: PLR0913 - exact destination, ledger, independent reread and effect guard
    output: Path,
    *,
    ledger: Path,
    verify: Callable[[], dict[str, object]],
    create: Callable[[], dict[str, object]],
    guard: Callable[[], None],
    continuing: bool,
) -> dict[str, object]:
    guard()
    if not output.exists() and not output.is_symlink():
        return create()
    if not continuing:
        raise RetirementError(
            "preservation destination already exists; explicit continuation required"
        )
    try:
        return verify()
    except ValueError, OSError:
        # Incomplete bytes are not a disposal proof. Preserve them separately,
        # only while every effect is still demonstrably unsubmitted.
        if any(ledger.glob("*.submitted.json")) or any(ledger.glob("*.submitted.json.partial")):
            raise RetirementError(
                "incomplete preservation after a submission cannot be restarted"
            ) from None
        directory(output)
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            files._parent_linked(output.parent, parent)
            with files.child(parent, output.name, is_directory=True) as source:
                guard()
                files._parent_linked(output.parent, parent)
                files._linked(parent, output.name, source)
                name = output.name + ".interrupted-" + uuid.uuid7().hex
                _rename_noreplace(parent, output.name, name)
                os.fsync(parent)
                record(
                    ledger / ("preservation-" + uuid.uuid7().hex + ".json"),
                    {
                        "original_destination": str(output),
                        "retained_partial": str(output.with_name(name)),
                        "resource_submissions": 0,
                        "partial_deleted": False,
                        "explicit_continuation": True,
                    },
                )
        finally:
            os.close(parent)
        sync(ledger)
    return create()
