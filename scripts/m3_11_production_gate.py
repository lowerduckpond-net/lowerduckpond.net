"""Permit only the configuration belonging to the original rollout phase."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_records as records

MAX_BYTES = 4096
FLAGS = {
    "recovery_enabled",
    "rotation_enabled",
    "publication_enabled",
    "reconstruction_enabled",
    "archive_enabled",
    "generation_enabled",
}
PHASES = {
    "namespace.started": ("bootstrap", False, False),
    "converged.started": ("converge", True, False),
    "rotation-enabled.started": ("converge", True, True),
    "accepted.started": ("acceptance", True, True),
}


def require(directory: Path, raw: bytes, *, owner: int) -> str:
    """Read actual immutable authority; the caller must also hold the action lease.

    A completed journal authorizes records-only inspection, never another
    convergence. Missing or interrupted authority cannot supply default flags.
    """
    if len(raw) > MAX_BYTES:
        raise ValueError("production configuration request exceeds its bound")
    request = json.loads(raw)
    if (
        type(request) is not dict
        or set(request) != FLAGS | {"stage", "artifact_sha256"}
        or any(type(request[name]) is not bool for name in FLAGS)
        or type(request["stage"]) is not str
        or type(request["artifact_sha256"]) is not str
    ):
        raise ValueError("production configuration request is invalid")
    state = journal.validate(records.decode(records.operate(directory, ["read"], b"", owner=owner)))
    expected = PHASES.get(str(state["phase"]))
    if expected is None:
        raise ValueError("production journal does not authorize configuration")
    original = cast(dict[str, object], state["original"])
    candidate = cast(dict[str, object], original["candidate"])
    if request != {
        "stage": expected[0],
        "artifact_sha256": candidate["artifact_sha256"],
        "recovery_enabled": expected[1],
        "rotation_enabled": expected[2],
        "publication_enabled": False,
        "reconstruction_enabled": False,
        "archive_enabled": True,
        "generation_enabled": True,
    }:
        raise ValueError("production configuration differs from its qualified phase")
    return str(state["phase"])
