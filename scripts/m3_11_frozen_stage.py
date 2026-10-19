"""Separate exact closeout authorities and append-only single-submission effects.

The original archive DELETE slot is never read as permission to mutate again.
This ledger is external to the fixture, survives directory disposal, and records
an effect before calling its fixed native adapter. A crash/interrupt consumes
that identity. Observation may reconcile absence; it never sends the effect.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from lowerduckpond_static_host_agent.durable import _rename_noreplace

from scripts.m3_11_frozen_retirement import fingerprint, reserve
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import RetirementError, digest, directory, record, sync
from scripts.m3_11_unattended.model import instant, stamp

AUTHORIZATION = "lowerduckpond-m3-11-staged-closeout-authorization-v1"
T = TypeVar("T")


def initialize(
    root: Path, plan: dict[str, object], approval: dict[str, object], *, continuing: bool = False
) -> None:
    """Publish both authority records atomically, before any effect or capture.

    Caller holds the exclusive fixture operation lock. Interrupted unpublished
    directories remain private evidence; they can never contain submitted work.
    An explicit continuation may complete metadata publication, but cannot
    replace a published authority or consume an existing effect a second time.
    """
    directory(root.parent)
    if root.exists() or root.is_symlink():
        if not continuing:
            raise FileExistsError("staged closeout already entered; no replay")
        directory(root)
        if (
            read_private(root / "plan.json") != plan
            or read_private(root / "authorization.json") != approval
        ):
            raise RetirementError("staged closeout original authority differs")
        return
    parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = root.name + ".unpublished-" + uuid.uuid7().hex
    try:
        os.mkdir(temporary, mode=0o700, dir_fd=parent)
        os.fsync(parent)
        scratch = root.parent / temporary
        record(scratch / "plan.json", plan)
        record(scratch / "authorization.json", approval)
        sync(scratch)
        _rename_noreplace(parent, temporary, root.name)
        os.fsync(parent)
    finally:
        os.close(parent)


def authorization(value: object, plan: dict[str, object], *, stage: str) -> dict[str, object]:
    result = fields(
        value,
        {
            "format",
            "stage",
            "plan_sha256",
            "approval_reference_sha256",
            "approved_at",
            "acknowledge_irreversible_scoped_removal",
            "acknowledge_execution_remains_excluded",
            "acknowledge_no_automatic_replay",
        },
    )
    if (
        result["format"] != AUTHORIZATION
        or result["stage"] != stage
        or stage not in {"remote-cleanup", "local-disposal"}
        or result["plan_sha256"] != digest(plan)
        or instant(result["approved_at"]) > datetime.now(UTC)
        or any(
            result[key] is not True
            for key in (
                "acknowledge_irreversible_scoped_removal",
                "acknowledge_execution_remains_excluded",
                "acknowledge_no_automatic_replay",
            )
        )
    ):
        raise RetirementError("staged closeout lacks its exact separate effect authority")
    fingerprint(result["approval_reference_sha256"])
    return result


class Effects:
    def __init__(self, root: Path, *, plan: dict[str, object], approval: dict[str, object]) -> None:
        directory(root)
        self.root, self.plan, self.approval = root, plan, approval

    def _value(self, name: str, identity: dict[str, object]) -> dict[str, object]:
        if name not in {"remote-cleanup", "remove-directory", "remove-image"} and not any(
            name.startswith(prefix)
            and len(name) == len(prefix) + 64
            and all(char in "0123456789abcdef" for char in name[len(prefix) :])
            for prefix in (
                "remove-container-",
                "delete-backup-",
                "remove-entry-",
                "continue-remote-",
            )
        ):
            raise RetirementError("staged closeout effect is outside its fixed grammar")
        return {
            "format": "lowerduckpond-m3-11-staged-effect-v1",
            "effect": name,
            "identity": identity,
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(self.approval),
        }

    def submit(self, name: str, identity: dict[str, object], operation: Callable[[], T]) -> T:
        value = self._value(name, identity)
        reserve(self.root / (name + ".submitted.json"), value)
        result = operation()
        record(self.root / (name + ".acknowledged.json"), {"submission_sha256": digest(value)})
        return result

    def submitted(self, name: str, identity: dict[str, object]) -> bool:
        value = self._value(name, identity)
        path = self.root / (name + ".submitted.json")
        if not path.exists() and not path.is_symlink():
            return False
        if read_private(path) != value:
            raise RetirementError("staged effect original submission is ambiguous or changed")
        return True

    def observe(self, name: str, identity: dict[str, object], *, absent: bool) -> dict[str, object]:
        # Return an observation, not an invented acknowledgement of the command.
        # The caller may retain this as a new external observation file.
        if not self.submitted(name, identity):
            raise RetirementError("absence has no original exact staged submission")
        return {
            "effect": name,
            "submission_sha256": digest(self._value(name, identity)),
            "observed_at": stamp(datetime.now(UTC)),
            "absent": absent,
            "mutation_submissions": 0,
            "no_replay": True,
        }
