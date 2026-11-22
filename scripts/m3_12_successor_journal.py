"""Durable successor phase receipts under the host's original action lease."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC
from pathlib import Path
from typing import NamedTuple, Self

from lowerduckpond_static_host_agent.durable import DurableDirectory

from scripts import m3_11_production_lease as lease
from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    AdmissionContext,
    Document,
    Evidence,
    decode,
    digest,
    encode,
    require,
)
from scripts.m3_12_transaction import (
    STAGE_VIEWS,
    History,
    Reconciliation,
    RollbackReadback,
    read_history,
    validate_rollback,
    validate_transition,
)

ORIGINAL = "transaction.json"
PHASE = re.compile(r"phase-([0-9]{10})\.json", re.ASCII)
ROLLBACK = re.compile(r"rollback-([0-9]{10})\.json", re.ASCII)


class Snapshot(NamedTuple):
    original: bytes
    history: History
    phases: tuple[Document, ...]
    rollbacks: tuple[Document, ...]


class SuccessorJournal:
    """The caller supplies trusted readback, never effect claims from arguments."""

    def __init__(self, root: DurableDirectory, owner: int) -> None:
        self.root = root
        self.owner = owner

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.root.close()

    def read(self, name: str) -> bytes:
        return self.root.read_regular(
            (name,),
            expected_owner=self.owner,
            expected_mode=0o600,
            maximum_bytes=MAX_RECORD_BYTES,
        )

    def immutable(self, name: str, value: bytes) -> None:
        try:
            current = self.read(name)
        except FileNotFoundError:
            self.root.create_immutable((name,), value)
        else:
            require(current == value, "successor-original-conflict")
            fd = self.root.duplicate_descriptor()
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def pin(self, raw: bytes) -> None:
        decode(raw, "transaction")
        self.immutable(ORIGINAL, raw)

    def rows(self, pattern: re.Pattern[str], kind: str) -> tuple[bytes, ...]:
        fd = self.root.duplicate_descriptor()
        try:
            names = os.listdir(fd)  # noqa: PTH208 - directory is already descriptor-verified
            matches = sorted(name for name in names if pattern.fullmatch(name))
        finally:
            os.close(fd)
        rows = []
        for index, name in enumerate(matches):
            match = pattern.fullmatch(name)
            require(match is not None and int(match[1]) == index, "successor-gap")
            raw = self.read(name)
            decode(raw, kind)
            rows.append(raw)
        return tuple(rows)

    def snapshot(self) -> Snapshot:
        original = self.read(ORIGINAL)
        phases = self.rows(PHASE, "phase-receipt")
        documents = tuple(decode(raw, "phase-receipt") for raw in phases)
        records = {digest(record): raw for record, raw in zip(documents, phases, strict=True)}
        require(len(records) == len(phases), "successor-replay")
        history = read_history(original, records, Evidence(records))
        rollbacks = tuple(decode(raw, "rollback") for raw in self.rows(ROLLBACK, "rollback"))
        for index, decision in enumerate(rollbacks):
            require(
                decision["transactionSha256"] == history.transaction_sha256
                and decision["priorHeadSha256"] in records.keys() | {None}
                and decision["action"]
                == ("restore-platform-only" if index % 2 == 0 else "reactivate-same-policy"),
                "successor-rollback-conflict",
            )
        return Snapshot(original, history, documents, rollbacks)

    def advance(
        self, transition: str, authority: AdmissionContext, readback: Reconciliation
    ) -> Document:
        original, history, phases, rollbacks = self.snapshot()
        require(history.phase is not None and len(rollbacks) % 2 == 0, "successor-closed")
        phase = history.phase
        if phase is None:
            raise ValueError("successor-closed")
        raw = encode(
            {
                "format": "lowerduckpond-m3-12-phase-receipt-v1",
                "transactionSha256": history.transaction_sha256,
                "previousSha256": history.head_sha256,
                "phase": phase,
                "transition": transition,
                "stageConfigurationSha256": readback.stage_configuration_sha256,
                "publicationView": STAGE_VIEWS[phase],
                "invocationId": authority.invocation_id,
                "leaseSha256": authority.lease_sha256,
                "recordedAt": authority.now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "evidenceSha256": readback.evidence_sha256,
            }
        )
        receipt = validate_transition(raw, original, history, authority, readback)
        if history.pending:
            require(
                phases[-1]["stageConfigurationSha256"] == receipt["stageConfigurationSha256"],
                "successor-phase-config-changed",
            )
        self.immutable(f"phase-{len(phases):010}.json", raw)
        return receipt

    def rollback(
        self, decision: bytes, authority: AdmissionContext, readback: RollbackReadback
    ) -> Document:
        original, history, _, rollbacks = self.snapshot()
        record = validate_rollback(decision, original, history, authority, readback)
        active = len(rollbacks) % 2 == 1
        require(
            readback.rollback_active == active
            and record["action"]
            == ("reactivate-same-policy" if active else "restore-platform-only"),
            "successor-rollback-conflict",
        )
        self.immutable(f"rollback-{len(rollbacks):010}.json", decision)
        return record


@contextmanager
def leased_journal(
    directory: Path, lease_directory: Path, token: str
) -> Iterator[SuccessorJournal]:
    """Take the original M3.11-style action exclusion before changing any record."""
    with (
        lease.action(lease_directory, owner=0, token=token),
        DurableDirectory.open(directory, expected_owner=0, expected_directory_mode=0o700) as root,
    ):
        yield SuccessorJournal(root, 0)
