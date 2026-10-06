"""One-invocation creation pipeline; cleanup keeps synchronous journal persistence."""

from __future__ import annotations

import time
from contextlib import nullcontext

from scripts.m3_11_unattended.connect_journal import ConnectJournal
from scripts.m3_11_unattended.model import LifecycleError


class ProvisioningJournal:
    """Stage each returned ID now, confirm it with the next intent before CREATE.

    This adapter is private to one provisioning call. Its provisional credential
    results must not escape until flush() succeeds. It never defers ordinary
    persistence or crosses more than one provider creation at a time.
    """

    def __init__(self, journal: ConnectJournal) -> None:
        self.journal = journal
        self.pending: list[tuple[dict[str, object], float]] = []

    def records(self) -> list[dict[str, object]]:
        return self.journal.records()

    def append(self, record: dict[str, object]) -> None:
        self.journal.append(record)

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        if record["kind"] != "intent":
            self.flush()
            return self.journal.persist(record)
        self.journal.check_cancelled()
        until = min((deadline for _, deadline in self.pending), default=None)
        if until is not None and time.monotonic() >= until:
            raise LifecycleError("previous credential awaits independent persistence")
        # Staging the next intent consumes, rather than renews, the previous
        # pair's remaining observation budget.
        with (
            self.journal.ledger.read_budget(deadline=until, check_cancelled=lambda: None)
            if until is not None
            else nullcontext()
        ):
            original = self.journal._original(record)
            self.journal.ledger.stage(original)
        self.pending.append((original, time.monotonic() + self.journal.wait_seconds))
        self.flush()
        return original

    def persist_creation(self, created: dict[str, object], marker: dict[str, object]) -> None:
        if self.pending:
            raise LifecycleError("previous creation has not crossed its persistence barrier")
        original, related, until = self.journal.stage_creation(created, marker)
        self.pending.extend(((original, until), (related, until)))

    def flush(self) -> None:
        self.journal.wait_many(self.pending)
        self.pending.clear()
        self.journal.check_cancelled()
