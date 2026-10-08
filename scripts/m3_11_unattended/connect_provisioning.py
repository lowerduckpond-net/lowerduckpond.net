"""One-invocation creation pipeline; cleanup keeps synchronous journal persistence."""

from __future__ import annotations

import time
from contextlib import nullcontext
from datetime import UTC, datetime

from scripts.m3_11_unattended.connect_admission import WINDOW
from scripts.m3_11_unattended.connect_journal import ConnectJournal
from scripts.m3_11_unattended.connect_ledger import ReadbackExpiredError
from scripts.m3_11_unattended.creation_outcome import run_payload
from scripts.m3_11_unattended.journal import Journal
from scripts.m3_11_unattended.model import LifecycleError, instant


def persist_run(
    journal: Journal, record: dict[str, object], *, deadline: float
) -> dict[str, object]:
    """Wait for this run's reservation within its original creation window only."""
    if not isinstance(journal, ConnectJournal):
        return journal.persist(record)
    if record["kind"] != "run":
        raise LifecycleError("creation reservation requires a run record")
    run_payload(record["payload"])

    def cutoff(value: dict[str, object]) -> tuple[datetime, float]:
        accepted = instant(value["recorded_at"]).replace(microsecond=0)
        now = datetime.now(UTC)
        expires = accepted + WINDOW
        if not accepted <= now < expires:
            raise LifecycleError("original creation reservation window is unavailable")
        return expires, min(deadline, time.monotonic() + (expires - now).total_seconds())

    expires, until = cutoff(record)
    original: dict[str, object] | None = None
    staged = False
    last_observation: ReadbackExpiredError | None = None
    while True:
        journal.check_cancelled()
        if time.monotonic() >= until or datetime.now(UTC) >= expires:
            raise LifecycleError(
                "original creation reservation window elapsed"
            ) from last_observation
        try:
            with journal.ledger.read_budget(deadline=until, check_cancelled=lambda: None):
                if original is None:
                    original = journal._original(record)
                    # A retained canonical record can be older than the proposal.
                    # Observation retries never renew either original deadline.
                    expires, original_until = cutoff(original)
                    until = min(until, original_until)
                with journal.ledger.read_budget(deadline=until, check_cancelled=lambda: None):
                    if not staged:
                        # stage's retained intent permits only readback after an
                        # uncertain POST; this loop never resubmits that POST.
                        journal.ledger.stage(original)
                        staged = True
                    result = journal._wait_for(
                        original, until=until if journal.wait_seconds else time.monotonic()
                    )
        except ReadbackExpiredError as error:
            if not journal.wait_seconds:
                raise  # Explicit single-observation mode for local doubles.
            last_observation = error
            # Each complete read still has its original 60-second cap. This
            # includes canonicalization and the first write's readback, not just
            # the subsequent independent ACK observation.
            continue
        journal.check_cancelled()
        if time.monotonic() >= until or datetime.now(UTC) >= expires:
            raise LifecycleError("original creation reservation window elapsed")
        return result


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
            original, _ = self.journal._stage(record)
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
