"""Connect journals with explicit independent persistence, never cache-only admission."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from functools import partial

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.connect_auth import identity as account_identity
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint, Stored
from scripts.m3_11_unattended.connect_ledger import ACK_FORMAT, ConnectLedger, SnapshotChangedError
from scripts.m3_11_unattended.journal import event, validate
from scripts.m3_11_unattended.model import LifecycleError, digest, identity
from scripts.m3_11_unattended.state import cleanup_lock
from scripts.production_qualification_inputs import revision
from scripts.qualification_timing import measure

ACK_WAIT_SECONDS = 120
ACK_POLL_SECONDS = 5
OBSERVATION_SECONDS = 5


def acknowledgement(record: dict[str, object]) -> bool:
    payload = record.get("payload")
    return (
        record.get("kind") == "heartbeat"
        and isinstance(payload, dict)
        and payload.get("format") == ACK_FORMAT
    )


def logical_key(record: dict[str, object]) -> str:
    validate(record)
    return digest({key: record[key] for key in ("kind", "run_id", "payload")})


@dataclass(frozen=True)
class Witness:
    epoch: str
    helper: str
    server: str
    author: str
    genesis: Stored
    active_helper: str | None = None

    def __post_init__(self) -> None:
        identity(self.epoch)
        revision(self.helper)
        account_identity(self.server)
        account_identity(self.author)
        if self.active_helper is not None:
            revision(self.active_helper)

    @property
    def current_helper(self) -> str:
        return self.active_helper or self.helper

    def binding(self) -> dict[str, object]:
        return {
            "epoch": self.epoch,
            "helper_revision": self.helper,
            "genesis": {"identity": self.genesis.identity, "sha256": self.genesis.sha256},
        }


class _Canonical:
    def __init__(self, ledger: ConnectLedger) -> None:
        self.ledger = ledger
        self.logical = ledger.spool / "logical"
        self.logical.mkdir(mode=0o700, exist_ok=True)

    def records(self) -> list[dict[str, object]]:
        return self.ledger.records()

    def _stage(
        self, record: dict[str, object], *, admit: Callable[[], bool] | None = None
    ) -> tuple[dict[str, object], bool]:
        with self.ledger.staging_observation():
            original = self._original(record)
            if admit is not None and not admit():
                return original, False
            return original, self.ledger.stage(original, admit=admit)

    def _original(self, record: dict[str, object]) -> dict[str, object]:
        """A retry keeps its original event ID even when its first POST is unseen."""
        key = logical_key(record)
        path = self.logical / (key + ".json")
        with cleanup_lock(self.logical):
            if path.exists():
                original = validate(read_private(path))
                if logical_key(original) != key:
                    raise LifecycleError("retained Connect journal event changed")
                return original
            matches = [value for value in self.records() if logical_key(value) == key]
            exact = [value for value in matches if value == record]
            if not exact and len(matches) > 1:
                raise LifecycleError("Connect logical journal event is ambiguous")
            original = exact[0] if exact else matches[0] if matches else record
            write_private(path, original)
            return original


class ConnectJournal(_Canonical):
    """Controller/watchdog adapter: provider work waits for an independent ACK."""

    def __init__(
        self,
        ledger: ConnectLedger,
        witness: Witness,
        *,
        wait_seconds: int = ACK_WAIT_SECONDS,
        check_cancelled: Callable[[], None] = lambda: None,
    ) -> None:
        super().__init__(ledger)
        if not 0 <= wait_seconds <= ACK_WAIT_SECONDS:
            raise LifecycleError("Connect acknowledgement wait exceeds its bound")
        self.witness, self.wait_seconds, self.check_cancelled = (
            witness,
            wait_seconds,
            check_cancelled,
        )

    @property
    def check_cancelled(self) -> Callable[[], None]:
        return self.ledger.check_cancelled

    @check_cancelled.setter
    def check_cancelled(self, value: Callable[[], None]) -> None:
        self.ledger.check_cancelled = value

    def records(self) -> list[dict[str, object]]:
        return self.ledger.stable_records()

    def append(self, record: dict[str, object]) -> None:
        self._stage(record)

    def confirmed(
        self, record: dict[str, object], *, observed: list[dict[str, object]] | None = None
    ) -> bool:
        if self.ledger.minimum.get(identity(record["event_id"])) == digest(record):
            # The explicitly approved genesis checkpoint contains this inventory.
            return True
        return self.ledger.confirmed(
            record,
            independent_server=self.witness.server,
            independent_author=self.witness.author,
            binding=self.witness.binding(),
            genesis_checkpoint=self.witness.genesis,
            observed=self.records() if observed is None else observed,
        )

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        original, _ = self._stage(record)
        until = time.monotonic() + self.wait_seconds
        self.check_cancelled()
        # Staging just completed a full native readback. Historical cleanup
        # records often already have their independent ACK in that same view.
        # Use its matching native metadata before any further ledger I/O; a
        # missing ACK still takes the ordinary bounded observation path.
        if original["kind"] in {"created", "resolved", "result"} and self.confirmed(
            original, observed=self.ledger.observed_records()
        ):
            self.check_cancelled()
            if not self.wait_seconds or time.monotonic() < until:
                return original
        return self._wait_for(original, until=until)

    def persist_creation(self, created: dict[str, object], marker: dict[str, object]) -> None:
        original, related, until = self.stage_creation(created, marker)
        self.wait_many([(original, until), (related, until)])

    def stage_creation(
        self, created: dict[str, object], marker: dict[str, object]
    ) -> tuple[dict[str, object], dict[str, object], float]:
        """Retain both canonical writes immediately; never defer a returned identity."""
        original, _ = self._stage(created)
        # Start the first record's ACK clock at the same boundary as persist().
        # Marker staging and both confirmations share that original deadline.
        until = time.monotonic() + self.wait_seconds
        deadline = until if self.wait_seconds else time.monotonic() + ACK_WAIT_SECONDS
        try:
            with self.ledger.read_budget(deadline=deadline, check_cancelled=lambda: None):
                related, _ = self._stage(marker)
        except Exception as primary:
            # Even a failed marker write must still try to confirm the returned ID.
            # Retained stage intents ensure uncertainty never repeats either POST.
            try:
                self._wait_for(original, until=until)
            except Exception as secondary:
                raise primary from secondary
            raise
        return original, related, until

    def _wait_for(self, original: dict[str, object], *, until: float) -> dict[str, object]:
        self.wait_many([(original, until)])
        return original

    def wait_many(self, pending: list[tuple[dict[str, object], float]]) -> None:
        """Each event keeps its original deadline and requires a fresh native ACK."""
        outstanding = list(pending)
        while outstanding:
            self.check_cancelled()
            until = min(deadline for _, deadline in outstanding)
            if self.wait_seconds and time.monotonic() >= until:
                raise LifecycleError("Connect event awaits independent persistence")
            # The zero-wait double still performs one read. Ordinary polling
            # shares the original ACK deadline across all snapshot requests.
            deadline = until if self.wait_seconds else time.monotonic() + ACK_WAIT_SECONDS
            with self.ledger.read_budget(deadline=deadline, check_cancelled=lambda: None):
                try:
                    if len(outstanding) == 1:
                        # Keep the ordinary single-event observation boundary.
                        confirmed = [self.confirmed(outstanding[0][0])]
                    else:
                        observed = self.records()
                        confirmed = [
                            self.confirmed(record, observed=observed) for record, _ in outstanding
                        ]
                except SnapshotChangedError:
                    confirmed = [False] * len(outstanding)
            self.check_cancelled()
            now = time.monotonic()
            outstanding = [
                (record, deadline)
                for (record, deadline), ready in zip(outstanding, confirmed, strict=True)
                if not ready or (self.wait_seconds and now >= deadline)
            ]
            if not outstanding:
                return
            until = min(deadline for _, deadline in outstanding)
            remaining = until - time.monotonic()
            if remaining <= 0:
                raise LifecycleError("Connect event awaits independent persistence")
            time.sleep(min(ACK_POLL_SECONDS, remaining))


class IndependentJournal(_Canonical):
    """Protected GitHub adapter: recoverable checkpoints precede any acknowledgement."""

    def __init__(
        self,
        ledger: ConnectLedger,
        checkpoint: Checkpoint,
        witness: Witness,
        *,
        capacity: Callable[[], int] = lambda: 0,
    ) -> None:
        super().__init__(ledger)
        if checkpoint.epoch != witness.epoch or checkpoint.genesis != witness.genesis:
            raise LifecycleError("independent Connect checkpoint differs from its pinned witness")
        self.checkpoint, self.witness = checkpoint, witness
        self.capacity = capacity
        checkpoint.restore()
        self.cache_complete = False
        self._reconciling = False
        self._observation: list[dict[str, object]] | None = None
        self._observed_until = 0.0

    def _invalidate(self) -> None:
        self._observation = None
        self._observed_until = 0.0

    @contextmanager
    def reconciliation(self) -> Iterator[None]:
        """Reuse exact durable history only within a short cleanup observation."""
        previous = self._reconciling
        self._invalidate()
        self._reconciling = True
        try:
            yield
        finally:
            self._invalidate()
            self._reconciling = previous

    @contextmanager
    def _fresh(self) -> Iterator[None]:
        previous = self._reconciling
        self._invalidate()
        self._reconciling = False
        try:
            yield
        finally:
            self._invalidate()
            self._reconciling = previous

    def records(self) -> list[dict[str, object]]:
        if self._reconciling and time.monotonic() < self._observed_until:
            return deepcopy(self._observation or [])
        self._invalidate()
        try:
            if self._reconciling:
                # A pass never inherits an old registry/artifact observation.
                self.checkpoint.restore()
            observed = self.ledger.records()
        except LifecycleError, OSError, ValueError:
            # This actor can still delete exactly owned credentials recovered
            # from the authoritative checkpoint, while reporting itself unready.
            self.cache_complete = False
            if not self.checkpoint.records:
                raise LifecycleError("independent obligations are unavailable") from None
            return list(self.checkpoint.records.values())
        merged = self._merge(observed)
        if self._reconciling and self.cache_complete:
            self._observation = deepcopy(merged)
            self._observed_until = time.monotonic() + OBSERVATION_SECONDS
        return merged

    def _merge(self, observed: list[dict[str, object]]) -> list[dict[str, object]]:
        self.cache_complete = self.checkpoint.records.keys() <= {
            identity(record["event_id"]) for record in observed
        }
        return self.checkpoint.merge(observed)

    def admission_records(self) -> list[dict[str, object]]:
        """Include later canonicalization/stage reads without another exchange."""
        if not self.cache_complete:
            raise LifecycleError("creation admission requires complete independent recovery")
        observed = self._merge(self.ledger.observed_records())
        if not self.cache_complete:
            raise LifecycleError("creation admission requires a complete current observation")
        return observed

    def fresh_records(self) -> list[dict[str, object]]:
        """Admission cannot use a cleanup observation or recovered-only fallback."""
        with self._fresh():
            self.cache_complete = False
            self.checkpoint.restore()
            records = self._merge(self.ledger.stable_records())
            if not self.cache_complete:
                raise LifecycleError("admission needs a complete fresh obligation observation")
            # Preserve newly observed obligations even if later replica I/O
            # fails and cleanup falls back to the independently recovered set.
            retained = {
                str(value["event_id"]): value for value in records if not acknowledgement(value)
            }
            verified = self.checkpoint.verified_at
            if (
                retained != self.checkpoint.records
                or verified is None
                or not 0 <= time.monotonic() - verified < OBSERVATION_SECONDS
            ):
                self._retain(records)
            return records

    def _retain(self, records: list[dict[str, object]]) -> Stored:
        return self.checkpoint.persist([value for value in records if not acknowledgement(value)])

    def persist(self, record: dict[str, object]) -> dict[str, object]:
        original = self._original(record)
        records = self.records()
        if (
            self._reconciling
            and time.monotonic() < self._observed_until
            and self.cache_complete
            and self.checkpoint.records.get(str(original["event_id"])) == original
            and original in records
        ):
            # This exact record is already present in both freshly validated
            # stores. New IDs/proofs still take the full write/readback path.
            return original
        self._invalidate()
        if not any(value == original for value in records):
            records.append(original)
        self._retain(records)
        try:
            self.ledger.stage(original)
        except LifecycleError, OSError, ValueError:
            # Failure here cannot forget the recovered ID or proof: it is
            # already durable off host. The receipt must remain unready.
            self.cache_complete = False
        return original

    def append(self, record: dict[str, object]) -> None:
        # Informational receipts must exist with this server's native author
        # before they enter the authoritative snapshot. Otherwise a lost POST
        # strands a checkpoint-only heartbeat forever after process restart.
        # Do not select an arbitrary equal-payload checkpoint row here: that
        # could relabel a controller's forged receipt as independently authored.
        with self._fresh():
            self.ledger.stage(record)
            self.records()
            if not self.ledger.authored(record, self.witness.author):
                raise LifecycleError("independent receipt awaits native author readback")
            self.persist(record)

    def readiness(self) -> dict[str, object]:
        with self._fresh():
            stored = self._retain(self.records())
        capacity = self.capacity()
        if type(capacity) is not int or capacity < 0:
            raise LifecycleError("independent checkpoint write capacity is unavailable")
        return {
            "epoch": self.witness.epoch,
            "checkpoint": {"identity": stored.identity, "sha256": stored.sha256},
            "cache_complete": self.cache_complete,
            # Publishing this heartbeat consumes one additional registry entry.
            "remaining_capacity": max(0, capacity - 1),
        }

    def acknowledge(
        self, *, run_id: int, attempt: int, allow: Callable[[dict[str, object]], bool]
    ) -> int:
        observation, until = self._observation, self._observed_until
        history = self.checkpoint.history
        with self._fresh():
            published = self._acknowledge(run_id=run_id, attempt=attempt, allow=allow)
        if (
            published == 0
            and self._reconciling
            and observation is not None
            and time.monotonic() < until
            and self.cache_complete
            and self.checkpoint.history == history
            and self._merge(self.ledger.observed_records()) == observation
        ):
            # A no-op progress poll cannot invalidate an unchanged complete
            # cleanup observation. Keep its original expiry; never renew it or
            # reuse it after new obligations, a write, or a failed observation.
            self._observation, self._observed_until = observation, until
        elif published > 0 and self._reconciling and self.cache_complete:
            # An actual publication also verifies the complete checkpoint and
            # reads back native ACK metadata. Reuse that completed work only
            # while its original verification is fresh and the final native
            # snapshot has exactly the same non-ACK records. New arrivals or
            # a slow ACK readback must take the ordinary recovery path.
            verified = self.checkpoint.verified_at
            observed = self.ledger.observed_records()
            retained = {
                str(value["event_id"]): value for value in observed if not acknowledgement(value)
            }
            if (
                verified is not None
                and 0 <= time.monotonic() - verified < OBSERVATION_SECONDS
                and retained == self.checkpoint.records
            ):
                self._observation = deepcopy(self._merge(observed))
                self._observed_until = verified + OBSERVATION_SECONDS
        return published

    @measure("credential-acknowledgement")
    def _acknowledge(
        self, *, run_id: int, attempt: int, allow: Callable[[dict[str, object]], bool]
    ) -> int:
        if type(run_id) is not int or run_id < 1 or type(attempt) is not int or attempt < 1:
            raise LifecycleError("independent acknowledgement needs its GitHub execution identity")
        try:
            observed = self.ledger.stable_records()
        except LifecycleError, OSError, ValueError:
            self.cache_complete = False
            raise LifecycleError(
                "Connect replica remains incomplete; cleanup is not ready"
            ) from None
        records = self._merge(observed)
        retained = {
            str(value["event_id"]): value for value in records if not acknowledgement(value)
        }
        # New obligations must survive even a malformed ACK or admission
        # callback failure. Retain them before inspecting transport receipts.
        stored = (
            self._retain(records)
            if retained != self.checkpoint.records or not self.cache_complete
            else None
        )
        if not self.cache_complete:
            raise LifecycleError("Connect replica remains incomplete; cleanup is not ready")
        # Decide which records already have native acknowledgements from one
        # complete snapshot. Do this before stage/_original/allow can perform
        # ledger I/O: its author metadata must describe the same observation.
        # Re-reading the entire vault for each historical event both races new
        # writes and consumes the fixed creation window as history grows.
        pending = []
        for record in records:
            if acknowledgement(record) or self.ledger.minimum.get(
                identity(record["event_id"])
            ) == digest(record):
                continue
            if self.ledger.confirmed(
                record,
                independent_server=self.witness.server,
                independent_author=self.witness.author,
                binding=self.witness.binding(),
                genesis_checkpoint=self.witness.genesis,
                observed=observed,
            ):
                continue
            pending.append(record)
        if stored is None and not any(allow(record) for record in pending):
            # A cleanup progress poll can have no eligible ACKs. It emits no
            # readiness or durability claim, so unchanged obligations need no
            # registry/artifact recovery here. New obligations must still be
            # retained even when their creation ACK is currently prohibited.
            return 0
        if stored is None:
            stored = self._retain(records)
        published = 0
        for record in pending:
            # Readback/checkpoint I/O or an earlier ACK may consume the original
            # admission window. Recheck immediately before another ACK mutation.
            if not allow(record):
                continue
            proof = event(
                "heartbeat",
                identity(record["run_id"]),
                {
                    "format": ACK_FORMAT,
                    "event_id": record["event_id"],
                    "event_sha256": digest(record),
                    "binding": self.witness.binding(),
                    "github_run_id": run_id,
                    "github_run_attempt": attempt,
                    "independent_server_id": self.witness.server,
                    "checkpoint": {"identity": stored.identity, "sha256": stored.sha256},
                },
            )
            # ACKs are transport receipts, not new obligations to ACK recursively.
            _, submitted = self._stage(proof, admit=partial(allow, record))
            if submitted:
                published += 1
        return published
