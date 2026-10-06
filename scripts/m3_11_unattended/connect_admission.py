"""Fresh per-attempt independent capacity and authority precede any creation ACK."""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import audit_policy_recovery
from scripts.m3_11_unattended.connect_journal import IndependentJournal
from scripts.m3_11_unattended.creation_outcome import FORMAT as CREATION_PROTOCOL
from scripts.m3_11_unattended.creation_outcome import run_payload
from scripts.m3_11_unattended.github_checkpoint import MINIMUM_START_CAPACITY
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import (
    LIFETIME,
    Authority,
    Intent,
    LifecycleError,
    Targets,
    digest,
    identity,
    instant,
    stamp,
    strings,
)
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-connect-creation-reservation-v1"
WINDOW = timedelta(minutes=10)


def run_digest(run_id: str, payload: dict[str, object]) -> str:
    selected = (
        {key: value for key, value in payload.items() if key != "creation_protocol"}
        if payload.get("creation_protocol") == CREATION_PROTOCOL
        else payload
    )
    # The launch request identifies the same attempt across protocol versions;
    # the independent native ACK still covers the complete original run record.
    return digest({"run_id": identity(run_id), "payload": selected})


class Admission:
    def __init__(self, journal: IndependentJournal, *, targets: Targets, now: datetime) -> None:
        self.journal, self.targets, self.now = journal, targets, now
        self.records = journal.records()

    def _policy_clear(self, now: datetime) -> bool:
        return audit_policy_recovery.admission_clear(
            self.records,
            now=now,
            independent=lambda record: (
                self.journal.ledger.authored(record, self.journal.witness.author)
                and self.journal.checkpoint.records.get(str(record["event_id"])) == record
            ),
        )

    def _run(self, record: dict[str, object]) -> dict[str, str]:
        payload = run_payload(record["payload"])
        binding = strings(fields(payload["binding"], BINDING))
        if (
            record["kind"] != "run"
            or identity(record["run_id"]) != identity(binding["managed_run_id"])
            or revision(binding["source_revision"]) != revision(binding["helper_revision"])
            or binding["helper_revision"] != self.journal.witness.current_helper
            or binding["storage_target_sha256"] != self.targets.storage_digest
            or payload["mode"] not in {"rehearsal", "qualification"}
            or not isinstance(payload["approval_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["approval_sha256"]) is None
            or any(
                re.fullmatch(r"[0-9a-f]{64}", binding[key]) is None
                for key in ("artifact_sha256", "qualification_inputs_sha256")
            )
        ):
            raise LifecycleError("Connect creation request differs from its approved binding")
        return binding

    def _reservation(
        self, record: dict[str, object], *, durable: bool = True
    ) -> dict[str, object] | None:
        wanted = run_digest(
            identity(record["run_id"]),
            run_payload(record["payload"]),
        )
        matches = []
        for value in self.records:
            payload = value["payload"]
            if (
                value["kind"] == "heartbeat"
                and value["run_id"] == record["run_id"]
                and isinstance(payload, dict)
                and payload.get("format") == FORMAT
                and payload.get("run_sha256") == wanted
                and payload.get("witness") == self.journal.witness.binding()
                and (
                    not durable
                    or self.journal.checkpoint.records.get(str(value["event_id"])) == value
                )
                and self.journal.ledger.authored(value, self.journal.witness.author)
            ):
                matches.append(value)
        if len(matches) > 1:
            raise LifecycleError("Connect creation reservation is ambiguous")
        return matches[0] if matches else None

    def reserve(
        self, expected: str, authority: Authority, *, require_clear: Callable[[], None]
    ) -> bool:
        """Called only for the exact request dispatched by the authorized launcher."""
        if not self._policy_clear(self.now):
            raise LifecycleError("diagnostic policy restoration blocks creation admission")
        if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise LifecycleError("Connect witness dispatch needs an exact request digest")
        matches = [
            record
            for record in self.records
            if record["kind"] == "run"
            and isinstance(record["payload"], dict)
            and run_digest(identity(record["run_id"]), record["payload"]) == expected
        ]
        if not matches:
            return False
        if len(matches) != 1:
            raise LifecycleError("Connect witness dispatch request is ambiguous")
        record = matches[0]
        self._run(record)
        previous = self._reservation(record, durable=False)
        if previous is not None:
            # A native receipt can survive a failed checkpoint upload. Persist
            # that exact decision; a merely checkpointed controller record never
            # qualifies for this recovery path.
            self.journal.persist(previous)
            self.records = self.journal.records()
            return True  # Restart keeps the original capacity reservation and window.
        if (
            not self.journal.cache_complete
            or not self.now - timedelta(minutes=2) <= instant(record["recorded_at"]) <= self.now
            or self.journal.capacity() < MINIMUM_START_CAPACITY
        ):
            raise LifecycleError("Connect attempt lacks fresh independent capacity")
        authority.require(self.now + WINDOW + LIFETIME)
        require_clear()
        # The clearance callback refreshes independent state; a diagnostic
        # obligation may have arrived after this Admission object was built.
        self.records = self.journal.records()
        if not self._policy_clear(self.now):
            raise LifecycleError("diagnostic policy changed during creation admission")
        # Anchor both timing and event identity to the immutable dispatched run.
        # Even a late POST after ephemeral-spool loss produces identical copies,
        # rather than another window or an ambiguous logical decision.
        accepted = instant(record["recorded_at"]).replace(microsecond=0)
        receipt = event(
            "heartbeat",
            identity(record["run_id"]),
            {
                "format": FORMAT,
                "run_sha256": expected,
                "witness": self.journal.witness.binding(),
                "accepted_at": stamp(accepted),
                "create_before": stamp(accepted + WINDOW),
                "authority_expires_at": stamp(authority.valid_until),
                "provider_authorities": {
                    kind: authority.provider_identity(kind)
                    for kind in ("spaces", "cloudflare-account", "cloudflare-user")
                },
                "reserved_capacity": MINIMUM_START_CAPACITY,
            },
        )
        raw_id = bytearray(uuid.UUID(identity(record["run_id"])).bytes)
        raw_id[6:] = hashlib.sha256(("connect-reservation:" + expected).encode()).digest()[6:16]
        raw_id[6], raw_id[8] = (raw_id[6] & 0x0F) | 0x70, (raw_id[8] & 0x3F) | 0x80
        receipt["event_id"] = str(uuid.UUID(bytes=bytes(raw_id)))
        receipt["recorded_at"] = record["recorded_at"]
        self.journal.ledger.stage(receipt)
        self.records = self.journal.records()
        if not self.journal.cache_complete or not self.journal.ledger.authored(
            receipt, self.journal.witness.author
        ):
            raise LifecycleError("Connect capacity reservation awaits native readback")
        self.journal.persist(receipt)
        self.records = self.journal.records()
        return True

    def allow(  # noqa: PLR0911 - explicit admission gates
        self, record: dict[str, object], *, now: datetime | None = None
    ) -> bool:
        """Cleanup/proof ACKs continue after admission closes; creation ACKs cannot."""
        observed_at = self.now if now is None else now
        if record["kind"] not in {"run", "intent"}:
            return True
        if not self._policy_clear(observed_at):
            return False
        candidates = [
            row
            for row in self.records
            if row["kind"] == "run" and row["run_id"] == record["run_id"]
        ]
        if len(candidates) != 1:
            return False
        run = candidates[0]
        payload = run["payload"]
        if isinstance(payload, dict) and isinstance(payload.get("binding"), dict):
            previous_helper = payload["binding"].get("helper_revision")
            if (
                isinstance(previous_helper, str)
                and previous_helper != self.journal.witness.current_helper
            ):
                return False  # Historical attempts keep their evidence and cannot regain CREATE.
        binding = self._run(run)
        reserved = self._reservation(run)
        if reserved is None:
            return False
        receipt = fields(
            reserved["payload"],
            {
                "format",
                "run_sha256",
                "witness",
                "accepted_at",
                "create_before",
                "authority_expires_at",
                "provider_authorities",
                "reserved_capacity",
            },
        )
        accepted, before = instant(receipt["accepted_at"]), instant(receipt["create_before"])
        if before - accepted != WINDOW or not accepted <= observed_at < before:
            return False
        if record["kind"] == "run":
            return True
        intent = Intent.parse(record["payload"])
        authorities = strings(receipt["provider_authorities"])
        return (
            intent.run_id == run["run_id"]
            and intent.source_revision == binding["source_revision"]
            and intent.helper_revision == binding["helper_revision"]
            and intent.targets == self.targets
            and intent.cleanup_authority_sha256 == authorities.get(intent.provider)
            and accepted <= instant(intent.requested_at) < before
            and observed_at < instant(intent.create_before)
        )
