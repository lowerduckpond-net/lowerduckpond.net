"""Bounded existing-controller entry; no automatic launch or deletion retry."""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts import production_qualification_inputs as source
from scripts.m3_11_frozen_context import NativeFixture, require
from scripts.m3_11_frozen_failure import document
from scripts.m3_11_frozen_frames import frame
from scripts.m3_11_frozen_retirement import FrozenRetirement, require_supported_closeout
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import instant
from scripts.m3_11_unattended.storage_admission import (
    ReadOnlyDocker,
    bounded_helper,
    require_remaining,
)

ACK_SECONDS = 720  # Full 600-second local child plus frame/fsync/report overhead.
NEXT_EFFECT_RESERVE = 180
FRAME_BYTES = 1024 * 1024


def emit(value: dict[str, object]) -> None:
    print(json.dumps(value, sort_keys=True), flush=True)


class LocalProof:
    def __init__(self, evidence_sha256: str) -> None:
        self.evidence_sha256 = evidence_sha256
        self.valid_until: datetime | None = None

    def current(self) -> None:
        require(
            self.valid_until is not None
            and self.valid_until - datetime.now(UTC) > timedelta(seconds=NEXT_EFFECT_RESERVE),
            "cleanup proof lacks time for the next bounded effect and report",
        )

    def __call__(self) -> str:
        require_remaining(ACK_SECONDS)
        nonce = str(uuid.uuid7())
        emit(
            {
                "operation": "revalidate-preserved-files-and-cleanup",
                "nonce": nonce,
                "evidence_sha256": self.evidence_sha256,
            }
        )
        value = fields(
            frame(sys.stdin.buffer, deadline=time.monotonic() + ACK_SECONDS),
            {
                "nonce",
                "evidence_sha256",
                "status",
                "proof_valid_until",
                "observed_at",
            },
        )
        now = datetime.now(UTC)
        observed = instant(value["observed_at"])
        require(
            value["nonce"] == nonce
            and value["evidence_sha256"] == self.evidence_sha256
            and value["status"] == "native-files-and-cleanup-verified"
            and now - timedelta(seconds=ACK_SECONDS) <= observed <= now,
            "local proof is not the current bound validation",
        )
        self.valid_until = instant(value["proof_valid_until"])
        # The driver computes this from native run.created_at/host observed_at;
        # this bound prevents an accidental unlimited or future receipt window.
        require(
            self.valid_until <= now + timedelta(seconds=5400),
            "cleanup proof validity exceeds existing policy",
        )
        self.current()
        return self.evidence_sha256


def run(payload: object) -> int:
    started = time.monotonic()
    try:
        value = fields(
            payload, {"plan", "authorization", "fixture", "runtime_revision", "operation"}
        )
        require(value["operation"] in {"execute", "reconcile"}, "unknown retirement operation")
        if value["operation"] == "execute":
            require_supported_closeout()
        with bounded_helper():
            source.current_candidate(Path("/work/source"), str(value["runtime_revision"]))
            transaction_plan = value["plan"]
            if not isinstance(transaction_plan, dict):
                raise ValueError("retirement plan is missing")
            proof = LocalProof(str(transaction_plan["evidence_sha256"]))
            proof()
            fixture = NativeFixture(
                configuration=LeaseConfiguration.load(Path("/configuration/controller.json")),
                fixture=cast(dict[str, object], value["fixture"]),
                evidence_root=Path("/evidence"),
                revalidate_copies_and_cleanup=proof,
                docker=ReadOnlyDocker(),
                require_cleanup_current=proof.current,
            )
            result = FrozenRetirement(transaction_plan, fixture).execute(
                value["authorization"], reconcile_only=value["operation"] == "reconcile"
            )
            emit(
                {
                    "status": "observed" if value["operation"] == "reconcile" else "verified",
                    "retirement": result,
                    "elapsed_seconds": time.monotonic() - started,
                    "provider_delete_submissions": fixture.deletes,
                    "provider_inventory_owner_reads": fixture.reads,
                }
            )
        return 0
    except BaseException as error:
        emit(
            {
                "status": "unresolved",
                "failure": document(error, started=started),
                "no_replay": True,
                "qualification_authority": "none",
            }
        )
        return 1
