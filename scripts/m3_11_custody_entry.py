"""Bounded native-volume entry for the separately sealed migrated-custody caller.

The caller holds native daemon admission while this helper is mounted/running,
and authenticates the full preservation/current-cleanup proof exchange. No
arbitrary executable, endpoint, issuance or source-workspace action is accepted.
"""

from __future__ import annotations

import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_custody_context import NativeCustody
from scripts.m3_11_custody_domain import DomainDocker
from scripts.m3_11_custody_plan import plan, require
from scripts.m3_11_custody_retirement import CustodyRetirement
from scripts.m3_11_frozen_entry import ACK_SECONDS, NEXT_EFFECT_RESERVE, emit
from scripts.m3_11_frozen_failure import document
from scripts.m3_11_frozen_frames import frame
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import instant
from scripts.m3_11_unattended.storage_admission import bounded_helper, require_remaining
from scripts.production_qualification_inputs import current_candidate

SHORT_CONTAINER_ID = 12


class Proof:
    def __init__(self, approved: dict[str, object]) -> None:
        self.plan, self.valid_until = approved, datetime.min.replace(tzinfo=UTC)

    def current(self, seconds: int = NEXT_EFFECT_RESERVE) -> None:
        require(
            self.valid_until - datetime.now(UTC) > timedelta(seconds=seconds),
            "current cleanup proof lacks the next complete effect reserve",
        )

    def __call__(self) -> str:
        require_remaining(ACK_SECONDS)
        nonce = str(uuid.uuid7())
        emit(
            {
                "operation": "revalidate-migrated-custody-and-cleanup",
                "nonce": nonce,
                "custody_sha256": self.plan["custody_sha256"],
                "evidence_sha256": self.plan["evidence_sha256"],
                "cleanup_contract_sha256": self.plan["cleanup_contract_sha256"],
            }
        )
        result = fields(
            frame(sys.stdin.buffer, deadline=time.monotonic() + ACK_SECONDS),
            {
                "nonce",
                "status",
                "custody_sha256",
                "evidence_sha256",
                "cleanup_contract_sha256",
                "proof_valid_until",
                "observed_at",
            },
        )
        now = datetime.now(UTC)
        require(
            result["nonce"] == nonce
            and result["status"] == "native-custody-and-cleanup-verified"
            and all(
                result[key] == self.plan[key]
                for key in ("custody_sha256", "evidence_sha256", "cleanup_contract_sha256")
            )
            and now - timedelta(seconds=ACK_SECONDS) <= instant(result["observed_at"]) <= now,
            "current custody proof exchange differs",
        )
        self.valid_until = instant(result["proof_valid_until"])
        require(
            self.valid_until <= now + timedelta(seconds=5400),
            "cleanup proof exceeds native validity",
        )
        self.current()
        return str(result["custody_sha256"])


def run(payload: object) -> int:
    started = time.monotonic()
    try:
        value = fields(payload, {"plan", "authorization", "historical", "invocation", "operation"})
        require(
            value["operation"] in {"execute", "observe"}, "unknown migrated retirement operation"
        )
        approved = plan(value["plan"])
        # The private caller supplies the full native container ID. Match its
        # Docker-created hostname before inspecting that actor's real mounts.
        invocation = cast(dict[str, object], value["invocation"])
        hostname = Path("/etc/hostname").read_text().strip()
        require(
            len(hostname) >= SHORT_CONTAINER_ID
            and str(invocation["container_id"]).startswith(hostname),
            "retirement invocation does not identify this helper",
        )
        with bounded_helper():
            current_candidate(Path("/opt/lifecycle"), str(approved["implementation_revision"]))
            proof = Proof(approved)
            proof()
            fixture = NativeCustody(
                configuration=LeaseConfiguration.load(Path("/configuration/controller.json")),
                historical=value["historical"],
                invocation=invocation,
                docker=DomainDocker(),
                revalidate_custody_and_cleanup=proof,
                require_cleanup_current=proof.current,
            )
            result = CustodyRetirement(approved, fixture).execute(
                value["authorization"], observe_only=value["operation"] == "observe"
            )
            emit(
                {
                    "status": "observed" if value["operation"] == "observe" else "verified",
                    "retirement": result,
                    "plan_sha256": digest(approved),
                    "elapsed_seconds": time.monotonic() - started,
                    "provider_delete_submissions": fixture.deletes,
                    "provider_inventory_reads": fixture.reads,
                }
            )
        return 0
    except BaseException as error:
        emit(
            {
                "status": "unresolved",
                "failure": document(error, started=started, phase="custody-retirement"),
                "no_replay": True,
                "qualification_authority": "none",
            }
        )
        return 1


if __name__ == "__main__":
    try:
        payload = frame(sys.stdin.buffer, deadline=time.monotonic() + 30)
    except BaseException:
        emit({"status": "unresolved", "no_replay": True, "qualification_authority": "none"})
        raise SystemExit(1) from None
    raise SystemExit(run(payload))
