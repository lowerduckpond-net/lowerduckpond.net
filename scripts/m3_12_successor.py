"""The original-intent controller for one admitted successor transaction."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.platform_launch import verify_launch

from scripts import m3_11_production_journal as predecessor_journal
from scripts import m3_11_production_records as predecessor_records
from scripts.m3_12_contracts import (
    CANARY_TRANSACTION,
    AdmissionContext,
    Document,
    Evidence,
    decode,
    digest,
    require,
    require_canary_binding,
)
from scripts.m3_12_successor_journal import SuccessorJournal
from scripts.m3_12_transaction import STAGE_VIEWS, Reconciliation

CONFIGURATION_PHASES = {
    "dark-staging": "converge",
    "dark-repeat": "converge",
    "enabled-convergence": "converge",
    "enabled-repeat": "converge",
    "acceptance": "acceptance",
}


def accepted_predecessor(records: list[tuple[str, bytes]]) -> tuple[str, Document]:
    """Verify the entire immutable M3.11 chain before using its original bindings."""
    state = predecessor_journal.validate(records)
    require(state["phase"] == "complete", "successor-requires-accepted-predecessor")
    original = state["original"]
    if not isinstance(original, dict):  # Narrows the legacy reader's public type.
        raise ValueError("accepted predecessor is invalid")
    return predecessor_journal.digest(predecessor_records.encode(records)), original


def stage_configuration(phase: str, artifact: str) -> Document:
    """Derive one closed stage view from the approved candidate and phase."""
    operation = CONFIGURATION_PHASES.get(phase)
    if operation is None:
        raise ValueError("successor phase does not permit configuration")
    return {
        "stage": operation,
        "artifact_sha256": artifact,
        "recovery_enabled": True,
        "rotation_enabled": True,
        "publication_enabled": STAGE_VIEWS[phase] == "enabled",
        "reconstruction_enabled": False,
        "archive_enabled": True,
        "generation_enabled": True,
    }


def guard_configuration(  # noqa: PLR0913 - all independent bindings are explicit
    journal: SuccessorJournal,
    request: Document,
    authority: AdmissionContext,
    *,
    predecessor_sha256: str,
    candidate: Document,
    state: Path,
    directory: Path,
) -> str:
    """Called with the enrolled native successor action lease already verified."""
    original, history, phases, rollbacks = journal.snapshot()
    phase = history.phase
    if phase is None or not history.pending:
        raise ValueError("successor configuration lacks a pending intent")
    transaction = decode(original, "transaction")
    require(
        authority.active_authority
        and not authority.revoked
        and authority.enrolled_target.get("targetKind") == "production-host"
        and transaction["predecessorSha256"] == predecessor_sha256
        and transaction["predecessorSha256"] == authority.enrolled_target.get("predecessorSha256")
        and transaction["originalProposalSha256"]
        == authority.enrolled_target.get("successorProposalSha256")
        and transaction["leaseDomainSha256"] == authority.enrolled_target.get("leaseDomainSha256")
        and transaction["authorizationSha256"] == authority.authority_sha256
        and transaction["binding"]["targetSha256"] == digest(dict(authority.enrolled_target))
        and transaction["binding"]["runId"] == authority.run_id
        and transaction["binding"]["platformSha256"] == authority.platform_sha256
        and transaction["binding"]["candidateSha256"] == authority.candidate_sha256
        and authority.candidate_sha256 == digest(candidate)
        and phases[-1]["invocationId"] == authority.invocation_id
        and phases[-1]["leaseSha256"] == authority.lease_sha256
        and len(rollbacks) % 2 == 0,
        "successor-configuration-authority-changed",
    )
    expected = stage_configuration(phase, candidate["hostAgentSha256"])
    require(
        digest(request) == digest(expected)
        and phases[-1]["stageConfigurationSha256"] == digest(expected),
        "successor-stage-configuration-changed",
    )
    if expected["publication_enabled"]:
        receipt = verify_launch(state, directory)
        require(
            receipt["binding"] == transaction["binding"],
            "successor-launch-binding-changed",
        )
    return phase


def resume_phase(
    journal: SuccessorJournal,
    authority: AdmissionContext,
    readback: Callable[[], Reconciliation],
    apply: Callable[[Document], None],
) -> Document:
    """Submit one intent, or reconcile a previously started effect without replay."""
    history = journal.snapshot().history
    observed = readback()
    if history.pending:
        transition = "committed" if observed.outcome == "committed" else "not-applied"
        return journal.advance(transition, authority, observed)
    intent = journal.advance("started", authority, observed)
    # Departure or failure leaves the durable intent pending. Only a subsequent
    # independent observation can classify the effect; an exception cannot.
    apply(intent)
    return journal.advance("committed", authority, readback())


def preview(directory: Path) -> Document:
    """Read the pinned proposal and phase configuration without granting authority."""
    with DurableDirectory.open(
        directory, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as stored:
        journal = SuccessorJournal(stored, os.geteuid())
        snapshot = journal.snapshot()
        transaction = decode(snapshot.original, "transaction")
        target = decode(journal.read("target.json"), "target")
        candidate = decode(journal.read("candidate.json"), "candidate")
        platform = decode(journal.read("platform.json"), "platform")
        binding = transaction["binding"]
        require(
            binding["targetSha256"] == digest(target)
            and binding["candidateSha256"] == digest(candidate)
            and binding["platformSha256"] == digest(platform)
            and target["targetKind"] == "production-host"
            and target["predecessorSha256"] == transaction["predecessorSha256"],
            "successor-proposal-binding-changed",
        )
        result: Document = {
            "transactionSha256": snapshot.history.transaction_sha256,
            "predecessorSha256": transaction["predecessorSha256"],
            "target": target,
            "candidate": candidate,
            "platform": platform,
            "currentPhase": snapshot.history.phase,
            "pendingEffect": snapshot.history.pending,
            "rollbackActive": len(snapshot.rollbacks) % 2 == 1,
            "completed": list(snapshot.history.completed),
            "configurations": {
                phase: stage_configuration(phase, candidate["hostAgentSha256"])
                for phase in CONFIGURATION_PHASES
            },
        }
        if transaction["transactionId"] == CANARY_TRANSACTION:
            key = transaction["authorizationSha256"]
            decision = Evidence({key: journal.read("evidence-" + key + ".json")}).read(
                key, "first-canary-decision"
            )
            require_canary_binding(decision, target, binding)
            require(
                transaction["originalProposalSha256"] == target["successorProposalSha256"]
                and transaction["leaseDomainSha256"] == target["leaseDomainSha256"],
                "first-canary-authority-changed",
            )
            result["firstCanaryDecision"] = decision
            result["authoritySha256"] = key
        return result
