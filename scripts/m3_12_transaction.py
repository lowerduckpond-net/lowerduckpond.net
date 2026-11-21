"""Pure validation of production journal history and guarded continuation."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from scripts.m3_12_contracts import (
    CLOCK_TOLERANCE,
    AdmissionContext,
    Document,
    Evidence,
    decode,
    digest,
    instant,
    require,
)

PHASES = (
    "preparation",
    "dark-staging",
    "dark-repeat",
    "final-backup-verification",
    "activation-preparation",
    "durable-launch",
    "enabled-convergence",
    "enabled-repeat",
    "canary",
    "accounting",
    "acceptance",
)

STAGE_VIEWS = {
    "preparation": "predecessor",
    "dark-staging": "dark",
    "dark-repeat": "dark",
    "final-backup-verification": "dark",
    "activation-preparation": "dark",
    "durable-launch": "dark",
    "enabled-convergence": "enabled",
    "enabled-repeat": "enabled",
    "canary": "enabled",
    "accounting": "enabled",
    "acceptance": "enabled",
}


@dataclass(frozen=True)
class History:
    transaction_sha256: str
    head_sha256: str | None
    phase: str | None
    pending: bool
    recorded_at: datetime
    completed: tuple[str, ...]


def read_history(transaction_raw: bytes, chain: Iterable[str], evidence: Evidence) -> History:
    """Each link is authenticated by the retained journal reader."""
    transaction = decode(transaction_raw, "transaction")
    key = digest(transaction)
    head = None
    pending = False
    completed: list[str] = []
    recorded_at = instant(transaction["createdAt"])
    for link in chain:
        receipt = evidence.read(link, "phase-receipt")
        time = instant(receipt["recordedAt"])
        require(
            receipt["transactionSha256"] == key
            and receipt["previousSha256"] == head
            and time >= recorded_at
            and len(completed) < len(PHASES),
            "invalid-journal-link",
        )
        phase = PHASES[len(completed)]
        transition = receipt["transition"]
        require(receipt["phase"] == phase, "invalid-phase-order")
        require(receipt["publicationView"] == STAGE_VIEWS[phase], "wrong-stage-view")
        require((transition == "started") != pending, "invalid-phase-transition")
        pending = transition == "started"
        if transition == "committed":
            completed.append(phase)
        head, recorded_at = link, time
    upcoming = PHASES[len(completed)] if len(completed) < len(PHASES) else None
    return History(key, head, upcoming, pending, recorded_at, tuple(completed))


@dataclass(frozen=True)
class Reconciliation:
    """Independent phase readback or verified drain and original preconditions."""

    evidence_sha256: str
    outcome: str
    drained: bool
    preconditions_hold: bool
    stage_configuration_sha256: str


def _verify_transaction(
    transaction_raw: bytes, history: History, authority: AdmissionContext
) -> Document:
    transaction = decode(transaction_raw, "transaction")
    binding = transaction["binding"]
    target = authority.enrolled_target
    require(
        digest(transaction) == history.transaction_sha256
        and target.get("targetKind") == "production-host"
        and binding["targetSha256"] == digest(dict(target))
        and binding["runId"] == authority.run_id
        and binding["candidateSha256"] == authority.candidate_sha256
        and binding["platformSha256"] == authority.platform_sha256
        and transaction["authorizationSha256"] == authority.authority_sha256
        and transaction["predecessorSha256"] == target.get("predecessorSha256")
        and transaction["leaseDomainSha256"] == target.get("leaseDomainSha256")
        and transaction["originalProposalSha256"] == target.get("successorProposalSha256")
        and authority.active_authority
        and not authority.revoked,
        "inactive-transaction",
    )
    return transaction


def validate_transition(
    raw: bytes,
    transaction_raw: bytes,
    history: History,
    authority: AdmissionContext,
    readback: Reconciliation,
) -> Document:
    """Accept intent, verified commit, or a proved no-effect resolution."""
    _verify_transaction(transaction_raw, history, authority)
    receipt = decode(raw, "phase-receipt")
    require(
        receipt["transactionSha256"] == history.transaction_sha256
        and receipt["previousSha256"] == history.head_sha256
        and receipt["phase"] == history.phase
        and receipt["publicationView"] == STAGE_VIEWS.get(receipt["phase"])
        and receipt["stageConfigurationSha256"] == readback.stage_configuration_sha256
        and receipt["invocationId"] == authority.invocation_id
        and receipt["leaseSha256"] == authority.lease_sha256
        and history.recorded_at <= instant(receipt["recordedAt"]) <= authority.now + CLOCK_TOLERANCE
        and receipt["evidenceSha256"] == readback.evidence_sha256,
        "invalid-continuation",
    )
    transition = receipt["transition"]
    require((transition == "started") != history.pending, "invalid-phase-transition")
    require(readback.drained, "original-action-not-drained")
    if transition == "committed":
        require(readback.outcome == "committed", "unverified-postcondition")
    else:
        require(
            readback.outcome == "not-applied" and readback.preconditions_hold,
            "unverified-original-preconditions",
        )
    return receipt


@dataclass(frozen=True)
class RollbackReadback:
    """Same-invocation safety and original retained state from the verified journal."""

    invocation_id: str
    authorization_sha256: str
    evidence_sha256: str
    preceding_generation_sha256: str
    retained_launch_sha256: str | None
    retained_intent_sha256: str | None
    drained: bool
    platform_only_compatible: bool
    irreversible_history: bool
    policy_unchanged: bool
    rollback_active: bool


def validate_rollback(
    raw: bytes,
    transaction_raw: bytes,
    history: History,
    authority: AdmissionContext,
    readback: RollbackReadback,
) -> Document:
    _verify_transaction(transaction_raw, history, authority)
    decision = decode(raw, "rollback")
    require(
        decision["transactionSha256"] == history.transaction_sha256
        and decision["priorHeadSha256"] == history.head_sha256
        and decision["invocationId"] == authority.invocation_id == readback.invocation_id
        and decision["leaseSha256"] == authority.lease_sha256
        and history.recorded_at <= instant(decision["decidedAt"]) <= authority.now + CLOCK_TOLERANCE
        and decision["authorizationSha256"] == readback.authorization_sha256
        and decision["readbackSha256"] == readback.evidence_sha256
        and decision["precedingGenerationSha256"] == readback.preceding_generation_sha256
        and decision["retainedLaunchSha256"] == readback.retained_launch_sha256
        and decision["retainedIntentSha256"] == readback.retained_intent_sha256,
        "wrong-rollback-scope",
    )
    require(
        readback.drained
        and not history.pending
        and not (
            authority.tenant_history
            or authority.tenant_generation
            or authority.unfinished_lifecycle
            or readback.irreversible_history
        )
        and readback.platform_only_compatible
        and (
            "durable-launch" not in history.completed or readback.retained_launch_sha256 is not None
        )
        and (
            readback.retained_launch_sha256 is None or readback.retained_intent_sha256 is not None
        ),
        "unsafe-rollback",
    )
    if decision["action"] == "reactivate-same-policy":
        require(readback.rollback_active and readback.policy_unchanged, "invalid-reactivation")
    return decision
