"""Synthetic contract vectors. These records confer no real execution authority."""

import base64
import fcntl
import os
import sys
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from runpy import run_path
from typing import Literal
from uuid import UUID

import pytest
from jsonschema import Draft202012Validator
from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent import droplet_enrollment, platform_launch
from lowerduckpond_static_host_agent.durable import DurabilityBoundary, DurableDirectory
from lowerduckpond_static_host_agent.platform_launch import (
    initialize_launch,
    require_local_launch_binding,
    verify_launch,
)

from scripts import m3_11_production_lease as lease
from scripts import m3_12_droplet as droplet
from scripts import m3_12_droplet_inventory as droplet_inventory
from scripts import m3_12_droplet_observe as droplet_observe
from scripts import m3_12_native as native
from scripts.m3_12_contracts import (
    COMMON_SLOTS,
    DISPOSABLE,
    INSTALLED,
    MAX_RECORD_BYTES,
    PRODUCTION,
    PRODUCTION_SLOTS,
    SCHEMA,
    AdmissionContext,
    Document,
    Evidence,
    ValidationError,
    decode,
    digest,
    encode,
    validate_admission,
    validate_diagnostic,
    validate_launch,
    validate_report,
)
from scripts.m3_12_requirements import CoverageScope, validate_coverage, validate_inventory
from scripts.m3_12_successor import preview, resume_phase
from scripts.m3_12_successor_journal import SuccessorJournal
from scripts.m3_12_transaction import (
    PHASES,
    STAGE_VIEWS,
    Reconciliation,
    RollbackReadback,
    read_history,
    validate_rollback,
    validate_transition,
)
from scripts.qualification_context import RUN_ENV, resource_names

BASE = datetime(2026, 1, 1, tzinfo=UTC)
PURPOSES = {
    INSTALLED: "installed-test",
    DISPOSABLE: "disposable-qualification",
    PRODUCTION: "production",
}
DOMAIN = "lowerduckpond.net"
SUFFIX = "lowerduckpond.com"


def fixture_time(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def uuid(value: int) -> str:
    return f"00000000-0000-7000-8000-{value:012x}"


def proof(value: str) -> str:
    return digest({"synthetic": value})


def record(name: str, **fields: object) -> Document:
    return {"format": f"lowerduckpond-m3-12-{name}-v1", **fields}


def retain(records: dict[str, bytes], obj: Document) -> str:
    raw = encode(obj)
    key = digest(obj)
    records[key] = raw
    return key


def receipt(
    admission: Document, kind: str, start: int, end: int, observation: str | None = None
) -> Document:
    return record(
        "receipt",
        binding=admission["binding"],
        invocationId=admission["invocationId"],
        kind=kind,
        startedAt=fixture_time(start),
        finishedAt=fixture_time(end),
        oldestSupportingAt=fixture_time(start),
        observationSha256=observation or proof(kind),
        outcome="passed",
    )


def enroll(
    kind: str, report: Document | None = None
) -> tuple[Document, AdmissionContext, Evidence]:
    run_id = uuid(list(PURPOSES).index(kind))
    target = {
        "targetKind": kind,
        "purpose": PURPOSES[kind],
        **{
            field: proof(kind + field)
            for field in (
                "enrollmentSha256",
                "allocationSha256",
                "leaseDomainSha256",
                "inventorySha256",
                "stateSha256",
                "addressSetSha256",
                "transactionNamespaceSha256",
            )
        },
        "transport": {"kind": "ssh", "identitySha256": proof(kind + "ssh")},
    }
    if kind == INSTALLED:
        run_label = resource_names(UUID(run_id).hex)[RUN_ENV]
        target["docker"] = {
            "endpointSha256": proof("endpoint"),
            "daemonObservationSha256": proof("daemon"),
            "ownerManifestSha256": proof("owner"),
            "runLabel": run_label,
            "drainedAllocationSha256": proof("drained"),
            "roles": {
                role: {"id": proof(role), "image": proof(role + "image"), "runLabel": run_label}
                for role in ("host", "archive")
            },
        }
    else:
        target["droplet"] = {
            "projectIdSha256": proof("project"),
            "dropletId": 100 if kind == PRODUCTION else 101,
            "providerIdentitySha256": proof(kind + "provider"),
            "metadataIdentitySha256": proof(kind + "metadata"),
        }
    if kind == PRODUCTION:
        target["predecessorSha256"] = proof("predecessor")
        target["successorProposalSha256"] = proof("proposal")
    candidate = {
        "revision": "a" * 40,
        **{
            field: proof(field)
            for field in (
                "inputPolicySha256",
                "inputFingerprintSha256",
                "hostAgentSha256",
                "toolchainSha256",
                "requirementsSha256",
            )
        },
    }
    platform = {
        "namespaceSha256": proof("namespace" + kind),
        "storageTargetSha256": proof("storage" + kind),
        "storageBackend": "minio" if kind == INSTALLED else "spaces",
        "cloudflareNetworkSetSha256": proof("network-set"),
        "trustedPlatformDomain": DOMAIN,
        "aliasSuffix": SUFFIX,
        "tenantOriginSuffix": SUFFIX,
        "cookiePolicyVersion": "lowerduckpond-cookie-policy-v1",
        "edgePolicyVersion": "lowerduckpond-edge-policy-v1",
    }
    admission = record(
        "admission",
        binding={
            "targetKind": kind,
            "purpose": PURPOSES[kind],
            "runId": run_id,
            "targetSha256": digest(target),
            "candidateSha256": digest(candidate),
            "platformSha256": digest(platform),
        },
        target=target,
        candidate=candidate,
        platform=platform,
        invocationId=uuid(30),
        authoritySha256=proof("authorization"),
        leaseSha256=proof("lease"),
        preparedAt=fixture_time(88),
        prerequisites={},
    )
    slots = PRODUCTION_SLOTS if kind == PRODUCTION else COMMON_SLOTS
    times = {
        "component": (0, 2),
        "transportBootstrap": (5, 6),
        "darkStage": (74, 75),
        "darkRepeat": (78, 79),
        "targetSafety": (81, 82),
        "livePreflight": (60, 63),
        "predecessor": (55, 56),
        "successor": (55, 56),
        "backupRestore": (80, 81),
    }
    records = {}
    for key, receipt_kind in slots.items():
        observation = {
            "predecessor": target.get("predecessorSha256"),
            "successor": target.get("successorProposalSha256"),
        }.get(key)
        admission["prerequisites"][key] = retain(
            records, receipt(admission, receipt_kind, *times[key], observation)
        )
    platform_digest = None
    if report is not None:
        admission["prerequisites"]["completeDisposable"] = retain(records, report)
        platform_digest = report["completion"]["binding"]["platformSha256"]
    context = AdmissionContext(
        now=BASE + timedelta(minutes=89),
        invocation_id=admission["invocationId"],
        enrolled_target=deepcopy(target),
        candidate_sha256=digest(candidate),
        platform_sha256=digest(platform),
        authority_sha256=admission["authoritySha256"],
        lease_sha256=admission["leaseSha256"],
        run_id=run_id,
        active_authority=True,
        revoked=False,
        tenant_history=False,
        tenant_generation=False,
        unfinished_lifecycle=False,
        production_identifiers=frozenset({100, proof("enrolled-production"), "reserved-address"}),
        qualified_disposable_platform_sha256=platform_digest,
    )
    return admission, context, Evidence(records)


def launch_records(admission: Document, minute: int) -> tuple[Document, Document, Document]:
    binding = admission["binding"]
    platform = admission["platform"]
    intent = record(
        "launch-intent",
        binding=binding,
        admissionSha256=digest(admission),
        invocationId=admission["invocationId"],
        leaseSha256=admission["leaseSha256"],
        intendedAt=fixture_time(minute),
    )
    launch = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "LaunchRecord",
        "configurationVersion": admission["candidate"]["revision"],
        "trustedPlatformDomain": DOMAIN,
        "aliasSuffix": SUFFIX,
        "tenantOriginSuffix": SUFFIX,
        "cookiePolicyVersion": platform["cookiePolicyVersion"],
        "edgePolicyVersion": platform["edgePolicyVersion"],
        "cloudflareNetworkSetDigest": {
            "format": "lowerduckpond-cloudflare-network-set-v1",
            "algorithm": "sha256",
            "value": platform["cloudflareNetworkSetSha256"],
        },
        "acceptanceEvidenceDigest": {
            "format": "lowerduckpond-m3-acceptance-v1",
            "algorithm": "sha256",
            "value": digest(admission),
        },
        "launchedAt": fixture_time(minute),
    }
    launched = record(
        "launch-receipt",
        binding=binding,
        admissionSha256=digest(admission),
        intentSha256=digest(intent),
        launchRecordSha256=digest(launch),
        launchedAt=launch["launchedAt"],
    )
    return intent, launch, launched


def completed(kind: str) -> tuple[Document, Evidence]:
    admission, _, evidence = enroll(kind)
    # Earlier owned run with the same candidate.
    records = {}
    admission["preparedAt"] = fixture_time(-10)
    for key, value in admission["prerequisites"].items():
        original = evidence.read(value, "receipt")
        shift = timedelta(minutes=100)
        for field in ("startedAt", "finishedAt", "oldestSupportingAt"):
            measured = datetime.fromisoformat(original[field])
            original[field] = (measured - shift).isoformat().replace("+00:00", "Z")
        admission["prerequisites"][key] = retain(records, original)
    intent, launch, launched = launch_records(admission, 0)
    for doc in (admission, intent, launch, launched):
        retain(records, doc)
    completion = {
        "kind": "complete-disposable" if kind == DISPOSABLE else "installed-diagnostic",
        "binding": admission["binding"],
        "receipts": {
            phase: retain(records, receipt(admission, phase, start, start + 5))
            for phase, start in (("functional", 1), ("accounting", 20), ("teardown", 26))
        },
    }
    seal = record(
        "seal",
        completion=completion,
        admissionSha256=digest(admission),
        launchReceiptSha256=digest(launched),
        oldestEvidenceAt=fixture_time(-100),
        finishedAt=fixture_time(31),
        sealedAt=fixture_time(40),
    )
    report = record(
        "report",
        completion=completion,
        sealSha256=retain(records, seal),
        packagedAt=fixture_time(50),
    )
    return report, Evidence(records)


def test_schema_uses_closed_versioned_records() -> None:
    schema = decode_json_object(SCHEMA.read_bytes(), maximum_bytes=SCHEMA.stat().st_size)
    Draft202012Validator.check_schema(schema)
    bundle, _, _ = enroll(INSTALLED)
    assert Draft202012Validator(schema).is_valid(bundle)
    for bad in (
        encode(bundle).rstrip(),
        b'{"format":"repeat","format":"duplicate"}\n',
        encode({**bundle, "unexpected": "discard"}),
    ):
        with pytest.raises(ValidationError, match=r"^invalid-record$"):
            decode(bad, "admission")


@pytest.mark.parametrize("kind", [INSTALLED, DISPOSABLE, PRODUCTION])
def test_three_paired_admissions_and_existing_launch_record(kind: str) -> None:
    live, earlier = completed(DISPOSABLE) if kind == PRODUCTION else (None, Evidence({}))
    bundle, context, receipts = enroll(kind, live)
    evidence = Evidence(dict(earlier.records) | dict(receipts.records))
    assert validate_admission(encode(bundle), context, evidence) == bundle
    intent, launch, launched = launch_records(bundle, 89)
    assert (
        validate_launch(encode(bundle), encode(intent), encode(launch), encode(launched))
        == launched
    )
    changed = {**launched, "launchedAt": fixture_time(90)}
    with pytest.raises(ValidationError, match="wrong-launch-time"):
        validate_launch(encode(bundle), encode(intent), encode(launch), encode(changed))


@pytest.mark.parametrize(
    ("kind", "path", "value"),
    [
        (INSTALLED, ("docker", "endpointSha256"), proof("different-endpoint")),
        (INSTALLED, ("docker", "daemonObservationSha256"), proof("replacement-daemon")),
        (INSTALLED, ("docker", "roles", "host", "id"), proof("recreated-container")),
        (INSTALLED, ("docker", "roles", "host", "image"), proof("another-image")),
        (INSTALLED, ("docker", "roles", "host", "runLabel"), UUID(uuid(9)).hex),
        (INSTALLED, ("docker", "ownerManifestSha256"), proof("copied-manifest")),
        (INSTALLED, ("docker", "drainedAllocationSha256"), proof("unknown-allocation")),
        (INSTALLED, ("leaseDomainSha256",), proof("another-lock")),
        (DISPOSABLE, ("transport", "identitySha256"), proof("another-host-key")),
        (DISPOSABLE, ("stateSha256",), proof("wrong-state")),
        (DISPOSABLE, ("droplet", "dropletId"), 999),
    ],
)
def test_target_substitution_rejected_even_when_rehashed(
    kind: str, path: tuple[str, ...], value: object
) -> None:
    bundle, context, evidence = enroll(kind)
    parent = bundle["target"]
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    bundle["binding"]["targetSha256"] = digest(bundle["target"])
    with pytest.raises(ValidationError, match=r"enrollment-mismatch|invalid-fixture-roles"):
        validate_admission(encode(bundle), context, evidence)


@pytest.mark.parametrize(
    ("label", "error"),
    [(uuid(0), "invalid-record"), (UUID(uuid(9)).hex, "invalid-fixture-roles")],
)
def test_installed_labels_keep_the_observed_hex_form_and_original_run(
    label: str, error: str
) -> None:
    bundle, context, evidence = enroll(INSTALLED)
    assert validate_admission(encode(bundle), context, evidence) == bundle
    docker = bundle["target"]["docker"]
    for observation in (docker, *docker["roles"].values()):
        observation["runLabel"] = label
    bundle["binding"]["targetSha256"] = digest(bundle["target"])
    with pytest.raises(ValidationError, match=error):
        validate_admission(encode(bundle), context, evidence)


@pytest.mark.parametrize("field", ["inventorySha256", "stateSha256", "transactionNamespaceSha256"])
def test_disposable_rejects_production_aliases(field: str) -> None:
    bundle, context, evidence = enroll(DISPOSABLE)
    context = replace(context, production_identifiers=frozenset({bundle["target"][field]}))
    with pytest.raises(ValidationError, match="production-crossover"):
        validate_admission(encode(bundle), context, evidence)


def test_crossover_cannot_be_selected_by_an_argument_or_mixed_pair() -> None:
    bundle, context, evidence = enroll(INSTALLED)
    _, production, _ = enroll(PRODUCTION)
    with pytest.raises(ValidationError, match="enrollment-mismatch"):
        validate_admission(encode(bundle), production, evidence)
    for purpose in ("disposable-qualification", "production", "fixture"):
        bundle["target"]["purpose"] = purpose
        with pytest.raises(ValidationError, match="invalid-record"):
            validate_admission(encode(bundle), context, evidence)
    bundle["target"]["purpose"] = PURPOSES[INSTALLED]
    bundle["target"]["docker"]["roles"]["spare"] = bundle["target"]["docker"]["roles"]["archive"]
    with pytest.raises(ValidationError, match="invalid-record"):
        validate_admission(encode(bundle), context, evidence)


@pytest.mark.parametrize(
    "changed",
    [
        {"active_authority": False},
        {"revoked": True},
        {"tenant_history": True},
        {"tenant_generation": True},
        {"unfinished_lifecycle": True},
        {"invocation_id": uuid(99)},
        {"lease_sha256": proof("wrong-fence")},
        {"observed_disposable_identifiers": frozenset({"reserved-address"})},
    ],
)
def test_current_authority_and_history_are_mandatory(changed: dict[str, object]) -> None:
    bundle, context, receipts = enroll(DISPOSABLE)
    with pytest.raises(ValidationError):
        validate_admission(encode(bundle), replace(context, **changed), receipts)


def test_untrusted_swapped_cross_target_and_future_receipts_are_rejected() -> None:
    bundle, context, evidence = enroll(DISPOSABLE)
    original = bundle["prerequisites"]["component"]
    store = dict(evidence.records)
    installed, _, installed_evidence = enroll(INSTALLED)
    store.update(installed_evidence.records)
    attempts = (
        (proof("self-authored-success"), "untrusted-evidence"),
        (bundle["prerequisites"]["darkRepeat"], "wrong-receipt"),
        (installed["prerequisites"]["component"], "wrong-receipt"),
        (retain(store, receipt(bundle, "component", 90, 91)), "invalid-chronology"),
        (retain(store, receipt(bundle, "component", 75, 75)), "invalid-stage-order"),
    )
    for value, error in attempts:
        bundle["prerequisites"]["component"] = value
        with pytest.raises(ValidationError, match=error):
            validate_admission(encode(bundle), context, Evidence(store))
    bundle["prerequisites"]["component"] = original
    bundle["prerequisites"]["completeDisposable"] = proof("post-launch-cycle")
    with pytest.raises(ValidationError, match=r"invalid-record|wrong-prerequisites"):
        validate_admission(encode(bundle), context, Evidence(store))


def test_completed_installed_report_cannot_satisfy_production() -> None:
    report, prior = completed(INSTALLED)
    bundle, context, current = enroll(PRODUCTION, report)
    with pytest.raises(ValidationError, match="wrong-disposable-proof"):
        validate_admission(
            encode(bundle), context, Evidence(dict(prior.records) | dict(current.records))
        )
    report["completion"]["kind"] = "complete-disposable"
    with pytest.raises(ValidationError, match="invalid-record"):
        validate_report(encode(report), prior, context.now)


def test_delayed_packaging_does_not_refresh_original_evidence() -> None:
    report, prior = completed(DISPOSABLE)
    later = BASE + timedelta(days=10)
    report["packagedAt"] = later.isoformat().replace("+00:00", "Z")
    _, seal = validate_report(encode(report), prior, later)
    assert seal["oldestEvidenceAt"] == fixture_time(-100)
    report["packagedAt"] = fixture_time(50)
    bundle, context, current = enroll(PRODUCTION, report)
    all_records = Evidence(dict(prior.records) | dict(current.records))
    with pytest.raises(ValidationError, match="stale-disposable-proof"):
        validate_admission(encode(bundle), replace(context, now=later), all_records)
    with pytest.raises(ValidationError, match="wrong-disposable-proof"):
        validate_admission(
            encode(bundle),
            replace(context, qualified_disposable_platform_sha256=proof("other")),
            all_records,
        )


def test_same_invocation_preflight_and_final_backup_are_required() -> None:
    report, prior = completed(DISPOSABLE)
    bundle, context, current = enroll(PRODUCTION, report)
    store = dict(prior.records) | dict(current.records)
    other = receipt(bundle, "live-preflight", 59, 60)
    other["invocationId"] = uuid(66)
    bundle["prerequisites"]["livePreflight"] = retain(store, other)
    with pytest.raises(ValidationError, match="invalid-production-stage-order"):
        validate_admission(encode(bundle), context, Evidence(store))
    bundle["prerequisites"]["livePreflight"] = retain(
        store, receipt(bundle, "live-preflight", 60, 63)
    )
    bundle["prerequisites"]["backupRestore"] = retain(
        store, receipt(bundle, "final-backup-restore", 76, 77)
    )
    with pytest.raises(ValidationError, match="invalid-production-stage-order"):
        validate_admission(encode(bundle), context, Evidence(store))


def diagnostic() -> Document:
    return record(
        "diagnostic",
        runId=uuid(40),
        invocationId=uuid(41),
        sequence=0,
        stage="bootstrap",
        operation="ssh",
        startedAt=fixture_time(0),
        startedMonotonicMs=42,
        terminalEvidence="missing",
        outcome="interrupted",
        result="unknown",
        attempts=1,
        failures=[],
        omissions=["no-terminal-evidence"],
        inspection="inspect",
    )


def test_diagnostics_distinguish_missing_terminal_primary_and_secondary() -> None:
    doc = diagnostic()
    assert validate_diagnostic(encode(doc))["result"] == "unknown"
    doc["outcome"] = "known"
    with pytest.raises(ValidationError, match="diagnostic-terminal-mismatch"):
        validate_diagnostic(encode(doc))
    doc.update(
        terminalEvidence="recorded",
        finishedAt=fixture_time(1),
        finishedMonotonicMs=45,
        result="failed",
    )
    cause = {"type": "connection", "operation": "ssh", "errno": 111, "frames": []}
    failure = {
        "role": "primary",
        "category": "transport",
        "prerequisite": "ownership",
        "causes": [cause],
    }
    doc["failures"] = [dict(failure, role="cleanup")]
    with pytest.raises(ValidationError, match="invalid-diagnostic-result"):
        validate_diagnostic(encode(doc))
    doc["failures"].insert(0, failure)
    assert validate_diagnostic(encode(doc))["failures"] == [failure, dict(failure, role="cleanup")]
    cause["message"] = "synthetic-unallowlisted-data"
    with pytest.raises(ValidationError, match=r"^invalid-record$"):
        validate_diagnostic(encode(doc))


def production_transaction() -> tuple[Document, AdmissionContext]:
    admission, authority, _ = enroll(PRODUCTION)
    target = admission["target"]
    transaction = record(
        "transaction",
        binding=admission["binding"],
        transactionId=uuid(77),
        predecessorSha256=target["predecessorSha256"],
        originalProposalSha256=target["successorProposalSha256"],
        leaseDomainSha256=target["leaseDomainSha256"],
        authorizationSha256=authority.authority_sha256,
        createdAt=fixture_time(50),
    )
    return transaction, authority


def phase_link(
    transaction: Document,
    authority: AdmissionContext,
    previous: str | None,
    phase: str,
    transition: str,
) -> Document:
    return record(
        "phase-receipt",
        transactionSha256=digest(transaction),
        previousSha256=previous,
        phase=phase,
        transition=transition,
        publicationView=STAGE_VIEWS[phase],
        stageConfigurationSha256=proof("stage-view"),
        invocationId=authority.invocation_id,
        leaseSha256=authority.lease_sha256,
        recordedAt=fixture_time(55),
        evidenceSha256=proof("readback"),
    )


def test_journal_crash_resumes_original_intent_and_refuses_replay() -> None:
    transaction, authority = production_transaction()
    raw = encode(transaction)
    records: dict[str, bytes] = {}
    history = read_history(raw, [], Evidence(records))
    readback = Reconciliation(proof("readback"), "not-applied", True, True, proof("stage-view"))
    start = phase_link(transaction, authority, None, PHASES[0], "started")
    assert validate_transition(encode(start), raw, history, authority, readback) == start
    with pytest.raises(ValidationError, match="invalid-continuation"):
        validate_transition(
            encode({**start, "publicationView": "enabled"}), raw, history, authority, readback
        )
    started = retain(records, start)
    history = read_history(raw, [started], Evidence(records))
    assert history.pending
    not_applied = phase_link(transaction, authority, started, PHASES[0], "not-applied")
    with pytest.raises(ValidationError, match="original-action-not-drained"):
        validate_transition(
            encode(not_applied), raw, history, authority, replace(readback, drained=False)
        )
    with pytest.raises(ValidationError, match="unverified-original-preconditions"):
        validate_transition(
            encode(not_applied), raw, history, authority, replace(readback, outcome="unknown")
        )
    assert (
        validate_transition(encode(not_applied), raw, history, authority, readback) == not_applied
    )
    commit = phase_link(transaction, authority, started, PHASES[0], "committed")
    assert (
        validate_transition(
            encode(commit), raw, history, authority, replace(readback, outcome="committed")
        )
        == commit
    )
    committed = retain(records, commit)
    history = read_history(raw, [started, committed], Evidence(records))
    assert history.completed == (PHASES[0],)
    assert history.phase == PHASES[1]
    with pytest.raises(ValidationError, match="invalid-continuation"):
        validate_transition(encode(commit), raw, history, authority, readback)
    with pytest.raises(ValidationError, match="invalid-journal-link"):
        read_history(raw, [committed], Evidence(records))
    bad_tx = {**transaction, "predecessorSha256": proof("substituted")}
    bad_history = read_history(encode(bad_tx), [], Evidence({}))
    with pytest.raises(ValidationError, match="inactive-transaction"):
        validate_transition(encode(start), encode(bad_tx), bad_history, authority, readback)


@pytest.mark.parametrize("launch_state", ["absent", "intent-only", "durable"])
def test_rollback_requires_exact_scope_and_zero_history_even_with_no_current_tenants(
    launch_state: str,
) -> None:
    transaction, authority = production_transaction()
    raw = encode(transaction)
    records: dict[str, bytes] = {}
    chain: list[str] = []
    last_phase = "durable-launch" if launch_state == "durable" else "dark-staging"
    for phase in PHASES[: PHASES.index(last_phase) + 1]:
        start = retain(
            records,
            phase_link(transaction, authority, chain[-1] if chain else None, phase, "started"),
        )
        chain.extend(
            (start, retain(records, phase_link(transaction, authority, start, phase, "committed")))
        )
    history = read_history(raw, chain, Evidence(records))
    readback = RollbackReadback(
        invocation_id=authority.invocation_id,
        authorization_sha256=proof("rollback-consent"),
        evidence_sha256=proof("rollback-readback"),
        preceding_generation_sha256=proof("predecessor-generation"),
        retained_launch_sha256=proof("retained-launch") if launch_state == "durable" else None,
        retained_intent_sha256=proof("retained-intent") if launch_state != "absent" else None,
        drained=True,
        platform_only_compatible=True,
        irreversible_history=False,
        policy_unchanged=True,
        rollback_active=False,
    )
    decision = record(
        "rollback",
        transactionSha256=digest(transaction),
        priorHeadSha256=chain[-1],
        authorizationSha256=readback.authorization_sha256,
        invocationId=authority.invocation_id,
        leaseSha256=authority.lease_sha256,
        readbackSha256=readback.evidence_sha256,
        precedingGenerationSha256=readback.preceding_generation_sha256,
        decidedAt=fixture_time(59),
        action="restore-platform-only",
        retainedLaunchSha256=readback.retained_launch_sha256,
        retainedIntentSha256=readback.retained_intent_sha256,
    )
    assert validate_rollback(encode(decision), raw, history, authority, readback) == decision
    for altered in (
        replace(readback, irreversible_history=True),
        replace(readback, drained=False),
        replace(readback, platform_only_compatible=False),
    ):
        with pytest.raises(ValidationError, match="unsafe-rollback"):
            validate_rollback(encode(decision), raw, history, authority, altered)
    decision["action"] = "reactivate-same-policy"
    with pytest.raises(ValidationError, match="invalid-reactivation"):
        validate_rollback(encode(decision), raw, history, authority, readback)

    authority = replace(authority, invocation_id=uuid(66))
    active = replace(
        readback,
        invocation_id=authority.invocation_id,
        evidence_sha256=proof("reactivation-readback"),
        rollback_active=True,
    )
    decision.update(invocationId=authority.invocation_id, readbackSha256=active.evidence_sha256)
    assert validate_rollback(encode(decision), raw, history, authority, active) == decision
    with pytest.raises(ValidationError, match="invalid-reactivation"):
        validate_rollback(
            encode(decision), raw, history, authority, replace(active, policy_unchanged=False)
        )
    with pytest.raises(ValidationError, match="wrong-rollback-scope"):
        validate_rollback(
            encode(decision),
            raw,
            history,
            authority,
            replace(active, invocation_id=readback.invocation_id),
        )
    for field in ("retainedIntentSha256", "retainedLaunchSha256"):
        with pytest.raises(ValidationError, match="wrong-rollback-scope"):
            validate_rollback(
                encode({**decision, field: proof("substituted")}), raw, history, authority, active
            )
    if launch_state == "durable":
        with pytest.raises(ValidationError, match="unsafe-rollback"):
            validate_rollback(
                encode({**decision, "retainedLaunchSha256": None}),
                raw,
                history,
                authority,
                replace(active, retained_launch_sha256=None),
            )


def test_inventory_covers_every_source_paragraph_and_rejects_stale_or_missing_entries() -> None:
    root = Path(__file__).resolve().parents[2]
    inventory = decode_json_object(
        (root / "schemas/m3-12/v1/requirements.json").read_bytes(), maximum_bytes=MAX_RECORD_BYTES
    )
    validate_inventory(root, inventory)
    requirements = inventory["requirements"]
    assert isinstance(requirements, list)
    removed = requirements.pop()
    with pytest.raises(ValidationError, match="missing-source-requirement"):
        validate_inventory(root, inventory)
    requirements.append({**removed, "sha256": proof("different-paragraph")})
    with pytest.raises(ValidationError, match="missing-or-stale-requirement"):
        validate_inventory(root, inventory)


def test_exact_requirement_coverage_rejects_missing_skipped_duplicate_and_installed_proof() -> None:
    installed, _, _ = enroll(INSTALLED)
    admitted, _, _ = enroll(DISPOSABLE)
    slot = "ADR0022-001/droplet"
    node = "tests/infrastructure/test_m3_12_contracts.py::test_schema_uses_closed_versioned_records"
    specification = {"slot": slot, "environment": "droplet", "state": "mapped", "nodes": [node]}
    inventory = {"requirements": [{"proofs": [specification]}]}
    completed = record(
        "requirement-proof",
        inventorySha256=digest(inventory),
        binding=admitted["binding"],
        invocationId=admitted["invocationId"],
        slot=slot,
        nodes=[node],
        startedAt=fixture_time(0),
        finishedAt=fixture_time(1),
        originalEvidenceSha256=proof("original-result"),
        outcome="passed",
    )
    scope = CoverageScope(False, {slot: admitted["binding"]}, BASE + timedelta(minutes=1))
    store: dict[str, bytes] = {}
    accepted = retain(store, completed)
    evidence = Evidence(store)
    assert validate_coverage(inventory, scope, [accepted], evidence) == BASE
    for keys, error in (
        ([], "missing-requirement-proof"),
        ([accepted, accepted], "unknown-or-duplicate-proof"),
        (
            [retain(store, {**completed, "binding": installed["binding"]})],
            "wrong-requirement-proof",
        ),
        ([retain(store, {**completed, "outcome": "skipped"})], "invalid-record"),
        (
            [retain(store, {**completed, "inventorySha256": proof("stale")})],
            "wrong-requirement-proof",
        ),
        ([retain(store, {**completed, "finishedAt": fixture_time(2)})], "wrong-requirement-proof"),
    ):
        with pytest.raises(ValidationError, match=error):
            validate_coverage(inventory, scope, keys, evidence)
    specification["state"] = "pending"
    with pytest.raises(ValidationError, match="unmapped-proof"):
        validate_coverage(inventory, scope, [accepted], evidence)


@pytest.mark.parametrize(
    ("earlier_slots", "preflight", "allowed"),
    [
        (("darkStage",), (76, 77), True),
        (("darkStage",), (79, 80), False),
        (("darkStage", "darkRepeat"), (79, 81), False),
        (("darkStage", "darkRepeat", "backupRestore"), (82, 83), True),
    ],
)
def test_resumed_admission_orders_preflight_before_current_mutations(
    earlier_slots: tuple[str, ...], preflight: tuple[int, int], allowed: bool
) -> None:
    report, prior = completed(DISPOSABLE)
    bundle, context, current = enroll(PRODUCTION, report)
    store = dict(prior.records) | dict(current.records)
    for slot in earlier_slots:
        earlier = current.read(bundle["prerequisites"][slot], "receipt")
        earlier["invocationId"] = uuid(65)
        bundle["prerequisites"][slot] = retain(store, earlier)
    bundle["prerequisites"]["livePreflight"] = retain(
        store, receipt(bundle, "live-preflight", *preflight)
    )
    if allowed:
        assert validate_admission(encode(bundle), context, Evidence(store)) == bundle
    else:
        with pytest.raises(ValidationError, match="invalid-production-stage-order"):
            validate_admission(encode(bundle), context, Evidence(store))


def _launch_paths(tmp_path: Path, namespace: Document) -> tuple[Path, Path]:
    state = tmp_path / "state"
    authority = tmp_path / "successor"
    authority.mkdir(mode=0o700)
    for name in (
        "locks",
        "platform",
        "tenants",
        "intents",
        "audit",
        "authorization/jobs",
        "authorization/results",
        "authorization/correlations",
    ):
        path = state / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.mkdir(mode=0o700)
    for key in ("tenant-state.lock", "publication.lock"):
        (state / "locks" / key).touch(mode=0o600)
    record_path = state / "platform/namespace.json"
    record_path.write_bytes(encode(namespace))
    record_path.chmod(0o600)
    return state, authority


class LaunchInterruptedError(Exception):
    """Interrupt the writer at one descriptor-relative durability boundary."""


@pytest.mark.parametrize("boundary", tuple(DurabilityBoundary)[:-1])
def test_native_launch_retry_keeps_the_original_intent(
    tmp_path: Path, boundary: DurabilityBoundary
) -> None:
    admission, context, _ = enroll(INSTALLED)
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": SUFFIX,
        "initializedAt": fixture_time(5),
    }
    admission["platform"]["namespaceSha256"] = digest(namespace)
    platform_digest = digest(admission["platform"])
    admission["binding"]["platformSha256"] = platform_digest
    context = replace(context, platform_sha256=platform_digest)
    records: dict[str, bytes] = {}
    for slot, kind, start, end in (
        ("component", "component", 0, 2),
        ("transportBootstrap", "transport-bootstrap", 5, 6),
        ("darkStage", "dark-stage", 74, 75),
        ("darkRepeat", "dark-repeat", 78, 79),
        ("targetSafety", "target-safety", 81, 82),
    ):
        admission["prerequisites"][slot] = retain(records, receipt(admission, kind, start, end))
    state, authority = _launch_paths(tmp_path, namespace)
    owner = os.geteuid()

    def interrupt(observed: DurabilityBoundary) -> None:
        if observed is boundary:
            raise LaunchInterruptedError

    raw = encode(admission)
    evidence = Evidence(records)
    with pytest.raises(LaunchInterruptedError):
        initialize_launch(
            state, authority, raw, evidence, lambda: context, owner=owner, failure_hook=interrupt
        )
    with pytest.raises(FileNotFoundError):
        verify_launch(state, authority, owner=owner)
    original = (authority / "launch-intent.json").read_bytes()
    resumed = replace(
        context,
        now=context.now + timedelta(hours=1),
        invocation_id=uuid(31),
        lease_sha256=proof("fresh-lease"),
    )
    fresh = deepcopy(admission)
    fresh["invocationId"] = resumed.invocation_id
    fresh["leaseSha256"] = resumed.lease_sha256
    fresh["preparedAt"] = fixture_time(148)
    fresh["prerequisites"]["targetSafety"] = retain(
        records, receipt(fresh, "target-safety", 145, 146)
    )
    result = initialize_launch(
        state, authority, encode(fresh), evidence, lambda: resumed, owner=owner
    )
    assert result["launchedAt"] == fixture_time(89)
    assert (authority / "launch-intent.json").read_bytes() == original
    assert (authority / "admission.json").read_bytes() == raw
    assert verify_launch(state, authority, owner=owner) == result
    (state / "platform/namespace.json").write_bytes(
        encode({**namespace, "initializedAt": fixture_time(6)})
    )
    with pytest.raises(ValidationError, match="launch-namespace-changed"):
        verify_launch(state, authority, owner=owner)


def test_enabled_successor_gate_reads_original_launch_with_tenant_lock_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    state, authority = tmp_path / "static", tmp_path / "successor"
    state.mkdir(mode=0o700)
    for path in (authority, state / "locks", state / "platform"):
        path.mkdir(mode=0o700)
    lock = state / "locks/tenant-state.lock"
    lock.touch(mode=0o600)
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": SUFFIX,
        "initializedAt": fixture_time(5),
    }
    admission, _, _ = enroll(INSTALLED)
    admission["platform"]["namespaceSha256"] = digest(namespace)
    admission["binding"]["platformSha256"] = digest(admission["platform"])
    intent, launch, receipt = launch_records(admission, 89)
    for path, value in (
        (state / "platform/namespace.json", namespace),
        (state / "platform/launch.json", launch),
        (authority / "admission.json", admission),
        (authority / "launch-intent.json", intent),
        (authority / "launch-receipt.json", receipt),
        (authority / "installed-target.json", admission["target"]),
    ):
        path.write_bytes(encode(value))
        path.chmod(0o600)

    gate = Path(__file__).parents[2] / (
        "config/ansible/roles/static_host_agent/files/static-publication-gate"
    )
    main = run_path(str(gate))["main"]
    main.__globals__.update(
        STATE=state,
        SUCCESSOR=authority,
        INSTALLATION=tmp_path,
        require_restore_admission=lambda: None,
    )
    owner = os.geteuid()
    monkeypatch.setattr(
        platform_launch, "verify_launch", lambda s, a: verify_launch(s, a, owner=owner)
    )
    monkeypatch.setattr(
        platform_launch,
        "require_local_launch_binding",
        lambda a, r, **_: require_local_launch_binding(a, r, disposable=True, owner=owner),
    )
    monkeypatch.setattr(sys, "path", sys.path.copy())
    monkeypatch.setattr(sys, "argv", [str(gate), "caddy-generation", "0"])
    main.__globals__["publication_enabled"] = lambda: True
    main()
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        main()

        launch_path = state / "platform/launch.json"
        launch_path.write_bytes(encode({**launch, "launchedAt": fixture_time(90)}))
        with pytest.raises(SystemExit, match="78"):
            main()
        assert capsys.readouterr().err == "launch_authority_unavailable\n"
        launch_path.write_bytes(encode(launch))

        (state / "platform/namespace.json").write_bytes(
            encode({**namespace, "initializedAt": fixture_time(6)})
        )
        with pytest.raises(SystemExit, match="78"):
            main()
        assert capsys.readouterr().err == "launch_authority_unavailable\n"
    (state / "platform/namespace.json").write_bytes(encode(namespace))
    lock.unlink()
    with pytest.raises(SystemExit, match="78"):
        main()
    assert capsys.readouterr().err == "launch_authority_unavailable\n"


def test_native_successor_reconciles_after_departure_without_replaying(
    tmp_path: Path,
) -> None:
    transaction, authority = production_transaction()
    raw = encode(transaction)
    location = tmp_path / "journal"
    location.mkdir(mode=0o700)
    effect = False
    applied = 0

    def observe() -> Reconciliation:
        return Reconciliation(
            evidence_sha256=proof("observed-effect" if effect else "observed-original"),
            outcome="committed" if effect else "not-applied",
            drained=True,
            preconditions_hold=not effect,
            stage_configuration_sha256=proof("preparation-stage-config"),
        )

    def apply(_intent: Document) -> None:
        nonlocal effect, applied
        applied += 1
        effect = True
        raise LaunchInterruptedError

    owner = os.geteuid()
    with DurableDirectory.open(location, expected_owner=owner, expected_directory_mode=0o700) as fd:
        journal = SuccessorJournal(fd, owner)
        journal.pin(raw)
        with pytest.raises(LaunchInterruptedError):
            resume_phase(journal, authority, observe, apply)
        assert journal.snapshot().history.pending

    with DurableDirectory.open(location, expected_owner=owner, expected_directory_mode=0o700) as fd:
        journal = SuccessorJournal(fd, owner)
        assert resume_phase(journal, authority, observe, apply)["transition"] == "committed"
        assert journal.snapshot().history.completed == ("preparation",)
        assert applied == 1


def test_prepare_reopens_only_the_pinned_production_configuration(tmp_path: Path) -> None:
    transaction, _ = production_transaction()
    admission, _, _ = enroll(PRODUCTION)
    location = tmp_path / "proposal"
    location.mkdir(mode=0o700)
    owner = os.geteuid()
    with DurableDirectory.open(location, expected_owner=owner, expected_directory_mode=0o700) as fd:
        journal = SuccessorJournal(fd, owner)
        journal.pin(encode(transaction))
        for kind in ("candidate", "target", "platform"):
            journal.immutable(kind + ".json", encode(admission[kind]))
    before = {path.name: path.read_bytes() for path in location.iterdir()}
    proposal = preview(location)
    assert proposal["currentPhase"] == "preparation"
    configurations = proposal["configurations"]
    assert configurations["dark-repeat"]["publication_enabled"] is False
    assert configurations["enabled-repeat"]["publication_enabled"] is True
    assert {path.name: path.read_bytes() for path in location.iterdir()} == before
    with (location / "candidate.json").open("wb") as candidate:
        candidate.write(encode({**admission["candidate"], "revision": "b" * 40}))
    with pytest.raises(ValidationError, match="successor-proposal-binding-changed"):
        preview(location)


def test_native_successor_accepts_only_the_distinct_action_unit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unit = tmp_path / "cgroup"
    unit.write_text("0::/system.slice/lowerduckpond-m3-11-action.service\n")
    monkeypatch.setattr(native, "REQUIRE_CGROUP", unit)
    directory = tmp_path / "production-proposal"
    directory.mkdir(mode=0o700)
    owner = os.geteuid()
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        with pytest.raises(ValidationError, match="native-successor-outside-action"):
            native.dispatch(journal, ["gate", "a" * 64])


def test_publication_requires_launch_bound_to_this_target(tmp_path: Path) -> None:
    directory = tmp_path / "local-launch"
    directory.mkdir(mode=0o700)
    owner = os.geteuid()
    admission, _, _ = enroll(INSTALLED)
    receipt = {"binding": admission["binding"]}
    transaction, _ = production_transaction()
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        records.create_immutable(("installed-target.json",), encode(admission["target"]))
        require_local_launch_binding(directory, receipt, disposable=True, owner=owner)
        with pytest.raises(ValidationError, match="installed-publication-requires-disposable"):
            require_local_launch_binding(directory, receipt, disposable=False, owner=owner)
        records.create_immutable(("transaction.json",), encode(transaction))
        with pytest.raises(ValidationError, match="native-publication-binding-changed"):
            require_local_launch_binding(directory, receipt, disposable=False, owner=owner)
        production = {"binding": transaction["binding"]}
        require_local_launch_binding(directory, production, disposable=False, owner=owner)
        with pytest.raises(ValidationError, match="native-publication-binding-changed"):
            require_local_launch_binding(directory, production, disposable=True, owner=owner)


def test_native_phase_refuses_an_observation_from_a_different_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction, context = production_transaction()
    directory = tmp_path / "native-phases"
    directory.mkdir(mode=0o700)
    owner = os.geteuid()
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        journal.pin(encode(transaction))
        monkeypatch.setattr(
            native,
            "read_authority",
            lambda *_: native.NativeAuthority(
                context, transaction["predecessorSha256"], {}, {}, {}
            ),
        )
        observed = {"originalPreconditions": True}
        key = digest(observed)
        journal.immutable("evidence-" + key + ".json", encode(observed))
        proposal = record(
            "native-phase-readback",
            transactionSha256=digest(transaction),
            priorHeadSha256=None,
            phase="preparation",
            invocationId=uuid(90),
            leaseSha256=context.lease_sha256,
            readbackSha256=key,
            outcome="not-applied",
            processDrained=True,
            originalPreconditions=True,
            configurationSha256=proof("native-config"),
        )
        journal.immutable("phase-readback.json", encode(proposal))
        with pytest.raises(ValidationError, match="native-successor-readback-changed"):
            native.phase(journal, "start", "a" * 64)
        assert not journal.snapshot().history.pending
        original = directory / "phase-readback.json"
        original.write_bytes(encode({**proposal, "invocationId": context.invocation_id}))
        assert native.phase(journal, "start", "a" * 64)["transition"] == "started"
        assert journal.snapshot().history.pending


def test_native_durable_launch_requires_resume_after_the_intent_is_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction, context = production_transaction()
    directory = tmp_path / "native-launch"
    directory.mkdir(mode=0o700)
    owner = os.geteuid()
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        journal.pin(encode(transaction))
        head = None
        for index, (phase, transition) in enumerate(
            [(name, state) for name in PHASES[:5] for state in ("started", "committed")]
            + [("durable-launch", "started")]
        ):
            link = phase_link(transaction, context, head, phase, transition)
            journal.immutable(f"phase-{index:010}.json", encode(link))
            head = digest(link)
        monkeypatch.setattr(native, "ROOT", directory)
        monkeypatch.setattr(
            native,
            "read_authority",
            lambda *_: native.NativeAuthority(
                context, transaction["predecessorSha256"], {}, {}, {}
            ),
        )
        observed = {"originalPreconditions": True}
        key = digest(observed)
        journal.immutable(f"evidence-{key}.json", encode(observed))
        journal.immutable("launch-intent.json", b"original intent\n")
        journal.immutable(
            "phase-readback.json",
            encode(
                record(
                    "native-phase-readback",
                    transactionSha256=digest(transaction),
                    priorHeadSha256=head,
                    phase="durable-launch",
                    invocationId=context.invocation_id,
                    leaseSha256=context.lease_sha256,
                    readbackSha256=key,
                    outcome="not-applied",
                    processDrained=True,
                    originalPreconditions=True,
                    configurationSha256=proof("stage-view"),
                )
            ),
        )
        with pytest.raises(ValidationError, match="native-successor-launch-resume-required"):
            native.phase(journal, "reconcile", "a" * 64)
        assert journal.snapshot().history.head_sha256 == head
        assert journal.snapshot().history.pending


@pytest.fixture
def droplet_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Document, Path, Path]:
    owner = os.geteuid()
    identity_files = {
        "MACHINE_ID": b"a" * 32 + b"\n",
        "SYSTEM_UUID": b"11111111-2222-3333-4444-555555555555\n",
        "HOST_KEY": (
            b"ssh-ed25519 "
            + base64.b64encode(droplet_observe.ED25519_WIRE_HEADER + b"A" * 32)
            + b" synthetic\n"
        ),
    }
    for name, content in identity_files.items():
        path = tmp_path / name
        path.write_bytes(content)
        path.chmod(0o600)
        monkeypatch.setattr(droplet_observe, name, path)
    monkeypatch.setattr(droplet_enrollment, "DOCKER_MARKER", tmp_path / "not-a-container")
    monkeypatch.setattr(droplet, "metadata_identity", lambda: (101, "192.0.2.14"))
    monkeypatch.setattr(droplet, "require_dark_health", lambda: None)

    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": SUFFIX,
        "initializedAt": fixture_time(5),
    }
    state, root = _launch_paths(tmp_path, namespace)
    authority = root / droplet_enrollment.PUBLICATION_VIEW
    authority.mkdir(mode=0o700)
    monkeypatch.setattr(droplet, "ROOT", root)
    monkeypatch.setattr(droplet, "STATE", state)
    lease_path = tmp_path / "lease"
    lease_path.mkdir(mode=0o700)
    monkeypatch.setattr(droplet, "LEASE", lease_path)

    admission, _, earlier = enroll(DISPOSABLE)
    binding = admission["binding"]
    original_target = admission["target"]
    local = droplet_enrollment.host_identity(owner)
    exclusions = record(
        "droplet-production-exclusions",
        dropletIds=[100],
        addresses=["192.0.2.18"],
        identityDigests=[proof("enrolled-production")],
    )
    identity = droplet_inventory.ProviderIdentity(
        original_target["droplet"]["projectIdSha256"], 101, "192.0.2.14"
    )
    allocation = droplet_inventory.ApprovedAllocation(
        run_id=binding["runId"],
        role="source",
        state_sha256=original_target["stateSha256"],
        allocation_sha256=original_target["allocationSha256"],
        inventory_sha256=original_target["inventorySha256"],
        transaction_namespace_sha256=original_target["transactionNamespaceSha256"],
        identity=identity,
    )
    connected = droplet_inventory.ConnectedDroplet(
        provider=identity,
        metadata_id=101,
        metadata_ipv4="192.0.2.14",
        host_identity=local,
        pinned_host_key_sha256=local["hostKeySha256"],
    )
    target, enrollment = droplet_inventory.enrollment_records(
        allocation, connected, encode(exclusions)
    )
    admission["target"] = target
    binding["targetSha256"] = digest(target)
    admission["authoritySha256"] = digest(enrollment)
    admission["platform"]["namespaceSha256"] = digest(namespace)
    binding["platformSha256"] = digest(admission["platform"])

    selection = tmp_path / "current"
    candidate = tmp_path / admission["candidate"]["hostAgentSha256"]
    candidate.mkdir()
    selection.symlink_to(candidate)
    monkeypatch.setattr(droplet, "SELECTION", selection)
    with DurableDirectory.open(
        authority, expected_owner=owner, expected_directory_mode=0o700
    ) as fd:
        for name, document in (
            (droplet_enrollment.TARGET, target),
            (droplet_enrollment.ENROLLMENT, enrollment),
            (droplet_enrollment.EXCLUSIONS, exclusions),
        ):
            fd.create_immutable((name,), encode(document))
    with DurableDirectory.open(root, expected_owner=owner, expected_directory_mode=0o700) as fd:
        for slot, key in admission["prerequisites"].items():
            original = earlier.read(key, "receipt")
            original["binding"] = binding
            updated = digest(original)
            admission["prerequisites"][slot] = updated
            fd.create_immutable((f"evidence-{updated}.json",), encode(original))
    return admission, state, authority


def _pin_droplet_attempt(authority: Path, admission: Document, token: str) -> None:
    lease_digest = sha256(token.encode()).hexdigest()
    admission["leaseSha256"] = lease_digest
    with DurableDirectory.open(
        authority.parent, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as fd:
        fd.create_immutable(
            (f"droplet-attempt-{lease_digest}.json",),
            encode(
                record(
                    "droplet-launch-attempt",
                    binding=admission["binding"],
                    invocationId=admission["invocationId"],
                    leaseSha256=lease_digest,
                )
            ),
        )


def test_droplet_launch_uses_original_binding_and_active_attempt(
    droplet_attempt: tuple[Document, Path, Path],
) -> None:
    admission, state, authority = droplet_attempt
    owner = os.geteuid()
    with lease.controller(droplet.LEASE, owner=owner, drain=lambda: None) as token:
        _pin_droplet_attempt(authority, admission, token)
        wrong_invocation = {**admission, "invocationId": uuid(91)}
        with pytest.raises(ValidationError, match="droplet-launch-attempt-changed"):
            droplet.launch(token, encode(wrong_invocation), owner=owner)
        assert not (state / "platform/launch.json").exists()
        receipt = droplet.launch(token, encode(admission), owner=owner)
        assert droplet.launch(token, encode(admission), owner=owner) == receipt
    with pytest.raises(ValueError, match="controller was superseded"):
        droplet.launch(token, encode(admission), owner=owner)
    assert verify_launch(state, authority, owner=owner) == receipt
    require_local_launch_binding(authority, receipt, disposable=False, owner=owner)


@pytest.mark.parametrize(
    ("fact", "value"),
    [
        ("MACHINE_ID", b"b" * 32 + b"\n"),
        ("SYSTEM_UUID", b"22222222-3333-4444-5555-666666666666\n"),
        (
            "HOST_KEY",
            b"ssh-ed25519 " + base64.b64encode(droplet_observe.ED25519_WIRE_HEADER + b"B" * 32),
        ),
    ],
)
def test_copied_droplet_launch_and_enrollment_do_not_authorize_another_host(
    droplet_attempt: tuple[Document, Path, Path], fact: str, value: bytes
) -> None:
    admission, state, authority = droplet_attempt
    owner = os.geteuid()
    with lease.controller(droplet.LEASE, owner=owner, drain=lambda: None) as token:
        _pin_droplet_attempt(authority, admission, token)
        receipt = droplet.launch(token, encode(admission), owner=owner)
        getattr(droplet_observe, fact).write_bytes(value)
        assert verify_launch(state, authority, owner=owner) == receipt
        with pytest.raises(ValidationError, match="droplet-enrollment-changed"):
            require_local_launch_binding(authority, receipt, disposable=False, owner=owner)
        with pytest.raises(ValidationError, match="droplet-enrollment-changed"):
            droplet.launch(token, encode(admission), owner=owner)


@pytest.mark.parametrize("observed", [(999, "192.0.2.14"), (101, "192.0.2.19")])
def test_droplet_launch_rechecks_provider_metadata(
    droplet_attempt: tuple[Document, Path, Path],
    observed: tuple[int, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admission, state, authority = droplet_attempt
    owner = os.geteuid()
    monkeypatch.setattr(droplet, "metadata_identity", lambda: observed)
    with lease.controller(droplet.LEASE, owner=owner, drain=lambda: None) as token:
        _pin_droplet_attempt(authority, admission, token)
        with pytest.raises(ValidationError, match="droplet-metadata-changed"):
            droplet.launch(token, encode(admission), owner=owner)
    assert not (state / "platform/launch.json").exists()


@pytest.mark.parametrize("identity", ["dropletIds", "addresses", "identityDigests"])
def test_droplet_launch_and_publication_refuse_production_identities(
    droplet_attempt: tuple[Document, Path, Path], identity: str
) -> None:
    admission, state, authority = droplet_attempt
    owner = os.geteuid()
    target = admission["target"]
    excluded = authority / droplet_enrollment.EXCLUSIONS
    exclusions = decode(excluded.read_bytes(), "droplet-production-exclusions")
    registration_path = authority / droplet_enrollment.ENROLLMENT
    registration = decode(registration_path.read_bytes(), "droplet-enrollment")
    overlap = {
        "dropletIds": target["droplet"]["dropletId"],
        "addresses": registration["ipv4"],
        "identityDigests": target["transport"]["identitySha256"],
    }
    exclusions[identity].append(overlap[identity])
    registration["productionExclusionsSha256"] = digest(exclusions)
    target["enrollmentSha256"] = digest(registration)
    admission["authoritySha256"] = digest(registration)
    admission["binding"]["targetSha256"] = digest(target)
    excluded.write_bytes(encode(exclusions))
    registration_path.write_bytes(encode(registration))
    (authority / droplet_enrollment.TARGET).write_bytes(encode(target))
    with pytest.raises(ValidationError, match="production-crossover"):
        droplet.launch("a" * 64, encode(admission), owner=owner)
    with pytest.raises(ValidationError, match="production-crossover"):
        require_local_launch_binding(
            authority, {"binding": admission["binding"]}, disposable=False, owner=owner
        )
    assert not (state / "platform/launch.json").exists()


@pytest.mark.parametrize("drift", ["provider", "metadata", "ssh-pin"])
def test_droplet_enrollment_refuses_independent_observation_mismatch(drift: str) -> None:
    identity = droplet_inventory.ProviderIdentity(proof("project"), 101, "192.0.2.14")
    allocation = droplet_inventory.ApprovedAllocation(
        run_id=uuid(32),
        role="source",
        state_sha256=proof("state"),
        allocation_sha256=proof("plan"),
        inventory_sha256=proof("inventory"),
        transaction_namespace_sha256=proof("namespace"),
        identity=identity,
    )
    observation = droplet_inventory.ConnectedDroplet(
        provider=identity,
        metadata_id=101,
        metadata_ipv4="192.0.2.14",
        host_identity={"hostKeySha256": proof("key")},
        pinned_host_key_sha256=proof("key"),
    )
    changed = {
        "provider": replace(
            observation, provider=replace(identity, project_id_sha256=proof("swap"))
        ),
        "metadata": replace(observation, metadata_id=102),
        "ssh-pin": replace(observation, pinned_host_key_sha256=proof("copied-key")),
    }
    excluded = record(
        "droplet-production-exclusions",
        dropletIds=[100],
        addresses=["192.0.2.18"],
        identityDigests=[proof("production-key")],
    )
    with pytest.raises(ValidationError, match="droplet-allocation-observation-changed"):
        droplet_inventory.enrollment_records(allocation, changed[drift], encode(excluded))


@pytest.mark.parametrize("conflict", ["transaction.json", "installed-target.json", "revoked"])
def test_droplet_publication_refuses_conflicting_local_authority(
    droplet_attempt: tuple[Document, Path, Path], conflict: str
) -> None:
    admission, state, authority = droplet_attempt
    owner = os.geteuid()
    with lease.controller(droplet.LEASE, owner=owner, drain=lambda: None) as token:
        _pin_droplet_attempt(authority, admission, token)
        receipt = droplet.launch(token, encode(admission), owner=owner)
    (authority / conflict).touch(mode=0o600)
    assert verify_launch(state, authority, owner=owner) == receipt
    with pytest.raises(ValidationError, match="droplet-enrollment-conflicts"):
        require_local_launch_binding(authority, receipt, disposable=False, owner=owner)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (("101", "192.0.2.14"), (101, "192.0.2.14")),
        (("01", "192.0.2.14"), None),
        (("101", "malformed-address"), None),
    ],
)
def test_droplet_metadata_identity_uses_only_bound_fields(
    values: tuple[str, str],
    expected: tuple[int, str] | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replies = dict(
        zip(
            ("/metadata/v1/id", "/metadata/v1/interfaces/public/0/ipv4/address"),
            values,
            strict=True,
        )
    )
    monkeypatch.setattr(droplet_observe, "_metadata_value", replies.__getitem__)
    if expected is None:
        with pytest.raises(ValueError, match=r"^droplet-metadata-invalid$"):
            droplet_observe.metadata_identity()
    else:
        assert droplet_observe.metadata_identity() == expected


def _allocated_droplet(
    droplet_id: int, ipv4: str, *, run_id: str, role: Literal["source", "restore"]
) -> droplet_inventory.OwnedDroplet:
    identity = droplet_inventory.ProviderIdentity(proof("project"), droplet_id, ipv4)
    label = str(droplet_id)
    host = {
        "machineSha256": proof("machine" + label),
        "systemUuidSha256": proof("system" + label),
        "hostKeySha256": proof("key" + label),
    }
    return droplet_inventory.OwnedDroplet(
        droplet_inventory.ApprovedAllocation(
            run_id=run_id,
            role=role,
            state_sha256=proof("run-state"),
            allocation_sha256=proof("allocation" + label),
            inventory_sha256=proof("inventory" + label),
            transaction_namespace_sha256=proof("namespace" + label),
            identity=identity,
        ),
        droplet_inventory.ConnectedDroplet(
            provider=identity,
            metadata_id=droplet_id,
            metadata_ipv4=ipv4,
            host_identity=host,
            pinned_host_key_sha256=host["hostKeySha256"],
        ),
    )


def test_source_and_cold_restore_require_separate_actual_host_identities() -> None:
    source = _allocated_droplet(101, "192.0.2.14", run_id=uuid(31), role="source")
    restore = _allocated_droplet(102, "192.0.2.19", run_id=uuid(31), role="restore")
    excluded = encode(
        record(
            "droplet-production-exclusions",
            dropletIds=[100],
            addresses=["192.0.2.18"],
            identityDigests=[proof("production-key")],
        )
    )
    pair = droplet_inventory.prepare_source_and_restore(source, restore, excluded)
    assert pair["source"][0]["droplet"]["dropletId"] == source.observation.provider.droplet_id
    assert pair["restore"][0]["droplet"]["dropletId"] == restore.observation.provider.droplet_id

    wrong_run = _allocated_droplet(102, "192.0.2.19", run_id=uuid(32), role="restore")
    with pytest.raises(ValidationError, match="droplet-restore-scope-changed"):
        droplet_inventory.prepare_source_and_restore(source, wrong_run, excluded)

    for field in ("machineSha256", "systemUuidSha256", "hostKeySha256"):
        restored = {
            **restore.observation.host_identity,
            field: source.observation.host_identity[field],
        }
        copied = replace(
            restore,
            observation=replace(
                restore.observation,
                host_identity=restored,
                pinned_host_key_sha256=restored["hostKeySha256"],
            ),
        )
        with pytest.raises(ValidationError, match="droplet-restore-must-be-independent"):
            droplet_inventory.prepare_source_and_restore(source, copied, excluded)
