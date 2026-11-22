"""The disposable journey runs against synthetic, independently scoped adapters."""

from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Literal

import pytest

from infrastructure.test_m3_11_production_journal import records as records  # noqa: PLC0414
from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_diagnostic_store import Attempt, read
from scripts.m3_12_droplet_inventory import (
    ApprovedAllocation,
    ConnectedDroplet,
    ProviderIdentity,
    enrollment_records,
)
from scripts.m3_12_droplet_journey import PHASES, run_journey
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_successor import accepted_predecessor

CANARY = "synthetic-private-provider-error"
PHASE_NAMES = tuple(phase.name for phase in PHASES)


def proof(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def host(
    role: Literal["source", "restore", "fresh"], run: str, index: int, exclusions: Document
) -> Document:
    provider = ProviderIdentity(proof("disposable project"), index, f"11.1.2.{index}")
    approved = ApprovedAllocation(
        run_id=run,
        role=role,
        state_sha256=proof(role + " state"),
        allocation_sha256=proof(role + " allocation"),
        inventory_sha256=proof(role + " inventory"),
        transaction_namespace_sha256=proof(role + " transaction"),
        identity=provider,
    )
    key = proof(role + " public key")
    observed = ConnectedDroplet(
        provider=provider,
        metadata_id=index,
        metadata_ipv4=provider.ipv4,
        host_identity={
            "machineSha256": proof(role + " machine"),
            "systemUuidSha256": proof(role + " uuid"),
            "hostKeySha256": key,
        },
        pinned_host_key_sha256=key,
    )
    target, enrollment = enrollment_records(approved, observed, encode(exclusions))
    return {
        "target": target,
        "enrollment": enrollment,
        "stateKey": f"qualification/m3-12/{run}/{role}.tfstate",
        "adminCidrs": ["192.0.2.3/32"],
    }


@pytest.fixture
def fixture(
    tmp_path: Path, records: list[tuple[str, bytes]]
) -> tuple[Attempt, Document, ReviewedJourney]:
    attempt = Attempt.allocate(tmp_path / "attempts")
    run = attempt.directory.parent.name
    excluded: Document = {
        "format": "lowerduckpond-m3-12-droplet-journey-exclusions-v1",
        "hosts": {
            "format": "lowerduckpond-m3-12-droplet-production-exclusions-v1",
            "dropletIds": [1000],
            "addresses": ["11.2.2.20"],
            "identityDigests": [proof("production allocation")],
        },
        "zoneNames": ["production.example"],
        "zoneIds": [proof("production zone")[:32]],
        "certificateIds": [proof("production certificate")[:32]],
        "buckets": ["production-bucket"],
    }
    scope: Document = {
        "format": "lowerduckpond-m3-12-droplet-journey-allocation-v1",
        "targetKind": "disposable-droplet",
        "purpose": "disposable-qualification",
        "runId": run,
        "invocationId": attempt.directory.name,
        "productionExclusionsSha256": digest(excluded),
        "predecessorSha256": accepted_predecessor(records)[0],
        "predecessorBootstrapSha256": proof("historical bootstrap inputs"),
        "sitePolicySha256": proof("disposable site inputs"),
        "candidate": {
            "revision": proof("synthetic candidate revision")[:40],
            **{
                name: proof(name)
                for name in (
                    "hostAgentSha256",
                    "inputPolicySha256",
                    "inputFingerprintSha256",
                    "toolchainSha256",
                    "requirementsSha256",
                )
            },
        },
        "resources": {
            "hosts": {
                "source": host("source", run, 10, excluded["hosts"]),
                "restore": host("restore", run, 11, excluded["hosts"]),
                "fresh": host("fresh", run, 12, excluded["hosts"]),
            },
            "edge": {
                zone: {
                    "zoneId": proof(zone)[:32],
                    "zoneName": f"{zone}.example",
                    "registrableDomain": f"{zone}.example",
                    **{
                        role: {
                            "name": f"{role}.{zone}.example",
                            "certificateIds": {
                                operation: proof(zone + role + operation)[:32]
                                for operation in ("primary", "replacement")
                            },
                        }
                        for role in ("source", "fresh")
                    },
                }
                for zone in ("platform", "tenant")
            },
            "storage": {
                role: {
                    kind: {"region": "abc7", "bucket": f"{role}-{kind}", "prefix": f"runs/{run}"}
                    for kind in ("restic", "archive")
                }
                for role in ("source", "fresh")
            },
        },
    }
    return (
        attempt,
        scope,
        ReviewedJourney(
            manifest_sha256=digest(scope),
            predecessor_records=tuple(records),
            predecessor_bootstrap_sha256=scope["predecessorBootstrapSha256"],
            site_policy_sha256=scope["sitePolicySha256"],
            candidate=encode(scope["candidate"]),
            observed_resources=encode(scope["resources"]),
            production_exclusions=encode(excluded),
        ),
    )


class Offline:
    def __init__(self, attempt: Attempt, scope: Document) -> None:
        self.attempt = attempt
        self.raw = encode(scope)
        self.submitted: list[str] = []
        self.submitted_intents: set[str] = set()
        self.reads: list[str] = []
        self.interrupt: str | None = None
        self.failed: str | None = None
        self.not_applied: str | None = None
        self.unknown: str | None = None
        self.wrong_receipt: str | None = None

    def submit(self, intent: bytes, allocation: bytes) -> None:
        assert allocation == self.raw
        job = json.loads(intent)
        phase = job["phase"]
        job_sha = digest(job)
        assert job_sha not in self.submitted_intents
        self.submitted_intents.add(job_sha)
        previous = job["priorNoEffectSha256"]
        key = f"journey-{phase}" if previous is None else f"journey-{phase}-{previous}"
        assert read(self.attempt.directory, f"{key}-intent.json") == job
        assert all(
            digest(read(self.attempt.directory, receipt["file"])) == receipt["sha256"]
            for receipt in job["prerequisites"].values()
        )
        self.submitted.append(phase)
        if phase == self.interrupt:
            raise ConnectionError(CANARY)

    def readback(self, intent: bytes, allocation: bytes) -> bytes:
        assert allocation == self.raw
        job = json.loads(intent)
        label = job["phase"]
        phase = next(value for value in PHASES if value.name == label)
        self.reads.append(label)
        assert digest(job) in self.submitted_intents
        outcome = "committed"
        if label == self.failed:
            outcome = "failed"
        if label == self.not_applied and job["priorNoEffectSha256"] is None:
            outcome = "not-applied"
        if label == self.unknown:
            outcome = "unknown"
        return encode(
            {
                "format": "lowerduckpond-m3-12-droplet-journey-observation-v1",
                "intentSha256": proof("foreign intent")
                if label == self.wrong_receipt
                else digest(job),
                "outcome": outcome,
                "evidence": {
                    name: proof(label + name)
                    for name in (phase.evidence if outcome == "committed" else {"observation"})
                },
            }
        )


def test_runs_the_full_eligible_sequence_and_reopens_every_receipt(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, reviewed = fixture
    adapter = Offline(attempt, scope)
    complete = run_journey(attempt, encode(scope), reviewed, adapter)
    assert complete["sequenceComplete"]
    assert adapter.submitted == adapter.reads == list(PHASE_NAMES)
    originals = {p.name: p.read_bytes() for p in attempt.directory.glob("journey-*.json")}
    assert run_journey(attempt, encode(scope), reviewed, adapter) == complete
    assert originals == {p.name: p.read_bytes() for p in attempt.directory.glob("journey-*.json")}
    assert adapter.submitted == adapter.reads == list(PHASE_NAMES)
    restore = read(attempt.directory, "journey-cold-install-intent.json")
    assert restore["targets"] == {
        "restore": digest(scope["resources"]["hosts"]["restore"]["target"])
    }
    assert set(restore["prerequisites"]) == {"backup-fence"}


@pytest.mark.parametrize(
    ("changed", "error"),
    [
        ("review", "droplet-journey-review-changed"),
        ("incomplete", "successor-requires-accepted-predecessor"),
        ("readback", "droplet-journey-inputs-changed"),
        ("candidate", "droplet-journey-inputs-changed"),
        ("bootstrap", "droplet-journey-inputs-changed"),
        ("site-policy", "droplet-journey-inputs-changed"),
        ("production-zone", "droplet-journey-zone-crossover"),
        ("shared-dns", "droplet-journey-dns-scope-overlap"),
        ("shared-site", "droplet-journey-edge-identity-overlap"),
        ("shared-storage", "droplet-journey-storage-crossover"),
        ("production-certificate", "droplet-journey-edge-identity-overlap"),
        ("wrong-state", "droplet-journey-host-binding-changed"),
        ("copied-host", "droplet-journey-hosts-overlap"),
        ("unexpected-input", "invalid-record"),
    ],
)
def test_no_adapter_can_run_until_the_entire_scope_is_verified(  # noqa: PLR0912 - explicit substitution cases
    fixture: tuple[Attempt, Document, ReviewedJourney], changed: str, error: str
) -> None:
    attempt, scope, reviewed = fixture
    resources = scope["resources"]
    if changed == "production-zone":
        resources["edge"]["tenant"]["zoneName"] = "lowerduckpond.com"
    elif changed == "shared-dns":
        resources["edge"]["tenant"]["fresh"]["name"] = "child.source.tenant.example"
    elif changed == "shared-site":
        for name in ("platform", "tenant"):
            zone = resources["edge"][name]
            zone["registrableDomain"] = "owned.example"
            zone["zoneName"] = f"{name}.owned.example"
            for role in ("source", "fresh"):
                zone[role]["name"] = f"{role}.{name}.owned.example"
    elif changed == "shared-storage":
        resources["storage"]["source"]["archive"]["bucket"] = "source-restic"
    elif changed == "production-certificate":
        resources["edge"]["tenant"]["source"]["certificateIds"]["primary"] = proof(
            "production certificate"
        )[:32]
    elif changed == "wrong-state":
        resources["hosts"]["restore"]["stateKey"] = "known-other.tfstate"
    elif changed == "copied-host":
        hosts = resources["hosts"]
        hosts["restore"].update(
            target=hosts["source"]["target"], enrollment=hosts["source"]["enrollment"]
        )
    elif changed == "unexpected-input":
        scope["operatorInput"] = CANARY

    reviewed = replace(
        reviewed, manifest_sha256=digest(scope), observed_resources=encode(resources)
    )
    if changed == "review":
        reviewed = replace(reviewed, manifest_sha256=proof("other review"))
    elif changed == "incomplete":
        reviewed = replace(reviewed, predecessor_records=reviewed.predecessor_records[:-1])
    elif changed == "readback":
        resources["storage"]["source"]["archive"]["prefix"] = "different/owned/prefix"
        reviewed = replace(reviewed, manifest_sha256=digest(scope))
    elif changed == "candidate":
        scope["candidate"]["hostAgentSha256"] = proof("substituted artifact")
        reviewed = replace(reviewed, manifest_sha256=digest(scope))
    elif changed == "bootstrap":
        reviewed = replace(reviewed, predecessor_bootstrap_sha256=proof("bad bootstrap"))
    elif changed == "site-policy":
        reviewed = replace(reviewed, site_policy_sha256=proof("bad site policy"))
    adapter = Offline(attempt, scope)
    with pytest.raises(ValidationError, match=error):
        run_journey(attempt, encode(scope), reviewed, adapter)
    assert adapter.submitted == adapter.reads == []
    assert not list(attempt.directory.glob("journey-*"))


def test_lost_response_reconciles_original_intent_and_keeps_independent_work(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, reviewed = fixture
    adapter = Offline(attempt, scope)
    adapter.interrupt = "launch"
    first = run_journey(attempt, encode(scope), reviewed, adapter)
    assert not first["sequenceComplete"]
    assert first["phases"]["launch"] == "uncertain"
    assert first["phases"]["enabled-converge"] == "blocked"
    assert first["phases"]["fresh-reboot"] == "committed"
    assert first["phases"]["teardown"] == "blocked"
    pending = attempt.directory / "journey-launch-intent.json"
    original_intent = pending.read_bytes()
    adapter.unknown = "launch"
    assert run_journey(attempt, encode(scope), reviewed, adapter)["phases"]["launch"] == "uncertain"
    assert pending.read_bytes() == original_intent
    adapter.unknown = None
    assert run_journey(attempt, encode(scope), reviewed, adapter)["sequenceComplete"]
    assert adapter.submitted.count("launch") == 1
    assert pending.read_bytes() == original_intent
    assert all(CANARY not in p.read_text() for p in attempt.directory.glob("*.json"))


def test_failed_backup_blocks_restore_and_teardown_preserving_the_original(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, reviewed = fixture
    adapter = Offline(attempt, scope)
    adapter.failed = "backup-fence"
    first = run_journey(attempt, encode(scope), reviewed, adapter)
    assert first["phases"]["backup-fence"] == "failed"
    assert first["phases"]["cold-install"] == first["phases"]["teardown"] == "blocked"
    path = attempt.directory / "journey-backup-fence-result.json"
    original = path.read_bytes()
    assert run_journey(attempt, encode(scope), reviewed, adapter) == first
    assert path.read_bytes() == original
    assert adapter.submitted.count("backup-fence") == 1


def test_a_foreign_receipt_never_opens_the_next_phase(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, reviewed = fixture
    adapter = Offline(attempt, scope)
    adapter.wrong_receipt = "launch"
    with pytest.raises(ValidationError, match="droplet-journey-evidence-changed"):
        run_journey(attempt, encode(scope), reviewed, adapter)
    assert adapter.submitted == ["predecessor", "dark-stage", "dark-repeat", "launch"]
    assert not (attempt.directory / "journey-launch-result.json").exists()
    assert not (attempt.directory / "journey-enabled-converge-intent.json").exists()


def test_resubmission_requires_fresh_no_effect_proof_and_preserves_original_dispatch(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, reviewed = fixture
    adapter = Offline(attempt, scope)
    adapter.not_applied = "launch"
    initial = run_journey(attempt, encode(scope), reviewed, adapter)
    assert initial["phases"]["launch"] == "not-applied"
    assert initial["phases"]["enabled-converge"] == "blocked"
    assert run_journey(attempt, encode(scope), reviewed, adapter) == initial
    result = attempt.directory / "journey-launch-result.json"
    first = result.read_bytes()
    original = read(attempt.directory, result.name)
    retry_path = attempt.directory / f"journey-launch-{digest(original)}-intent.json"

    adapter.unknown = "launch"
    with pytest.raises(ValidationError, match="droplet-journey-retry-not-proven"):
        run_journey(attempt, encode(scope), reviewed, adapter, retry_not_applied="launch")
    assert adapter.submitted.count("launch") == 1
    assert not retry_path.exists()

    adapter.unknown = None
    latest = run_journey(attempt, encode(scope), reviewed, adapter, retry_not_applied="launch")
    assert latest["sequenceComplete"]
    assert result.read_bytes() == first
    assert read(attempt.directory, retry_path.name)["priorNoEffectSha256"] == digest(original)
    assert adapter.submitted.count("launch") == 2  # noqa: PLR2004 - one original, one proved retry
    assert run_journey(attempt, encode(scope), reviewed, adapter) == latest


def test_new_review_cannot_replace_the_original_attempt_scope(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, reviewed = fixture
    adapter = Offline(attempt, scope)
    adapter.failed = "predecessor"
    run_journey(attempt, encode(scope), reviewed, adapter)
    original = (attempt.directory / "journey-allocation.json").read_bytes()
    scope["resources"]["storage"]["fresh"]["archive"]["prefix"] = "another/private/prefix"
    new_review = replace(
        reviewed,
        manifest_sha256=digest(scope),
        observed_resources=encode(scope["resources"]),
    )
    attempted = Offline(attempt, scope)
    with pytest.raises(ValidationError, match="droplet-journey-original-changed"):
        run_journey(attempt, encode(scope), new_review, attempted)
    assert attempted.submitted == attempted.reads == []
    assert (attempt.directory / "journey-allocation.json").read_bytes() == original
