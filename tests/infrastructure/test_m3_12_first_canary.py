"""Synthetic evidence for the two-tenant production exception; no network or provider."""

import json
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from lowerduckpond_static_host_agent import first_canary, platform_launch
from lowerduckpond_static_host_agent.durable import DurableDirectory

from infrastructure.test_m3_12_contracts import (
    _launch_paths,
    enroll,
    fixture_time,
    production_transaction,
    proof,
    retain,
    uuid,
)
from scripts import m3_11_production_lease as lease
from scripts import m3_12_droplet_observe
from scripts import m3_12_native as native
from scripts.m3_12_contracts import (
    CANARY_DROPLET,
    CANARY_PREDECESSOR,
    CANARY_PREDECESSOR_HEAD,
    CANARY_PROJECT_SHA,
    CANARY_TRANSACTION,
    FIRST_CANARY,
    PRODUCTION,
    AdmissionContext,
    Document,
    Evidence,
    ValidationError,
    decode,
    digest,
    encode,
)
from scripts.m3_12_successor_journal import SuccessorJournal
from scripts.m3_12_transaction import PHASES, Reconciliation


def create_request(number: int) -> Document:
    return {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "OperationRequest",
        "operation": "create",
        "slug": f"m312-canary-{number}",
        "correlationId": uuid(number),
        "quotas": {"storageMiB": 100, "entries": 5000},
    }


def canary(
    tmp_path: Path, *, host_identity: Document | None = None
) -> tuple[Path, Path, Document, AdmissionContext, Evidence]:
    admission, context, old = enroll(PRODUCTION)
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": fixture_time(5),
    }
    state, root = _launch_paths(tmp_path, namespace)
    admission["target"]["droplet"].update(
        projectIdSha256=CANARY_PROJECT_SHA, dropletId=CANARY_DROPLET
    )
    admission["platform"]["namespaceSha256"] = digest(namespace)
    binding = admission["binding"]
    binding.update(
        platformSha256=digest(admission["platform"]), targetSha256=digest(admission["target"])
    )
    admission["format"] = FIRST_CANARY
    decision = {
        "format": "lowerduckpond-m3-12-first-canary-decision-v1",
        "approval": "Sentinel_c1a03d66ef1c819188af86d6dbc24b64",
        "transactionId": CANARY_TRANSACTION,
        "binding": binding,
        "predecessorSha256": admission["target"]["predecessorSha256"],
        "successorProposalSha256": admission["target"]["successorProposalSha256"],
        "hostIdentity": host_identity
        or {k: proof(k) for k in ("machineSha256", "systemUuidSha256", "hostKeySha256")},
        "operatorPrincipal": "operator@example.test",
        "renameSlug": "m312-canary-renamed",
        "unproven": [
            "complete-disposable",
            "hostile-isolation",
            "origin-outage",
            "acme-failure-and-rollover",
            "disposable-fresh-and-recovery-matrix",
        ],
        "customerAdmission": "closed",
        "creates": [
            {"slug": r["slug"], "correlationId": r["correlationId"], "requestSha256": digest(r)}
            for r in (create_request(1), create_request(2))
        ],
    }
    records: dict[str, bytes] = {}
    admission.update(authoritySha256=retain(records, decision), decision=decision)
    for slot, key in list(admission["prerequisites"].items()):
        row = old.read(key, "receipt")
        row["binding"] = binding
        admission["prerequisites"][slot] = retain(records, row)
    transaction, _ = production_transaction()
    transaction.update(
        binding=binding, transactionId=CANARY_TRANSACTION, authorizationSha256=digest(decision)
    )
    context = replace(
        context,
        enrolled_target=admission["target"],
        platform_sha256=digest(admission["platform"]),
        authority_sha256=digest(decision),
        transaction_id=CANARY_TRANSACTION,
        predecessor_transaction=CANARY_PREDECESSOR,
        predecessor_head=CANARY_PREDECESSOR_HEAD,
    )
    with DurableDirectory.open(
        root, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as protected:
        journal = SuccessorJournal(protected, os.geteuid())
        journal.pin(encode(transaction))
        for field in ("target", "candidate", "platform"):
            journal.immutable(field + ".json", encode(admission[field]))
        for key, raw in records.items():
            journal.immutable("evidence-" + key + ".json", raw)
        evidence = native.admission_evidence(journal, admission)
    return state, root, admission, context, evidence


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_sha256", proof("different")),
        ("transaction_id", uuid(99)),
        ("run_id", uuid(77)),
        ("predecessor_head", proof("foreign")),
        ("predecessor_transaction", uuid(19)),
        ("tenant_history", True),
        ("unfinished_lifecycle", True),
        ("revoked", True),
    ],
)
def test_original_canary_cannot_be_replayed(tmp_path: Path, field: str, value: object) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)
    with pytest.raises(ValidationError):
        platform_launch.initialize_launch(
            state,
            root,
            encode(admission),
            evidence,
            lambda: replace(ctx, **cast(dict[str, Any], {field: value})),
            owner=os.geteuid(),
        )
    assert not (state / "platform/launch.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        "backupRestore",
        "livePreflight",
        "authority",
        "wrong-target",
        "wrong-candidate",
        "foreign-create",
    ],
)
def test_canary_requires_independent_evidence(tmp_path: Path, change: str) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)
    if change == "wrong-target":
        admission["target"]["droplet"]["dropletId"] += 1
    elif change == "wrong-candidate":
        admission["candidate"]["hostAgentSha256"] = proof("other")
    elif change == "foreign-create":
        admission["decision"]["creates"][0]["slug"] = "customer"
    else:
        records = dict(evidence.records)
        key = (
            admission["authoritySha256"]
            if change == "authority"
            else admission["prerequisites"][change]
        )
        del records[key]
        evidence = Evidence(records)
    with pytest.raises(ValidationError):
        platform_launch.initialize_launch(
            state, root, encode(admission), evidence, lambda: ctx, owner=os.geteuid()
        )
    assert not (root / "launch-intent.json").exists()


def test_launch_worker_restore_and_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)
    owner = os.geteuid()
    receipt = platform_launch.initialize_launch(
        state, root, encode(admission), evidence, lambda: ctx, owner=owner
    )
    assert (
        platform_launch.initialize_launch(
            state, root, encode(admission), evidence, lambda: ctx, owner=owner
        )
        == receipt
    )
    with pytest.raises(ValidationError):
        decode(encode(admission), "admission")  # Ineligible for ordinary production acceptance.
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        first_canary.project_launch(records, owner)
        first_canary.project_launch(records, owner)
        view = root / first_canary.VIEW
        assert {p.name for p in view.iterdir()} == {
            "transaction.json",
            "admission.json",
            "launch-receipt.json",
            "launch-intent.json",
        }
        assert platform_launch.verify_launch(state, view, owner=owner) == receipt
        local = admission["decision"]["hostIdentity"]
        monkeypatch.setattr(m3_12_droplet_observe, "host_identity", lambda _: local)

        def open_worker() -> None:
            platform_launch.require_local_launch_binding(
                view, receipt, disposable=False, owner=owner
            )

        open_worker()
        first_canary.fence_worker_view(records, owner, closed=True)
        with pytest.raises(ValidationError, match="fenced"):
            open_worker()
        first_canary.fence_worker_view(records, owner, closed=False)
        open_worker()
        monkeypatch.setattr(
            m3_12_droplet_observe,
            "host_identity",
            lambda _: {**local, "systemUuidSha256": proof("copy")},
        )
        with pytest.raises(ValidationError, match="wrong-guest"):
            open_worker()


@pytest.mark.parametrize(("wrong_backup", "crash"), [(False, False), (False, True), (True, False)])
def test_native_launch_consumes_original_backup_and_seals_worker_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrong_backup: bool, crash: bool
) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)
    owner = os.geteuid()
    backup = evidence.read(admission["prerequisites"]["backupRestore"], "receipt")
    candidate = tmp_path / "artifacts"
    selected = candidate / admission["candidate"]["hostAgentSha256"]
    selected.mkdir(parents=True)
    selection = candidate / "current"
    selection.symlink_to(selected)
    for name, path in {
        "STATE": state,
        "ROOT": root,
        "CANDIDATE": candidate,
        "SELECTION": selection,
    }.items():
        monkeypatch.setattr(native, name, path)
    trusted = native.NativeAuthority(
        ctx,
        admission["target"]["predecessorSha256"],
        admission["candidate"],
        admission["platform"],
        evidence.read(admission["prerequisites"]["livePreflight"], "receipt"),
    )
    monkeypatch.setattr(native, "read_authority", lambda _journal, _token: trusted)
    monkeypatch.setattr(native, "require_dark_health", lambda: None)
    monkeypatch.setattr(lease, "require_action", lambda *_args, **_kwargs: None)

    # The native program runs as root. The test owns its synthetic data.
    def initialize(
        state: Path,
        authority: Path,
        raw: bytes,
        records: Evidence,
        observe: Callable[[], AdmissionContext],
    ) -> Document:
        return platform_launch.initialize_launch(
            state, authority, raw, records, observe, owner=owner
        )

    monkeypatch.setattr(native, "initialize_launch", initialize)
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        journal.immutable("prepared-admission.json", encode(admission))
        for phase in PHASES:
            observation = (
                backup["observationSha256"]
                if phase == "final-backup-verification" and not wrong_backup
                else proof(phase)
            )
            data = Reconciliation(observation, "not-applied", True, True, proof("configuration"))
            journal.advance("started", ctx, data)
            if phase == "durable-launch":
                break
            journal.advance("committed", ctx, replace(data, outcome="committed"))
        if wrong_backup:
            with pytest.raises(ValidationError, match="final-backup-changed"):
                native.launch(journal, "synthetic")
            assert not (state / "platform/launch.json").exists()
        else:
            if crash:
                project = first_canary.project_launch

                def interrupted(source: DurableDirectory, uid: int) -> None:
                    project(source, uid)
                    (root / first_canary.VIEW / "launch-receipt.json").unlink()
                    raise OSError("interrupted during worker projection")

                with monkeypatch.context() as patch:
                    patch.setattr(native, "project_launch", interrupted)
                    with pytest.raises(OSError, match="interrupted"):
                        native.launch(journal, "synthetic")
                receipt = platform_launch.verify_launch(state, root, owner=owner)
                monkeypatch.setattr(native, "verify_launch", lambda state, root: receipt)
                current = journal.snapshot().history
                observation = digest(receipt)
                journal.immutable("evidence-" + observation + ".json", encode(receipt))
                journal.immutable(
                    "phase-readback.json",
                    encode(
                        {
                            "format": "lowerduckpond-m3-12-native-phase-readback-v1",
                            "transactionSha256": current.transaction_sha256,
                            "priorHeadSha256": current.head_sha256,
                            "phase": current.phase,
                            "invocationId": ctx.invocation_id,
                            "leaseSha256": ctx.lease_sha256,
                            "readbackSha256": observation,
                            "outcome": "committed",
                            "processDrained": True,
                            "originalPreconditions": True,
                            "configurationSha256": proof("configuration"),
                        }
                    ),
                )
                native.phase(journal, "reconcile", "synthetic")
                assert journal.snapshot().history.phase == "enabled-convergence"
            else:
                receipt = native.launch(journal, "synthetic")
            assert receipt == platform_launch.verify_launch(
                state, root / first_canary.VIEW, owner=owner
            )


def test_preparation_reopens_review_and_native_audit_blocks_first_intent(tmp_path: Path) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)

    def prepare() -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603 - fixed local preparation CLI and owned fixture
            [sys.executable, "-B", "-m", "scripts.m3_12_diagnostics", "prepare", str(root)],
            capture_output=True,
            check=False,
        )

    review = prepare()
    assert review.returncode == 0, review.stderr
    assert json.loads(review.stdout)["authoritySha256"] == digest(admission["decision"])
    fixture = (
        Path(__file__).parents[2] / "tests/static-publication/fixtures/accepted/audit-entry.json"
    )
    entry = json.loads(fixture.read_bytes())
    path = state / "audit/segment-00000000000000000000.jsonl"
    path.write_bytes(encode(entry))
    path.chmod(0o600)
    with pytest.raises(ValidationError, match="launch-history-or-work"):
        platform_launch.initialize_launch(
            state, root, encode(admission), evidence, lambda: ctx, owner=os.geteuid()
        )
    assert not (root / "launch-intent.json").exists()
    (root / ("evidence-" + ctx.authority_sha256 + ".json")).unlink()
    assert prepare().returncode != 0
