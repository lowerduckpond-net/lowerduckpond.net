from __future__ import annotations

import grp
import os
import stat
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import production_rollout_backup as rollout
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.production_backup import BackupAuthority

from scripts import m3_11_production_initialize as locks
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as predecessor
from scripts import m3_12_backup_evidence as backup
from scripts import m3_12_native as native
from scripts import m3_12_native_backup as adapter
from scripts.m3_12_backup_evidence import PHASE, seal_verified_restore
from scripts.m3_12_contracts import Document, ValidationError, decode, digest, encode, require
from scripts.m3_12_successor_journal import SuccessorJournal
from scripts.m3_12_transaction import PHASES, Reconciliation

from .test_m3_12_contracts import fixture_time, proof
from .test_m3_12_first_canary import canary


@pytest.mark.parametrize("fault", ["none", "index", "early", "candidate", "tenant"])
def test_native_restore_result_is_bound_to_pending_phase(  # noqa: PLR0915 - exact retry and rejection checks
    tmp_path: Path, fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, root, admission, context, _ = canary(tmp_path)
    owner = os.geteuid()
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        initial = Reconciliation(proof("initial"), "not-applied", True, True, proof("config"))
        for phase in PHASES:
            journal.advance("started", context, initial)
            if phase == PHASE:
                break
            journal.advance("committed", context, replace(initial, outcome="committed"))
        history = journal.snapshot().history
        assert history.head_sha256 is not None
        authority = BackupAuthority(
            original_sha256=history.transaction_sha256,
            phase_sha256=history.head_sha256,
            report_sha256=context.authority_sha256,
            artifact_sha256=admission["candidate"]["hostAgentSha256"],
            repository_binding=proof("repository"),
            lineage_sha256=proof("lineage"),
            namespace={},
            launch=None,
        )
        verified = {
            "snapshot_id": proof("snapshot"),
            "descriptor_sha256": proof("descriptor"),
            "index_sha256": proof("index"),
            "restored_tree_sha256": proof("restored tree"),
            "report_sha256": context.authority_sha256,
        }
        start = history.recorded_at
        if fault == "early":
            start -= timedelta(seconds=1)
        if fault == "candidate":
            authority = replace(authority, artifact_sha256=proof("wrong artifact"))
        if fault == "tenant":
            context = replace(context, tenant_history=True)

        def seal() -> tuple[Document, Reconciliation]:
            return seal_verified_restore(
                journal,
                context,
                authority,
                verified,
                started=start,
                finished=start,
                expected_index_sha256=proof("wrong index" if fault == "index" else "index"),
            )

        if fault != "none":
            with pytest.raises(ValidationError, match="native-backup-"):
                seal()
            assert journal.snapshot().history == history
            return
        with pytest.raises(ValidationError, match="native-backup-result-changed"):
            backup.capture_verified_restore(
                journal,
                lambda: context,
                authority,
                lambda: {**verified, "index_sha256": proof("bad result")},
                now=lambda: start,
                expected_index_sha256=proof("index"),
            )
        with pytest.raises(FileNotFoundError):
            journal.read(f"backup-finish-{authority.phase_sha256}.json")
        calls = 0

        def verify() -> dict[str, str]:
            nonlocal calls
            calls += 1
            return verified

        def capture() -> tuple[Document, Reconciliation]:
            return backup.capture_verified_restore(
                journal,
                lambda: context,
                authority,
                verify,
                now=lambda: start,
                expected_index_sha256=proof("index"),
            )

        def interrupt(*_args: object, **_kwargs: object) -> None:
            raise OSError("interrupted after durable materialization")

        with monkeypatch.context() as patch:
            patch.setattr(backup, "seal_verified_restore", interrupt)
            with pytest.raises(OSError, match="interrupted"):
                capture()
        receipt, data = capture()
        assert capture() == (receipt, data)
        assert calls == 1

        verified["snapshot_id"] = proof("different snapshot")
        with pytest.raises(ValidationError, match="successor-original-conflict"):
            seal()
        verified["snapshot_id"] = proof("snapshot")
        assert receipt["observationSha256"] == data.evidence_sha256
        assert decode(journal.read(f"evidence-{digest(receipt)}.json"), "receipt") == receipt
        committed = journal.advance("committed", context, data)
        assert committed["evidenceSha256"] == receipt["observationSha256"]
        with pytest.raises(ValidationError, match="native-backup-not-current"):
            seal()


def test_canary_backup_cannot_use_generic_phase_reconcile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, root, admission, context, _ = canary(tmp_path)
    monkeypatch.setattr(
        native,
        "read_authority",
        lambda *_: native.NativeAuthority(
            context,
            context.enrolled_target["predecessorSha256"],
            admission["candidate"],
            admission["platform"],
            {},
        ),
    )
    with DurableDirectory.open(
        root, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, os.geteuid())
        initial = Reconciliation(proof("initial"), "not-applied", True, True, proof("config"))
        for phase in PHASES:
            journal.advance("started", context, initial)
            if phase == PHASE:
                break
            journal.advance("committed", context, replace(initial, outcome="committed"))
        original = journal.snapshot()
        with pytest.raises(
            ValidationError, match="first-canary-requires-native-backup-verification"
        ):
            native.phase(journal, "reconcile", "token")
        assert journal.snapshot() == original


@pytest.mark.parametrize("selected", [True, False])
def test_native_adapter_binds_capture_to_exact_selected_candidate(  # noqa: PLR0915 - fixture boundaries
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selected: bool
) -> None:
    _, root, admission, context, _ = canary(tmp_path)
    owner = os.geteuid()
    namespace = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": fixture_time(5),
    }
    prior = context.enrolled_target["predecessorSha256"]
    lineage = {
        "lineage_sha256": proof("lineage"),
        "genesis_snapshot_id": proof("genesis"),
        "audit_head_sha256": proof("audit"),
    }
    candidate = admission["candidate"]
    link = tmp_path / "current"
    selected_path = tmp_path / (candidate["hostAgentSha256"] if selected else "other")
    selected_path.mkdir()
    link.symlink_to(selected_path, target_is_directory=True)
    monkeypatch.setattr(adapter, "SELECTION", link)
    public_mode, private_mode = 0o755, 0o700
    public_cache = tmp_path / "var-cache"
    public_cache.mkdir()
    public_cache.chmod(public_mode)
    private_cache = public_cache / "lowerduckpond-backup"
    private_cache.mkdir(mode=private_mode)
    monkeypatch.setattr(adapter, "CACHE", private_cache)
    monkeypatch.setattr(locks, "_lock", lambda *args: nullcontext(11))
    monkeypatch.setattr(predecessor, "operate", lambda *a, **k: b"fixture")
    monkeypatch.setattr(
        predecessor, "decode", lambda _: [("lineage", encode({"observations": lineage}))]
    )
    monkeypatch.setattr(
        adapter,
        "accepted_predecessor",
        lambda _: (prior, {"namespace": namespace, "repository_binding": proof("repository")}),
    )
    monkeypatch.setattr(probe, "read", lambda *a, **k: b"fixture")
    monkeypatch.setattr(probe, "configuration", lambda _: {})
    monkeypatch.setattr(probe, "environment", lambda *a, **k: {})
    content_group = 42
    monkeypatch.setattr(grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=content_group))
    calls = []

    def capture(
        directory: Path,
        authority: BackupAuthority,
        _environment: dict[str, str],
        descriptors: tuple[int, int],
        **kwargs: object,
    ) -> dict[str, str]:
        calls.append(authority)
        assert context.transaction_id is not None
        assert directory == private_cache / "m3-12" / context.transaction_id
        assert stat.S_IMODE(directory.parent.stat().st_mode) == private_mode
        assert stat.S_IMODE(public_cache.stat().st_mode) == public_mode
        assert descriptors == (11, 11)
        assert kwargs["genesis_snapshot_id"] == lineage["genesis_snapshot_id"]
        assert kwargs["audit_head_sha256"] == lineage["audit_head_sha256"]
        assert kwargs["content_group"] == content_group
        assert authority.artifact_sha256 == candidate["hostAgentSha256"]
        assert authority.repository_binding == proof("repository")
        return {
            "snapshot_id": proof("snapshot"),
            "descriptor_sha256": proof("descriptor"),
            "index_sha256": proof("audit"),
            "restored_tree_sha256": proof("restored tree"),
            "report_sha256": context.authority_sha256,
        }

    monkeypatch.setattr(rollout, "run", capture)

    def observe() -> native.NativeAuthority:
        return native.NativeAuthority(
            replace(context, now=datetime.now(UTC)), prior, candidate, admission["platform"], {}
        )

    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        initial = Reconciliation(proof("initial"), "not-applied", True, True, proof("config"))
        for phase in PHASES:
            journal.advance("started", context, initial)
            if phase == PHASE:
                break
            journal.advance("committed", context, replace(initial, outcome="committed"))

        # Only the outer root check is emulated; the journal retains real ownership.
        monkeypatch.setattr(
            adapter,
            "require",
            lambda ok, code: require(True if code == "native-backup-root-required" else ok, code),
        )
        if not selected:
            with pytest.raises(ValidationError, match="native-backup-live-binding-changed"):
                adapter.run(journal, observe, lambda: None)
            assert not calls
            assert not (private_cache / "m3-12").exists()
            assert journal.snapshot().history.pending
            return
        result = adapter.run(journal, observe, lambda: None)
        assert len(calls) == 1
        assert result["phase"]["evidenceSha256"] == result["receipt"]["observationSha256"]
        assert not journal.snapshot().history.pending
