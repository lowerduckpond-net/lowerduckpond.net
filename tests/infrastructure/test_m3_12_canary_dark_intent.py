"""The one-time canary can start a dark phase only from native observations."""

from __future__ import annotations

import os
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.durable import DurableDirectory

from scripts import m3_11_production_initialize as locks
from scripts import m3_11_production_observe as predecessor_state
from scripts import m3_12_native as native
from scripts.m3_11_playbook_recap import COUNTERS
from scripts.m3_12_contracts import ValidationError, digest, encode
from scripts.m3_12_successor import stage_configuration
from scripts.m3_12_successor_journal import SuccessorJournal
from scripts.m3_12_transaction import Reconciliation

from .test_m3_12_contracts import proof
from .test_m3_12_first_canary import canary


@pytest.mark.parametrize("fault", ["none", "active", "wrong-artifact", "live", "health"])
def test_native_dark_repeat_start_records_fresh_observation(  # noqa: PLR0915 - one durable start-to-commit flow
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)
    owner = os.geteuid()
    candidate = admission["candidate"]
    artifact = candidate["hostAgentSha256"]
    artifacts = tmp_path / "artifacts"
    selected = artifacts / (artifact if fault != "wrong-artifact" else proof("unrelated"))
    selected.mkdir(parents=True)
    link = artifacts / "current"
    link.symlink_to(selected)
    for key, value in {
        "STATE": state,
        "ROOT": root,
        "SELECTION": link,
        "CANDIDATE": artifacts,
    }.items():
        monkeypatch.setattr(native, key, value)
    if fault == "live":
        (root / "launch-intent.json").touch()
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "cgroup.procs").write_text(
        f"{os.getpid()}\n" + ("777\n" if fault == "active" else "")
    )
    (cgroup / "cgroup.stat").write_text("nr_descendants 0\n")
    monkeypatch.setattr(native, "CGROUP_EVENTS", cgroup / "cgroup.events")
    monkeypatch.setattr(locks, "_lock", lambda *_: nullcontext())
    monkeypatch.setattr(predecessor_state, "_empty", lambda _: None)

    def require_dark() -> None:
        if fault == "health":
            raise ValidationError("fixture health failure")

    monkeypatch.setattr(native, "require_dark_health", require_dark)
    trusted = native.NativeAuthority(
        ctx,
        admission["target"]["predecessorSha256"],
        candidate,
        admission["platform"],
        evidence.read(admission["prerequisites"]["livePreflight"], "receipt"),
    )
    monkeypatch.setattr(native, "read_authority", lambda *_: trusted)
    initial = Reconciliation(proof("initial"), "not-applied", True, True, proof("config"))
    committed = Reconciliation(proof("committed"), "committed", True, True, proof("config"))
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as records:
        journal = SuccessorJournal(records, owner)
        for _ in range(2):
            journal.advance("started", ctx, initial)
            journal.advance("committed", ctx, committed)
        before = journal.snapshot()
        assert before.history.phase == "dark-repeat"
        if fault != "none":
            with pytest.raises(ValidationError, match=r"first-canary-dark-|fixture health"):
                native.phase(journal, "start", "native-test-token")
            assert journal.snapshot() == before
            return
        with pytest.raises(ValidationError, match="first-canary-dark-not-pending"):
            native.canary_pending_dark(journal, "native-test-token")
        receipt = native.phase(journal, "start", "native-test-token")
        assert native.canary_pending_dark(journal, "native-test-token") == receipt
        monkeypatch.setattr(
            native,
            "read_authority",
            lambda *_: replace(trusted, context=replace(ctx, lease_sha256=proof("other lease"))),
        )
        with pytest.raises(ValidationError, match="first-canary-dark-pending-authority-changed"):
            native.canary_pending_dark(journal, "native-test-token")
        monkeypatch.setattr(native, "read_authority", lambda *_: trusted)
        assert receipt["stageConfigurationSha256"] == digest(
            stage_configuration("dark-repeat", artifact)
        )
        key = receipt["evidenceSha256"]
        observation = native.decode_json_object(journal.read(f"evidence-{key}.json"))
        assert observation["selectedArtifactSha256"] == artifact
        assert observation["priorHeadSha256"] == before.history.head_sha256
        assert digest(observation) == key
        assert journal.snapshot().history.pending
        with pytest.raises(ValidationError, match="first-canary-dark-intent-unavailable"):
            native.phase(journal, "start", "native-test-token")
        pending = journal.snapshot()
        with pytest.raises(ValidationError, match="first-canary-requires-dark-playbook-proof"):
            native.phase(journal, "reconcile", "native-test-token")
        counters = dict.fromkeys(COUNTERS, 0)
        counters["ok"] = 1
        recap = {
            "format": "lowerduckpond-m3-11-playbook-recap-v1",
            "context_sha256": pending.history.head_sha256,
            "hosts": {native.CANARY_PLAYBOOK_HOST: counters},
        }
        counters["changed"] = 1
        with pytest.raises(ValueError, match="not idempotent"):
            native._canary_dark(journal, trusted, "native-test-token", encode(recap))
        counters["changed"] = 0
        with pytest.raises(ValueError, match="exactly its intended host"):
            native._canary_dark(
                journal,
                trusted,
                "native-test-token",
                encode({**recap, "context_sha256": proof("other phase")}),
            )
        assert journal.snapshot() == pending
        result = native._canary_dark(journal, trusted, "native-test-token", encode(recap))
        assert result["transition"] == "committed"
        assert journal.snapshot().history.phase == "final-backup-verification"
        with pytest.raises(ValidationError, match="first-canary-dark-not-pending"):
            native.canary_pending_dark(journal, "native-test-token")
