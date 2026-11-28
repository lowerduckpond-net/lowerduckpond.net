"""A live canary cannot cross preparation on assertions from its caller."""

from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.durable import DurableDirectory

from scripts import m3_11_production_initialize as locks
from scripts import m3_11_production_observe as predecessor_state
from scripts import m3_11_production_records as predecessor_records
from scripts import m3_12_canary_baseline as baseline
from scripts import m3_12_native as native
from scripts.m3_12_contracts import ValidationError
from scripts.m3_12_successor_journal import SuccessorJournal

from .test_m3_12_contracts import proof
from .test_m3_12_first_canary import canary


@pytest.mark.parametrize("fault", ["none", "unstaged", "selected", "interrupted"])
def test_native_preparation_reopens_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    state, root, admission, ctx, evidence = canary(tmp_path)
    owner = os.geteuid()
    candidate = admission["candidate"]
    archive = candidate["hostAgentSha256"]
    predecessor = proof("original selected artifact")
    artifacts = tmp_path / "artifacts"
    for value in (archive, predecessor):
        (artifacts / value).mkdir(parents=True)
    link = artifacts / "current"
    link.symlink_to(artifacts / (archive if fault == "selected" else predecessor))
    for key, value in {
        "STATE": state,
        "ROOT": root,
        "SELECTION": link,
        "CANDIDATE": artifacts,
    }.items():
        monkeypatch.setattr(native, key, value)
    trusted = native.NativeAuthority(
        ctx,
        admission["target"]["predecessorSha256"],
        candidate,
        admission["platform"],
        evidence.read(admission["prerequisites"]["livePreflight"], "receipt"),
    )
    monkeypatch.setattr(native, "read_authority", lambda *_: trusted)
    monkeypatch.setattr(predecessor_records, "operate", lambda *_, **__: b"stored")
    monkeypatch.setattr(predecessor_records, "decode", lambda _: [])
    monkeypatch.setattr(
        native,
        "accepted_predecessor",
        lambda _: (trusted.predecessor, {"candidate": {"artifact_sha256": predecessor}}),
    )
    monkeypatch.setattr(locks, "_lock", lambda *_: nullcontext())
    monkeypatch.setattr(predecessor_state, "_empty", lambda _: None)
    monkeypatch.setattr(native, "_require_only_readback_process", lambda: None)
    monkeypatch.setattr(native, "require_dark_health", lambda: None)
    verified: list[str] = []

    def verify(value: str) -> None:
        verified.append(value)
        if fault == "unstaged" and value == archive:
            raise ValidationError("artifact not staged")

    monkeypatch.setattr(baseline, "_verify_artifact", verify)
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as storage:
        journal = SuccessorJournal(storage, owner)
        before = journal.snapshot()
        with pytest.raises(ValidationError, match="requires-native-preparation"):
            native.phase(journal, "start", "fixture-token")
        if fault in {"unstaged", "selected"}:
            with pytest.raises(
                ValidationError, match=r"artifact not staged|preparation-not-original"
            ):
                native.canary_preparation(journal, "fixture-token")
            assert journal.snapshot() == before
            return
        if fault == "interrupted":
            advance = journal.advance

            def interrupt(transition: str, *values: object) -> object:
                if transition == "committed":
                    raise InterruptedError
                return advance(transition, *values)  # type: ignore[arg-type]

            with monkeypatch.context() as failed:
                failed.setattr(journal, "advance", interrupt)
                with pytest.raises(InterruptedError):
                    native.canary_preparation(journal, "fixture-token")
            assert journal.snapshot().history.pending
        result = native.canary_preparation(journal, "fixture-token")
        assert result["transition"] == "committed"
        assert journal.snapshot().history.phase == "dark-staging"
        assert verified == [predecessor, archive] * (2 if fault == "interrupted" else 1)
        assert link.resolve(strict=True) == artifacts / predecessor
