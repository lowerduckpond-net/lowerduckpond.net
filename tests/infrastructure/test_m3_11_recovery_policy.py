"""Multi-day history stays immutable while final cleanup evidence must be fresh."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_finalization as recovery
from scripts import m3_11_functional_completion as functional
from scripts import m3_11_production_controller as rollout
from scripts import m3_11_production_journal as journal
from scripts import m3_11_qualification_evidence as evidence
from scripts import production_qualification_inputs as inputs
from scripts import qualification_deadline
from scripts.m3_11_private_inputs import publish_bytes, read_private
from scripts.m3_11_unattended.model import instant
from scripts.m3_11_unattended.state import RunState
from scripts.qualification_storage_lease import FD_ENV

from . import test_m3_11_qualification_report as fixtures
from . import test_m3_11_unattended_inputs as credentials
from .test_m3_11_finalization_report import prepared
from .test_m3_11_qualification_report import ARTIFACT, TARGET, Run, child


def clock(value: datetime) -> SimpleNamespace:
    return SimpleNamespace(
        now=lambda _zone: value,
        fromisoformat=datetime.fromisoformat,
        fromtimestamp=datetime.fromtimestamp,
    )


def historical(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, days: int
) -> tuple[Run, dict[str, str], Mock]:
    before = datetime.now(UTC) - timedelta(days=days)
    with monkeypatch.context() as patch:
        for module in (fixtures, credentials, reports, evidence):
            patch.setattr(module, "datetime", clock(before))
        run: Run = getattr(fixtures.run, "__wrapped__")(tmp_path)  # noqa: B009 - pytest wrapper typing
        environment, removal = prepared(run, monkeypatch)
    return run, environment, removal


def invocation(run: Run, name: str) -> Path:
    directory = run.directory / name
    directory.mkdir(mode=0o700)
    return directory


def verify(run: Run) -> bytes:
    return reports.verify_report(
        run.directory / "qualification.json",
        source=run.source,
        artifact=ARTIFACT,
        repository=run.repository,
        storage_target=TARGET,
        milestone="3.11",
    )


@pytest.mark.parametrize("days", [3, 12])
def test_multiday_recovery_preserves_history_and_consumes_from_fresh_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    days: int,
) -> None:
    run, environment, removal = historical(tmp_path, monkeypatch, days)
    original = functional.files(run.directory)
    checkpoint = (run.directory / "functional-completion.json").read_bytes()
    monkeypatch.setattr(recovery, "_command", Mock())
    recovery.finish(run.directory, invocation(run, "recovered"), environment)
    raw = verify(run)
    report = read_private(run.directory / "qualification.json")
    assert functional.files(run.directory) == original
    assert (run.directory / "functional-completion.json").read_bytes() == checkpoint
    assert evidence.parse_timestamp(report["oldest_evidence_at"]) < datetime.now(UTC) - timedelta(
        days=days
    )
    removal.run.assert_called_once()
    observation = child(report, "finalization_recovery", "final_observation")
    assert reports.freshness_start(report) == observation["started_at"]
    observed = evidence.parse_timestamp(observation["started_at"])
    with monkeypatch.context() as patch:
        patch.setattr(reports, "datetime", clock(observed + timedelta(days=6)))
        assert verify(run) == raw
        patch.setattr(reports, "datetime", clock(observed + timedelta(days=7, seconds=1)))
        with pytest.raises(ValueError, match="stale"):
            verify(run)


def test_new_storage_timestamp_cannot_refresh_stale_cleanup_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, environment, _ = historical(tmp_path, monkeypatch, 3)
    monkeypatch.setattr(recovery, "_command", Mock())
    recovery.finish(run.directory, invocation(run, "recovered"), environment)
    report = read_private(run.directory / "qualification.json")
    observation = child(report, "finalization_recovery", "final_observation")
    old = datetime.now(UTC) - timedelta(days=2)
    observation["started_at"] = old.isoformat().replace("+00:00", "Z")
    # All later timestamps and hashes still describe the fresh successful run.
    with pytest.raises(ValueError, match="stale"):
        run.verify(report)


def test_interrupted_package_keeps_old_summary_and_uses_one_new_complete_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, environment, removal = historical(tmp_path, monkeypatch, 3)
    commands = Mock()
    monkeypatch.setattr(recovery, "_command", commands)
    first = invocation(run, "first")
    with monkeypatch.context() as patch:
        patch.setattr(
            reports, "publish_report", Mock(side_effect=OSError("publication interrupted"))
        )
        with pytest.raises(OSError):
            recovery.finish(run.directory, first, environment)
    summary = (run.directory / "finalization-recovery.json").read_bytes()
    prior = (first / "final-observation.json").read_bytes()
    second = invocation(run, "second")
    # An additional quota gap must not refresh the preserved first summary.
    future = datetime.now(UTC) + timedelta(days=3)
    for module in (recovery, reports, evidence):
        monkeypatch.setattr(module, "datetime", clock(future))
    recovery.finish(run.directory, second, environment)
    report = read_private(run.directory / "qualification.json")
    assert child(report, "finalization_recovery", "final_observation") == read_private(
        second / "final-observation.json"
    )
    assert (first / "final-observation.json").read_bytes() == prior
    assert (run.directory / "finalization-recovery.json").read_bytes() == summary
    assert instant(read_private(second / "final-observation.json")["started_at"]) >= future
    assert removal.run.call_count == 2  # noqa: PLR2004
    assert sum("molecule" in call.args[0] for call in commands.call_args_list) == 1
    verify(run)


def test_delayed_checksum_repair_keeps_original_bytes_without_recreating_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, environment, _ = historical(tmp_path, monkeypatch, 3)
    monkeypatch.setattr(recovery, "_command", Mock())
    recovery.finish(run.directory, invocation(run, "recovered"), environment)
    report = run.directory / "qualification.json"
    original = report.read_bytes(), report.stat().st_mtime_ns
    (run.directory / "qualification.sha256").unlink()
    monkeypatch.setattr(reports, "datetime", clock(datetime.now(UTC) + timedelta(days=30)))
    monkeypatch.setattr(
        reports, "create_report", Mock(side_effect=AssertionError("must not recreate"))
    )
    # The finalizer's complete-report path must also work without live authority.
    monkeypatch.setattr(recovery, "RunState", lambda _: Mock(lock=nullcontext))
    monkeypatch.setattr(recovery, "run_lease", lambda _: nullcontext())
    monkeypatch.setattr(recovery, "access", Mock(side_effect=AssertionError("no credentials")))
    recovery.run(run.directory, invocation(run, "checksum-repair"))
    assert (report.read_bytes(), report.stat().st_mtime_ns) == original
    assert (run.directory / "qualification.sha256").exists()
    with pytest.raises(ValueError, match="stale"):
        verify(run)


@pytest.mark.parametrize("fault", ["inputs", "revocation"])
def test_delayed_checksum_repair_still_requires_current_candidate_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    run, environment, _ = historical(tmp_path, monkeypatch, 3)
    monkeypatch.setattr(recovery, "_command", Mock())
    recovery.finish(run.directory, invocation(run, "recovered"), environment)
    (run.directory / "qualification.sha256").unlink()
    monkeypatch.setattr(reports, "datetime", clock(datetime.now(UTC) + timedelta(days=30)))
    if fault == "inputs":
        (run.repository / "runtime.py").write_text("changed = True\n")
    else:
        # Prove the historical age clock never bypasses the current revocation gate.
        monkeypatch.setattr(reports, "assert_not_revoked", Mock(side_effect=ValueError("revoked")))
    with pytest.raises(ValueError):
        reports.publish_report(
            run.directory, repository=run.repository, storage_target=TARGET, milestone="3.11"
        )
    assert not (run.directory / "qualification.sha256").exists()


@pytest.mark.parametrize("fault", ["outcome", "result", "checkpoint", "summary"])
def test_checksum_repair_rejects_changed_original_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    run, environment, _ = historical(tmp_path, monkeypatch, 3)
    monkeypatch.setattr(recovery, "_command", Mock())
    recovery.finish(run.directory, invocation(run, "recovered"), environment)
    original = (run.directory / "qualification.json").read_bytes()
    (run.directory / "qualification.sha256").unlink()
    path = run.directory.parent.parent / "journey-result.json"
    if fault in {"checkpoint", "summary"}:
        path = run.directory / (
            "functional-completion.json" if fault == "checkpoint" else "finalization-recovery.json"
        )
    value = read_private(path)
    if fault == "outcome":
        value["outcome"] = "interrupted"
    elif fault == "result":
        value["exit_status"] = 1
    else:
        value["completed_at"] = "2000-01-01T00:00:00Z"
    path.write_bytes(evidence.canonical_bytes(value))
    with pytest.raises(ValueError, match="original evidence binding"):
        reports.publish_report(
            run.directory, repository=run.repository, storage_target=TARGET, milestone="3.11"
        )
    assert (run.directory / "qualification.json").read_bytes() == original
    assert not (run.directory / "qualification.sha256").exists()


@pytest.mark.parametrize("reason", ["expired", "cancelled"])
def test_access_loss_after_report_construction_cannot_publish_or_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    run, environment, _ = historical(tmp_path, monkeypatch, 12)
    monkeypatch.setattr(recovery, "_command", Mock())
    deadline = instant(
        child(read_private(run.directory / "managed-credentials.json"), "receipts", "fixture")[
            "deadline"
        ]
    )

    def stage(path: Path, raw: bytes, *, before_publish: Callable[[], None] | None = None) -> None:
        if path.name != "qualification.json":
            publish_bytes(path, raw, before_publish=before_publish)
            return
        if reason == "expired":
            monkeypatch.setattr(reports, "datetime", clock(deadline))
        else:
            monkeypatch.setattr(recovery, "require_live", Mock(side_effect=ValueError("cancelled")))
        publish_bytes(path, raw, before_publish=before_publish)

    monkeypatch.setattr(reports, "publish_bytes", stage)
    with pytest.raises(ValueError, match=r"expiry|cancelled"):
        recovery.finish(run.directory, invocation(run, "recovered"), environment)
    assert not (run.directory / "qualification.json").exists()
    assert not (run.directory / "qualification.sha256").exists()
    # No existing-report repair can promote the unpublished staged bytes.
    with pytest.raises(ValueError):
        reports.publish_report(
            run.directory, repository=run.repository, storage_target=TARGET, milestone="3.11"
        )


def test_ordinary_report_still_rejects_multiday_packaging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    past = datetime.now(UTC) - timedelta(days=3)
    with monkeypatch.context() as patch:
        for module in (fixtures, reports, evidence):
            patch.setattr(module, "datetime", clock(past))
        run: Run = getattr(fixtures.run, "__wrapped__")(tmp_path)  # noqa: B009 - pytest wrapper typing
    with pytest.raises(ValueError, match="stale"):
        run.create()


@pytest.mark.parametrize("reason", ["expired", "cancelled"])
def test_access_loss_during_subprocess_stops_before_more_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    process = Mock()
    process.wait.side_effect = subprocess.TimeoutExpired("synthetic", 1)
    monkeypatch.setattr(subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(
        recovery, "require_live", Mock(side_effect=[None, None, ValueError(reason)])
    )
    with pytest.raises(ValueError, match=reason):
        recovery._command(
            ["synthetic"], {FD_ENV: "9"}, tmp_path / "command.log", cwd=tmp_path, directory=tmp_path
        )
    process.kill.assert_called_once()
    process.wait.assert_called_once()


def test_production_guard_ages_fresh_recovery_instead_of_historical_functional_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, environment, _ = historical(tmp_path, monkeypatch, 12)
    monkeypatch.setattr(recovery, "_command", Mock())
    recovery.finish(run.directory, invocation(run, "recovered"), environment)
    raw = verify(run)
    # Exercise the independent mutation guard after the full report validator.
    candidate = object.__new__(rollout.Candidate)
    candidate.source, candidate.target = run.source, TARGET
    candidate.artifact, candidate.report_path = (
        tmp_path / "artifact",
        run.directory / "qualification.json",
    )
    candidate.artifact_sha256, candidate.raw = ARTIFACT, raw
    candidate.report, candidate.completed = read_private(candidate.report_path), False
    monkeypatch.setattr(rollout, "ROOT", run.repository)
    monkeypatch.setattr(inputs, "storage_target_digest", lambda: TARGET)
    monkeypatch.setattr(
        rollout,
        "_digest",
        lambda path: ARTIFACT if path == candidate.artifact else journal.digest(raw),
    )
    candidate.guard()
    observed = instant(reports.freshness_start(candidate.report))
    monkeypatch.setattr(rollout, "datetime", clock(observed + timedelta(days=7, seconds=1)))
    with pytest.raises(ValueError, match="stale"):
        candidate.guard()


def test_selected_budget_is_recorded_and_timeout_does_not_cancel_retained_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "original"
    directory.mkdir(mode=0o700)
    execute = Mock(return_value=qualification_deadline.Exit(124, "deadline-exceeded", 7200, True))
    monkeypatch.setattr(qualification_deadline, "execute", execute)
    cancel = Mock(side_effect=AssertionError("timeout must not cancel the attempt"))
    monkeypatch.setattr(RunState, "cancel", cancel)
    monkeypatch.setattr(sys, "argv", ["finalization", str(directory), "--seconds", "7200"])
    assert recovery.main() == 124  # noqa: PLR2004
    (attempt,) = directory.glob("finalization-*")
    assert read_private(attempt / "started.json")["seconds"] == 7200  # noqa: PLR2004
    assert read_private(attempt / "result.json")["reason"] == "deadline-exceeded"
    assert execute.call_args.kwargs["seconds"] == 7200  # noqa: PLR2004
    assert execute.call_args.args[0][-3:] == ["7200", "--worker", str(attempt)]
    cancel.assert_not_called()


@pytest.mark.parametrize("seconds", ["0", "-1", str(2**31)])
def test_execution_budget_rejects_unbounded_or_nonpositive_values(seconds: str) -> None:
    import argparse  # noqa: PLC0415

    with pytest.raises(argparse.ArgumentTypeError):
        recovery.execution_seconds(seconds)
