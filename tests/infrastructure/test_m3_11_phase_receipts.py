"""Partial, failed, reordered or replaced phase observations never complete a run."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_phase_receipts as phases
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_private_inputs import read_private, write_private


@pytest.fixture
def recorder(tmp_path: Path) -> phases.Recorder:
    context: dict[str, object] = {
        "captured_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    }
    write_private(tmp_path / "combined-context.json", context)
    return phases.Recorder(tmp_path, context)


def test_records_actual_interval_and_original_private_observations(
    recorder: phases.Recorder,
) -> None:
    for name in evidence.PHASE_CHECKS:
        with recorder.phase(name) as observations:
            assert (recorder.destination / f"{name}.started.json").is_file()
            assert not (recorder.destination / f"{name}.json").exists()
            with pytest.raises(ValueError, match="incomplete"):
                recorder.receipts()
            observations["actual_private_assertion_detail"] = {"opaque_hash": "a" * 64}
    previous = None
    for name, receipt in recorder.receipts().items():
        raw = (recorder.destination / f"{name}.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == receipt["evidence_sha256"]
        assert receipt["checks"] == dict.fromkeys(evidence.PHASE_CHECKS[name], "passed")
        started = datetime.fromisoformat(str(receipt["started_at"]))
        completed = datetime.fromisoformat(str(receipt["completed_at"]))
        assert started <= completed
        assert previous is None or previous <= started
        previous = completed
    evidence._phases(recorder.receipts(), maximum_age=timedelta(hours=24))
    assert not (recorder.directory / "combined.json").exists()


@pytest.mark.parametrize("fault", ["assertion", "context", "empty", "clock", "existing-output"])
def test_failed_phase_keeps_original_start_and_cannot_retry(
    recorder: phases.Recorder, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    first = next(iter(evidence.PHASE_CHECKS))
    if fault == "clock":
        now = datetime.now(UTC)
        monkeypatch.setattr(phases, "_now", Mock(side_effect=[now, now - timedelta(seconds=1)]))
    elif fault == "existing-output":
        write_private(recorder.destination / f"{first}.json", {"original": "interrupted write"})
    with (
        pytest.raises((AssertionError, ValueError, FileExistsError)),
        recorder.phase(first) as observations,
    ):
        if fault == "assertion":
            raise AssertionError("installed assertion failed")
        if fault == "context":
            (recorder.directory / "combined-context.json").write_bytes(
                evidence.canonical_bytes({"changed": True})
            )
        if fault != "empty":
            observations["original_snapshot_sha256"] = "a" * 64
    started = (recorder.destination / f"{first}.started.json").read_bytes()
    for name in tuple(evidence.PHASE_CHECKS)[:2]:
        with pytest.raises(ValueError, match="uninterrupted"), recorder.phase(name):
            pytest.fail("a failed phase was rerun")
    assert (recorder.destination / f"{first}.started.json").read_bytes() == started
    with pytest.raises(ValueError):
        recorder.receipts()
    if fault != "existing-output":
        assert not (recorder.destination / f"{first}.json").exists()


def test_cannot_repeat_or_skip_a_phase_or_recapture_the_attempt(recorder: phases.Recorder) -> None:
    first, second, third, *_ = evidence.PHASE_CHECKS
    with pytest.raises(ValueError, match="ordered"), recorder.phase(second):
        pytest.fail("first phase was skipped")
    with recorder.phase(first) as observations:
        observations["observed"] = "original"
    for name in (first, third):
        with pytest.raises(ValueError, match="ordered"), recorder.phase(name):
            pytest.fail("phase order changed")
    original = read_private(recorder.directory / "combined-context.json")
    with pytest.raises(FileExistsError):
        phases.Recorder(recorder.directory, original)


def test_completion_rereads_original_phase_bytes(recorder: phases.Recorder) -> None:
    for name in evidence.PHASE_CHECKS:
        with recorder.phase(name) as observations:
            observations["observed"] = "original"
    first = next(iter(evidence.PHASE_CHECKS))
    path = recorder.destination / f"{first}.json"
    changed = read_private(path)
    changed["observations"] = {"replacement": True}
    path.write_bytes(evidence.canonical_bytes(changed))
    with pytest.raises(ValueError, match="original observations changed"):
        recorder.receipts()
