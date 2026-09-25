from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lowerduckpond_m3_archive.report import ArchiveQualificationReport
from lowerduckpond_m3_archive.storage import AcceptanceEvidence

from scripts.m3_10_qualification_report import (
    EMPTY_ACCOUNTING,
    PHASES,
    create_report,
    verify_report,
)


@pytest.fixture
def completed_run(tmp_path: Path) -> Path:
    source = "a" * 40
    (tmp_path / "source-revision").write_text(source + "\n")
    evidence = AcceptanceEvidence(True, True, True, True, True, True, True)
    report = ArchiveQualificationReport.create(evidence, source_revision=source)
    report.write(tmp_path / "storage.json")
    for phase in PHASES[:-1]:
        (tmp_path / f"{phase}.passed").write_text("passed\n")
    (tmp_path / "installed.json").write_text(
        json.dumps({"artifact_sha256": "b" * 64, **EMPTY_ACCOUNTING})
    )
    (tmp_path / "final-proof.started-at").write_text(
        datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    (tmp_path / "destroy.passed").write_text("passed\n")
    return tmp_path


def test_sanitized_report_binds_completed_storage_and_installed_artifact(
    completed_run: Path,
) -> None:
    report = create_report(completed_run)
    assert report["source_revision"] == "a" * 40
    assert report["artifact_sha256"] == "b" * 64
    assert report["accounting"] == EMPTY_ACCOUNTING
    assert "bucket" not in json.dumps(report)
    assert "credential" not in json.dumps(report)


def test_packaging_uses_the_recorded_final_proof_time(completed_run: Path) -> None:
    report = create_report(completed_run)
    assert report["completed_at"] == (completed_run / "final-proof.started-at").read_text()
    assert str(report["oldest_evidence_at"]) <= str(report["completed_at"])


@pytest.mark.parametrize(
    "evidence",
    [
        "storage.json",
        "installed.json",
        "final-proof.started-at",
        *(f"{phase}.passed" for phase in PHASES),
    ],
)
@pytest.mark.parametrize("offset", [timedelta(days=-2), timedelta(hours=1)])
def test_old_or_future_input_proofs_cannot_be_repackaged(
    completed_run: Path, evidence: str, offset: timedelta
) -> None:
    timestamp = datetime.now(UTC) + offset
    path = completed_run / evidence
    if evidence == "storage.json":
        document = json.loads(path.read_text())
        document["generated_at"] = timestamp.isoformat().replace("+00:00", "Z")
        path.write_text(json.dumps(document))
    elif evidence == "final-proof.started-at":
        path.write_text(timestamp.isoformat().replace("+00:00", "Z"))
    else:
        os.utime(path, (timestamp.timestamp(), timestamp.timestamp()))
    with pytest.raises(ValueError, match="stale or future"):
        create_report(completed_run)


def test_fresh_envelope_cannot_hide_expired_earlier_evidence(completed_run: Path) -> None:
    report = create_report(completed_run)
    report["oldest_evidence_at"] = (
        (datetime.now(UTC) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
    )
    path = completed_run / "qualification.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="stale or future"):
        verify_report(path, source="a" * 40, artifact="b" * 64)


@pytest.mark.parametrize("phase", PHASES)
def test_no_passing_report_before_every_phase_and_destroy(completed_run: Path, phase: str) -> None:
    (completed_run / f"{phase}.passed").unlink()
    with pytest.raises(OSError):
        create_report(completed_run)


@pytest.mark.parametrize("field", list(EMPTY_ACCOUNTING))
def test_unresolved_accounting_cannot_be_reported_as_complete(
    completed_run: Path, field: str
) -> None:
    path = completed_run / "installed.json"
    record = json.loads(path.read_text())
    record[field] = True if field == "quarantine" else 1
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="unresolved"):
        create_report(completed_run)


def test_report_rejects_foreign_source_and_unknown_potential_secret_fields(
    completed_run: Path,
) -> None:
    source = completed_run / "source-revision"
    source.write_text("c" * 40)
    with pytest.raises(ValueError, match="another source"):
        create_report(completed_run)
    source.write_text("a" * 40)
    path = completed_run / "installed.json"
    record = json.loads(path.read_text())
    record["access_key"] = "secret-canary"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="unknown fields"):
        create_report(completed_run)


def test_report_rejects_boolean_instead_of_zero(completed_run: Path) -> None:
    path = completed_run / "installed.json"
    record = json.loads(path.read_text())
    record["remote_versions_and_markers"] = False
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="unresolved"):
        create_report(completed_run)


def test_exact_release_report_is_accepted(completed_run: Path) -> None:
    path = completed_run / "qualification.json"
    raw = (json.dumps(create_report(completed_run), indent=3) + "\n\n").encode()
    path.write_bytes(raw)
    assert verify_report(path, source="a" * 40, artifact="b" * 64) == raw


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_revision", "c" * 40),
        ("artifact_sha256", "c" * 64),
        ("environment", "minio"),
        ("phases", {}),
        ("storage_run_id", "00000000-0000-0000-0000-000000000000"),
        ("storage_report_sha256", "invalid"),
    ],
)
def test_release_gate_refuses_mismatched_or_incomplete_evidence(
    completed_run: Path, field: str, value: object
) -> None:
    report = create_report(completed_run)
    report[field] = value
    path = completed_run / "qualification.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        verify_report(path, source="a" * 40, artifact="b" * 64)


@pytest.mark.parametrize("offset", [timedelta(days=-2), timedelta(hours=1)])
def test_release_gate_requires_fresh_evidence(completed_run: Path, offset: timedelta) -> None:
    report = create_report(completed_run)
    report["completed_at"] = (datetime.now(UTC) + offset).isoformat().replace("+00:00", "Z")
    path = completed_run / "qualification.json"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="stale or future"):
        verify_report(path, source="a" * 40, artifact="b" * 64)
