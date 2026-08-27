from __future__ import annotations

import json
import stat
from dataclasses import asdict
from pathlib import Path

import pytest
from lowerduckpond_m3_archive.report import (
    ArchiveQualificationReport,
    UnsafeArchiveReportError,
)
from lowerduckpond_m3_archive.storage import AcceptanceEvidence

PRIVATE_FILE_MODE = 0o600


def _evidence() -> AcceptanceEvidence:
    return AcceptanceEvidence(
        buckets_versioned=True,
        credential_isolation=True,
        exact_version_read=True,
        delete_marker=True,
        forced_pagination=True,
        empty_archive_baseline=True,
        cleanup_complete=True,
    )


def test_report_round_trip_contains_only_sanitized_proofs(tmp_path: Path) -> None:
    report = ArchiveQualificationReport.create(_evidence(), source_revision="a" * 40)
    output = tmp_path / "m3-archive-qualification.json"

    report.write(output)
    parsed = ArchiveQualificationReport.from_json(output.read_text(encoding="utf-8"))

    assert parsed == report
    assert stat.S_IMODE(output.stat().st_mode) == PRIVATE_FILE_MODE
    raw = output.read_text(encoding="utf-8")
    assert "VersionId" not in raw
    assert "access_key" not in raw
    assert "object_key" not in raw
    assert "credential" in raw  # Fixed check ID only; no credential values are serialized.


def test_report_rejects_unrecognized_fields() -> None:
    report = ArchiveQualificationReport.create(_evidence(), source_revision="b" * 40)
    value = json.loads(report.to_json())
    value["unexpected"] = "unsafe"

    with pytest.raises(UnsafeArchiveReportError, match="shape"):
        ArchiveQualificationReport.from_json(json.dumps(value))


def test_report_requires_every_proof() -> None:
    evidence = _evidence()
    incomplete = AcceptanceEvidence(**{**asdict(evidence), "forced_pagination": False})

    with pytest.raises(UnsafeArchiveReportError, match="every acceptance proof"):
        ArchiveQualificationReport.create(incomplete, source_revision="c" * 40)


def test_report_never_overwrites_existing_evidence(tmp_path: Path) -> None:
    report = ArchiveQualificationReport.create(_evidence(), source_revision="d" * 40)
    output = tmp_path / "m3-archive-qualification.json"
    output.write_text("preserve me\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        report.write(output)

    assert output.read_text(encoding="utf-8") == "preserve me\n"
