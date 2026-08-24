from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_m3_qualification.report import (
    CheckResult,
    QualificationReport,
    UnsafeReportError,
    combine_reports,
)

FIXED_TIME = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
SANITIZED_REPORT_MODE = 0o644


def test_report_round_trip_is_bounded_and_deterministic() -> None:
    report = QualificationReport.create(
        environment="hermetic-ci",
        checks=(
            CheckResult(
                check_id="m3.0.python.runtime",
                status="passed",
                evidence={"version": "3.14.7"},
            ),
        ),
        now=FIXED_TIME,
    )

    assert report.passed
    assert QualificationReport.from_json(report.to_json()) == report
    assert report.generated_at == "2026-08-24T12:00:00Z"


@pytest.mark.parametrize(
    "evidence",
    [
        {"cookie": "value"},
        {"raw_log": "value"},
        {"header_value": "value"},
        {"value": "contains=a;cookie-shaped=value"},
        {"nested": {"unsafe": True}},
    ],
)
def test_report_rejects_sensitive_or_unbounded_evidence(evidence: object) -> None:
    with pytest.raises(UnsafeReportError):
        CheckResult(
            check_id="m3.0.python.runtime",
            status="passed",
            evidence=evidence,  # type: ignore[arg-type]
        )


def test_failed_check_requires_fixed_error_code() -> None:
    with pytest.raises(UnsafeReportError):
        CheckResult(check_id="m3.0.python.runtime", status="failed", evidence={})


def test_atomic_report_write_sets_public_evidence_mode(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report = QualificationReport.create(
        environment="hermetic-ci",
        checks=(
            CheckResult(
                check_id="m3.0.host.caddy-log-safety",
                status="passed",
                evidence={"structured": True, "values_omitted": True},
            ),
        ),
        now=FIXED_TIME,
    )

    report.write(path)

    assert json.loads(path.read_text(encoding="utf-8"))["report_schema"].endswith("/v1")
    assert path.stat().st_mode & 0o777 == SANITIZED_REPORT_MODE


def test_combine_requires_exact_check_set() -> None:
    fragment = QualificationReport.create(
        environment="hermetic-ci",
        checks=(
            CheckResult(
                check_id="m3.0.python.runtime",
                status="passed",
                evidence={"version": "3.14.7"},
            ),
        ),
        now=FIXED_TIME,
    )

    combined = combine_reports((fragment,), required_check_ids=frozenset({"m3.0.python.runtime"}))
    assert combined.passed

    with pytest.raises(UnsafeReportError):
        combine_reports((fragment,), required_check_ids=frozenset({"m3.0.python.rfc8785"}))
