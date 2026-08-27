from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from lowerduckpond_m3_qualification.checks import EVIDENCE_KEYS_BY_CHECK
from lowerduckpond_m3_qualification.report import (
    FIXED_INTEGER_EVIDENCE,
    FIXED_STRING_EVIDENCE,
    FORBIDDEN_EVIDENCE_WORDS,
    CheckResult,
    QualificationReport,
    UnsafeReportError,
    combine_reports,
    run_check,
)

FIXED_TIME = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
SANITIZED_REPORT_MODE = 0o644
RUN_ID = "0198d17f-6f4a-7000-8000-000000000001"
SOURCE_REVISION = "a" * 40
SOURCE_ROOT = Path(__file__).parents[1] / "src/lowerduckpond_m3_qualification"


def test_report_round_trip_is_bounded_and_deterministic() -> None:
    report = QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
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


def _representative_value(key: str) -> bool | int | str:
    if key == "handoff_ms":
        return 1
    if key == "nameservers":
        return 2
    if key in FIXED_INTEGER_EVIDENCE:
        return next(iter(FIXED_INTEGER_EVIDENCE[key]))
    if key == "version":
        return "1.0.0"
    if key in FIXED_STRING_EVIDENCE:
        return next(iter(FIXED_STRING_EVIDENCE[key]))
    return True


def test_every_registered_success_evidence_shape_is_report_safe() -> None:
    for check_id, keys in EVIDENCE_KEYS_BY_CHECK.items():
        result = CheckResult(
            check_id=check_id,
            status="passed",
            evidence={key: _representative_value(key) for key in keys},
        )
        assert result.status == "passed"


def test_literal_returned_evidence_keys_do_not_use_forbidden_words() -> None:
    violations: list[str] = []
    for path in SOURCE_ROOT.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Dict):
                continue
            for key_node in node.value.keys:
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                    words = set(key_node.value.split("_"))
                    if words.intersection(FORBIDDEN_EVIDENCE_WORDS):
                        violations.append(f"{path.name}:{node.lineno}:{key_node.value}")
    assert violations == []


def test_check_runner_contains_report_validation_failures(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = run_check(
        "m3.0.host.sudo-uuid",
        lambda: {"accepted": 1, "rejected": 7},
    )

    assert result.status == "failed"
    assert result.error_code == "probe_failed"
    assert capsys.readouterr().err == "m3.0.host.sudo-uuid: FAIL (UnsafeReportError)\n"


def test_atomic_report_write_sets_public_evidence_mode(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    report = QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
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

    assert json.loads(path.read_text(encoding="utf-8"))["report_schema"].endswith("/v3")
    assert path.stat().st_mode & 0o777 == SANITIZED_REPORT_MODE


def test_combine_requires_exact_check_set() -> None:
    fragment = QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
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


@pytest.mark.parametrize(
    ("run_id", "source_revision"),
    [
        ("0198d17f-6f4a-7000-8000-000000000002", SOURCE_REVISION),
        (RUN_ID, "b" * 40),
    ],
)
def test_combine_rejects_fragments_from_different_runs(run_id: str, source_revision: str) -> None:
    first = QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
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
    second = QualificationReport.create(
        run_id=run_id,
        source_revision=source_revision,
        environment="hermetic-ci",
        checks=(
            CheckResult(
                check_id="m3.0.python.rfc8785",
                status="passed",
                evidence={"version": "0.1.4"},
            ),
        ),
        now=FIXED_TIME,
    )

    with pytest.raises(UnsafeReportError):
        combine_reports(
            (first, second),
            required_check_ids=frozenset({"m3.0.python.runtime", "m3.0.python.rfc8785"}),
        )
