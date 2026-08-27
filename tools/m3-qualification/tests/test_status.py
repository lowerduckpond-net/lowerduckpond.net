from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_m3_qualification.cli import _report_status
from lowerduckpond_m3_qualification.libraries import run_library_checks
from lowerduckpond_m3_qualification.report import CheckResult, QualificationReport
from lowerduckpond_m3_qualification.session import QualificationSession

RUN_ID = "0198d17f-6f4a-7000-8000-000000000001"
SOURCE_REVISION = "a" * 40


def _write_session(path: Path) -> None:
    QualificationSession.create(
        identity={
            "droplet_id": "123",
            "droplet_urn": "do:droplet:123",
            "ipv4_address": "8.8.8.8",
        },
        source_revision=SOURCE_REVISION,
        run_id=RUN_ID,
    ).write(path)


def test_status_identifies_first_missing_fragment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    session_path = tmp_path / "session.json"
    report_path = tmp_path / "libraries.json"
    _write_session(session_path)
    QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
        environment="hermetic-ci",
        checks=run_library_checks(),
    ).write(report_path)

    status = _report_status(
        session_path=session_path,
        source_revision=SOURCE_REVISION,
        fragments=(f"libraries={report_path}", f"host={tmp_path / 'host.json'}"),
    )

    assert status == 0
    captured = capsys.readouterr()
    assert "libraries: passed" in captured.out
    assert "host: absent" in captured.out
    assert "next: host" in captured.out


def test_status_rejects_a_report_under_the_wrong_fragment_label(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    session_path = tmp_path / "session.json"
    report_path = tmp_path / "host.json"
    _write_session(session_path)
    QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
        environment="hermetic-ci",
        checks=run_library_checks(),
    ).write(report_path)

    assert (
        _report_status(
            session_path=session_path,
            source_revision=SOURCE_REVISION,
            fragments=(f"host={report_path}",),
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "host: invalid" in captured.out
    assert "next: host" in captured.out


@pytest.mark.parametrize(
    ("label", "environment"),
    (
        ("edge-replacement", "live-cloudflare-edge"),
        ("edge-primary", "live-dual-domain"),
    ),
)
def test_status_rejects_the_wrong_edge_stage_or_environment(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    label: str,
    environment: str,
) -> None:
    session_path = tmp_path / "session.json"
    report_path = tmp_path / "edge.json"
    _write_session(session_path)
    QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
        environment=environment,
        checks=(
            CheckResult(
                check_id="m3.0.edge.aop-primary",
                status="passed",
                evidence={"associations_exact": True, "edge_reachable": True},
            ),
        ),
    ).write(report_path)

    assert (
        _report_status(
            session_path=session_path,
            source_revision=SOURCE_REVISION,
            fragments=(f"{label}={report_path}",),
        )
        == 0
    )
    captured = capsys.readouterr()
    assert f"{label}: invalid" in captured.out
    assert f"next: {label}" in captured.out


def test_status_rejects_a_stale_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    session_path = tmp_path / "session.json"
    report_path = tmp_path / "host.json"
    _write_session(session_path)
    QualificationReport.create(
        run_id="0198d17f-6f4a-7000-8000-000000000002",
        source_revision=SOURCE_REVISION,
        environment="ubuntu-26.04-disposable",
        checks=(
            CheckResult(
                check_id="m3.0.host.caddy-log-safety",
                status="passed",
                evidence={"structured": True, "values_omitted": True},
            ),
        ),
    ).write(report_path)

    assert (
        _report_status(
            session_path=session_path,
            source_revision=SOURCE_REVISION,
            fragments=(f"host={report_path}",),
        )
        == 0
    )
    assert "host: stale" in capsys.readouterr().out


def test_status_rejects_an_empty_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    session_path = tmp_path / "session.json"
    report_path = tmp_path / "host.json"
    _write_session(session_path)
    QualificationReport.create(
        run_id=RUN_ID,
        source_revision=SOURCE_REVISION,
        environment="ubuntu-26.04-disposable",
        checks=(),
    ).write(report_path)

    assert (
        _report_status(
            session_path=session_path,
            source_revision=SOURCE_REVISION,
            fragments=(f"host={report_path}",),
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "host: invalid" in captured.out
    assert "host: passed" not in captured.out
    assert "next: host" in captured.out
