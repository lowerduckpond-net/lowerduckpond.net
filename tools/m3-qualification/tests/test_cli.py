from __future__ import annotations

from pathlib import Path

from lowerduckpond_m3_qualification.cli import main
from lowerduckpond_m3_qualification.report import QualificationReport

RUN_ID = "0198d17f-6f4a-7000-8000-000000000001"
SOURCE_REVISION = "a" * 40


def test_libraries_command_writes_passing_fragment(tmp_path: Path) -> None:
    output = tmp_path / "libraries.json"

    status = main(
        (
            "libraries",
            "--run-id",
            RUN_ID,
            "--source-revision",
            SOURCE_REVISION,
            "--output",
            str(output),
        )
    )

    assert status == 0
    report = QualificationReport.from_json(output.read_text(encoding="utf-8"))
    assert report.environment == "hermetic-ci"
    assert report.run_id == RUN_ID
    assert report.source_revision == SOURCE_REVISION
    assert report.passed
