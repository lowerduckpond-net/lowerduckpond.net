from __future__ import annotations

from pathlib import Path

from lowerduckpond_m3_qualification.cli import main
from lowerduckpond_m3_qualification.report import QualificationReport


def test_libraries_command_writes_passing_fragment(tmp_path: Path) -> None:
    output = tmp_path / "libraries.json"

    status = main(("libraries", "--output", str(output)))

    assert status == 0
    report = QualificationReport.from_json(output.read_text(encoding="utf-8"))
    assert report.environment == "hermetic-ci"
    assert report.passed
