"""Only allowlisted diagnostics leave the private retirement transaction."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_failed_retirement as cli
from scripts import m3_11_production_journal as production
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_probe as probe
from scripts.m3_11_retirement_receipt import receipt
from scripts.m3_11_retirement_transaction import Retirement

from .test_m3_11_retirement_transaction import Fixture
from .test_m3_11_retirement_transaction import case as case  # noqa: PLC0414


def test_inspection_exposes_only_counts_and_digests_and_grants_no_qualification(
    case: tuple[Retirement, Fixture],
) -> None:
    transaction, fixture = case
    run = transaction.root.parent
    assert cli.inspect(run)["stage"] == "not-prepared"
    plan = transaction.prepare()
    before = {path.name: path.read_bytes() for path in transaction.root.iterdir()}
    output = cli.inspect(run)
    assert output["deletion_authorized"] is False
    assert output["versions_retired"] == 0
    assert output["archive_versions"] == len(fixture.selected)
    assert "one" not in json.dumps(output) and "test-archives" not in json.dumps(output)
    assert before == {path.name: path.read_bytes() for path in transaction.root.iterdir()}
    result = transaction.retire(str(plan["plan_sha256"]), acknowledge=True)
    assert cli.inspect(run) == result
    assert result["qualification_authority"] == "none"
    with pytest.raises(ValueError):
        evidence.validate(result, binding={}, maximum_age=timedelta(hours=24))
    path = transaction.root / "retired.json"
    with pytest.raises(ValueError):
        reports.verify_report(path, source="a" * 40, artifact="b" * 64, milestone="3.11")
    with pytest.raises(ValueError):
        production.validate([("original.json", path.read_bytes())])


@pytest.mark.parametrize("damage", ["extra", "count", "authority", "future", "private-digest"])
def test_inspection_refuses_foreign_receipt_fields(
    case: tuple[Retirement, Fixture], damage: str
) -> None:
    transaction, _ = case
    result = transaction.retire(str(transaction.prepare()["plan_sha256"]), acknowledge=True)
    key, value = {
        "extra": ("private", "credential-canary"),
        "count": ("versions_retired", True),
        "authority": ("qualification_authority", "passed"),
        "future": ("final_absence_at", "2999-01-01T00:00:00+00:00"),
        "private-digest": ("plan_sha256", "credential-canary"),
    }[damage]
    result[key] = value
    with pytest.raises(ValueError):
        receipt(result)
    # An operator-edited document is not eligible for diagnostic publication.
    path = transaction.root / "retired.json"
    path.write_bytes(evidence.canonical_bytes(result))
    with pytest.raises(ValueError):
        cli.inspect(transaction.root.parent)


def test_cli_does_not_print_provider_errors_or_private_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys, "argv", ["retirement", "prepare", str(tmp_path), "--exclusive-archive-writers"]
    )
    monkeypatch.setattr(cli, "Context", Mock(side_effect=RuntimeError("private-credential-canary")))
    assert cli.main() == 1
    output = capsys.readouterr()
    assert "private-credential-canary" not in output.out + output.err
    assert str(tmp_path) not in output.out + output.err
    assert json.loads(output.out)["outcome"] == "incomplete"


@pytest.mark.parametrize("limit", [0, -1, True, probe.MAX_BYTES + 1])
def test_invalid_observation_limit_never_launches(
    limit: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    launch = Mock()
    monkeypatch.setattr(subprocess, "Popen", launch)
    with pytest.raises(ValueError):
        probe.bounded_command([sys.executable], maximum=limit)
    launch.assert_not_called()


def test_larger_private_probe_does_not_expand_default_diagnostic_limit() -> None:
    raw_size = probe.MAX_COMMAND_BYTES + 1
    command = [sys.executable, "-I", "-c", f"import sys; sys.stdout.write('x' * {raw_size})"]
    assert probe.bounded_command(command) is None
    assert probe.bounded_command(command, maximum=raw_size) == b"x" * raw_size
    assert probe.bounded_command(command, maximum=raw_size - 1) is None
