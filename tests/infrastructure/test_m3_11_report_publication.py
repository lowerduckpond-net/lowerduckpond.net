"""Publish complete report bytes once, including interruption between outputs."""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent import durable

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_finalization as finalization
from scripts import m3_11_functional_completion as functional
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_private_inputs import (
    publish_bytes,
    read_private,
    read_private_bytes,
    write_private,
)

from .test_m3_11_finalization_report import prepared
from .test_m3_11_qualification_report import TARGET, Run
from .test_m3_11_qualification_report import run as run  # noqa: PLC0414 - shared pytest fixture


def publish(run: Run, *, milestone: str = "3.11") -> None:
    reports.publish_report(
        run.directory, repository=run.repository, storage_target=TARGET, milestone=milestone
    )


@pytest.mark.parametrize("fault", ["old-storage", "late-destroy", "future-destroy"])
def test_legacy_checksum_repair_keeps_original_packaging_window(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    publish(run, milestone="3.10")
    report = read_private(run.directory / "qualification.json")
    if fault == "old-storage":
        path = run.directory / "storage.json"
        value = json.loads(path.read_bytes())
        value["generated_at"] = (
            (datetime.now(UTC) - timedelta(days=3)).isoformat().replace("+00:00", "Z")
        )
        path.write_bytes(evidence.canonical_bytes(value))
        report["oldest_evidence_at"] = value["generated_at"]
        report["storage_report_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    else:
        path = run.directory / "destroy.passed"
        future = datetime.now(UTC) + (
            timedelta(days=3) if fault == "late-destroy" else timedelta(hours=2)
        )
        os.utime(path, (future.timestamp(), future.timestamp()))
        if fault == "late-destroy":
            from .test_m3_11_recovery_policy import clock  # noqa: PLC0415

            monkeypatch.setattr(reports, "datetime", clock(datetime.now(UTC) + timedelta(days=4)))
    with pytest.raises(ValueError, match="stale or future"):
        reports.create_report(
            run.directory, repository=run.repository, storage_target=TARGET, milestone="3.10"
        )
    raw = evidence.canonical_bytes(report)
    (run.directory / "qualification.json").write_bytes(raw)
    (run.directory / "qualification.sha256").unlink()
    with pytest.raises(ValueError, match="historical packaging window"):
        publish(run, milestone="3.10")
    assert (run.directory / "qualification.json").read_bytes() == raw
    assert not (run.directory / "qualification.sha256").exists()


def test_legacy_checksum_repair_preserves_five_minute_clock_tolerance(run: Run) -> None:
    storage_path = run.directory / "storage.json"
    storage = json.loads(storage_path.read_bytes())
    storage["generated_at"] = (
        (datetime.now(UTC) - timedelta(hours=23, minutes=59)).isoformat().replace("+00:00", "Z")
    )
    storage_path.write_bytes(evidence.canonical_bytes(storage))
    future = datetime.now(UTC) + timedelta(minutes=2)
    (run.directory / "final-proof.started-at").write_text(future.isoformat().replace("+00:00", "Z"))
    destroy = future + timedelta(seconds=1)
    os.utime(run.directory / "destroy.passed", (destroy.timestamp(), destroy.timestamp()))
    publish(run, milestone="3.10")
    original = (run.directory / "qualification.json").read_bytes()
    (run.directory / "qualification.sha256").unlink()
    publish(run, milestone="3.10")
    assert (run.directory / "qualification.json").read_bytes() == original
    assert (run.directory / "qualification.sha256").exists()


@pytest.mark.parametrize("name", ["combined-context.json", "combined-names.json"])
def test_checksum_repair_preserves_retained_context_age_checks(run: Run, name: str) -> None:
    publish(run)
    (run.directory / "qualification.sha256").unlink()
    before = (datetime.now(UTC) - timedelta(days=3)).timestamp()
    os.utime(run.directory / name, (before, before))
    with pytest.raises(ValueError, match="stale"):
        publish(run)
    assert not (run.directory / "qualification.sha256").exists()


def test_missing_checksum_recovers_original_report_and_packaging_time(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_write = reports.write_once

    def interrupt(path: Path, raw: bytes) -> None:
        if path.name == "qualification.sha256":
            raise OSError("interrupted publication")
        original_write(path, raw)

    monkeypatch.setattr(reports, "write_once", interrupt)
    with pytest.raises(OSError):
        publish(run)
    path = run.directory / "qualification.json"
    original, mtime = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr(reports, "write_once", original_write)
    publish(run)
    assert path.read_bytes() == original and path.stat().st_mtime_ns == mtime
    assert (
        read_private_bytes(run.directory / "qualification.sha256")
        == (hashlib.sha256(original).hexdigest() + "  qualification.json\n").encode()
    )


@pytest.mark.parametrize("after", [False, True])
def test_interrupted_publication_has_no_partial_final_file_or_second_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after: bool
) -> None:
    path = tmp_path / "qualification.json"
    rename = durable._rename_noreplace

    def interrupt(fd: int, source: str, destination: str, **kwargs: object) -> None:
        if after:
            rename(fd, source, destination)
        raise OSError("interrupted rename")

    with monkeypatch.context() as patch:
        patch.setattr(durable, "_rename_noreplace", interrupt)
        with pytest.raises(OSError):
            publish_bytes(path, b"complete original bytes\n")
    assert path.exists() is after
    reports.write_once(path, b"complete original bytes\n")
    assert path.stat().st_nlink == 1
    assert read_private_bytes(path) == b"complete original bytes\n"


def test_conflicting_checksum_or_report_never_overwrites_evidence(run: Run) -> None:
    publish(run)
    path = run.directory / "qualification.sha256"
    path.write_bytes(b"conflicting original bytes\n")
    original = (run.directory / "qualification.json").read_bytes()
    with pytest.raises(ValueError, match="differs"):
        publish(run)
    assert path.read_bytes() == b"conflicting original bytes\n"
    assert (run.directory / "qualification.json").read_bytes() == original


def test_recovery_summary_preserves_original_failure_and_is_validated(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment, _ = prepared(run, monkeypatch)
    monkeypatch.setattr(finalization, "_command", Mock())
    attempt = run.directory / "recovery"
    attempt.mkdir(mode=0o700)
    finalization.finish(run.directory, attempt, environment)
    raw = (run.directory / "qualification.json").read_bytes()
    assert b'"original_outcome":"failed"' in raw
    reports.verify_report(
        run.directory / "qualification.json",
        source=run.source,
        artifact="b" * 64,
        repository=run.repository,
        storage_target=TARGET,
        milestone="3.11",
    )


def test_existing_report_finalizer_repairs_checksum_without_credentials_or_new_summary(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    publish(run)
    original = (run.directory / "qualification.json").read_bytes()
    (run.directory / "qualification.sha256").unlink()
    write_private(
        run.directory / "fixture.json", {"environment": {"DOCKER_HOST": "unix:///synthetic.sock"}}
    )
    monkeypatch.setattr(finalization, "ROOT", run.repository)
    monkeypatch.setattr(finalization, "environment_for", lambda _, env: env)
    monkeypatch.setattr(functional, "load", lambda *args: None)
    # The real controller/run locks are covered by the managed access tests.
    monkeypatch.setattr(finalization, "run_lease", lambda _: nullcontext())
    monkeypatch.setattr(finalization, "RunState", lambda _: Mock(lock=nullcontext))
    (run.directory / "combined-context.json").chmod(0o600)
    from .test_m3_11_recovery_policy import clock  # noqa: PLC0415

    monkeypatch.setattr(reports, "datetime", clock(datetime.now(UTC) + timedelta(days=30)))
    monkeypatch.setattr(reports, "create_report", Mock(side_effect=AssertionError("no new report")))
    provider = Mock(side_effect=AssertionError("no provider or credentials allowed"))
    monkeypatch.setattr(finalization, "access", provider)
    finalization.run(run.directory, run.directory)
    assert (run.directory / "qualification.sha256").exists()
    assert (run.directory / "qualification.json").read_bytes() == original
    assert not (run.directory / "finalization-recovery.json").exists()
    provider.assert_not_called()
