"""Publish complete report bytes once, including interruption between outputs."""

from __future__ import annotations

import hashlib
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent import durable

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_finalization as finalization
from scripts import m3_11_functional_completion as functional
from scripts.m3_11_private_inputs import publish_bytes, read_private_bytes, write_private

from .test_m3_11_qualification_report import TARGET, Run, child
from .test_m3_11_qualification_report import run as run  # noqa: PLC0414 - shared pytest fixture


def publish(run: Run) -> None:
    reports.publish_report(
        run.directory, repository=run.repository, storage_target=TARGET, milestone="3.11"
    )


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


def test_recovery_summary_preserves_original_failure_and_is_validated(run: Run) -> None:
    directory = run.directory.parent / "attempt/qualification/synthetic"
    directory.parent.mkdir(parents=True)
    run.directory.rename(directory)
    run.directory = directory
    proof = run.create()["combined"]
    assert isinstance(proof, dict)
    stamp = child(proof, "phases", "owned-teardown")["started_at"]
    checkpoint = {"completed_at": stamp}
    original = {"outcome": "failed", "exit_status": 124}
    write_private(run.directory / "functional-completion.json", checkpoint)
    write_private(run.directory.parent.parent / "journey-result.json", original)
    write_private(
        run.directory / "finalization-recovery.json",
        {
            "functional_completed_at": stamp,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "original_outcome": "failed",
            "original_result_sha256": functional.digest(original),
            "checkpoint_sha256": functional.digest(checkpoint),
        },
    )
    publish(run)
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
    provider = Mock(side_effect=AssertionError("no provider or credentials allowed"))
    monkeypatch.setattr(finalization, "access", provider)
    finalization.run(run.directory, run.directory)
    assert (run.directory / "qualification.sha256").exists()
    assert (run.directory / "qualification.json").read_bytes() == original
    assert not (run.directory / "finalization-recovery.json").exists()
    provider.assert_not_called()
