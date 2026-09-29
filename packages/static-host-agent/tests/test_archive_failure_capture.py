"""First-run evidence survives successful cleanup and unavailable journald."""

from __future__ import annotations

import json
import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import archive_entrypoint as entry
from lowerduckpond_static_host_agent import archive_failure_capture as capture

JOB = "0198d17f-6f4a-7000-8000-000000000001"
CORRELATION = "0198d17f-6f4a-7000-8000-000000000002"
CANARY = "private-request-provider-token-must-not-appear"


@pytest.fixture
def logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "archive-failures"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(capture, "ROOT", root)
    monkeypatch.setenv("LDP_ARCHIVE_FAILURE_CAPTURE", "1")
    monkeypatch.setenv("INVOCATION_ID", "a" * 32)
    capture.reset()
    return root


def fail() -> None:
    try:
        raise OSError(CANARY)
    except OSError as cause:
        raise RuntimeError(CANARY) from cause


def test_failure_chain_has_only_locations_and_durable_job_identity(logs: Path) -> None:
    capture.bind_job({"jobId": JOB, "request": {"correlationId": CORRELATION}}, JOB)
    try:
        fail()
    except RuntimeError as error:
        capture.capture("construction", error)
    path = logs / "construction.json"
    raw = path.read_text()
    (record,) = json.loads(raw)
    assert CANARY not in raw
    assert str(logs.parent) not in raw
    assert path.stat().st_mode & 0o777 == 0o600  # noqa: PLR2004
    assert record["job_id"] == JOB
    assert record["correlation_id"] == CORRELATION
    assert record["invocation"] == "a" * 32
    assert [cause["exception"] for cause in record["chain"]] == ["RuntimeError", "OSError"]
    assert all(cause["locations"][-1]["file"] == Path(__file__).name for cause in record["chain"])


def test_cleanup_and_successful_calls_preserve_construction_evidence(
    logs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture.capture("construction", ValueError(CANARY))
    original = (logs / "construction.json").read_bytes()
    capture.capture("cleanup", OSError(CANARY))
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(entry, "require_restore_admission", lambda: None)
    monkeypatch.setattr(entry, "_accept_connection", lambda: nullcontext(object()))
    monkeypatch.setattr(entry, "StateRepository", lambda *_a, **_k: nullcontext(object()))
    monkeypatch.setattr(entry, "ExportSpool", lambda *_a, **_k: nullcontext(object()))
    monkeypatch.setattr(
        entry, "load_archive_configuration", lambda: SimpleNamespace(remote_store=object)
    )
    monkeypatch.setattr(entry, "serve_archive_export", lambda *_a: None)
    assert entry.archive_export_main([]) == 0
    assert (logs / "construction.json").read_bytes() == original
    assert not (logs / "export.json").exists()


def test_history_is_bounded_and_keeps_latest_invocations(
    logs: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for number in range(capture.MAX_EVENTS + 3):
        monkeypatch.setenv("INVOCATION_ID", f"{number:032x}")
        capture.capture("construction", ValueError(CANARY))
    path = logs / "construction.json"
    records = json.loads(path.read_bytes())
    assert len(records) == capture.MAX_EVENTS
    assert records[0]["invocation"] == f"{3:032x}"
    assert len(list(logs.iterdir())) == 1
    assert path.stat().st_size <= capture.MAX_BYTES


@pytest.mark.parametrize("name", ["construction.json", "construction.next"])
@pytest.mark.parametrize("damage", ["symlink", "hardlink", "writable", "fifo", "oversized"])
def test_unsafe_evidence_is_not_followed_or_modified(
    logs: Path,
    tmp_path: Path,
    name: str,
    damage: str,
) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"retained original")
    path = logs / name
    if damage == "symlink":
        path.symlink_to(target)
    elif damage == "hardlink":
        os.link(target, path)
    elif damage == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(b"x" * (capture.MAX_BYTES + 1) if damage == "oversized" else b"[]")
        path.chmod(0o600 if damage == "oversized" else 0o666)
    capture.capture("construction", RuntimeError(CANARY))
    assert target.read_bytes() == b"retained original"
    if damage in {"oversized", "writable"}:
        assert path.read_bytes() == (
            b"x" * (capture.MAX_BYTES + 1) if damage == "oversized" else b"[]"
        )


def test_disabled_capture_does_not_open_files(logs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LDP_ARCHIVE_FAILURE_CAPTURE")
    capture.capture("construction", RuntimeError(CANARY))
    assert not list(logs.iterdir())


def test_unavailable_capture_preserves_original_exit_and_fixed_error(
    logs: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    capture.bind_job({"jobId": JOB, "request": {"correlationId": CORRELATION}}, JOB)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(entry, "require_restore_admission", fail)
    records: list[dict[str, object]] = []

    def unavailable(operation: str, record: dict[str, object]) -> None:
        records.append(record)
        raise OSError(CANARY)

    monkeypatch.setattr(capture, "_write", unavailable)
    assert entry.archive_construction_main([]) == 1
    assert records[0]["job_id"] == "unknown"  # Previous invocation cannot leak into this one.
    assert capsys.readouterr().err == "archive_construction_service_failed category=unexpected\n"
    assert not list(logs.iterdir())
