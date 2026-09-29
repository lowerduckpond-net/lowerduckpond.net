"""Retained archive diagnostics survive missing journals without changing execution."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent.host_restore_journal import RestorePhase, RestoreStore

from scripts import m3_11_debug_archive_repair as repair
from scripts import m3_11_debug_archive_trace as trace
from scripts import m3_11_debug_capture as capture
from scripts import m3_11_debug_runner as runner
from scripts import qualification_restore as owned
from scripts.m3_11_private_inputs import PRIVATE_FILE_MODE, read_private, write_private

RESTORE = "0198d17f-6f4a-7000-8000-000000000001"
NATIVE = Path("config/ansible/roles/static_host_agent/files")


@pytest.fixture
def installation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes]:
    native = tmp_path / "launchers"
    native.mkdir()
    systemd = tmp_path / "systemd"
    systemd.mkdir()
    monkeypatch.setattr(repair, "LAUNCHERS", native)
    monkeypatch.setattr(repair, "SYSTEMD", systemd)
    monkeypatch.setattr(repair, "LOGS", tmp_path / "logs")
    originals = {}
    for operation in repair.OPERATIONS:
        name = f"archive-{operation}-service"
        originals[name] = (NATIVE / name).read_bytes()
        (native / name).write_bytes(originals[name])
    return originals


def test_install_preserves_native_launchers_and_reuses_exact_diagnostic_copies(
    installation: dict[str, bytes],
) -> None:
    first = repair.install(RESTORE, owner=os.geteuid())
    (repair.LOGS / "construction.log").write_bytes(b"prior private failure\n")
    assert repair.install(RESTORE, owner=os.geteuid()) == first
    assert (repair.LOGS / "construction.log").read_bytes() == b"prior private failure\n"
    target = repair.LAUNCHERS / ("archive-diagnostic-" + RESTORE)
    for operation in repair.OPERATIONS:
        name = f"archive-{operation}-service"
        assert (repair.LAUNCHERS / name).read_bytes() == installation[name]
        assert (target / (name + ".original")).read_bytes() == installation[name]
        patched = (target / name).read_text()
        # Instrumentation comes after the native selection lease and imports.
        assert patched.index("_SELECTION_LOCK_FD = acquire_selection_lock()") < patched.index(
            "m3_11_debug_archive_observer.py"
        )
        dropin = repair.SYSTEMD / (
            f"lowerduckpond-archive-{operation}@request.service.d/90-diagnostic.conf"
        )
        assert dropin.read_text().splitlines() == [
            "[Service]",
            "ExecStart=",
            f"ExecStart={target / name}",
            f"StandardError=append:{repair.LOGS / (operation + '.log')}",
        ]
        assert (repair.LOGS / (operation + ".log")).stat().st_mode & 0o777 == PRIVATE_FILE_MODE


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "writable", "copy", "dropin"])
def test_existing_diagnostic_paths_cannot_redirect_or_replace_native_inputs(
    installation: dict[str, bytes], tmp_path: Path, damage: str
) -> None:
    repair.install(RESTORE, owner=os.geteuid())
    path = repair.LOGS / "construction.log"
    if damage == "symlink":
        path.unlink()
        path.symlink_to(repair.LAUNCHERS / "archive-construction-service")
    elif damage == "hardlink":
        os.link(path, tmp_path / "alias")
    elif damage == "writable":
        path.chmod(0o666)
    elif damage == "copy":
        path = repair.LAUNCHERS / ("archive-diagnostic-" + RESTORE) / "archive-construction-service"
        path.write_bytes(b"changed")
    else:
        path = (
            repair.SYSTEMD
            / "lowerduckpond-archive-construction@request.service.d/90-diagnostic.conf"
        )
        path.write_bytes(b"changed")
    with pytest.raises(ValueError):
        repair.install(RESTORE, owner=os.geteuid())
    for name, original in installation.items():
        assert (repair.LAUNCHERS / name).read_bytes() == original


@pytest.mark.parametrize("operation", repair.OPERATIONS)
@pytest.mark.parametrize("failure", [False, True])
def test_native_entrypoint_captures_exception_chain_without_messages_or_journald(
    tmp_path: Path, operation: str, failure: bool
) -> None:
    driver = """
from contextlib import nullcontext
from lowerduckpond_static_host_agent import archive_entrypoint as entry
entry.os.geteuid = lambda: 0
entry.require_restore_admission = lambda: None
entry._accept_connection = lambda: nullcontext(None)
entry.StateRepository = lambda *a, **kw: nullcontext(None)
entry.ExportSpool = lambda *a, **kw: nullcontext(None)
def load_configuration():
    if FAILURE:
        try:
            raise OSError('private-provider-canary')
        except OSError as cause:
            raise ValueError('private-token-canary') from cause
    raise SystemExit(0)
entry.load_archive_configuration = load_configuration
""".replace("FAILURE", str(failure))
    driver += f"archive_{operation}_main = entry.archive_{operation}_main\n"
    driver += f"raise SystemExit(archive_{operation}_main())\n"
    script = tmp_path / "archive_fixture.py"
    script.write_bytes(repair.instrument(driver.encode(), operation))
    log = tmp_path / "private.log"
    with log.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        result = subprocess.run(  # noqa: S603 - isolated native entrypoint, no providers
            [sys.executable, str(script)],
            env={**os.environ, "INVOCATION_ID": "a" * 32},
            stdout=subprocess.DEVNULL,
            stderr=output,
            check=False,
            timeout=10,
        )
    assert result.returncode == int(failure)
    raw = log.read_text()
    assert "private-provider-canary" not in raw and "private-token-canary" not in raw
    events = [
        trace.event(line.removeprefix(trace.PREFIX), "a" * 32)
        for line in raw.splitlines()
        if line.startswith(trace.PREFIX)
    ]
    if failure:
        assert len(events) == 1 and events[0] is not None
        chain = cast("list[dict[str, object]]", events[0]["chain"])
        assert [item["exception"] for item in chain] == ["ValueError", "OSError"]
        assert f"archive_{operation}_service_failed category=unexpected" in raw
    else:
        assert not events


@pytest.mark.parametrize(
    "defect", ["none", "old-invocation", "message", "source-line", "long-chain"]
)
def test_summary_rejects_stale_or_private_fields(tmp_path: Path, defect: str) -> None:
    locations: list[dict[str, object]] = [{"file": "archive.py", "line": 14}]
    chain: list[dict[str, object]] = [{"exception": "ValueError", "locations": locations}]
    value: dict[str, object] = {
        "helper": "construction",
        "invocation": "a" * 32,
        "chain": chain,
    }
    if defect == "old-invocation":
        value["invocation"] = "b" * 32
    elif defect == "message":
        value["message"] = "private-canary"
    elif defect == "source-line":
        locations[0]["source"] = "private-canary"
    elif defect == "long-chain":
        value["chain"] = chain * 5
    log, journal = tmp_path / "archive.log", tmp_path / "journals.log"
    log.write_text(trace.PREFIX + json.dumps(value) + "\n")
    journal.write_text(
        "lowerduckpond-archive-construction@request.service\nInvocationID=" + "a" * 32 + "\n"
    )
    observed = trace.summarize(log, journal)
    assert observed["collection"] == ("observed" if defect == "none" else "unavailable")
    assert "private-canary" not in str(observed)


def test_new_diagnostic_can_start_at_replay_after_checking_live_restore(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "attempts").mkdir(mode=0o700)
    visited = []

    def execute(command: list[str], *args: object) -> int:
        visited.append(command[-1])
        return 0

    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(
        tmp_path, {}, start="replay", guard=Mock(), prepare=Mock(), capture=Mock(), repair=True
    )
    assert visited == ["repair", "restore", "replay", "public-ca", "accounting", "teardown-check"]
    stages = cast("dict[str, object]", result["stages"])
    assert stages["reconstruction"] == {"outcome": "not-run"}
    assert stages["reboot"] == {"outcome": "not-run"}
    assert result["outcome"] == "diagnostic-incomplete"


def test_failed_live_restore_check_blocks_explicit_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "attempts").mkdir(mode=0o700)
    execute = Mock(return_value=1)
    monkeypatch.setattr(runner, "execute", execute)
    result = runner.run(tmp_path, {}, start="replay", guard=Mock(), prepare=Mock(), capture=Mock())
    assert execute.call_count == 1 and execute.call_args.args[0][-1] == "restore"
    stages = cast("dict[str, object]", result["stages"])
    assert stages["replay"] == {"outcome": "blocked", "dependencies": ["restore"]}


@pytest.mark.parametrize("defect", ["none", "not-docker", "busy", "incomplete"])
def test_repair_refuses_unsafe_guest_state_before_changing_units(
    monkeypatch: pytest.MonkeyPatch, defect: str
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        Path, "read_text", Mock(return_value="podman" if defect == "not-docker" else "docker")
    )
    command = Mock(
        return_value=subprocess.CompletedProcess(
            [], 0, stdout=b"worker" if defect == "busy" else b""
        )
    )
    monkeypatch.setattr(subprocess, "run", command)
    journal = SimpleNamespace(
        restore_id=RESTORE,
        phase=RestorePhase.INSTALLED if defect == "incomplete" else RestorePhase.COMPLETE,
    )
    monkeypatch.setattr(
        RestoreStore,
        "locked",
        Mock(return_value=nullcontext(Mock(read=Mock(return_value=journal)))),
    )
    install = Mock(return_value={})
    monkeypatch.setattr(repair, "install", install)
    if defect == "none":
        repair.main()
        install.assert_called_once_with(RESTORE)
        assert command.call_args.args[0] == ["/usr/bin/systemctl", "daemon-reload"]
    else:
        with pytest.raises(ValueError):
            repair.main()
        install.assert_not_called()


def test_archive_collection_failure_keeps_destination_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "restore").mkdir(mode=0o700)
    write_private(tmp_path / "restore/destination.json", {"id": "original-destination"})
    attempt = tmp_path / "attempt"
    attempt.mkdir(mode=0o700)
    monkeypatch.setattr(subprocess, "run", Mock(return_value=subprocess.CompletedProcess([], 1)))
    monkeypatch.setattr(
        owned, "observations", Mock(return_value={"destination": {"phase": "complete"}})
    )
    capture.checkpoint(tmp_path, attempt, "replay", {})
    value = read_private(attempt / "replay.diagnostics.json")
    assert value["destination"] == {"phase": "complete"}
    assert value["archive_trace"] == {"collection": "unavailable"}
    assert (attempt / "replay.archives.log").stat().st_mode & 0o777 == PRIVATE_FILE_MODE
