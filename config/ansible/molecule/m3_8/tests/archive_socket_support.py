"""Prove that helper teardown cannot discard the next archive request."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import test_export_import as exports
import test_lifecycle as support
from testinfra.host import Host

_DIRECTORY = "/run/lowerduckpond-m3-10-socket-queue"
_DROP_IN = "/run/systemd/system/lowerduckpond-archive-cleanup@.service.d/m3-10-queue.conf"


def _active_cleanup_units(host: Host) -> list[str]:
    active = host.run(
        "systemctl list-units --state=active,activating,deactivating "
        "--plain --no-legend 'lowerduckpond-archive-cleanup@*.service'"
    )
    assert active.rc == 0, active.stderr
    return [line.split()[0] for line in active.stdout.splitlines()]


def assert_cleanup_request_queues_through_service_teardown(host: Host, job_id: str) -> None:
    # This runs after a fully validated restore. Both probes only recheck the
    # retired archive's absence; neither creates a job nor mutates remote data.
    setup = host.run(
        "/usr/bin/python3 -I -B -c %s",
        f"""
from pathlib import Path
directory = Path({_DIRECTORY!r})
directory.mkdir(mode=0o700)
hold = directory / 'hold.py'
hold.write_text("from pathlib import Path\\nimport time\\n"
    "root = Path({_DIRECTORY!r})\\n"
    "(root / 'ready').touch()\\n"
    "while not (root / 'release').exists(): time.sleep(0.05)\\n")
hold.chmod(0o600)
drop_in = Path({_DROP_IN!r})
drop_in.parent.mkdir(parents=True, exist_ok=True)
drop_in.write_text('[Service]\\nBindPaths={_DIRECTORY}\\n'
    'ExecStopPost=/usr/bin/python3 -I {_DIRECTORY}/hold.py\\n')
""",
    )
    assert setup.rc == 0, setup.stderr
    reload = host.run("systemctl daemon-reload")
    assert reload.rc == 0, reload.stderr
    script = exports._selected_python(
        host,
        f"""
import json
from pathlib import Path
from lowerduckpond_static_host_agent.archive_cleanup_service import (
    ArchiveCleanupClient, connect_archive_cleanup,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
root = Path({support.STATE_ROOT!r})
job = json.loads((root / 'authorization/jobs' / {job_id + ".json"!r}).read_text())
assert job['executionValidated'] is True
assert job['request']['operation'] == 'restore'
attempt_marker = None
def connect():
    stream = connect_archive_cleanup()
    if attempt_marker is not None:
        attempt_marker.touch()
    return stream
with ExportSpool(root, expected_owner=0) as spool:
    assert ArchiveCleanupClient(spool, connector=connect).verify_terminal(
        {job_id!r}, job['sourceAuthority']['archiveRecord'], mode='retired')
""",
    )
    try:
        first = host.run("/usr/bin/python3 -I -B -c %s", script)
        assert first.rc == 0, first.stderr
        deadline = time.monotonic() + 5
        while not host.file(f"{_DIRECTORY}/ready").exists:
            assert time.monotonic() < deadline, "archive helper did not enter held teardown"
            time.sleep(0.05)
        units = _active_cleanup_units(host)
        assert len(units) == 1, units
        queued_script = script.replace(
            "attempt_marker = None",
            f"attempt_marker = Path({_DIRECTORY + '/attempted'!r})",
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            second = executor.submit(host.run, "/usr/bin/python3 -I -B -c %s", queued_script)
            try:
                deadline = time.monotonic() + 5
                while not host.file(f"{_DIRECTORY}/attempted").exists:
                    assert time.monotonic() < deadline, "second archive request did not start"
                    time.sleep(0.05)
                time.sleep(0.5)
                assert not second.done(), "next archive request was dropped during helper teardown"
                assert _active_cleanup_units(host) == units
                state = host.run("systemctl show --property=SubState --value %s", units[0])
                assert state.rc == 0 and state.stdout.strip() == "stop-post", state.stdout
            finally:
                released = host.run("touch %s", f"{_DIRECTORY}/release")
                assert released.rc == 0, released.stderr
            result = second.result(timeout=30)
            assert result.rc == 0, result.stderr
    finally:
        cleanup = host.run(
            "/usr/bin/python3 -I -B -c %s",
            f"""
from pathlib import Path
Path({_DIRECTORY + "/release"!r}).touch()
Path({_DROP_IN!r}).unlink()
""",
        )
        assert cleanup.rc == 0, cleanup.stderr
        reload = host.run("systemctl daemon-reload")
        assert reload.rc == 0, reload.stderr
        deadline = time.monotonic() + 30
        while _active_cleanup_units(host):
            assert time.monotonic() < deadline, "archive probe helper did not finish"
            time.sleep(0.1)
        removed = host.run(
            "/usr/bin/python3 -I -B -c %s",
            f"""
from pathlib import Path
root = Path({_DIRECTORY!r})
for name in ('hold.py', 'ready', 'release', 'attempted'):
    (root / name).unlink(missing_ok=True)
root.rmdir()
""",
        )
        assert removed.rc == 0, removed.stderr
