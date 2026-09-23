from __future__ import annotations

import ast
import fcntl
import json
import shlex
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "config/ansible/molecule/m3_8/tests"
UNIT = "lowerduckpond-audit-rotate.service"
MESSAGE = "ae8f7b866b0347b9af31fe1c80b127c0"


def load_function(module: str, name: str, **values: object) -> Callable[..., object]:
    path = FIXTURES / (module + ".py")
    tree = ast.parse(path.read_text())
    function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    )
    namespace = {"Host": object, "json": json, **values}
    exec(  # noqa: S102 - exercise the unchanged repository fixture function in isolation
        compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace
    )
    return cast(Callable[..., object], namespace[name])


@pytest.mark.parametrize("healthy", [True, False])
def test_health_assertion_serializes_before_the_unchanged_nonblocking_reader(
    tmp_path: Path, healthy: bool
) -> None:
    selection = tmp_path / "selection.lock"
    selection.touch(mode=0o600)
    state = tmp_path / "static"
    (state / "locks").mkdir(parents=True)
    lease = state / "locks/tenant-state.lock"
    lease.touch(mode=0o600)
    environment = tmp_path / "backup.env"
    environment.write_text("RESTIC_REPOSITORY=/owned\nLOWERDUCKPOND_BACKUP_NODE_NAME=fixture\n")
    checker = tmp_path / "checker"
    marker = tmp_path / "calls"
    checker.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        f"exec 7<{shlex.quote(str(lease))}\nflock --shared --nonblock 7\n"
        f"printf x >> {shlex.quote(str(marker))}\n"
        f"printf 'lowerduckpond_audit_protection_verified {int(healthy)}\\n'\n"
        f"exit {0 if healthy else 1}\n"
    )
    checker.chmod(0o700)
    started = Event()

    def run(command: str, script: str) -> SimpleNamespace:
        assert command == "/bin/bash -c %s"
        script = script.replace(
            "/opt/lowerduckpond/static-host-agent/selection.lock", str(selection)
        )
        script = script.replace("/etc/lowerduckpond/backup.env", str(environment))
        script = script.replace(
            "/usr/local/libexec/lowerduckpond/check-audit-protection", str(checker)
        )
        with subprocess.Popen(  # noqa: S603 - actual fixture wrapper with owned private paths
            ["/bin/bash", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        ) as process:
            started.set()
            stdout, stderr = process.communicate(timeout=5)
            return SimpleNamespace(rc=process.returncode, stdout=stdout, stderr=stderr)

    health = load_function("audit_protection_support", "health", ROOT=str(state))
    with lease.open("rb") as held, ThreadPoolExecutor(max_workers=1) as executor:
        fcntl.flock(held, fcntl.LOCK_EX)
        future = executor.submit(health, SimpleNamespace(run=run), succeeds=healthy)
        try:
            assert started.wait(5) and not future.done()
            assert not marker.exists()
        finally:
            fcntl.flock(held, fcntl.LOCK_UN)
        assert (
            future.result(timeout=5) == f"lowerduckpond_audit_protection_verified {int(healthy)}\n"
        )
    assert marker.read_text() == "x"


@pytest.mark.parametrize(
    "fault", [None, "missing", "duplicate", "unit", "pid", "unknown", "over-limit"]
)
def test_rotation_memory_evidence_is_fresh_unique_and_within_the_original_limit(
    fault: str | None,
) -> None:
    record = {"UNIT": UNIT, "MESSAGE_ID": MESSAGE, "_PID": "1", "MEMORY_PEAK": "200000000"}
    if fault == "unit":
        record["UNIT"] = "other.service"
    elif fault == "pid":
        record["_PID"] = "123"
    elif fault == "unknown":
        record["MEMORY_PEAK"] = "[not set]"
    elif fault == "over-limit":
        record["MEMORY_PEAK"] = str(256 * 1024 * 1024 + 1)
    records = [] if fault == "missing" else [record, record] if fault == "duplicate" else [record]
    host = Mock()
    host.run.side_effect = [
        SimpleNamespace(rc=0, stdout='{"__CURSOR":"before-this-invocation"}'),
        SimpleNamespace(rc=0),
        SimpleNamespace(rc=0, stdout="\n".join(json.dumps(value) for value in records)),
    ]
    audits = SimpleNamespace(run_unit=Mock())
    run = load_function(
        "audit_rotation_support",
        "run_bounded_rotation",
        UNIT=UNIT,
        _RESOURCE_MESSAGE=MESSAGE,
        audits=audits,
    )
    if fault is None:
        run(host)
    else:
        with pytest.raises(AssertionError):
            run(host)
    audits.run_unit.assert_called_once_with(host, UNIT)
    query = host.run.call_args.args
    assert "--after-cursor=%s" in query[0] and "_PID=1" in query[0]
    assert query[1:] == ("before-this-invocation", UNIT, MESSAGE)


def test_rotation_timer_restore_joins_the_persistent_verifier() -> None:
    host = Mock()
    host.run.return_value = SimpleNamespace(rc=0)
    audits = SimpleNamespace(run_unit=Mock(), VERIFY_UNIT="lowerduckpond-audit-verify.service")
    restore = load_function(
        "test_audit_rotation",
        "_restore_timers_after_verification",
        _TIMERS="owned.timer other.timer",
        audits=audits,
    )
    restore(host)
    host.run.assert_called_once_with("systemctl enable --now owned.timer other.timer")
    audits.run_unit.assert_called_once_with(host, audits.VERIFY_UNIT)
