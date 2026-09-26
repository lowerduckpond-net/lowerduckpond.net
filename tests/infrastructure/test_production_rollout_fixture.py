"""Fixture scheduling must not race or weaken the real predecessor gate."""

from __future__ import annotations

import shlex
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from .test_m3_10_completed_host import (
    ARTIFACT,
    completed_host,  # noqa: F401 - dependency of empty_completed_host
    empty_completed_host,  # noqa: F401 - real read-only preflight fixture
    executable,
    gate,
)


@pytest.mark.parametrize("fault", ["none", "history", "pause", "drain"])
def test_predecessor_gate_excludes_timer_races_without_hiding_failures(
    empty_completed_host: Path,  # noqa: F811 - imported fixture
    installed_module: Callable[[str], ModuleType],
    fault: str,
) -> None:
    module = installed_module("production_rollout_fixture")
    tree = empty_completed_host
    queued = tree / "queued"
    queued.touch()
    executable(
        tree / "bin/systemctl",
        'if [[ "$1" == list-jobs && -e '
        + shlex.quote(str(queued))
        + " ]]; then echo '42 lowerduckpond-static-reconcile.service start waiting'; fi",
    )
    # This is the unmodified host gate, not a simulated successful integrity
    # response. A timer tick on an otherwise valid predecessor rejects it.
    assert "publication or lifecycle work is queued" in gate(tree, "upgrade-host").stderr
    state = tree / "var/lib/lowerduckpond/static"
    if fault == "history":
        (state / "platform/unexpected").write_text("must remain rejected and untouched")
    original = {path: path.read_bytes() for path in state.rglob("*") if path.is_file()}
    timers = {
        "lowerduckpond-static-reconcile.timer",
        "lowerduckpond-static-emergency-reconcile.timer",
    }
    services = {unit.removesuffix(".timer") + ".service" for unit in timers}
    active = set(timers)
    checks = 0

    def remote(_name: str, arguments: list[str], data: bytes = b"") -> bytes:
        nonlocal checks
        if arguments[:2] == ["systemctl", "is-active"]:
            assert arguments[-1] in active
        elif arguments[:2] == ["systemctl", "stop"]:
            units = set(arguments[2:])
            if units == timers:
                active.remove(arguments[2])
                assert fault != "pause", "partial timer stop failed"
                active.clear()
            else:
                assert units == services and not active
                assert fault != "drain", "service drain failed"
                queued.unlink()
        elif arguments[:2] == ["systemctl", "start"]:
            assert set(arguments[2:]) == timers
            active.update(timers)
            queued.touch()  # A subsequent timer tick is possible again.
        else:
            assert arguments == ["bash", "-s", "--", ARTIFACT, "upgrade-host", module.PREDECESSOR]
            assert data == (module.ROOT / "scripts/m3-10-completed-host-preflight").read_bytes()
            checks += 1
            result = gate(tree, "upgrade-host")
            assert result.returncode == 0, result.stderr
            return result.stdout.encode()
        return b""

    fixture = SimpleNamespace(remote=remote)
    if fault == "none":
        module.Fixture.predecessor_integrity(fixture, ARTIFACT)
    else:
        message = "empty authoritative history" if fault == "history" else "failed"
        with pytest.raises(AssertionError, match=message):
            module.Fixture.predecessor_integrity(fixture, ARTIFACT)
    assert active == timers
    assert checks == (0 if fault in {"pause", "drain"} else 1)
    assert "publication or lifecycle work is queued" in gate(tree, "upgrade-host").stderr
    assert {path: path.read_bytes() for path in state.rglob("*") if path.is_file()} == original
