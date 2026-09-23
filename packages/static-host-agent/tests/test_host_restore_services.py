from __future__ import annotations

import pytest
from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError


def test_quiescence_masks_admission_then_stops_every_discovered_worker_without_ssh_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    stopped = False
    worker = "lowerduckpond-static-worker@0198d17f-6f4a-7000-8000-000000000001.service"

    def run(command: tuple[str, ...], **kwargs: object) -> bytes:
        nonlocal stopped
        calls.append(command)
        if command[1] == "list-units":
            state = "inactive dead" if stopped else "active running"
            return f"caddy.service loaded {state} Caddy\n{worker} loaded {state} Worker\n".encode()
        if command[1] == "stop":
            assert command[2:] == ("caddy.service", worker)
            stopped = True
        return b""

    monkeypatch.setattr(services, "require_command", run)
    services.close_public_ingress()
    masked = services.quiesce_host()
    assert calls[0][0] == "/usr/sbin/nft"
    assert calls[1][1:3] == ("mask", "--runtime")
    assert "lowerduckpond-static-worker@.service" in masked
    assert "caddy.service" in masked
    assert not any(
        "ssh" in argument or argument == "reset-failed" for call in calls for argument in call
    )


@pytest.mark.parametrize(
    "output",
    [
        b"lowerduckpond-static-reconcile.service loaded active running Reconcile\n",
        b"unrelated.service loaded inactive dead Unrelated\n",
        b"caddy.service loaded inactive dead Caddy\ncaddy.service loaded inactive dead Duplicate\n",
        b"caddy.service loaded unknown none Caddy\n",
        b"incomplete\n",
    ],
)
def test_unsettled_or_ambiguous_service_inventory_cannot_prove_quiescence(
    output: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(services, "require_command", lambda *args, **kwargs: output)
    with pytest.raises(HostRestoreError):
        services.require_quiescent()


def test_caddy_is_the_only_permitted_running_service_during_certificate_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        services,
        "require_command",
        lambda *args, **kwargs: b"caddy.service loaded active running Caddy\n",
    )
    services.require_quiescent(caddy=False)
    with pytest.raises(HostRestoreError, match="not_quiescent"):
        services.require_quiescent()


def test_completion_restores_only_reviewed_schedules_and_does_not_reset_start_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **kwargs: object) -> bytes:
        calls.append(command)
        return b""

    monkeypatch.setattr(services, "require_command", run)
    services.start_caddy()
    services.restore_schedules(audit_rotation=False)
    services.remove_public_gate()
    starts = [call for call in calls if len(call) > 1 and call[1] == "start"]
    assert starts[0] == ("/usr/bin/systemctl", "start", "caddy.service")
    assert "lowerduckpond-audit-rotate.timer" not in starts[1]
    enabled = next(call for call in calls if call[1] == "enable")
    assert "caddy.service" in enabled
    assert "lowerduckpond-audit-rotate.timer" not in enabled
    assert calls[-1] == ("/usr/sbin/nft", "destroy", "table", "inet", "lowerduckpond_restore")
    assert not any("reset-failed" in call for call in calls)
