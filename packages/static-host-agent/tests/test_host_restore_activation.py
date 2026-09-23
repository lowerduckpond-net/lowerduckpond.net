from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object
from lowerduckpond_static_host_agent import host_restore_activation as activation
from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.host_restore_gate import close_gate, restore_admission
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    GATE,
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414


@pytest.mark.parametrize(
    "boundary", ["startup", "publication", "schedules-ready", "schedules", "firewall", "gate"]
)
def test_hard_exit_activation_keeps_durable_gate_until_all_schedules_restored(  # noqa: PLR0913,PLR0917 - fixtures and hard-exit boundary
    root: Path,
    journal: RestoreJournal,
    configuration: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    inputs = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    journal = replace(journal, bindings={**journal.bindings, "trustedInputs": inputs.digest})
    caddy = tmp_path / "caddy"
    caddy.mkdir(mode=0o750)
    (caddy / "intents").mkdir(mode=0o700)
    policy = tmp_path / "configuration"
    policy.mkdir(mode=0o755)
    policy = policy / "static-publication.json"
    policy.write_bytes(
        canonical_json_bytes(
            {
                "format": "lowerduckpond-static-publication-gate-v1",
                "static_publication_enabled": False,
            }
        )
    )
    policy.chmod(0o400)
    ready = tmp_path / "run/schedules-ready"
    completed = tmp_path / "activation-calls"

    def schedules(*, audit_rotation: bool) -> None:
        assert not restore_admission(root, owner=os.geteuid())
        assert ready.is_file()
        assert (
            decode_json_object(policy.read_bytes())["static_publication_enabled"]
            == inputs.document["publicationEnabled"]
        )
        with completed.open("a") as stream:
            stream.write("schedules\n")

    def firewall() -> None:
        assert completed.read_text().endswith("schedules\n")
        assert not restore_admission(root, owner=os.geteuid())
        with completed.open("a") as stream:
            stream.write("firewall\n")

    monkeypatch.setattr(services, "restore_schedules", schedules)
    monkeypatch.setattr(services, "remove_public_gate", firewall)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        store.begin(journal)
        close_gate(store, journal.restore_id)
        with pytest.raises(HostRestoreError, match="requires_complete"):
            activation.activate_completed_restore(
                store, inputs, caddy, configuration=policy, ready=ready
            )
        assert not ready.exists()
        for phase in PHASES[1:]:
            journal = store.advance(journal, phase, {})
    child = os.fork()
    if child == 0:
        with RestoreStore.locked(root, owner=os.geteuid()) as store:
            activation.activate_completed_restore(
                store,
                inputs,
                caddy,
                configuration=policy,
                ready=ready,
                failure_hook=lambda value: os._exit(81) if value == boundary else None,
            )
        os._exit(0)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 81  # noqa: PLR2004 - hard-exit sentinel
    assert (root / GATE[0]).exists() == (boundary != "gate")
    assert (
        RestoreJournal.from_bytes((root / "host-restore.json").read_bytes()).phase
        is RestorePhase.COMPLETE
    )
    # Reboot loses the volatile permission; replay must recreate it while the
    # durable gate still prevents all worker activity.
    ready.unlink(missing_ok=True)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        activation.activate_completed_restore(
            store, inputs, caddy, configuration=policy, ready=ready
        )
        assert not activation.activation_pending(store)
        before = completed.read_bytes()
        activation.activate_completed_restore(
            store, inputs, caddy, configuration=policy, ready=ready
        )
        assert completed.read_bytes() == before
    assert restore_admission(root, owner=os.geteuid())
