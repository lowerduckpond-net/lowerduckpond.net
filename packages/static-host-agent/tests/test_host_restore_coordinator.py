from __future__ import annotations

import os
import time
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import host_restore_coordinator as coordinator
from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.host_restore_gate import (
    INGRESS,
    close_gate,
    ingress_record,
    open_gate,
    restore_admission,
)
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_paths import RestorePaths
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414


@pytest.fixture
def root(tmp_path: Path) -> Path:
    result = tmp_path / "coordinator-recovery"
    result.mkdir(mode=0o700)
    return result


@pytest.mark.parametrize("fault", ["audit", "archives", "state", "selection", "tls", "none"])
def test_no_caddy_start_before_all_independent_authority_checks(  # noqa: PLR0913,PLR0917
    root: Path,
    journal: RestoreJournal,
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    configuration: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    inputs = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    journal = replace(journal, bindings={**journal.bindings, "trustedInputs": inputs.digest})
    events = []

    def prove(name: str) -> dict[str, object]:
        events.append(name)
        assert not restore_admission(root, owner=os.geteuid())
        if name == fault:
            raise HostRestoreError("injected unavailable " + name)
        return {name: True}

    monkeypatch.setattr(coordinator, "verify_installed_roots", lambda *args: None)
    monkeypatch.setattr(coordinator, "verify_kernel_locks", lambda *args: None)
    monkeypatch.setattr(coordinator, "verify_reconstructed_audit", lambda *args: prove("audit"))
    monkeypatch.setattr(coordinator, "verify_settled_state", lambda *args, **kwargs: prove("state"))
    monkeypatch.setattr(
        coordinator,
        "verify_installed_runtime",
        lambda *args, running=True, **kwargs: prove("runtime" if running else "selection"),
    )
    monkeypatch.setattr(coordinator.HostRestore, "_archive", lambda *args: prove("archives"))
    monkeypatch.setattr(coordinator.HostRestore, "_cold", lambda *args: None)
    monkeypatch.setattr(coordinator.HostRestore, "_capacity", lambda *args: None)
    monkeypatch.setattr(coordinator.HostRestore, "_tls", lambda *args: prove("tls"))
    monkeypatch.setattr(
        coordinator.HostRestore, "_repository", lambda *args, **kwargs: nullcontext(object())
    )
    monkeypatch.setattr(
        coordinator.HostRestore,
        "_files",
        lambda *args: SimpleNamespace(require_inputs=lambda inputs: None),
    )
    monkeypatch.setattr(services, "require_quiescent", lambda **kwargs: None)
    monkeypatch.setattr(services, "start_caddy", lambda: events.append("start"))
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        store.begin(journal)
        close_gate(store, journal.restore_id)
        for phase in PHASES[1 : PHASES.index(RestorePhase.INSTALLED) + 1]:
            journal = store.advance(journal, phase, {})
        operation = coordinator.HostRestore(
            store,
            restic[0],
            inputs,
            RestorePaths(journal.restore_id, os.getegid(), recovery=root),
            {},
            -1,
            "b" * 64,
            os.geteuid(),
            "b" * 32,
            b"not used by phase fixture",
            time.monotonic() + 60,
        )
        if fault == "none":
            assert operation._verify()["tls"] == {"tls": True}
        else:
            with pytest.raises(HostRestoreError, match="injected unavailable"):
                operation._verify()
        assert store.read() == journal
    assert ("start" in events) == (fault in {"tls", "none"})
    if "start" in events:
        assert all(
            events.index(name) < events.index("start")
            for name in ("audit", "archives", "state", "selection")
        )
    assert not restore_admission(root, owner=os.geteuid())


@pytest.mark.parametrize(
    "phase", [RestorePhase.INSTALLED, RestorePhase.VERIFIED, RestorePhase.COMPLETE]
)
@pytest.mark.parametrize("gated", [False, True])
def test_resume_reverifies_before_activation_and_never_reopens_completed_work(  # noqa: PLR0913,PLR0917
    root: Path,
    journal: RestoreJournal,
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    configuration: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    phase: RestorePhase,
    gated: bool,
) -> None:
    inputs = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    journal = replace(journal, restore_id=inputs.restore_id, snapshot_id=inputs.snapshot_id)
    events = []
    monkeypatch.setattr(coordinator, "require_source_fence", lambda *args: None)
    monkeypatch.setattr(coordinator.HostRestore, "_begin", lambda self: self.store.read())
    monkeypatch.setattr(coordinator.HostRestore, "_cold", lambda *args: None)
    monkeypatch.setattr(RestorePaths, "prepare_parents", lambda *args: None)
    monkeypatch.setattr(services, "close_public_ingress", lambda: events.append("closed"))
    monkeypatch.setattr(services, "quiesce_host", lambda **kwargs: events.append("quiescent"))

    def verify(operation: coordinator.HostRestore) -> dict[str, object]:
        assert not restore_admission(root, owner=os.geteuid())
        events.append("fresh-proof")
        return {"actual-current-proof": True}

    def seal(store: RestoreStore) -> dict[str, str]:
        assert events[-1] == "fresh-proof"
        return {"fixture": "inventory"}

    def activate(store: RestoreStore, *args: object) -> None:
        current = store.read()
        assert current is not None and current.phase is RestorePhase.COMPLETE
        assert events[-1] == "fresh-proof"
        events.append("activation")
        open_gate(store)

    monkeypatch.setattr(coordinator.HostRestore, "_verify", verify)
    monkeypatch.setattr(coordinator, "seal_provenance", seal)
    monkeypatch.setattr(coordinator, "activate_completed_restore", activate)
    monkeypatch.setattr(services, "remove_public_gate", lambda: events.append("firewall"))
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        store.begin(journal)
        for next_phase in PHASES[1 : PHASES.index(phase) + 1]:
            journal = store.advance(journal, next_phase, {})
        if gated:
            close_gate(store, journal.restore_id)
        elif phase is RestorePhase.COMPLETE:
            store.immutable(INGRESS[0], ingress_record(store))
        result = coordinator.HostRestore(
            store,
            restic[0],
            inputs,
            RestorePaths(journal.restore_id, os.getegid(), recovery=root),
            {},
            -1,
            "b" * 64,
            os.geteuid(),
            "b" * 32,
            b"phase fixture",
            time.monotonic() + 60,
        ).run()
        assert result.phase is RestorePhase.COMPLETE
    if phase is RestorePhase.COMPLETE and not gated:
        assert events == ["firewall"]
    else:
        assert events == ["closed", "quiescent", "fresh-proof", "activation"]
    assert restore_admission(root, owner=os.geteuid())
