"""Bind the ordinary invocation-fenced start to the explicit restore authority."""

from __future__ import annotations

from pathlib import Path

from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartIntent,
    CaddyStartMode,
    CaddyStartTarget,
    CaddyStartupStore,
    start_target,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_gate import RECOVERY_ROOT
from lowerduckpond_static_host_agent.host_restore_history import provenance_stores
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_mapping import _read_runtime_mapping


def require_restore_startup(
    intent: CaddyStartIntent | None,
    active: CaddyStartTarget,
    invocation_id: str,
    *,
    root: Path = RECOVERY_ROOT,
    owner: int = 0,
) -> None:
    """Run before the start attempt write and again before process-health commit."""
    try:
        directory = DurableDirectory.open(root, expected_owner=owner, expected_directory_mode=0o700)
    except FileNotFoundError:
        if intent is not None and intent.mode is CaddyStartMode.HOST_RESTORE:
            raise HostRestoreError("restore_startup_missing_journal") from None
        return
    with directory:
        store = RestoreStore(directory, owner)
        journal = store.read()
        restoring = intent is not None and intent.mode is CaddyStartMode.HOST_RESTORE
        if journal is None:
            if restoring:
                raise HostRestoreError("restore_startup_missing_journal")
            return
        if journal.phase is RestorePhase.COMPLETE and not restoring:
            return
        if (
            intent is None
            or not restoring
            or intent.restore_id != journal.restore_id
            or PHASES.index(journal.phase) < PHASES.index(RestorePhase.INSTALLED)
        ):
            raise HostRestoreError("restore_startup_transaction_mismatch")
        with provenance_stores(store) as stores:
            for source in stores:
                mapping = _read_runtime_mapping(source, private_preparation=False)
                if mapping is None:
                    raise HostRestoreError("restore_startup_mapping_missing")
                prior = mapping.inputs.evidence.intent
                if prior is not None and invocation_id in (
                    *prior.candidate_invocations,
                    *prior.recovery_invocations,
                ):
                    raise HostRestoreError("restore_startup_reuses_captured_invocation")
                if source is store and (
                    active
                    != start_target(mapping.inputs.generation_id, mapping.manifest.to_bytes())
                    or intent.candidate != active
                ):
                    raise HostRestoreError("restore_startup_generation_mismatch")


def complete_restore_startup(
    store: RestoreStore, startup: CaddyStartupStore, intent: CaddyStartIntent
) -> None:
    journal = store.read()
    if (
        journal is None
        or journal.phase is not RestorePhase.COMPLETE
        or intent.restore_id != journal.restore_id
    ):
        raise HostRestoreError("restore_startup_completion_not_durable")
    mapping = _read_runtime_mapping(store, private_preparation=False)
    if mapping is None or intent.candidate != start_target(
        mapping.inputs.generation_id, mapping.manifest.to_bytes()
    ):
        raise HostRestoreError("restore_startup_generation_mismatch")
    startup.complete_host_restore(intent, restore_id=journal.restore_id)
