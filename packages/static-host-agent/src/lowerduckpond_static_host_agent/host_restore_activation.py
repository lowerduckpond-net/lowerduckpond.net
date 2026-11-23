"""Resume activation after durable completion without reopening restored authority."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore
from lowerduckpond_static_host_agent.durable import DurableDirectory, StateAlreadyExistsError
from lowerduckpond_static_host_agent.host_restore_authority import require_saved_authority
from lowerduckpond_static_host_agent.host_restore_gate import (
    INGRESS,
    gate_pending,
    ingress_pending,
    ingress_record,
    open_gate,
    projected_recovery,
    require_scoped_activation,
)
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_paths import private_directory
from lowerduckpond_static_host_agent.host_restore_startup import complete_restore_startup
from lowerduckpond_static_host_agent.host_restore_verification import verify_current_runtime

CONFIGURATION = Path("/etc/lowerduckpond/static-publication.json")


def activation_pending(store: RestoreStore) -> bool:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore_activation_requires_complete")
    if gate_pending(store) or ingress_pending(store):
        return True
    if not projected_recovery(store):
        return False
    if services.public_gate_present():
        return True
    try:
        require_scoped_activation(store)
    except OSError, RuntimeError, ValueError:
        return True
    return False


def finish_public_ingress(
    store: RestoreStore, *, failure_hook: Callable[[str], None] = lambda _boundary: None
) -> None:
    """Finish only the committed ingress change; ordinary state may have advanced."""
    ingress_record(store)  # Require durable completion even after cleanup committed.
    if gate_pending(store):
        raise HostRestoreError("restore_ingress_requires_admission_commit")
    pending = ingress_pending(store)
    # A completed projected restore may have been fenced again at boot.
    # It cannot clear the kernel table until the new boot's proof is present.
    projected = projected_recovery(store)
    if projected:
        try:
            require_scoped_activation(store)
        except OSError, RuntimeError, ValueError:
            services.close_public_ingress()
            raise
        if not pending and not services.public_gate_present():
            return
        services.close_public_ingress()
        _start_projected_caddy(store)
        verify_current_runtime(store, require_saved_authority(store)[0])
        require_scoped_activation(store)
    elif pending:
        require_scoped_activation(store)
    else:
        return
    services.remove_public_gate()
    failure_hook("firewall")
    store.directory.remove(INGRESS, missing_ok=True)
    failure_hook("ingress")


def _start_projected_caddy(store: RestoreStore) -> None:
    from scripts.m3_12_droplet_observe import boot_sha256  # noqa: PLC0415 - projected hosts only

    if services.caddy_failed():
        marker = f"projected-caddy-recovery-{boot_sha256(store.owner)}.json"
        # Reserve this recovery before resetting the manager. An interrupted or
        # repeatedly failing current-boot start must never reset the budget again.
        try:
            store.directory.create_immutable((marker,), ingress_record(store), mode=0o600)
        except StateAlreadyExistsError:
            raise HostRestoreError("restore_caddy_boot_recovery_exhausted") from None
        services.reset_caddy_start_limit()
    services.start_caddy()


def _publication(path: Path, enabled: bool, owner: int) -> None:
    with DurableDirectory.open(
        path.parent, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        previous = decode_json_object(
            directory.read_regular(
                (path.name,), expected_owner=owner, expected_mode=0o400, maximum_bytes=4096
            )
        )
        expected = {
            "format": "lowerduckpond-static-publication-gate-v1",
            "static_publication_enabled": enabled,
        }
        if previous not in (expected, {**expected, "static_publication_enabled": False}):
            raise HostRestoreError("restore_publication_policy_changed")
        directory.replace((path.name,), canonical_json_bytes(expected), mode=0o400)


def activate_completed_restore(  # noqa: PLR0913 - fixed inputs and interruption fixture paths
    store: RestoreStore,
    inputs: RestoreInputs,
    caddy: Path,
    *,
    configuration: Path = CONFIGURATION,
    ready: Path = services.SCHEDULES_READY,
    failure_hook: Callable[[str], None] = lambda _boundary: None,
) -> None:
    """Caller freshly verified runtime/TLS on this invocation before activation.

    Services still require the durable gate to be absent. Only timers and
    sockets can start under the volatile token, after COMPLETE. Commit ordinary
    admission while ingress remains closed, then remove the firewall table.
    The separate ingress intent survives a crash or reboot until cleanup ends.
    After admission commit, retry never replays checks against tenant authority
    that ordinary work may already have advanced.
    """
    if not activation_pending(store):
        return
    journal = store.read()
    assert journal is not None  # noqa: S101 - activation_pending requires it
    if inputs.digest != journal.bindings["trustedInputs"]:
        raise HostRestoreError("restore_activation_policy_unbound")
    require_scoped_activation(store, inputs)
    if not gate_pending(store):
        finish_public_ingress(store, failure_hook=failure_hook)
        return
    with CaddyStartupStore.open(caddy / "intents", expected_owner=store.owner) as startup:
        intent = startup.read()
        if intent is not None:
            complete_restore_startup(store, startup, intent)
    failure_hook("startup")
    if inputs.droplet_scope is not None:
        require_scoped_activation(store, inputs)
    _publication(configuration, bool(inputs.document["publicationEnabled"]), store.owner)
    failure_hook("publication")
    private_directory(ready.parent, owner=store.owner)
    with DurableDirectory.open(
        ready.parent, expected_owner=store.owner, expected_directory_mode=0o700
    ) as directory:
        directory.replace((ready.name,), journal.to_bytes(), mode=0o600)
    failure_hook("schedules-ready")
    services.restore_schedules(audit_rotation=bool(inputs.document["auditRotationEnabled"]))
    failure_hook("schedules")
    store.immutable(INGRESS[0], ingress_record(store))
    failure_hook("ingress-ready")
    open_gate(store)
    failure_hook("gate")
    finish_public_ingress(store, failure_hook=failure_hook)
