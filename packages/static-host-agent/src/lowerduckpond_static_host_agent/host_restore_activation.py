"""Resume activation after durable completion without reopening restored authority."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent import host_restore_services as services
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_gate import close_gate, open_gate
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    GATE,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_paths import private_directory
from lowerduckpond_static_host_agent.host_restore_startup import complete_restore_startup

CONFIGURATION = Path("/etc/lowerduckpond/static-publication.json")


def activation_pending(store: RestoreStore) -> bool:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore_activation_requires_complete")
    try:
        store.read_bytes(GATE[0])
    except FileNotFoundError:
        return False
    close_gate(store, journal.restore_id)  # Recheck canonical identity without replacing it.
    return True


def _publication(path: Path, enabled: bool, owner: int) -> None:
    with DurableDirectory.open(
        path.parent, expected_owner=owner, expected_directory_mode=0o755
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
    sockets can start under the volatile token, after COMPLETE. Removing the
    durable gate last means every interrupted activation is resumable. After
    that removal, another invocation must not replay checks against historical
    tenant authority that ordinary work may already have advanced.
    """
    if not activation_pending(store):
        return
    journal = store.read()
    assert journal is not None  # noqa: S101 - activation_pending requires it
    if inputs.digest != journal.bindings["trustedInputs"]:
        raise HostRestoreError("restore_activation_policy_unbound")
    with CaddyStartupStore.open(caddy / "intents", expected_owner=store.owner) as startup:
        intent = startup.read()
        if intent is not None:
            complete_restore_startup(store, startup, intent)
    failure_hook("startup")
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
    services.remove_public_gate()
    failure_hook("firewall")
    open_gate(store)
    failure_hook("gate")
