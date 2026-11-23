"""Durable host-restore admission, independent of replaced tenant/kernel locks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Final

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_journal import (
    DROPLET_BINDING,
    GATE,
    JOURNAL,
    LOCK,
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
    exact_object,
)

if TYPE_CHECKING:
    from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs

DROPLET_PUBLICATION_ROOT: Final = Path(
    "/var/lib/lowerduckpond/convergence/m3-12/droplet-publication"
)

RECOVERY_ROOT: Final = Path("/var/lib/lowerduckpond/recovery")
GATE_SCHEMA: Final = "lowerduckpond-host-restore-gate-v1"
INGRESS: Final = ("ingress-pending.json",)
INGRESS_SCHEMA: Final = "lowerduckpond-host-restore-ingress-v1"


def close_gate(store: RestoreStore, restore_id: str) -> None:
    """Persist before stopping services or materializing any recovered bytes."""
    store.immutable(
        GATE[0],
        canonical_json_bytes({"schema": GATE_SCHEMA, "restoreId": validate_uuid7(restore_id)}),
    )


def _read(directory: DurableDirectory, path: tuple[str, ...], owner: int) -> bytes:
    return directory.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RESTORE_BYTES
    )


def gate_pending(store: RestoreStore) -> bool:
    try:
        raw = store.read_bytes(GATE[0])
    except FileNotFoundError:
        return False
    journal = store.read()
    if journal is None or raw != canonical_json_bytes(
        {"schema": GATE_SCHEMA, "restoreId": journal.restore_id}
    ):
        raise HostRestoreError("restore gate belongs to another transaction")
    return True


def ingress_record(store: RestoreStore) -> bytes:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore ingress requires durable completion")
    return canonical_json_bytes(
        {"schema": INGRESS_SCHEMA, "completedJournalDigest": journal.digest}
    )


def ingress_pending(store: RestoreStore) -> bool:
    try:
        raw = store.read_bytes(INGRESS[0])
    except FileNotFoundError:
        return False
    if raw != ingress_record(store):
        raise HostRestoreError("restore ingress authorization changed")
    return True


def _read_gate(directory: DurableDirectory, owner: int) -> dict[str, object] | None:
    try:
        raw = _read(directory, GATE, owner)
    except FileNotFoundError:
        return None
    gate = exact_object(decode_json_object(raw), {"schema", "restoreId"})
    if gate["schema"] != GATE_SCHEMA or canonical_json_bytes(gate) != raw:
        raise HostRestoreError("restore gate is invalid")
    validate_uuid7(gate["restoreId"])
    return gate


def restore_admission(
    root: Path = RECOVERY_ROOT, *, owner: int = 0, caddy: bool = False, boot: bool = False
) -> bool:
    """Return permission only from a complete, canonical root-owned transaction.

    An incomplete gate may precede the first journal. Caddy alone is permitted
    at installed, behind the independent firewall gate, to acquire certificates
    through its ordinary invocation-fenced start. All mutation stays closed.
    """
    if not os.path.lexists(root):
        return True
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        gate = _read_gate(directory, owner)
        try:
            journal = RestoreJournal.from_bytes(_read(directory, JOURNAL, owner))
        except FileNotFoundError:
            if gate is not None:
                return False
            temporaries = directory.publication_temporaries(
                expected_owner=owner, expected_mode=0o600, maximum_entries=64
            )
            descriptor = directory.duplicate_descriptor()
            try:
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        if entry.name not in temporaries and (
                            entry.name != LOCK or _read(directory, (LOCK,), owner) != b""
                        ):
                            raise HostRestoreError("restore provenance lost its journal") from None
            finally:
                os.close(descriptor)
            return True
        # Read and bind every immutable phase receipt, even at complete.
        if RestoreStore(directory, owner).read() != journal:
            raise HostRestoreError("restore provenance changed while reading")
        store = RestoreStore(directory, owner)
        if gate is None:
            return _completed_admission(store, journal, boot=boot, caddy=caddy)
        if gate["restoreId"] != journal.restore_id:
            raise HostRestoreError("restore gate belongs to another transaction")
        if not caddy or journal.phase not in {
            RestorePhase.INSTALLED,
            RestorePhase.VERIFIED,
            RestorePhase.COMPLETE,
        }:
            return False
        _require_projected_start(store)
        return True


def projected_recovery(store: RestoreStore) -> bool:
    journal = store.read()
    if journal is None or DROPLET_BINDING not in journal.bindings:
        return False
    from lowerduckpond_static_host_agent.host_restore_authority import (  # noqa: PLC0415 - avoid a recovery import cycle
        require_saved_authority,
    )

    inputs, _ = require_saved_authority(store)
    return inputs.disposable_routing is not None


def _require_projected_start(store: RestoreStore) -> None:
    if projected_recovery(store):
        from lowerduckpond_static_host_agent.installed_routing import (  # noqa: PLC0415 - project only scoped restores
            require_saved_restore_routing,
        )

        require_saved_restore_routing(store)


def _completed_admission(
    store: RestoreStore, journal: RestoreJournal, *, boot: bool, caddy: bool
) -> bool:
    pending = ingress_pending(store)
    if journal.phase is not RestorePhase.COMPLETE or (boot and pending):
        return False
    if boot and DROPLET_BINDING in journal.bindings:
        projected = projected_recovery(store)
        try:
            require_scoped_activation(store)
        except OSError, RuntimeError, ValueError:
            if not projected:
                raise
            return False  # Boot can install the closed gate and still bring up networking.
    elif caddy:
        _require_projected_start(store)
    return True


def require_restore_admission(*, caddy: bool = False) -> None:
    if not restore_admission(caddy=caddy):
        raise HostRestoreError("host_restore_pending")


def require_scoped_activation(store: RestoreStore, inputs: RestoreInputs | None = None) -> None:
    """Load the Droplet-only dependency only for a durable scoped transaction."""
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore completion is not durable")
    if DROPLET_BINDING not in journal.bindings:
        if os.path.lexists(DROPLET_PUBLICATION_ROOT) or (
            inputs is not None and inputs.droplet_scope is not None
        ):
            raise HostRestoreError("droplet_restore_scope_missing")
        return
    from lowerduckpond_static_host_agent.host_restore_droplet import (  # noqa: PLC0415
        require_activation,
    )

    require_activation(store, inputs)


def open_gate(store: RestoreStore) -> None:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("restore completion is not durable")
    require_scoped_activation(store)
    # Commit ordinary admission before opening public ingress. A separate
    # durable intent keeps unfinished firewall cleanup resumable across reboot.
    store.directory.remove(GATE, missing_ok=True)
