"""Verify the enrolled role and current-boot cutover for a projected runtime."""

from __future__ import annotations

import grp
import os
from hashlib import sha256
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.caddy_bootstrap import require_exact_file
from lowerduckpond_static_host_agent.disposable_routes import DisposableRoutes
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_gate import RECOVERY_ROOT
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreStore,
    exact_object,
    full_id,
)

CADDY_ROOT = Path("/etc/caddy")
AUTHORITY = Path("/var/lib/lowerduckpond/convergence/m3-12/droplet-publication")
PROJECTION = "disposable-routing.json"
ROLE = "routing-role.json"
CUTOVER_FORMAT = "lowerduckpond-m3-12-disposable-routing-cutover-v1"


def cutover_filename(boot: str) -> str:
    return f"routing-cutover-{full_id(boot)}.json"


def installed_projection(
    caddy: Path | None = None, *, owner: int = 0, group: int | None = None
) -> DisposableRoutes | None:
    """Read the nonsecret projection available to both the launcher and workers."""
    path = (CADDY_ROOT if caddy is None else caddy) / PROJECTION
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return DisposableRoutes.from_bytes(
        require_exact_file(
            path,
            owner=owner,
            group=grp.getgrnam("caddy").gr_gid if group is None else group,
            modes=(0o440,),
            maximum_bytes=MAX_RESTORE_BYTES,
        )
    )


def _record(directory: DurableDirectory, name: str, owner: int) -> bytes:
    return directory.read_regular(
        (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RESTORE_BYTES
    )


def require_role(routing: DisposableRoutes, role: str, *, owner: int) -> None:
    from lowerduckpond_static_host_agent.droplet_enrollment import (  # noqa: PLC0415 - opted-in installed view only
        read_enrollment,
    )

    with DurableDirectory.open(
        AUTHORITY, expected_owner=owner, expected_directory_mode=0o700
    ) as protected:
        enrolled = read_enrollment(AUTHORITY, protected, owner=owner)
        expected = routing.role_document(role)
        if (
            enrolled.registration["runId"] != routing.run_id
            or sha256(canonical_json_bytes(enrolled.target)).hexdigest() != expected["targetSha256"]
            or _record(protected, ROLE, owner) != canonical_json_bytes(expected)
        ):
            raise HostRestoreError("restore_disposable_routing_role_changed")


def require_restore_cutover(store: RestoreStore, inputs: RestoreInputs) -> None:
    routing = inputs.disposable_routing
    if routing is None:
        if os.path.lexists(AUTHORITY / ROLE):
            raise HostRestoreError("restore_disposable_routing_unbound")
        return
    if installed_projection(owner=store.owner) != routing:
        raise HostRestoreError("restore_disposable_routing_changed")
    require_role(routing, "restore", owner=store.owner)
    from scripts.m3_12_droplet_observe import boot_sha256  # noqa: PLC0415 - scoped host only

    boot = boot_sha256(store.owner)
    with DurableDirectory.open(
        AUTHORITY, expected_owner=store.owner, expected_directory_mode=0o700
    ) as protected:
        raw = _record(protected, cutover_filename(boot), store.owner)
    row = exact_object(
        decode_json_object(raw),
        {
            "format",
            "routingSha256",
            "allocationSha256",
            "sourceTargetSha256",
            "restoreTargetSha256",
            "sourceBootSha256",
            "restoreBootSha256",
            "restoreId",
            "sourceFenceSha256",
        },
    )
    full_id(row["sourceBootSha256"])
    fence = store.read_bytes(f"source-fence-{inputs.restore_id}.json")
    if (
        canonical_json_bytes(row) != raw
        or row["format"] != CUTOVER_FORMAT
        or row["routingSha256"] != routing.sha256
        or row["allocationSha256"] != routing.allocation_sha256
        or row["sourceTargetSha256"] != routing.source_target
        or row["restoreTargetSha256"] != routing.restore_target
        or row["restoreBootSha256"] != boot
        or row["restoreId"] != inputs.restore_id
        or row["sourceFenceSha256"] != sha256(fence).hexdigest()
    ):
        raise HostRestoreError("restore_disposable_routing_cutover_changed")


def require_caddy_routing(routing: DisposableRoutes | None) -> None:
    """Privileged service hooks independently verify the install and role."""
    if not os.path.lexists(AUTHORITY / ROLE):
        if routing is not None:
            raise HostRestoreError("restore_disposable_routing_role_missing")
        return
    if routing is None:
        raise HostRestoreError("restore_disposable_routing_missing")
    with DurableDirectory.open(
        AUTHORITY, expected_owner=0, expected_directory_mode=0o700
    ) as protected:
        role = _record(protected, ROLE, 0)
    if role == canonical_json_bytes(routing.role_document("source")):
        require_role(routing, "source", owner=0)
        return
    with DurableDirectory.open(
        RECOVERY_ROOT, expected_owner=0, expected_directory_mode=0o700
    ) as recovery:
        store = RestoreStore(recovery, 0)
        require_saved_restore_routing(store, projection=routing)


def require_saved_restore_routing(
    store: RestoreStore, *, projection: DisposableRoutes | None = None
) -> None:
    from lowerduckpond_static_host_agent.host_restore_authority import (  # noqa: PLC0415 - completed restore only
        require_saved_authority,
    )

    inputs, _ = require_saved_authority(store)
    if projection is None:
        projection = installed_projection(owner=store.owner)
    if inputs.disposable_routing is None or inputs.disposable_routing != projection:
        raise HostRestoreError("restore_disposable_routing_changed")
    require_restore_cutover(store, inputs)
