"""Destination-scoped admission for completed disposable Droplet recovery."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.droplet_enrollment import (
    protected_record,
    read_enrollment,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_authority import require_saved_authority
from lowerduckpond_static_host_agent.host_restore_gate import DROPLET_PUBLICATION_ROOT
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    DROPLET_BINDING,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from scripts.m3_12_contracts import DISPOSABLE, Document, decode, digest
from scripts.m3_12_droplet_observe import selected_artifact

STATE = Path("/var/lib/lowerduckpond/static")
AUTHORITY = DROPLET_PUBLICATION_ROOT


def require_activation(
    store: RestoreStore,
    inputs: RestoreInputs | None = None,
    *,
    authority_path: Path | None = None,
    receipt: Document | None = None,
) -> None:
    """Reopen native completion and independent local enrollment at each gate."""
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.COMPLETE:
        raise HostRestoreError("droplet_restore_completion_required")
    authority_path = AUTHORITY if authority_path is None else authority_path
    if DROPLET_BINDING not in journal.bindings:
        raise HostRestoreError("droplet_restore_scope_missing")

    saved, _ = require_saved_authority(store)
    scope = saved.droplet_scope
    if scope is None or (inputs is not None and saved != inputs):
        raise HostRestoreError("droplet_restore_scope_changed")
    from lowerduckpond_static_host_agent.installed_routing import (  # noqa: PLC0415 - after saved authority
        require_restore_cutover,
    )

    require_restore_cutover(store, saved)
    with DurableDirectory.open(
        authority_path, expected_owner=store.owner, expected_directory_mode=0o700
    ) as authority:
        enrolled = read_enrollment(authority_path, authority, owner=store.owner)
        if (
            enrolled.registration["runId"] != scope["runId"]
            or digest(enrolled.target) != scope["destinationTargetSha256"]
            or enrolled.registration["machineSha256"]
            != sha256(cast(str, saved.document["destinationMachineId"]).encode("ascii")).hexdigest()
            or selected_artifact(store.owner) != saved.document["originalArtifactSha256"]
        ):
            raise HostRestoreError("droplet_restore_destination_changed")
        if saved.document["launch"] is None:
            if receipt is not None or os.path.lexists(STATE / "platform/launch.json"):
                raise HostRestoreError("droplet_restore_launch_changed")
            return
        if receipt is None:
            from lowerduckpond_static_host_agent.platform_launch import (  # noqa: PLC0415 - break restore/launch import cycle
                verify_launch,
            )

            receipt = verify_launch(STATE, authority_path, owner=store.owner)
        require_source_launch(authority, store.owner, scope, saved, receipt)


def require_source_launch(
    authority: DurableDirectory,
    owner: int,
    scope: dict[str, object],
    inputs: RestoreInputs,
    receipt: Document,
) -> None:
    admission = decode(protected_record(authority, "admission.json", owner), "admission")
    binding = receipt["binding"]
    if (
        binding["targetKind"] != DISPOSABLE
        or binding["purpose"] != "disposable-qualification"
        or binding["runId"] != scope["runId"]
        or binding["targetSha256"] != scope["sourceTargetSha256"]
        or digest(receipt) != scope["sourceLaunchReceiptSha256"]
        or receipt["launchRecordSha256"] != digest(inputs.document["launch"])
        or receipt["admissionSha256"] != digest(admission)
        or admission["candidate"]["hostAgentSha256"] != inputs.document["originalArtifactSha256"]
        or admission["platform"]["namespaceSha256"] != digest(inputs.document["namespace"])
    ):
        raise HostRestoreError("droplet_restore_source_launch_changed")
