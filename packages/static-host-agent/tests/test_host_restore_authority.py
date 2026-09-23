from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_authority import (
    begin_restore_authority,
    require_saved_authority,
)
from lowerduckpond_static_host_agent.host_restore_fence import FENCE_SCHEMA
from lowerduckpond_static_host_agent.host_restore_gate import GATE_SCHEMA
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_services import (
    ORDINARY_ACTIVATORS,
    ORDINARY_SERVICES,
    TEMPLATES,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - pytest fixture
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414


@pytest.mark.parametrize("damage", ["none", "inputs", "descriptor", "destination", "fence"])
def test_saved_authority_rechecks_original_bindings_at_every_phase(
    tmp_path: Path,
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    configuration: dict[str, object],
    damage: str,
) -> None:
    snapshot, _ = restic
    descriptor = decode_json_object(snapshot.descriptor, maximum_bytes=256 * 1024)
    configuration["repositoryBinding"] = snapshot.identity.binding()
    fence = canonical_json_bytes(
        {
            "schema": FENCE_SCHEMA,
            "restoreId": configuration["restoreId"],
            "snapshotId": configuration["snapshotId"],
            "captureId": descriptor["captureId"],
            "lineageId": snapshot.lineage["lineageId"],
            "repositoryBinding": snapshot.identity.binding(),
            "artifactDigest": descriptor["artifactDigest"],
            "sourceMachineId": configuration["sourceMachineId"],
            "sourceGateDigest": framed_digest(
                GATE_SCHEMA,
                canonical_json_bytes(
                    {"schema": GATE_SCHEMA, "restoreId": configuration["restoreId"]}
                ),
            ),
            "maskedUnits": sorted(
                (*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES, "caddy.service")
            ),
        }
    )
    configuration["sourceFenceDigest"] = framed_digest(FENCE_SCHEMA, fence)
    inputs = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    root = tmp_path / "saved-authority"
    root.mkdir(mode=0o700)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        with pytest.raises(HostRestoreError, match="target_input_mismatch"):
            begin_restore_authority(
                store, snapshot, inputs, fence, destination_id="b" * 32, artifact_sha256="e" * 64
            )
        assert store.read() is None
        changed = {
            **inputs.document,
            "namespace": {
                **cast(dict[str, object], inputs.document["namespace"]),
                "initializedAt": "2026-08-28T12:00:00Z",
            },
        }
        with pytest.raises(HostRestoreError, match="trusted_input_mismatch"):
            begin_restore_authority(
                store,
                snapshot,
                RestoreInputs.from_bytes(canonical_json_bytes(changed)),
                fence,
                destination_id="b" * 32,
                artifact_sha256="b" * 64,
            )
        assert store.read() is None
        current = begin_restore_authority(
            store, snapshot, inputs, fence, destination_id="b" * 32, artifact_sha256="b" * 64
        )
        assert require_saved_authority(store) == (inputs, descriptor)
        current = store.advance(current, RestorePhase.RESTORED, {"restored": True})
        assert (
            begin_restore_authority(
                store, snapshot, inputs, fence, destination_id="b" * 32, artifact_sha256="b" * 64
            )
            == current
        )
        if damage == "none":
            return
        name = {
            "inputs": "trusted-inputs.json",
            "descriptor": "backup-descriptor.json",
            "destination": "destination.json",
            "fence": f"source-fence-{inputs.restore_id}.json",
        }[damage]
        path = root / name
        changed = decode_json_object(path.read_bytes(), maximum_bytes=256 * 1024)
        if damage == "inputs":
            changed["publicationEnabled"] = not changed["publicationEnabled"]
        elif damage == "descriptor":
            changed["captureId"] = "0198d17f-6f4a-7000-8000-000000000099"
        else:
            changed["restoreId"] = "0198d17f-6f4a-7000-8000-000000000099"
        path.write_bytes(canonical_json_bytes(changed, maximum_bytes=256 * 1024))
        with pytest.raises(HostRestoreError, match="authority_changed"):
            require_saved_authority(store)
