"""Persist only nonsecret operator and snapshot bindings in the recovery journal."""

from __future__ import annotations

from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_descriptor import (
    BACKUP_SCHEMA,
    decode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_fence import FENCE_SCHEMA, require_source_fence
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from lowerduckpond_static_host_agent.host_restore_validation import require_trusted_policy

DESTINATION_SCHEMA = "lowerduckpond-host-restore-destination-v1"


def begin_restore_authority(  # noqa: PLR0913 - original, trusted and local bindings
    store: RestoreStore,
    snapshot: RestoreSnapshot,
    inputs: RestoreInputs,
    fence: bytes,
    *,
    destination_id: str,
    artifact_sha256: str,
) -> RestoreJournal:
    inputs.require_destination(destination_id, artifact_sha256, snapshot.snapshot.snapshot_id)
    require_source_fence(fence, inputs, snapshot)
    descriptor = decode_backup_descriptor(snapshot.descriptor)
    require_trusted_policy(
        descriptor,
        repository_genesis=snapshot.lineage,
        artifact_sha256=artifact_sha256,
        namespace=cast(dict[str, object], inputs.document["namespace"]),
        launch=cast(dict[str, object] | None, inputs.document["launch"]),
    )
    destination = {
        "schema": DESTINATION_SCHEMA,
        "machineId": destination_id,
        "restoreId": inputs.restore_id,
    }
    expected = RestoreJournal(
        inputs.restore_id,
        snapshot.snapshot.snapshot_id,
        str(descriptor["captureId"]),
        str(snapshot.lineage["lineageId"]),
        {
            "backupDescriptor": framed_digest(BACKUP_SCHEMA, snapshot.descriptor),
            "repository": snapshot.identity.binding(),
            "originalArtifact": cast(dict[str, str], descriptor["artifactDigest"]),
            "trustedInputs": inputs.digest,
            "destination": framed_digest(DESTINATION_SCHEMA, canonical_json_bytes(destination)),
            "sourceFence": framed_digest(FENCE_SCHEMA, fence),
        },
    )
    current = store.read()
    if current is None:
        store.begin(expected)
        current = expected
    elif (
        current.restore_id != expected.restore_id
        or current.snapshot_id != expected.snapshot_id
        or current.capture_id != expected.capture_id
        or current.lineage_id != expected.lineage_id
        or current.bindings != expected.bindings
    ):
        raise HostRestoreError("restore_original_authority_changed")
    # These copies contain hashes, public policy and provenance, never either
    # storage credential set or the DNS environment. They remain byte-exact.
    store.immutable("backup-descriptor.json", snapshot.descriptor)
    store.immutable(
        "trusted-inputs.json",
        canonical_json_bytes(inputs.document, maximum_bytes=MAX_RESTORE_BYTES),
    )
    store.immutable("destination.json", canonical_json_bytes(destination))
    store.immutable(f"source-fence-{inputs.restore_id}.json", fence)
    return current


def require_saved_authority(store: RestoreStore) -> tuple[RestoreInputs, dict[str, object]]:
    """Read-side credential helper authority; caller separately proves coordinator lease."""
    current = store.read()
    if current is None:
        raise HostRestoreError("restore_original_authority_missing")
    inputs = RestoreInputs.from_bytes(store.read_bytes("trusted-inputs.json"))
    raw = store.read_bytes("backup-descriptor.json")
    descriptor = decode_backup_descriptor(raw)
    destination = decode_json_object(store.read_bytes("destination.json"))
    fence = store.read_bytes(f"source-fence-{current.restore_id}.json")
    if (
        inputs.restore_id != current.restore_id
        or inputs.snapshot_id != current.snapshot_id
        or inputs.digest != current.bindings["trustedInputs"]
        or framed_digest(BACKUP_SCHEMA, raw) != current.bindings["backupDescriptor"]
        or descriptor["artifactDigest"] != current.bindings["originalArtifact"]
        or descriptor["captureId"] != current.capture_id
        or cast(dict[str, object], descriptor["lineage"])["lineageId"] != current.lineage_id
        or inputs.document["repositoryBinding"] != current.bindings["repository"]
        or framed_digest(FENCE_SCHEMA, fence) != current.bindings["sourceFence"]
        or inputs.document["sourceFenceDigest"] != current.bindings["sourceFence"]
        or destination
        != {
            "schema": DESTINATION_SCHEMA,
            "machineId": inputs.document["destinationMachineId"],
            "restoreId": current.restore_id,
        }
        or framed_digest(DESTINATION_SCHEMA, canonical_json_bytes(destination))
        != current.bindings["destination"]
    ):
        raise HostRestoreError("restore_original_authority_changed")
    return inputs, descriptor
