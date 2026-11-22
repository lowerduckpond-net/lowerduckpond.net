"""Validate and read back the fixed P4 recovery authority delivery."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.droplet_enrollment import (
    ENROLLMENT,
    EXCLUSIONS,
    TARGET,
    protected_record,
    read_enrollment,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_droplet import AUTHORITY, require_source_launch
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from scripts.m3_12_contracts import DISPOSABLE, Document, decode, digest, encode, validate_launch

ENROLLMENT_FILES = (TARGET, ENROLLMENT, EXCLUSIONS)
LAUNCH_FILES = ("admission.json", "launch-intent.json", "launch-receipt.json")


def publication_files(
    directory: Path, inputs: RestoreInputs, *, owner: int, on_destination: bool = False
) -> dict[str, str]:
    """Return only fixed record names and content digests for scoped recovery."""
    scope = inputs.droplet_scope
    if scope is None:
        if on_destination:
            raise HostRestoreError("droplet_restore_scope_missing")
        return {}
    with DurableDirectory.open(
        directory, expected_owner=owner, expected_directory_mode=0o700
    ) as protected:
        records = {name: protected_record(protected, name, owner) for name in ENROLLMENT_FILES}
        target = decode(records[TARGET], "target")
        registration = decode(records[ENROLLMENT], "droplet-enrollment")
        exclusions = decode(records[EXCLUSIONS], "droplet-production-exclusions")
        expected_machine = sha256(
            cast(str, inputs.document["destinationMachineId"]).encode("ascii")
        ).hexdigest()
        if (
            target["targetKind"] != DISPOSABLE
            or digest(target) != scope["destinationTargetSha256"]
            or target["enrollmentSha256"] != digest(registration)
            or registration["productionExclusionsSha256"] != digest(exclusions)
            or registration["machineSha256"] != expected_machine
            or registration["runId"] != scope["runId"]
        ):
            raise HostRestoreError("droplet_restore_destination_changed")
        if on_destination:
            observed = read_enrollment(directory, protected, owner=owner)
            if observed.target != target or observed.registration != registration:
                raise HostRestoreError("droplet_restore_destination_changed")
        launch = inputs.document["launch"]
        if launch is not None:
            records.update(
                {name: protected_record(protected, name, owner) for name in LAUNCH_FILES}
            )
            admission, intent, original_receipt = (records[name] for name in LAUNCH_FILES)
            receipt = validate_launch(admission, intent, encode(launch), original_receipt)
            require_source_launch(protected, owner, scope, inputs, receipt)
        return {name: sha256(raw).hexdigest() for name, raw in records.items()}


def delivery_readback(
    inputs: RestoreInputs, artifact: str, *, owner: int, authority: Path = AUTHORITY
) -> Document:
    if inputs.document["originalArtifactSha256"] != artifact:
        raise HostRestoreError("droplet_restore_destination_changed")
    files = publication_files(authority, inputs, owner=owner, on_destination=True)
    return {
        "restoreId": inputs.restore_id,
        "trustedInputsDigest": inputs.digest,
        "activationScopeDigest": inputs.droplet_scope_digest,
        "publicationFiles": files,
    }
