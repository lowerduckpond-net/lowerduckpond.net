"""Narrow archive ownership checks, independent of failed legacy settled replay."""

from __future__ import annotations

import hashlib
from typing import Protocol, cast

from lowerduckpond_static_contracts import (
    archive_record_digest,
    canonical_json_bytes,
    decode_contract,
    decode_json_object,
    deployment_record_digest,
    manifest_digest,
    platform_state_digest,
    validate_uuid7,
)
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_authority import require_saved_authority
from lowerduckpond_static_host_agent.host_restore_journal import (
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.repository import StateRecordPath

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_archive import MAX_VERSIONS, records
from scripts.m3_11_retirement_files import RetirementError


class Reader(Protocol):
    def read(self, path: str) -> bytes: ...
    def names(self, path: str) -> dict[str, str]: ...


class SavedAuthority:
    """Read only the coordinator's original authority through either reader."""

    def __init__(self, reader: Reader, recovery: str) -> None:
        self.reader, self.recovery = reader, recovery

    def read_bytes(self, name: str) -> bytes:
        return self.reader.read(self.recovery + "/" + name)

    def read(self) -> RestoreJournal:
        return RestoreJournal.from_bytes(self.read_bytes("host-restore.json"))


def contract(reader: Reader, root: str, path: StateRecordPath) -> dict[str, object]:
    raw = reader.read(root + "/" + "/".join(path.components))
    value = decode_contract(raw, expected_kind=path.contract_kind)
    if raw != canonical_json_bytes(value):
        raise RetirementError("archive ownership record is not canonical")
    path.validate_binding(value)
    return value


def inventory(reader: Reader, root: str) -> list[dict[str, dict[str, object]]]:
    tenants = reader.names(root + "/tenants")
    if len(tenants) > MAX_VERSIONS or any(kind != "directory" for kind in tenants.values()):
        raise RetirementError("retirement tenant inventory is ambiguous")
    found: list[dict[str, dict[str, object]]] = []
    for tenant in sorted(tenants):
        validate_uuid7(tenant)
        desired = contract(reader, root, StateRecordPath.tenant_desired(tenant))
        for name, kind in reader.names(root + f"/tenants/{tenant}/archives").items():
            if kind != "regular" or not name.endswith(".json"):
                raise RetirementError("retirement archive path is unsafe")
            deployment = validate_uuid7(name.removesuffix(".json"))
            archive = contract(reader, root, StateRecordPath.tenant_archive(tenant, deployment))
            deployed = contract(reader, root, StateRecordPath.tenant_deployment(tenant, deployment))
            spec = cast(dict[str, object], desired["spec"])
            reference = cast(dict[str, object], spec.get("desiredDeployment"))
            if (
                spec.get("desiredState") != "archived"
                or not isinstance(reference, dict)
                or reference.get("id") != deployment
                or reference.get("archiveSha256") != deployed["archiveSha256"]
                or archive["releaseTreeDigest"] != deployed["releaseTreeDigest"]
            ):
                raise RetirementError("archive is not the exact retained archived deployment")
            found.append({"archive": archive, "deployment": deployed, "desired": desired})
            if len(found) > MAX_VERSIONS:
                raise RetirementError("retirement archive inventory exceeds its bound")
    return sorted(found, key=lambda item: str(item["archive"]["key"]))


def ownership(  # noqa: PLR0913 - distinct source/destination roots and archive binding
    source: Reader,
    destination: Reader,
    source_root: str,
    destination_base: str,
    *,
    artifact: str,
    bucket: str,
    repository: str,
) -> dict[str, object]:
    recovery = destination_base + "/recovery"
    raw_journal = destination.read(recovery + "/host-restore.json")
    journal = RestoreJournal.from_bytes(raw_journal)
    inputs, _ = require_saved_authority(cast(RestoreStore, SavedAuthority(destination, recovery)))
    if cast(dict[str, object], inputs.document["archiveTarget"])["bucket"] != bucket:
        raise RetirementError("retirement archive differs from original restore inputs")
    if journal.phase != RestorePhase.VALIDATED:
        raise RetirementError("retirement requires the failed validated reconstruction")
    raw = destination.read(recovery + "/backup-descriptor.json")
    descriptor = decode_backup_descriptor(raw)
    lineage = cast(dict[str, object], descriptor["lineage"])
    if (
        cast(dict[str, object], lineage["repository"])["locator"] != repository
        or lineage["repositoryBinding"] != journal.bindings["repository"]
        or cast(dict[str, str], descriptor["artifactDigest"])["value"] != artifact
        or journal.bindings["originalArtifact"]["value"] != artifact
        or journal.bindings["backupDescriptor"]
        != framed_digest("lowerduckpond-static-backup-v1", raw)
        or descriptor["captureId"] != journal.capture_id
    ):
        raise RetirementError("retirement descriptor differs from original reconstruction")
    candidate = destination_base + f"/.restore-{journal.restore_id}-state/candidate"
    before, after = inventory(source, source_root), inventory(destination, candidate)
    if before != after or not before:
        raise RetirementError("source and restored archive authority disagree")
    for reader, root in ((source, source_root), (destination, candidate)):
        namespace = contract(reader, root, StateRecordPath.platform_namespace())
        if platform_state_digest(namespace).to_dict() != descriptor["namespaceDigest"]:
            raise RetirementError("retirement namespace differs from its snapshot")
    tenants = cast(list[dict[str, object]], descriptor["tenants"])
    captured = {
        (row["tenantId"], item["deploymentId"]): item["recordDigest"]
        for row in tenants
        for item in cast(list[dict[str, object]], row["archives"])
    }
    actual = {
        (row["archive"]["tenantId"], row["archive"]["deploymentId"]): archive_record_digest(
            row["archive"]
        ).to_dict()
        for row in before
    }
    if actual != captured:
        raise RetirementError("retirement archive identities differ from their captured digests")
    deployments = {
        (row["tenantId"], item["deploymentId"]): item["recordDigest"]
        for row in tenants
        for item in cast(list[dict[str, object]], row["deployments"])
    }
    desired = {row["tenantId"]: row["desiredDigest"] for row in tenants}
    selected = []
    for row in before:
        archive = row["archive"]
        if (
            archive["bucket"] != bucket
            or desired.get(archive["tenantId"]) != manifest_digest(row["desired"]).to_dict()
            or deployments.get((archive["tenantId"], archive["deploymentId"]))
            != deployment_record_digest(row["deployment"]).to_dict()
        ):
            raise RetirementError("retirement archive target or deployment changed")
        selected.append(
            {
                "key": archive["key"],
                "version": archive["versionId"],
                "size": archive["bundleSize"],
                "sha256": cast(dict[str, str], archive["bundleDigest"])["value"],
            }
        )
    # Both gates are evidence, not a request to open them. Preserve their bytes.
    gates = [
        source.read(source_root.rsplit("/", 1)[0] + "/recovery/restore-gate.json"),
        destination.read(recovery + "/restore-gate.json"),
    ]
    for gate in gates:
        value = fields(decode_json_object(gate), {"schema", "restoreId"})
        if (
            value["schema"] != "lowerduckpond-host-restore-gate-v1"
            or canonical_json_bytes(value) != gate
        ):
            raise RetirementError("retirement ingress gate is invalid")
        validate_uuid7(value["restoreId"])
    if decode_json_object(gates[1])["restoreId"] != journal.restore_id:
        raise RetirementError("retirement destination gate belongs to another restore")
    return {
        "archives": records(selected),
        "descriptor_sha256": hashlib.sha256(raw).hexdigest(),
        "journal_sha256": hashlib.sha256(raw_journal).hexdigest(),
        "archive_records_sha256": hashlib.sha256(canonical_json_bytes(before)).hexdigest(),
        "gates_sha256": [hashlib.sha256(raw).hexdigest() for raw in gates],
        "unresolved_obligations": "preserved-in-frozen-state; not-settled",
    }
