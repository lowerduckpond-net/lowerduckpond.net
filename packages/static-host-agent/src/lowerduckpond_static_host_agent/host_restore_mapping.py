"""Independently reproducible authority for regenerated runtime observations."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import (
    canonical_json_bytes,
    decode_json_object,
    platform_state_digest,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.backup_descriptor import (
    LAUNCH_DIGEST_FORMAT,
    backup_descriptor_digest,
    encode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_BINARY_NAME,
    CADDY_CONFIGURATION_NAME,
    CADDY_ENVIRONMENT_NAME,
    CADDY_ROUTE_METADATA_NAME,
    MAX_CADDY_CONFIGURATION_BYTES,
    MAX_CADDY_ROUTE_METADATA_BYTES,
    CaddyGenerationManifest,
    _parse_manifest,
)
from lowerduckpond_static_host_agent.caddy_routes import (
    TenantCaddyRoutes,
    TenantRouteInput,
    build_tenant_caddy_routes,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_history import provenance_stores
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
    exact_object,
)
from lowerduckpond_static_host_agent.host_restore_selection import require_captured_selection
from lowerduckpond_static_host_agent.repository import StateRecordPath, _StateTransaction
from lowerduckpond_static_host_agent.route_snapshot import (
    TenantRouteSnapshot,
    snapshot_tenant_routes,
)

PLAN_SCHEMA: Final = "lowerduckpond-host-restore-runtime-inputs-v1"
MAPPING_SCHEMA: Final = "lowerduckpond-host-restore-runtime-mapping-v1"
PLAN_NAME: Final = "runtime-inputs.json"
MAPPING_NAME: Final = "runtime-mapping.json"
MAX_PLAN_BYTES: Final = 2 * 1024 * 1024


def _certificates(value: object) -> tuple[bytes, ...]:
    if type(value) is not list or not 1 <= len(value) <= 2:  # noqa: PLR2004 - current/next CA
        raise HostRestoreError("restore_runtime_trust_incomplete")
    result: list[bytes] = []
    for encoded in value:
        if type(encoded) is not str or not 0 < len(encoded) <= 64 * 1024:
            raise HostRestoreError("restore_runtime_trust_oversized")
        raw = base64.b64decode(encoded, validate=True)
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise HostRestoreError("restore_runtime_trust_noncanonical")
        result.append(raw)
    return tuple(result)


@dataclass(frozen=True)
class RuntimeInputs:
    document: dict[str, object]

    @classmethod
    def from_bytes(cls, raw: bytes) -> RuntimeInputs:
        document = exact_object(
            decode_json_object(raw, maximum_bytes=MAX_PLAN_BYTES),
            {
                "schema",
                "reconciledJournalDigest",
                "trustedInputs",
                "backupDescriptor",
                "newGenerationId",
                "tenants",
                "originalOriginPullCa",
                "originPullCa",
            },
        )
        if (
            document["schema"] != PLAN_SCHEMA
            or canonical_json_bytes(document, maximum_bytes=MAX_PLAN_BYTES) != raw
        ):
            raise HostRestoreError("restore_runtime_inputs_invalid")
        result = cls(document)
        validate_uuid7(result.generation_id)
        trusted = result.trusted
        descriptor = encode_backup_descriptor(cast(dict[str, object], document["backupDescriptor"]))
        backup_descriptor_digest(descriptor)
        if (
            cast(dict[str, object], document["backupDescriptor"])["namespaceDigest"]
            != platform_state_digest(
                cast(dict[str, object], trusted.document["namespace"])
            ).to_dict()
        ):
            raise HostRestoreError("restore_runtime_namespace_changed")
        original_descriptor = cast(dict[str, object], document["backupDescriptor"])
        launch = trusted.document["launch"]
        if (
            original_descriptor["launchDigest"]
            != (
                None
                if launch is None
                else framed_digest(LAUNCH_DIGEST_FORMAT, canonical_json_bytes(launch))
            )
            or cast(dict[str, str], original_descriptor["artifactDigest"])["value"]
            != trusted.document["originalArtifactSha256"]
        ):
            raise HostRestoreError("restore_runtime_original_inputs_changed")
        for name, values in (
            ("originalOriginPullCaSha256", result.original_ca),
            ("originPullCaSha256", result.current_ca),
        ):
            if [hashlib.sha256(value).hexdigest() for value in values] != trusted.caddy[name]:
                raise HostRestoreError("restore_runtime_trust_changed")
        original = result.original
        evidence = result.evidence
        if result.generation_id in {row.target.generation_id for row in evidence.generations}:
            raise HostRestoreError("restore_runtime_generation_reused")
        require_captured_selection(
            evidence,
            {"reconciled": (evidence.selected_target.generation_id, original)},
            result.original_ca,
        )
        result.routes()  # Validate every target contract and the complete projection.
        return result

    @property
    def trusted(self) -> RestoreInputs:
        return RestoreInputs.from_bytes(
            canonical_json_bytes(
                cast(dict[str, object], self.document["trustedInputs"]),
                maximum_bytes=MAX_RESTORE_BYTES,
            )
        )

    @property
    def generation_id(self) -> str:
        return validate_uuid7(self.document["newGenerationId"])

    @property
    def evidence(self) -> CaddyBackupEvidence:
        return CaddyBackupEvidence.from_dict(
            cast(dict[str, object], self.document["backupDescriptor"])["caddy"]
        )

    @property
    def original_ca(self) -> tuple[bytes, ...]:
        return _certificates(self.document["originalOriginPullCa"])

    @property
    def current_ca(self) -> tuple[bytes, ...]:
        return _certificates(self.document["originPullCa"])

    @property
    def original(self) -> TenantRouteSnapshot:
        rows = self.document["tenants"]
        if type(rows) is not list or len(rows) > 25:  # noqa: PLR2004 - production tenant bound
            raise HostRestoreError("restore_runtime_tenant_bound")
        tenants: list[TenantRouteInput] = []
        for row in rows:
            value = exact_object(row, {"manifest", "observed", "deployment"})
            if (
                type(value["manifest"]) is not dict
                or type(value["observed"]) is not dict
                or (value["deployment"] is not None and type(value["deployment"]) is not dict)
            ):
                raise HostRestoreError("restore_runtime_tenant_invalid")
            tenants.append(
                TenantRouteInput(
                    value["manifest"],
                    value["observed"],
                    cast(dict[str, object] | None, value["deployment"]),
                )
            )
        ids = [
            str(cast(dict[str, object], tenant.manifest["metadata"])["id"]) for tenant in tenants
        ]
        if ids != sorted(set(ids)):
            raise HostRestoreError("restore_runtime_tenants_not_canonical")
        return TenantRouteSnapshot(
            cast(dict[str, object], self.trusted.document["namespace"]), tuple(tenants)
        )

    @property
    def projected(self) -> TenantRouteSnapshot:
        original = self.original
        tenants: list[TenantRouteInput] = []
        for tenant in original.tenants:
            observed = deepcopy(tenant.observed_state)
            if observed["observedState"] == "active":
                observed["runtimeGenerationId"] = self.generation_id
            tenants.append(
                TenantRouteInput(deepcopy(tenant.manifest), observed, deepcopy(tenant.deployment))
            )
        return TenantRouteSnapshot(original.platform_namespace, tuple(tenants))

    def routes(self) -> TenantCaddyRoutes:
        target = self.projected
        return build_tenant_caddy_routes(
            platform_namespace=target.platform_namespace,
            tenants=target.tenants,
            runtime_generation_id=self.generation_id,
            origin_pull_ca_der=self.current_ca,
            origin_pull_required=True,
        )

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.document, maximum_bytes=MAX_PLAN_BYTES)

    @property
    def digest(self) -> dict[str, str]:
        return framed_digest(PLAN_SCHEMA, self.to_bytes())

    def require_journal(self, journal: RestoreJournal) -> None:
        descriptor = cast(dict[str, object], self.document["backupDescriptor"])
        if (
            self.document["reconciledJournalDigest"] != journal.digest
            or journal.phase is not RestorePhase.RECONCILED
            or self.trusted.restore_id != journal.restore_id
            or self.trusted.snapshot_id != journal.snapshot_id
            or self.trusted.digest != journal.bindings["trustedInputs"]
            or self.trusted.document["repositoryBinding"] != journal.bindings["repository"]
            or self.trusted.document["sourceFenceDigest"] != journal.bindings["sourceFence"]
            or descriptor["artifactDigest"] != journal.bindings["originalArtifact"]
            or backup_descriptor_digest(encode_backup_descriptor(descriptor))
            != journal.bindings["backupDescriptor"]
            or descriptor["captureId"] != journal.capture_id
        ):
            raise HostRestoreError("restore_runtime_journal_mismatch")


def prepare_runtime_inputs(  # noqa: PLR0913, PLR0917 - complete independently pinned original/current inputs
    store: RestoreStore,
    snapshot: TenantRouteSnapshot,
    descriptor: dict[str, object],
    trusted: RestoreInputs,
    generation_id: str,
    original_ca: tuple[bytes, ...],
    current_ca: tuple[bytes, ...],
) -> RuntimeInputs:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.RECONCILED:
        raise HostRestoreError("restore_runtime_requires_reconciled_state")
    if snapshot.platform_namespace != trusted.document["namespace"]:
        raise HostRestoreError("restore_runtime_namespace_changed")
    document = {
        "schema": PLAN_SCHEMA,
        "reconciledJournalDigest": journal.digest,
        "trustedInputs": trusted.document,
        "backupDescriptor": descriptor,
        "newGenerationId": generation_id,
        "originalOriginPullCa": [base64.b64encode(value).decode("ascii") for value in original_ca],
        "originPullCa": [base64.b64encode(value).decode("ascii") for value in current_ca],
        "tenants": [
            {"manifest": row.manifest, "observed": row.observed_state, "deployment": row.deployment}
            for row in snapshot.tenants
        ],
    }
    plan = RuntimeInputs.from_bytes(canonical_json_bytes(document, maximum_bytes=MAX_PLAN_BYTES))
    plan.require_journal(journal)
    with provenance_stores(store) as ancestors:
        for source in ancestors[:-1]:
            mapping = _read_runtime_mapping(source, private_preparation=False)
            if mapping is None or mapping.inputs.generation_id == plan.generation_id:
                raise HostRestoreError("restore_runtime_generation_reused")
    try:
        existing = _read_inputs(store)
    except FileNotFoundError:
        store.directory.create_immutable((PLAN_NAME,), plan.to_bytes(), mode=0o600)
    else:
        if existing.to_bytes() != plan.to_bytes():
            raise HostRestoreError("restore_runtime_inputs_changed")
    return plan


def _read_inputs(store: RestoreStore) -> RuntimeInputs:
    return RuntimeInputs.from_bytes(
        store.directory.read_regular(
            (PLAN_NAME,),
            expected_owner=store.owner,
            expected_mode=0o600,
            maximum_bytes=MAX_PLAN_BYTES,
        )
    )


@dataclass(frozen=True)
class RuntimeMapping:
    inputs: RuntimeInputs
    manifest: CaddyGenerationManifest

    def to_bytes(self) -> bytes:
        routes = self.inputs.routes()
        files = {row.name: row for row in self.manifest.files}
        if (
            self.manifest.generation_id != self.inputs.generation_id
            or self.manifest.route_state_digest.to_dict()
            != routes.route_metadata["routeStateDigest"]
            or files[CADDY_BINARY_NAME].sha256 != self.inputs.trusted.caddy["binarySha256"]
            or files[CADDY_ENVIRONMENT_NAME].sha256
            != self.inputs.trusted.caddy["environmentSha256"]
        ):
            raise HostRestoreError("restore_runtime_manifest_changed")
        for name, content, maximum in (
            (CADDY_CONFIGURATION_NAME, routes.configuration, MAX_CADDY_CONFIGURATION_BYTES),
            (CADDY_ROUTE_METADATA_NAME, routes.route_metadata, MAX_CADDY_ROUTE_METADATA_BYTES),
        ):
            raw = canonical_json_bytes(content, maximum_bytes=maximum)
            if files[name].sha256 != hashlib.sha256(raw).hexdigest() or files[name].size != len(
                raw
            ):
                raise HostRestoreError("restore_runtime_payload_changed")
        return canonical_json_bytes(
            {
                "schema": MAPPING_SCHEMA,
                "inputsDigest": self.inputs.digest,
                "targetManifest": self.manifest.to_dict(),
            },
            maximum_bytes=MAX_RESTORE_BYTES,
        )

    @property
    def digest(self) -> dict[str, str]:
        return framed_digest(MAPPING_SCHEMA, self.to_bytes())


def commit_runtime_mapping(store: RestoreStore, mapping: RuntimeMapping) -> dict[str, str]:
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.RECONCILED:
        raise HostRestoreError("restore_runtime_requires_reconciled_state")
    inputs = _read_inputs(store)
    inputs.require_journal(journal)
    if inputs.to_bytes() != mapping.inputs.to_bytes():
        raise HostRestoreError("restore_runtime_inputs_changed")
    store.immutable(MAPPING_NAME, mapping.to_bytes())
    return mapping.digest


def read_runtime_mapping(
    root: Path, *, owner: int, private_preparation: bool = False
) -> RuntimeMapping | None:
    try:
        directory = DurableDirectory.open(root, expected_owner=owner, expected_directory_mode=0o700)
    except FileNotFoundError:
        return None
    with directory:
        store = RestoreStore(directory, owner)
        return _read_runtime_mapping(store, private_preparation=private_preparation)


def _read_runtime_mapping(
    store: RestoreStore, *, private_preparation: bool
) -> RuntimeMapping | None:
    journal = store.read()
    if journal is None:
        try:
            store.read_bytes(MAPPING_NAME)
        except FileNotFoundError:
            return None
        raise HostRestoreError("restore_runtime_mapping_lost_journal")
    try:
        raw = store.read_bytes(MAPPING_NAME)
    except FileNotFoundError:
        if PHASES.index(journal.phase) < PHASES.index(RestorePhase.RUNTIME_PREPARED):
            return None
        raise
    mapping = exact_object(
        decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES),
        {"schema", "inputsDigest", "targetManifest"},
    )
    inputs = _read_inputs(store)
    inputs.require_journal(RestoreJournal.from_bytes(store.read_bytes("journal-reconciled.json")))
    manifest = _parse_manifest(
        cast(dict[str, object], mapping["targetManifest"]),
        expected_generation_id=inputs.generation_id,
    )
    result = RuntimeMapping(inputs, manifest)
    if result.to_bytes() != raw:
        raise HostRestoreError("restore_runtime_mapping_invalid")
    if PHASES.index(journal.phase) < PHASES.index(RestorePhase.RUNTIME_PREPARED):
        if not private_preparation or journal.phase is not RestorePhase.RECONCILED:
            raise HostRestoreError("restore_runtime_mapping_uncommitted")
    else:
        receipt = decode_json_object(
            store.read_bytes("runtime-prepared.json"), maximum_bytes=MAX_RESTORE_BYTES
        )
        if receipt.get("runtimeMapping") != result.digest:
            raise HostRestoreError("restore_runtime_mapping_unbound")
    return result


def require_mapped_current_observation(
    mapping: RuntimeMapping, manifest: dict[str, object], observed: dict[str, object]
) -> None:
    """Even replay using current observations must prove a restored runtime ID."""
    if observed.get("runtimeGenerationId") != mapping.inputs.generation_id:
        return
    tenant_id = cast(dict[str, object], manifest["metadata"])["id"]
    matching = [
        row
        for row in mapping.inputs.projected.tenants
        if cast(dict[str, object], row.manifest["metadata"])["id"] == tenant_id
    ]
    if (
        len(matching) != 1
        or matching[0].manifest != manifest
        or matching[0].observed_state != observed
    ):
        raise HostRestoreError("restore_runtime_current_observation_unproven")
    mapping.to_bytes()


def map_runtime_request(
    mapping: RuntimeMapping,
    tenant_id: str,
    manifest: dict[str, object],
    observed: dict[str, object] | None,
    generation_id: str | None,
) -> tuple[str | None, dict[str, object] | None]:
    """Translate only an exact historical observation; other authority stays exact.

    Readers apply preserved mappings in restore order and then compare against
    current state and the independently verified selected generation as usual.
    Existing cross-tenant audit rules still govern unrelated global generations.
    """
    mapping.to_bytes()
    original = mapping.inputs.original
    projected = mapping.inputs.projected
    old_global = mapping.inputs.evidence.selected_target.generation_id
    for source, target in zip(original.tenants, projected.tenants, strict=True):
        if cast(dict[str, object], source.manifest["metadata"])["id"] != tenant_id:
            continue
        if source.manifest != manifest:
            return generation_id, observed
        if observed not in (source.observed_state, target.observed_state) and not (
            observed is None and generation_id == old_global
        ):
            return generation_id, observed
        translated = deepcopy(target.observed_state)
        prior_generation = source.observed_state["runtimeGenerationId"]
        if generation_id is not None and generation_id in {old_global, prior_generation}:
            generation_id = mapping.inputs.generation_id
        return generation_id, translated
    # Archived tenants are excluded from both complete route snapshots. Their
    # immutable job/source and current archived record must still compare exactly
    # in the caller; only the globally selected generation can be translated.
    if (
        generation_id == old_global
        and cast(dict[str, object], manifest["spec"])["desiredState"] == "archived"
        and observed is not None
        and observed.get("tenantId") == tenant_id
        and observed.get("observedState") == "archived"
        and observed.get("runtimeGenerationId") is None
    ):
        return mapping.inputs.generation_id, observed
    return generation_id, observed


def apply_runtime_mapping(
    store: RestoreStore,
    transaction: _StateTransaction,
    mapping: RuntimeMapping,
    *,
    failure_hook: Callable[[str], None] = lambda _tenant: None,
) -> None:
    """Change only active runtime references, accepting exact old/new retry state."""
    journal = store.read()
    if journal is None or journal.phase is not RestorePhase.RECONCILED:
        raise HostRestoreError("restore_runtime_requires_reconciled_state")
    mapping.inputs.require_journal(journal)
    if (
        store.read_bytes(MAPPING_NAME) != mapping.to_bytes()
        or _read_inputs(store).digest != mapping.inputs.digest
    ):
        raise HostRestoreError("restore_runtime_mapping_uncommitted")
    if transaction.measure_intent_records().records:
        raise HostRestoreError("restore_runtime_lifecycle_unreconciled")
    actual = snapshot_tenant_routes(transaction)
    original, projected = mapping.inputs.original, mapping.inputs.projected
    if actual.platform_namespace != original.platform_namespace or len(actual.tenants) != len(
        original.tenants
    ):
        raise HostRestoreError("restore_runtime_state_changed")
    writes = []
    for current, source, target in zip(
        actual.tenants, original.tenants, projected.tenants, strict=True
    ):
        if (
            current.manifest != source.manifest
            or current.deployment != source.deployment
            or current.observed_state not in (source.observed_state, target.observed_state)
        ):
            raise HostRestoreError("restore_runtime_observation_changed")
        tenant = str(cast(dict[str, object], source.manifest["metadata"])["id"])
        path = StateRecordPath.tenant_observed(tenant)
        writes.append((path, transaction.read(path), target.observed_state))
    for path, stored, target_observed in writes:
        if stored.document != target_observed:
            transaction.compare_and_swap(path, stored.revision, target_observed)
        failure_hook(path.components[1])


def runtime_mappings(
    root: Path, *, owner: int, private_reconciliation: bool = False
) -> tuple[RuntimeMapping, ...]:
    try:
        directory = DurableDirectory.open(root, expected_owner=owner, expected_directory_mode=0o700)
    except FileNotFoundError:
        return ()
    with directory:
        store = RestoreStore(directory, owner)
        with provenance_stores(store) as stores:
            mappings: list[RuntimeMapping] = []
            for source in stores:
                journal = source.read()
                if journal is None:
                    raise HostRestoreError("restore_runtime_mapping_lost_journal")
                if private_reconciliation and PHASES.index(journal.phase) < PHASES.index(
                    RestorePhase.RUNTIME_PREPARED
                ):
                    # While local lifecycle reconciliation is running, only
                    # completed ancestors can authorize historical replay.
                    continue
                mapping = _read_runtime_mapping(source, private_preparation=False)
                if mapping is not None:
                    if mapping.inputs.generation_id in {
                        row.inputs.generation_id for row in mappings
                    }:
                        raise HostRestoreError("restore_runtime_generation_reused")
                    mappings.append(mapping)
            return tuple(mappings)


def translate_runtime_request(
    mappings: tuple[RuntimeMapping, ...],
    manifest: dict[str, object],
    observed: dict[str, object] | None,
    generation_id: str | None,
) -> tuple[str | None, dict[str, object] | None]:
    tenant = validate_uuid7(cast(dict[str, object], manifest["metadata"])["id"])
    for mapping in mappings:
        generation_id, observed = map_runtime_request(
            mapping, tenant, manifest, observed, generation_id
        )
    return generation_id, observed
