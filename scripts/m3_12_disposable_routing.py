"""Prepare an exclusive public presentation from the P4 reviewed source/restore pair."""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha256

from lowerduckpond_static_contracts import ContractError, decode_json_object
from lowerduckpond_static_host_agent.caddy_routes import (
    CaddyRouteError,
    PlatformOnlyCaddyRoutes,
    TenantCaddyRoutes,
)
from lowerduckpond_static_host_agent.disposable_routes import (
    DisposableRoutes,
    project_native_routes,
)
from lowerduckpond_static_host_agent.host_restore_fence import require_fence_policy
from lowerduckpond_static_host_agent.host_restore_gate import GATE_SCHEMA
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.installed_routing import (
    CUTOVER_FORMAT,
    PROJECTION,
    ROLE,
    cutover_filename,
)

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_diagnostic_store import Attempt, publish, read
from scripts.m3_12_droplet_native import AdapterInputs, inspect_host, require_endpoint
from scripts.m3_12_droplet_ssh import Endpoint, ReadExecutor, observe_restore_fence

SOURCE_PHASES = frozenset(
    {
        "dark-stage",
        "dark-repeat",
        "launch",
        "enabled-converge",
        "enabled-repeat",
        "rollback-resume",
        "source-reboot",
        "functional",
        "edge",
        "capacity",
        "backup-fence",
    }
)
RESTORE_PHASES = frozenset({"cold-install", "restore", "restore-reboot-closed", "restore-reboot"})
POLICY_FORMAT = "lowerduckpond-m3-12-disposable-routing-policy-v1"


@dataclass(frozen=True)
class PreparedRouting:
    policy: DisposableRoutes
    role: str
    target_sha256: str
    boot_sha256: str

    def document(self) -> Document:
        return {
            "format": "lowerduckpond-m3-12-disposable-routing-role-v1",
            "routingSha256": self.policy.sha256,
            "role": self.role,
            "targetSha256": self.target_sha256,
            "bootSha256": self.boot_sha256,
        }


def reviewed_routing_policy(scope: Document, raw: bytes) -> DisposableRoutes:
    """Reopen the exact site policy from an independently admitted allocation."""
    require(sha256(raw).hexdigest() == scope["sitePolicySha256"], "droplet-routing-policy-changed")
    try:
        value = decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
        require(
            set(value) == {"format", "runId", "invocationId", "platform", "tenantScope", "tenants"}
            and value["format"] == POLICY_FORMAT
            and encode(value) == raw
            and value["runId"] == scope["runId"]
            and value["invocationId"] == scope["invocationId"]
            and value["platform"] == scope["resources"]["edge"]["platform"]["source"]["name"]
            and value["tenantScope"] == scope["resources"]["edge"]["tenant"]["source"]["name"]
            and isinstance(value["tenants"], list),
            "droplet-routing-policy-changed",
        )
        rows = value["tenants"]
        assert isinstance(rows, list)  # noqa: S101 - checked above
        origins = []
        for row in rows:
            require(
                isinstance(row, dict)
                and set(row) == {"tenantId", "origin"}
                and all(isinstance(item, str) for item in row.values()),
                "droplet-routing-tenant-invalid",
            )
            origins.append((row["tenantId"], row["origin"]))
        hosts = scope["resources"]["hosts"]
        return DisposableRoutes(
            allocation_sha256=digest(scope),
            run_id=scope["runId"],
            invocation_id=scope["invocationId"],
            source_target=digest(hosts["source"]["target"]),
            restore_target=digest(hosts["restore"]["target"]),
            platform=scope["resources"]["edge"]["platform"]["source"]["name"],
            tenant_scope=scope["resources"]["edge"]["tenant"]["source"]["name"],
            tenants=tuple(origins),
        )
    except ContractError, CaddyRouteError:
        raise ValidationError("droplet-routing-policy-invalid") from None


def prepare_routing(
    inputs: AdapterInputs, endpoint: Endpoint, policy_raw: bytes, execute: ReadExecutor
) -> PreparedRouting:
    """Bind one presentation to the exact admitted role and fresh full guest identity."""
    role = endpoint.allocation.role
    require(role in {"source", "restore"}, "droplet-routing-role-changed")
    scope, action = inputs.open(SOURCE_PHASES if role == "source" else RESTORE_PHASES)
    host = require_endpoint(endpoint, scope, action)
    policy = reviewed_routing_policy(scope, policy_raw)
    observed = inspect_host(inputs, endpoint, execute)
    return PreparedRouting(policy, role, digest(host["target"]), observed["bootSha256"])


def observe_fence(  # noqa: PLR0913 - reviewed role, pinned transport and reboot identity
    inputs: AdapterInputs,
    endpoint: Endpoint,
    prepared: PreparedRouting,
    policy_raw: bytes,
    execute: ReadExecutor,
    *,
    completed_restore_id: str | None = None,
) -> Document:
    """Get current gate/firewall state over the existing independently pinned SSH path."""
    role = endpoint.allocation.role
    require(role in {"source", "restore"}, "droplet-routing-role-changed")
    phases = frozenset({"backup-fence"}) if role == "source" else RESTORE_PHASES
    scope, action = inputs.open(phases)
    host = require_endpoint(endpoint, scope, action)
    require(
        prepared.policy == reviewed_routing_policy(scope, policy_raw)
        and prepared.role == role
        and prepared.target_sha256 == digest(host["target"]),
        "droplet-routing-policy-changed",
    )
    record = observe_restore_fence(
        endpoint, executor=execute, completed_restore_id=completed_restore_id
    )
    guest, enrolled = record["observation"], host["enrollment"]
    require(
        guest["bootSha256"] == prepared.boot_sha256
        and guest["hostIdentity"]
        == {key: enrolled[key] for key in ("machineSha256", "systemUuidSha256", "hostKeySha256")},
        "droplet-routing-fence-host-changed",
    )
    return {
        "routingSha256": prepared.policy.sha256,
        "role": role,
        "targetSha256": prepared.target_sha256,
        "bootSha256": prepared.boot_sha256,
        "gateSha256": record["gateSha256"],
        "ingressClosed": record["ingressClosed"],
        "caddyInactive": record["caddyInactive"],
    }


@dataclass(frozen=True)
class RoutingEndpoint:
    inputs: AdapterInputs
    endpoint: Endpoint
    prepared: PreparedRouting


def verify_cutover(  # noqa: PLR0913 - native fence and pinned executor are independent inputs
    source_host: RoutingEndpoint,
    restore_host: RoutingEndpoint,
    *,
    policy_raw: bytes,
    restore: RestoreInputs,
    fence: bytes,
    execute: ReadExecutor,
) -> Document:
    """Read both pinned boots, then seal proof for an already fenced source."""
    inputs = restore_host.inputs
    source = source_host.prepared
    destination = restore_host.prepared
    require(
        source_host.inputs.attempt.directory == inputs.attempt.directory
        and source_host.endpoint.allocation.role == "source"
        and restore_host.endpoint.allocation.role == "restore",
        "droplet-routing-cutover-binding-changed",
    )
    scope, action = inputs.open(RESTORE_PHASES)
    require(
        source.role == "source"
        and destination.role == "restore"
        and source.policy
        == destination.policy
        == restore.disposable_routing
        == reviewed_routing_policy(scope, policy_raw)
        and source.target_sha256 == source.policy.source_target
        and destination.target_sha256 == source.policy.restore_target
        and destination.target_sha256 == action["targets"]["restore"],
        "droplet-routing-cutover-binding-changed",
    )
    reference = action["prerequisites"]["backup-fence"]
    receipt = read(inputs.attempt.directory, reference["file"])
    native = require_fence_policy(fence, restore)
    hosts = scope["resources"]["hosts"]
    binding = restore.droplet_scope
    require(
        digest(receipt) == reference["sha256"]
        and sha256(fence).hexdigest() == receipt["evidence"]["sourceFence"]
        and binding is not None
        and binding["runId"] == source.policy.run_id
        and binding["sourceTargetSha256"] == source.target_sha256
        and binding["destinationTargetSha256"] == destination.target_sha256
        and all(
            sha256(str(restore.document[key]).encode("ascii")).hexdigest()
            == hosts[role]["enrollment"]["machineSha256"]
            for role, key in (("source", "sourceMachineId"), ("restore", "destinationMachineId"))
        ),
        "droplet-routing-native-fence-changed",
    )
    gate = native["sourceGateDigest"]
    assert isinstance(gate, dict) and gate["format"] == GATE_SCHEMA  # noqa: S101 - verified above
    source_fence = observe_fence(
        source_host.inputs, source_host.endpoint, source, policy_raw, execute
    )
    destination_fence = observe_fence(
        inputs,
        restore_host.endpoint,
        destination,
        policy_raw,
        execute,
        completed_restore_id=(
            restore.restore_id
            if action["phase"] in {"restore-reboot-closed", "restore-reboot"}
            else None
        ),
    )
    require(
        encode(source_fence)
        == encode(
            {
                "routingSha256": source.policy.sha256,
                "role": "source",
                "targetSha256": source.target_sha256,
                "bootSha256": source.boot_sha256,
                "gateSha256": gate["value"],
                "ingressClosed": True,
                "caddyInactive": True,
            }
        )
        and destination_fence.keys() == source_fence.keys()
        and destination_fence["routingSha256"] == source.policy.sha256
        and destination_fence["role"] == "restore"
        and destination_fence["targetSha256"] == destination.target_sha256
        and destination_fence["bootSha256"] == destination.boot_sha256
        and destination_fence["gateSha256"] == gate["value"]
        and destination_fence["ingressClosed"] is True
        and type(destination_fence["caddyInactive"]) is bool,
        "droplet-routing-fence-unproven",
    )
    result = {
        "format": CUTOVER_FORMAT,
        "routingSha256": source.policy.sha256,
        "allocationSha256": digest(scope),
        "sourceTargetSha256": source.target_sha256,
        "restoreTargetSha256": destination.target_sha256,
        "sourceBootSha256": source.boot_sha256,
        "restoreBootSha256": destination.boot_sha256,
        "restoreId": restore.restore_id,
        "sourceFenceSha256": sha256(fence).hexdigest(),
    }
    _seal(
        inputs.attempt,
        "routing-source-fenced.json",
        {
            "routingSha256": source.policy.sha256,
            "sourceTargetSha256": source.target_sha256,
            "restoreTargetSha256": destination.target_sha256,
            "sourceFenceSha256": result["sourceFenceSha256"],
        },
    )
    _seal(inputs.attempt, f"routing-cutover-{digest(result)}.json", result)
    return result


def _seal(attempt: Attempt, name: str, record: Document) -> None:
    try:
        publish(attempt.directory, name, record)
    except FileExistsError:
        require(read(attempt.directory, name) == record, "droplet-routing-original-changed")


def require_prepared_cutover(
    inputs: AdapterInputs, destination: PreparedRouting, cutover: Document
) -> None:
    _, intent = inputs.open(RESTORE_PHASES)
    try:
        retained = read(inputs.attempt.directory, f"routing-cutover-{digest(cutover)}.json")
        fence = read(inputs.attempt.directory, "routing-source-fenced.json")
    except FileNotFoundError:
        raise ValidationError("droplet-routing-cutover-missing") from None
    require(
        retained == cutover
        and cutover["allocationSha256"] == intent["allocationSha256"]
        and cutover["routingSha256"] == destination.policy.sha256
        and destination.role == "restore"
        and cutover["restoreTargetSha256"]
        == destination.target_sha256
        == intent["targets"]["restore"]
        and cutover["restoreBootSha256"] == destination.boot_sha256
        and fence
        == {
            key: cutover[key]
            for key in (
                "routingSha256",
                "sourceTargetSha256",
                "restoreTargetSha256",
                "sourceFenceSha256",
            )
        },
        "droplet-routing-cutover-binding-changed",
    )


def prepare_installed_routing_delivery(
    inputs: AdapterInputs,
    prepared: PreparedRouting,
    policy_raw: bytes,
    *,
    cutover: Document | None = None,
) -> dict[str, bytes]:
    """Return fixed records from reviewed preparation without contacting either host."""
    _require_projection_admission(inputs, prepared, policy_raw, cutover)
    records = {ROLE: encode(prepared.policy.role_document(prepared.role))}
    if prepared.role == "source":
        records[PROJECTION] = encode(prepared.policy.document())
    elif cutover is not None:
        records[cutover_filename(prepared.boot_sha256)] = encode(cutover)
    return records


def prepare_projected_routes[Routes: PlatformOnlyCaddyRoutes | TenantCaddyRoutes](
    inputs: AdapterInputs,
    prepared: PreparedRouting,
    policy_raw: bytes,
    logical: Routes,
    *,
    cutover: Document | None = None,
) -> Routes:
    """Prepare a scoped Caddy payload while preserving the logical native generation."""
    _require_projection_admission(inputs, prepared, policy_raw, cutover)
    return project_native_routes(logical, prepared.policy)


def _require_projection_admission(
    inputs: AdapterInputs, prepared: PreparedRouting, policy_raw: bytes, cutover: Document | None
) -> None:
    role = prepared.role
    require(role in {"source", "restore"}, "droplet-routing-role-changed")
    scope, intent = inputs.open(SOURCE_PHASES if role == "source" else RESTORE_PHASES)
    require(
        prepared.policy == reviewed_routing_policy(scope, policy_raw)
        and prepared.target_sha256 == intent["targets"][role],
        "droplet-routing-policy-changed",
    )
    if role == "restore":
        if cutover is None:
            raise ValidationError("droplet-routing-cutover-missing")
        require_prepared_cutover(inputs, prepared, cutover)
    else:
        require(
            cutover is None
            and not os.path.lexists(inputs.attempt.directory / "routing-source-fenced.json"),
            "droplet-routing-source-fenced",
        )
