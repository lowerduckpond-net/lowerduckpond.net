"""Join an approved P4 saved plan, isolated state and provider readback offline."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address
from typing import Literal, cast
from uuid import UUID

from lowerduckpond_static_contracts import decode_json_object

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    decode,
    digest,
    require,
)
from scripts.m3_12_droplet_inventory import ApprovedAllocation, ProviderIdentity
from scripts.m3_12_droplet_plan import (
    CLOUD_INIT_OUTPUT,
    FIREWALL,
    HOST,
    HOST_FIELDS,
    MEMBERSHIP,
    PLAN_OUTPUTS,
    PROVIDER,
    ApprovedHostPlan,
    _droplet_id,
    _firewall,
    _resource_index,
)
from scripts.m3_12_droplet_plan_evidence import (
    BACKEND_FILES,
    InitialPlanEvidence,
    verify_saved_initial_host_plan,
)


@dataclass(frozen=True)
class ReviewedReadback:
    plan: ApprovedHostPlan
    configuration_sha256: str
    plan_evidence_sha256: str
    state_json_sha256: str
    state_key: str


def bind_initial_allocation(
    review: ReviewedReadback,
    plan: InitialPlanEvidence,
    state_json: bytes,
    provider: Document,
    production_exclusions: bytes,
) -> ApprovedAllocation:
    """Join state with independent provider facts, including the exact Droplet GET."""
    scope = review.plan
    require(
        review.state_key == f"qualification/m3-12/{scope.run_id}/{scope.role}.tfstate"
        and sha256(state_json).hexdigest() == review.state_json_sha256,
        "droplet-readback-review-changed",
    )
    require(
        plan.configuration.keys() >= BACKEND_FILES, "droplet-readback-backend-evidence-required"
    )
    verify_saved_initial_host_plan(
        plan,
        scope,
        reviewed_configuration_sha256=review.configuration_sha256,
        reviewed_evidence_sha256=review.plan_evidence_sha256,
    )
    state = decode_json_object(state_json, maximum_bytes=MAX_RECORD_BYTES)
    excluded = decode(production_exclusions, "droplet-production-exclusions")
    try:
        identity, allocation = _state_identity(scope, state, provider)
        return _enrolled(review, identity, allocation, excluded)
    except AttributeError, KeyError, TypeError:
        raise ValidationError("invalid-droplet-readback") from None


def _state_identity(
    scope: ApprovedHostPlan, state: Document, provider: Document
) -> tuple[ProviderIdentity, Document]:
    values = state["values"]
    root = values["root_module"]
    output = values["outputs"]["allocation"]
    require(
        not root.get("child_modules")
        and values["outputs"].keys() == PLAN_OUTPUTS
        and output["sensitive"] is False,
        "droplet-readback-state-resources-changed",
    )
    require(
        values["outputs"][CLOUD_INIT_OUTPUT]
        == {
            "sensitive": False,
            "type": "string",
            "value": scope.cloud_init_sha256,
        },
        "droplet-readback-cloud-init-changed",
    )
    resources = _resource_index(root["resources"])
    require(
        all(row["provider_name"] == PROVIDER for row in resources.values()),
        "droplet-readback-provider-changed",
    )
    host = resources[HOST]["values"]
    firewall = resources[FIREWALL]["values"]
    membership = resources[MEMBERSHIP]["values"]
    host_id = _droplet_id(host)
    if host_id is None:
        raise ValidationError("droplet-readback-id-unavailable")
    ipv4 = IPv4Address(host["ipv4_address"])
    require(
        ipv4.is_global
        and not ipv4.is_multicast
        and host["name"] == scope.name
        and not host.get("tags")
        and host.get("volume_ids") == []
        and all(
            type(host[key]) is type(value) and host[key] == value
            for key, value in HOST_FIELDS.items()
        ),
        "droplet-readback-host-changed",
    )
    urn = f"do:droplet:{host_id}"
    require(
        host["urn"] == urn
        and membership["project"] == scope.project_id
        and membership["resources"] == [urn]
        and firewall["droplet_ids"] == [host_id]
        and str(UUID(firewall["id"])) == firewall["id"],
        "droplet-readback-attachment-changed",
    )
    _firewall(firewall, scope)
    allocation = {
        "run_id": scope.run_id,
        "role": scope.role,
        "project_id": scope.project_id,
        "droplet_id": host_id,
        "urn": urn,
        "ipv4": str(ipv4),
        "firewall": firewall["id"],
    }
    emitted = output["value"]
    require(
        {**emitted, "droplet_id": _droplet_id({"id": emitted["droplet_id"]})} == allocation,
        "droplet-readback-output-changed",
    )
    _provider_identity(scope, provider, allocation, firewall)
    return ProviderIdentity(
        sha256(scope.project_id.encode()).hexdigest(), host_id, str(ipv4)
    ), allocation


def _provider_identity(
    scope: ApprovedHostPlan, provider: Document, allocation: Document, firewall: Document
) -> None:
    require(
        set(provider) == {"droplet", "firewalls", "projectMembership"}
        and provider["droplet"]
        == {
            "id": allocation["droplet_id"],
            "name": scope.name,
            "ipv4": allocation["ipv4"],
            "status": "active",
            "volume_ids": [],
            **{name: HOST_FIELDS[name] for name in ("region", "image", "size", "ipv6", "backups")},
        }
        and provider["projectMembership"]
        == {
            "project": scope.project_id,
            "resources": [allocation["urn"]],
        }
        and len(provider["firewalls"]) == 1,
        "droplet-readback-provider-identity-changed",
    )
    observed = provider["firewalls"][0]
    outbound_fields = {"protocol", "port_range", "destination_addresses"}
    if scope.source_fixture_egress_isolated:
        outbound_fields.add("action")
    require(
        set(observed) == {"id", "name", "droplet_ids", "inbound_rule", "outbound_rule", "settled"}
        and observed["id"] == firewall["id"]
        and observed["droplet_ids"] == firewall["droplet_ids"]
        and observed["settled"] is True
        and all(
            set(row) == {"protocol", "port_range", "source_addresses"}
            for row in observed["inbound_rule"]
        )
        and all(set(row) == outbound_fields for row in observed["outbound_rule"]),
        "droplet-readback-provider-firewall-changed",
    )
    _firewall(observed, scope)


def _enrolled(
    review: ReviewedReadback, identity: ProviderIdentity, allocation: Document, exclusions: Document
) -> ApprovedAllocation:
    approved = review.plan
    identity_digest = digest(identity.document())
    require(
        identity.droplet_id not in exclusions["dropletIds"]
        and identity.ipv4 not in exclusions["addresses"]
        and not {
            identity.project_id_sha256,
            identity_digest,
            review.state_json_sha256,
        }.intersection(exclusions["identityDigests"]),
        "production-crossover",
    )
    scope = {
        "runId": approved.run_id,
        "role": approved.role,
        "stateKeySha256": sha256(review.state_key.encode()).hexdigest(),
    }
    role = approved.role
    if role not in ("source", "restore", "fresh"):
        raise ValidationError("droplet-readback-role-changed")
    return ApprovedAllocation(
        run_id=approved.run_id,
        role=cast(Literal["source", "restore", "fresh"], role),
        state_sha256=review.state_json_sha256,
        allocation_sha256=digest(
            {
                **scope,
                "planEvidenceSha256": review.plan_evidence_sha256,
                "stateSha256": review.state_json_sha256,
                "allocation": allocation,
            }
        ),
        inventory_sha256=digest({**scope, "providerIdentitySha256": identity_digest}),
        transaction_namespace_sha256=digest(scope),
        identity=identity,
    )
