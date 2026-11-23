"""Review teardown and reconcile observations for one initial P4 host allocation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha256

from lowerduckpond_static_contracts import ContractError, decode_json_object

from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    Document,
    ValidationError,
    digest,
    encode,
    require,
)
from scripts.m3_12_droplet_inventory import ApprovedAllocation
from scripts.m3_12_droplet_plan import CONFIGURATION_FIELDS, PROVIDER, _resource_index
from scripts.m3_12_droplet_provider import ReviewedReadback, bind_initial_allocation


@dataclass(frozen=True)
class InitialRetirement:
    """An independently reviewed allocation, earlier than edge or storage work."""

    allocation: ApprovedAllocation
    state_key: str
    firewall_id: str
    urn: str
    _resources: tuple[tuple[str, bytes], ...] = field(repr=False)


def _document(raw: bytes) -> Document:
    try:
        return decode_json_object(raw, maximum_bytes=MAX_RECORD_BYTES)
    except ContractError:
        raise ValidationError("invalid-droplet-cleanup-document") from None


def capture_initial_retirement(
    review: ReviewedReadback,
    plan_json: bytes,
    state_json: bytes,
    provider: Document,
    production_exclusions: bytes,
) -> InitialRetirement:
    allocation = bind_initial_allocation(
        review, plan_json, state_json, provider, production_exclusions
    )
    values = _document(state_json)["values"]
    allocation_output = values["outputs"]["allocation"]["value"]
    resources = _resource_index(values["root_module"]["resources"])
    return InitialRetirement(
        allocation=allocation,
        state_key=review.state_key,
        firewall_id=allocation_output["firewall"],
        urn=allocation_output["urn"],
        _resources=tuple((address, encode(row["values"])) for address, row in resources.items()),
    )


def verify_initial_destroy_plan(
    original: InitialRetirement,
    plan_json: bytes,
    *,
    reviewed_sha256: str,
    state_key: str,
) -> None:
    """Allow only removal of the three exact reviewed resources from that role state."""
    require(
        state_key == original.state_key and sha256(plan_json).hexdigest() == reviewed_sha256,
        "droplet-cleanup-plan-changed",
    )
    require(
        {address for address, _ in original._resources} == set(CONFIGURATION_FIELDS)
        and len(original._resources) == len(CONFIGURATION_FIELDS),
        "droplet-cleanup-original-resource-set-changed",
    )
    plan = _document(plan_json)
    try:
        prior = plan["prior_state"]["values"]["root_module"]
        planned = plan["planned_values"]
        require(
            plan["errored"] is False
            and plan.get("complete", True) is True
            and not plan.get("resource_drift")
            and not plan.get("deferred_changes")
            and not prior.get("child_modules")
            and _empty_values(planned),
            "droplet-cleanup-plan-scope-changed",
        )
        rows = _resource_index(prior["resources"])
        changes = _resource_index(plan["resource_changes"])
        outputs = plan.get("output_changes", {})
        require(
            set(outputs) <= {"allocation"}
            and all(
                output["actions"] == ["delete"] and output["after"] is None
                for output in outputs.values()
            ),
            "droplet-cleanup-output-changed",
        )
        for address, expected in original._resources:
            row = rows[address]
            change = changes[address]["change"]
            require(
                row["provider_name"] == changes[address]["provider_name"] == PROVIDER
                and encode(row["values"]) == encode(change["before"]) == expected
                and change["actions"] == ["delete"]
                and change["after"] is None
                and change.get("after_unknown") in ({}, None, False)
                and not change.get("importing")
                and not change.get("replace_paths"),
                "droplet-cleanup-resource-changed",
            )
    except AttributeError, KeyError, TypeError:
        raise ValidationError("invalid-droplet-cleanup-plan") from None


def _empty_values(values: object) -> bool:
    if not isinstance(values, dict):
        return False
    root = values.get("root_module", {})
    return (
        set(values) <= {"root_module", "outputs"}
        and values.get("outputs", {}) == {}
        and isinstance(root, dict)
        and set(root) <= {"resources", "child_modules"}
        and root.get("resources", []) == []
        and root.get("child_modules", []) == []
    )


def retain_empty_state(raw: bytes) -> str:
    """Keep exact empty-state bytes only when all fields are safe to retain."""
    state = _document(raw)
    require(
        set(state) <= {"format_version", "terraform_version", "values", "checks"}
        and all(
            isinstance(version := state.get(key), str)
            and re.fullmatch(r"[0-9]{1,4}(\.[0-9]{1,4}){1,3}", version) is not None
            for key in ("format_version", "terraform_version")
        )
        and _empty_values(state.get("values", {}))
        and state.get("checks") in (None, []),
        "droplet-cleanup-unsafe-state-evidence",
    )
    return raw.decode("utf-8")


def reconcile_initial_retirement(
    original: InitialRetirement, state_json: bytes, readback: Document
) -> Document:
    """Classify exact independent absence readback without attempting cleanup."""
    identity = original.allocation.identity
    require(
        set(readback)
        == {
            "stateKey",
            "allocationSha256",
            "stateSha256",
            "projectIdSha256",
            "dropletId",
            "firewallId",
            "projectUrn",
            "droplet",
            "firewall",
            "projectMembership",
        }
        and readback["stateKey"] == original.state_key
        and readback["stateSha256"] == sha256(state_json).hexdigest()
        and readback["allocationSha256"] == original.allocation.allocation_sha256
        and readback["projectIdSha256"] == identity.project_id_sha256
        and type(readback["dropletId"]) is int
        and readback["dropletId"] == identity.droplet_id
        and readback["firewallId"] == original.firewall_id
        and readback["projectUrn"] == original.urn,
        "droplet-cleanup-readback-scope-changed",
    )
    states = [readback[key] for key in ("droplet", "firewall", "projectMembership")]
    require(
        all(state in ("absent", "present", "unverified") for state in states),
        "droplet-cleanup-readback-status-invalid",
    )
    observed_state = _document(state_json)
    version = observed_state.get("format_version")
    require(
        type(version) is str
        and version.startswith("1.")
        and isinstance(observed_state.get("terraform_version"), str)
        and set(observed_state) <= {"format_version", "terraform_version", "values", "checks"},
        "invalid-droplet-cleanup-state",
    )
    state_is_empty = _empty_values(observed_state.get("values", {}))
    return {
        "format": "lowerduckpond-m3-12-initial-retirement-observation-v1",
        "allocationSha256": original.allocation.allocation_sha256,
        "stateSha256": sha256(state_json).hexdigest(),
        "readbackSha256": digest(readback),
        "outcome": "absent"
        if state_is_empty and all(state == "absent" for state in states)
        else "unresolved",
    }
