"""Synthetic offline plan-scope vectors with no provider or state access."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from hashlib import sha1, sha256

import pytest

from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_droplet_cleanup import (
    InitialRetirement,
    capture_initial_retirement,
    reconcile_initial_retirement,
    verify_initial_destroy_plan,
)
from scripts.m3_12_droplet_empty_state import (
    AuthenticatedStateSnapshot,
    capture_empty_state_evidence,
)
from scripts.m3_12_droplet_plan import (
    CLOUD_INIT_OUTPUT,
    CONFIGURATION_FIELDS,
    EGRESS,
    FIREWALL,
    HOST,
    HOST_FIELDS,
    MEMBERSHIP,
    PINNED_PROVIDER,
    PROVIDER,
    ApprovedHostPlan,
)
from scripts.m3_12_droplet_plan import (
    verify_initial_host_plan as _verify_initial_host_plan,
)
from scripts.m3_12_droplet_plan_evidence import (
    BACKEND_FILES,
    INPUTS,
    OFFLINE_FILES,
    PLAN_VARIABLES,
    ROOT,
    InitialPlanEvidence,
    configuration_digest,
)
from scripts.m3_12_droplet_provider import ReviewedReadback, bind_initial_allocation

CLOUD_INIT = "#cloud-config\nssh_pwauth: false\n"


def verify_initial_host_plan(plan: Document, scope: ApprovedHostPlan) -> None:
    _verify_initial_host_plan(plan, scope, cloud_init=CLOUD_INIT.encode())


def _approved_output(scope: ApprovedHostPlan) -> Document:
    return {"sensitive": False, "type": "string", "value": scope.cloud_init_sha256}


def _review(
    plan: Document, scope: ApprovedHostPlan, state: bytes
) -> tuple[ReviewedReadback, InitialPlanEvidence]:
    files = dict.fromkeys(OFFLINE_FILES | BACKEND_FILES, b"synthetic reviewed file")
    files[INPUTS] = encode(dict.fromkeys(PLAN_VARIABLES, "synthetic reviewed input"))
    evidence = InitialPlanEvidence(
        files,
        encode({"encryption_version": "v0", "encrypted_data": "c3ludGhldGlj"}),
        encode(plan),
        CLOUD_INIT.encode(),
    )
    return (
        ReviewedReadback(
            scope,
            configuration_digest(files),
            evidence.evidence_sha256,
            sha256(state).hexdigest(),
            f"qualification/m3-12/{scope.run_id}/{scope.role}.tfstate",
        ),
        evidence,
    )


@pytest.fixture
def reviewed_plan() -> tuple[Document, ApprovedHostPlan]:
    scope = ApprovedHostPlan(
        run_id="00000000-0000-7000-8000-000000000001",
        role="restore",
        project_id="00000000-0000-4000-8000-000000000002",
        ssh_key_fingerprint="00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
        admin_cidrs=("192.0.2.14/32",),
        cloud_init_sha256=sha256(CLOUD_INIT.encode()).hexdigest(),
    )
    config = []
    for address, fields in CONFIGURATION_FIELDS.items():
        kind, name = address.split(".")
        config.append(
            {
                "address": address,
                "type": kind,
                "name": name,
                "mode": "managed",
                "provider_config_key": "digitalocean",
                "expressions": {field: {} for field in fields},
            }
        )
    config[1]["expressions"]["droplet_ids"] = {"references": [f"{HOST}.id", HOST]}
    config[2]["expressions"]["resources"] = {"references": [f"{HOST}.urn", HOST]}
    changes = []
    for resource, after in zip(
        config,
        (
            {
                **HOST_FIELDS,
                "name": scope.name,
                "user_data": sha1(CLOUD_INIT.encode(), usedforsecurity=False).hexdigest(),
                "ssh_keys": [scope.ssh_key_fingerprint],
                "id": "101",
            },
            {
                "name": scope.name,
                "droplet_ids": [101],
                "inbound_rule": [
                    {
                        "action": "allow",
                        "protocol": "tcp",
                        "port_range": "22",
                        "source_addresses": ["192.0.2.14/32"],
                    }
                ],
                "outbound_rule": [
                    {
                        "action": "allow",
                        "protocol": protocol,
                        "port_range": port,
                        "destination_addresses": ["0.0.0.0/0", "::/0"],
                    }
                    for protocol, port in sorted(EGRESS)
                ],
            },
            {"project": scope.project_id, "resources": ["do:droplet:101"]},
        ),
        strict=True,
    ):
        changes.append(
            {
                **{key: resource[key] for key in ("address", "mode", "name", "type")},
                "provider_name": PROVIDER,
                "change": {"actions": ["create"], "before": None, "after": after},
            }
        )
    return {
        "errored": False,
        "variables": {
            "qualification_run_id": {"value": scope.run_id},
            "fixture_role": {"value": scope.role},
        },
        "configuration": {
            "root_module": {"resources": config},
            "provider_config": {"digitalocean": dict(PINNED_PROVIDER)},
        },
        "planned_values": {
            "outputs": {"allocation": {}, CLOUD_INIT_OUTPUT: _approved_output(scope)}
        },
        "output_changes": {
            "allocation": {},
            CLOUD_INIT_OUTPUT: {
                "actions": ["create"],
                "before": None,
                "after": scope.cloud_init_sha256,
                "after_unknown": False,
                "before_sensitive": False,
                "after_sensitive": False,
            },
        },
        "resource_changes": changes,
    }, scope


def test_droplet_plan_accepts_only_the_reviewed_host_and_its_exact_attachments(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> None:
    plan, scope = reviewed_plan
    verify_initial_host_plan(plan, scope)
    host, firewall, membership = [resource["change"] for resource in plan["resource_changes"]]
    host["after"].pop("id")
    host["after_unknown"] = {"id": True, "volume_ids": True}
    firewall["after"]["droplet_ids"] = [None]
    firewall["after_unknown"] = {"droplet_ids": [True]}
    membership["after"].pop("resources")
    membership["after_unknown"] = {"resources": True}
    verify_initial_host_plan(plan, scope)

    firewall["after"]["droplet_ids"] = [999, None]
    with pytest.raises(ValidationError, match="droplet-plan-attachment-changed"):
        verify_initial_host_plan(plan, scope)


def test_plan_accepts_only_the_pinned_provider_computed_volume_shape(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> None:
    baseline, scope = reviewed_plan
    host = baseline["resource_changes"][0]["change"]
    host["after_unknown"] = {"volume_ids": True}

    plan = deepcopy(baseline)
    plan["configuration"]["provider_config"]["digitalocean"]["version_constraint"] = "2.107.0"
    with pytest.raises(ValidationError, match="droplet-plan-provider-changed"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(baseline)
    plan["configuration"]["root_module"]["resources"][0]["expressions"]["volume_ids"] = {
        "constant_value": []
    }
    with pytest.raises(ValidationError, match="droplet-plan-configuration-changed"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(baseline)
    plan["resource_changes"][0]["change"]["after_unknown"]["volume_ids"] = [True]
    with pytest.raises(ValidationError, match="droplet-plan-unsafe-unknown"):
        verify_initial_host_plan(plan, scope)

    host["after"]["volume_ids"] = []
    with pytest.raises(ValidationError, match="droplet-plan-unsafe-unknown"):
        verify_initial_host_plan(baseline, scope)


@pytest.mark.parametrize(
    ("address", "field", "value", "category"),
    [
        (HOST, "user_data", "1" * 40, "droplet-plan-provider-cloud-init-changed"),
        (HOST, "public_networking", False, "droplet-plan-host-changed"),
        (HOST, "volume_ids", ["unowned"], "droplet-plan-host-changed"),
        (FIREWALL, "droplet_ids", [999], "droplet-plan-attachment-changed"),
        (FIREWALL, "tags", ["production"], "droplet-plan-firewall-target-changed"),
        (FIREWALL, "inbound_rule", [], "droplet-plan-ingress-changed"),
        (
            FIREWALL,
            "inbound_rule",
            [{"protocol": "tcp", "port_range": "443", "source_addresses": ["192.0.2.14/32"]}],
            "droplet-plan-ingress-changed",
        ),
        (MEMBERSHIP, "project", "production", "droplet-plan-project-changed"),
        (MEMBERSHIP, "resources", ["do:droplet:999"], "droplet-plan-attachment-changed"),
    ],
)
def test_droplet_plan_refuses_foreign_host_scope(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
    address: str,
    field: str,
    value: object,
    category: str,
) -> None:
    plan, scope = reviewed_plan
    target = next(item for item in plan["resource_changes"] if item["address"] == address)
    target["change"]["after"][field] = value
    with pytest.raises(ValidationError, match=category):
        verify_initial_host_plan(plan, scope)


@pytest.mark.parametrize(
    ("direction", "category"),
    [
        ("inbound_rule", "droplet-plan-ingress-changed"),
        ("outbound_rule", "droplet-plan-egress-changed"),
    ],
)
@pytest.mark.parametrize("action", ["deny", "", None])
def test_droplet_plan_rejects_unexpected_firewall_action(
    reviewed_plan: tuple[Document, ApprovedHostPlan], direction: str, category: str, action: object
) -> None:
    plan, scope = reviewed_plan
    firewall = next(item for item in plan["resource_changes"] if item["address"] == FIREWALL)
    firewall["change"]["after"][direction][0]["action"] = action
    with pytest.raises(ValidationError, match=category):
        verify_initial_host_plan(plan, scope)


def test_droplet_plan_rejects_existing_changes_imports_and_unreviewed_graph(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> None:
    original, scope = reviewed_plan

    plan = deepcopy(original)
    plan["prior_state"] = {"values": {"root_module": {"resources": [{"address": HOST}]}}}
    with pytest.raises(ValidationError, match="droplet-plan-state-is-not-empty"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["resource_changes"][0]["change"]["importing"] = {"id": "101"}
    with pytest.raises(ValidationError, match="droplet-plan-is-not-creation"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["resource_changes"].append({"address": "digitalocean_reserved_ip.example"})
    with pytest.raises(ValidationError, match="droplet-plan-resource-set-changed"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["configuration"]["root_module"]["resources"][1]["expressions"]["droplet_ids"] = {
        "constant_value": [101]
    }
    with pytest.raises(ValidationError, match="invalid-droplet-plan"):
        verify_initial_host_plan(plan, scope)

    plan = deepcopy(original)
    plan["resource_changes"][1]["change"]["after_unknown"] = {
        "inbound_rule": [{"source_addresses": [True]}]
    }
    with pytest.raises(ValidationError, match="droplet-plan-unsafe-unknown"):
        verify_initial_host_plan(plan, scope)


@pytest.fixture
def readback(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
) -> tuple[Document, Document, Document]:
    plan, scope = reviewed_plan
    resources = [
        {
            **{key: row[key] for key in ("address", "mode", "name", "type", "provider_name")},
            "values": deepcopy(row["change"]["after"]),
        }
        for row in plan["resource_changes"]
    ]
    host, firewall, membership = [row["values"] for row in resources]
    host.update(ipv4_address="11.1.2.11", urn="do:droplet:101", volume_ids=[])
    firewall["id"] = "00000000-0000-4000-8000-000000000003"
    state = {
        "format_version": "1.0",
        "values": {
            "root_module": {"resources": resources},
            "outputs": {
                CLOUD_INIT_OUTPUT: _approved_output(scope),
                "allocation": {
                    "sensitive": False,
                    "value": {
                        "run_id": scope.run_id,
                        "role": scope.role,
                        "project_id": scope.project_id,
                        "droplet_id": "101",
                        "urn": host["urn"],
                        "ipv4": host["ipv4_address"],
                        "firewall": firewall["id"],
                    },
                },
            },
        },
    }
    observed_firewall = deepcopy(firewall)
    for direction in ("inbound_rule", "outbound_rule"):
        for rule in observed_firewall[direction]:
            rule.pop("action")
    observed = {
        "droplet": {
            "id": 101,
            "name": scope.name,
            "ipv4": host["ipv4_address"],
            "status": "active",
            "volume_ids": [],
            **{key: host[key] for key in ("region", "image", "size", "ipv6", "backups")},
        },
        "firewalls": [{**observed_firewall, "settled": True}],
        "projectMembership": deepcopy(membership),
    }
    exclusions = {
        "format": "lowerduckpond-m3-12-droplet-production-exclusions-v1",
        "dropletIds": [999],
        "addresses": ["11.1.2.20"],
        "identityDigests": ["1" * 64],
    }
    return state, observed, exclusions


def test_initial_provider_readback_joins_only_the_exact_reviewed_role(
    reviewed_plan: tuple[Document, ApprovedHostPlan], readback: tuple[Document, Document, Document]
) -> None:
    plan, scope = reviewed_plan
    state, observed, exclusions = readback
    state_raw = encode(state)
    review, original_plan = _review(plan, scope, state_raw)
    result = bind_initial_allocation(review, original_plan, state_raw, observed, encode(exclusions))
    assert result.run_id == scope.run_id
    assert result.role == scope.role
    assert result.identity.ipv4 == "11.1.2.11"
    assert result.state_sha256 == review.state_json_sha256
    with pytest.raises(ValidationError, match="droplet-readback-review-changed"):
        bind_initial_allocation(
            replace(review, state_key=review.state_key.replace("restore", "source")),
            original_plan,
            state_raw,
            observed,
            encode(exclusions),
        )
    foreign = deepcopy(state)
    foreign["values"]["root_module"]["resources"].append(
        {"address": "digitalocean_reserved_ip.foreign"}
    )
    foreign_raw = encode(foreign)
    with pytest.raises(ValidationError, match="droplet-plan-resource-set-changed"):
        bind_initial_allocation(
            replace(review, state_json_sha256=sha256(foreign_raw).hexdigest()),
            original_plan,
            foreign_raw,
            observed,
            encode(exclusions),
        )
    observed["firewalls"][0]["settled"] = False
    with pytest.raises(ValidationError, match="droplet-readback-provider-firewall-changed"):
        bind_initial_allocation(review, original_plan, state_raw, observed, encode(exclusions))
    observed["firewalls"][0]["settled"] = True
    observed["projectMembership"]["resources"] = []
    with pytest.raises(ValidationError, match="droplet-readback-provider-identity-changed"):
        bind_initial_allocation(review, original_plan, state_raw, observed, encode(exclusions))
    observed["projectMembership"]["resources"] = ["do:droplet:101"]
    exclusions["dropletIds"] = [101]
    with pytest.raises(ValidationError, match="production-crossover"):
        bind_initial_allocation(review, original_plan, state_raw, observed, encode(exclusions))


@pytest.mark.parametrize(
    ("evidence", "category"),
    [
        ("state", "droplet-readback-host-changed"),
        ("direct-get", "droplet-readback-provider-identity-changed"),
    ],
)
@pytest.mark.parametrize(
    "value",
    ["missing", None, False, "", {}, ["00000000-0000-4000-8000-000000000004"]],
)
def test_enrollment_requires_an_explicit_empty_volume_list_in_each_readback(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
    readback: tuple[Document, Document, Document],
    evidence: str,
    category: str,
    value: object,
) -> None:
    plan, scope = reviewed_plan
    state, observed, exclusions = readback
    target = (
        state["values"]["root_module"]["resources"][0]["values"]
        if evidence == "state"
        else observed["droplet"]
    )
    if value == "missing":
        target.pop("volume_ids")
    else:
        target["volume_ids"] = value
    raw_state = encode(state)
    review, original_plan = _review(plan, scope, raw_state)
    with pytest.raises(ValidationError, match=category):
        bind_initial_allocation(review, original_plan, raw_state, observed, encode(exclusions))


@pytest.mark.parametrize(
    ("fault", "category"),
    [
        ("changed-render", "droplet-plan-cloud-init-render-changed"),
        ("digest-unknown", "droplet-plan-cloud-init-digest-unverified"),
        ("digest-output-missing", "droplet-plan-cloud-init-digest-unverified"),
        ("digest-change-missing", "droplet-plan-cloud-init-digest-unverified"),
        ("digest-differs", "droplet-plan-cloud-init-digest-unverified"),
        ("different-provider-hash", "droplet-plan-provider-cloud-init-changed"),
    ],
)
def test_enrollment_verifies_both_cloud_init_checks_even_with_matching_evidence_digest(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
    readback: tuple[Document, Document, Document],
    fault: str,
    category: str,
) -> None:
    plan, scope = reviewed_plan
    state, observed, exclusions = readback
    raw_state = encode(state)
    if fault == "digest-unknown":
        plan["output_changes"][CLOUD_INIT_OUTPUT]["after_unknown"] = True
    if fault == "digest-output-missing":
        plan["planned_values"]["outputs"].pop(CLOUD_INIT_OUTPUT)
    if fault == "digest-change-missing":
        plan["output_changes"].pop(CLOUD_INIT_OUTPUT)
    if fault == "digest-differs":
        plan["output_changes"][CLOUD_INIT_OUTPUT]["after"] = "1" * 64
    if fault == "different-provider-hash":
        plan["resource_changes"][0]["change"]["after"]["user_data"] = "2" * 40
    review, evidence = _review(plan, scope, raw_state)
    if fault == "changed-render":
        evidence = replace(evidence, cloud_init=b"# independent unapproved render\n")
        review = replace(review, plan_evidence_sha256=evidence.evidence_sha256)
    with pytest.raises(ValidationError, match=category):
        bind_initial_allocation(review, evidence, raw_state, observed, encode(exclusions))


@pytest.mark.parametrize(
    ("fault", "category"),
    [
        ("configuration", "droplet-plan-producing-configuration-changed"),
        ("offline-configuration", "droplet-readback-backend-evidence-required"),
        ("plan-bytes", "droplet-plan-original-evidence-changed"),
        ("detached-json", "droplet-plan-original-evidence-changed"),
        ("missing-state-digest", "droplet-readback-state-resources-changed"),
        ("wrong-state-digest", "droplet-readback-cloud-init-changed"),
        ("plaintext", "droplet-plan-encrypted-envelope-required"),
    ],
)
def test_enrollment_reopens_the_reviewed_plan_and_state(
    reviewed_plan: tuple[Document, ApprovedHostPlan],
    readback: tuple[Document, Document, Document],
    fault: str,
    category: str,
) -> None:
    plan, scope = reviewed_plan
    state, observed, exclusions = readback
    outputs = state["values"]["outputs"]
    if fault == "missing-state-digest":
        outputs.pop(CLOUD_INIT_OUTPUT)
    if fault == "wrong-state-digest":
        outputs[CLOUD_INIT_OUTPUT]["value"] = "1" * 64
    raw_state = encode(state)
    review, evidence = _review(plan, scope, raw_state)
    if fault == "configuration":
        evidence = replace(
            evidence, configuration={**evidence.configuration, str(ROOT / "main.tf"): b"substitute"}
        )
        review = replace(review, plan_evidence_sha256=evidence.evidence_sha256)
    if fault == "offline-configuration":
        evidence = replace(
            evidence,
            configuration={
                name: raw for name, raw in evidence.configuration.items() if name in OFFLINE_FILES
            },
        )
    if fault == "plan-bytes":
        evidence = replace(evidence, encrypted_plan=evidence.encrypted_plan + b"\n")
    if fault == "detached-json":
        evidence = replace(evidence, plan_json=evidence.plan_json + b"\n")
    if fault == "plaintext":
        evidence = replace(evidence, encrypted_plan=encode({"encrypted_data": "pretend"}))
        review = replace(review, plan_evidence_sha256=evidence.evidence_sha256)
    with pytest.raises(ValidationError, match=category):
        bind_initial_allocation(review, evidence, raw_state, observed, encode(exclusions))


@pytest.fixture
def retirement(
    reviewed_plan: tuple[Document, ApprovedHostPlan], readback: tuple[Document, Document, Document]
) -> tuple[InitialRetirement, Document, Document]:
    plan, scope = reviewed_plan
    state, provider, exclusions = readback
    raw_state = encode(state)
    review, original_plan = _review(plan, scope, raw_state)
    original = capture_initial_retirement(
        review,
        original_plan,
        raw_state,
        provider,
        encode(exclusions),
    )
    resources = state["values"]["root_module"]["resources"]
    plan = {
        "errored": False,
        "prior_state": state,
        "planned_values": {"root_module": {}},
        "output_changes": {
            name: {"actions": ["delete"], "after": None} for name in state["values"]["outputs"]
        },
        "resource_changes": [
            {
                **{key: row[key] for key in ("address", "mode", "name", "type", "provider_name")},
                "change": {"actions": ["delete"], "before": deepcopy(row["values"]), "after": None},
            }
            for row in resources
        ],
    }
    return original, plan, state


def test_retirement_review_validates_only_original_deletions(
    retirement: tuple[InitialRetirement, Document, Document],
) -> None:
    original, destroy, _ = retirement

    def verify(plan: Document, *, key: str = original.state_key) -> None:
        raw = encode(plan)
        verify_initial_destroy_plan(
            original, raw, reviewed_sha256=sha256(raw).hexdigest(), state_key=key
        )

    verify(destroy)
    with pytest.raises(ValidationError, match="droplet-cleanup-plan-changed"):
        verify(destroy, key=original.state_key.replace("restore.tfstate", "source.tfstate"))
    replaced = deepcopy(destroy)
    replaced["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
    with pytest.raises(ValidationError, match="droplet-cleanup-resource-changed"):
        verify(replaced)
    foreign = deepcopy(destroy)
    foreign["resource_changes"][0]["change"]["before"]["id"] = "999"
    with pytest.raises(ValidationError, match="droplet-cleanup-resource-changed"):
        verify(foreign)
    extra = deepcopy(destroy)
    extra["resource_changes"].append({"address": "digitalocean_reserved_ip.foreign"})
    with pytest.raises(ValidationError, match="droplet-plan-resource-set-changed"):
        verify(extra)


def test_interrupted_retirement_requires_exact_independent_absence(
    retirement: tuple[InitialRetirement, Document, Document],
) -> None:
    original, _, occupied = retirement
    clean = encode({"format_version": "1.0", "terraform_version": "1.12.6"})
    nonempty = encode({**occupied, "terraform_version": "1.12.6"})
    identity = original.allocation.identity
    observed = {
        "stateKey": original.state_key,
        "allocationSha256": original.allocation.allocation_sha256,
        "projectIdSha256": identity.project_id_sha256,
        "dropletId": identity.droplet_id,
        "firewallId": original.firewall_id,
        "projectUrn": original.urn,
        "stateSha256": sha256(clean).hexdigest(),
        "droplet": "absent",
        "firewall": "absent",
        "projectMembership": "absent",
    }
    complete = reconcile_initial_retirement(original, clean, observed)
    assert complete["outcome"] == "absent"
    assert complete == reconcile_initial_retirement(original, clean, observed)
    assert (
        reconcile_initial_retirement(original, clean, {**observed, "firewall": "unverified"})[
            "outcome"
        ]
        == "unresolved"
    )
    assert (
        reconcile_initial_retirement(
            original, nonempty, {**observed, "stateSha256": sha256(nonempty).hexdigest()}
        )["outcome"]
        == "unresolved"
    )
    with pytest.raises(ValidationError, match="droplet-cleanup-readback-scope-changed"):
        reconcile_initial_retirement(original, clean, {**observed, "projectUrn": "do:droplet:999"})
    with pytest.raises(ValidationError, match="droplet-cleanup-readback-scope-changed"):
        reconcile_initial_retirement(original, nonempty, observed)


@pytest.fixture
def compact_retirement(
    retirement: tuple[InitialRetirement, Document, Document],
) -> tuple[InitialRetirement, AuthenticatedStateSnapshot, AuthenticatedStateSnapshot, Document]:
    original, _, initial_display = retirement
    header = {
        "version": 4,
        "terraform_version": "1.12.6",
        "lineage": "00000000-0000-4000-8000-000000000011",
    }
    before = AuthenticatedStateSnapshot(
        original.state_key,
        encode(initial_display),
        encode({"encryption_version": "v0", "encrypted_data": "fixture-before"}),
        encode({**header, "serial": 1, "resources": [{"mode": "managed"}], "outputs": {}}),
    )
    after = AuthenticatedStateSnapshot(
        original.state_key,
        b'{"format_version":"1.0"}\n',
        encode({"encryption_version": "v0", "encrypted_data": "fixture-after"}),
        encode({**header, "serial": 2, "resources": [], "outputs": {}}),
    )
    return (
        original,
        before,
        after,
        {
            "stateKey": original.state_key,
            "allocationSha256": original.allocation.allocation_sha256,
            "stateSha256": sha256(after.display).hexdigest(),
            "projectIdSha256": original.allocation.identity.project_id_sha256,
            "dropletId": original.allocation.identity.droplet_id,
            "firewallId": original.firewall_id,
            "projectUrn": original.urn,
            "droplet": "absent",
            "firewall": "absent",
            "projectMembership": "absent",
        },
    )


def test_compact_retirement_requires_bound_version_and_independent_absence(
    compact_retirement: tuple[
        InitialRetirement, AuthenticatedStateSnapshot, AuthenticatedStateSnapshot, Document
    ],
) -> None:
    original, before, after, observation = compact_retirement
    with pytest.raises(ValidationError, match="invalid-droplet-cleanup-state"):
        reconcile_initial_retirement(original, after.display, observation)
    evidence = capture_empty_state_evidence(before, after)
    verified = {**observation, "stateEvidenceSha256": digest(evidence)}
    assert (
        reconcile_initial_retirement(original, after.display, verified, evidence)["outcome"]
        == "absent"
    )
    assert (
        reconcile_initial_retirement(
            original, after.display, {**verified, "droplet": "unverified"}, evidence
        )["outcome"]
        == "unresolved"
    )
    with pytest.raises(ValidationError, match="readback-scope-changed"):
        reconcile_initial_retirement(original, after.display, observation, evidence)
    foreign = {**evidence, "stateKey": original.state_key.replace("restore", "source")}
    with pytest.raises(ValidationError, match="evidence-scope-changed"):
        reconcile_initial_retirement(
            original, after.display, {**verified, "stateEvidenceSha256": digest(foreign)}, foreign
        )
    changed = {**evidence, "before": {**evidence["before"], "displaySha256": "9" * 64}}
    with pytest.raises(ValidationError, match="evidence-scope-changed"):
        reconcile_initial_retirement(
            original, after.display, {**verified, "stateEvidenceSha256": digest(changed)}, changed
        )


@pytest.mark.parametrize(
    ("fieldset", "category"),
    [
        ({"terraform_version": "1.12.7"}, "evidence-invalid"),
        ({"terraform_version": None}, "evidence-invalid"),
        ({"lineage": "00000000-0000-4000-8000-000000000012"}, "evidence-changed"),
        ({"serial": 1}, "evidence-changed"),
        ({"serial": True}, "evidence-invalid"),
        ({"resources": [{"mode": "managed"}]}, "snapshot-not-empty"),
        ({"outputs": {"allocation": {}}}, "snapshot-not-empty"),
        ({"child_modules": []}, "snapshot-not-empty"),
        ({"check_results": [{"object_kind": "var", "status": "fail"}]}, "snapshot-not-empty"),
    ],
)
def test_compact_retirement_rejects_bad_authenticated_state(
    compact_retirement: tuple[
        InitialRetirement, AuthenticatedStateSnapshot, AuthenticatedStateSnapshot, Document
    ],
    fieldset: Document,
    category: str,
) -> None:
    _, before, after, _ = compact_retirement
    invalid = replace(after, decoded=encode({**json.loads(after.decoded), **fieldset}))
    with pytest.raises(ValidationError, match=category):
        capture_empty_state_evidence(before, invalid)
