"""Exercise the exact P4 argv, storage and closeout guards with offline executors."""

from __future__ import annotations

import json
import os
import subprocess
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

import pytest
from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_host_agent.caddy_routes import build_platform_only_caddy_routes

from infrastructure.test_m3_12_droplet_journey import Offline, proof, public_key
from infrastructure.test_m3_12_droplet_journey import fixture as fixture  # noqa: PLC0414
from infrastructure.test_m3_12_droplet_journey import records as records  # noqa: PLC0414
from scripts.m3_12_contracts import Document, ValidationError, digest, encode
from scripts.m3_12_diagnostic_store import Attempt, publish, read
from scripts.m3_12_disposable_routing import POLICY_FORMAT
from scripts.m3_12_droplet_cleanup import InitialRetirement
from scripts.m3_12_droplet_controller import install_stage
from scripts.m3_12_droplet_edge import prepare_edge_proof, prove_edge_associations
from scripts.m3_12_droplet_inventory import ApprovedAllocation, ProviderIdentity
from scripts.m3_12_droplet_journey import run_journey
from scripts.m3_12_droplet_native import (
    MUTATING_SITE_UNAVAILABLE,
    AdapterInputs,
    SitePreview,
    inspect_host,
    preview_site,
)
from scripts.m3_12_droplet_observe import FORMAT
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_droplet_ssh import REMOTE_PROBE, Endpoint, installation_inventory
from scripts.m3_12_droplet_storage import StorageTarget, observe_storage, verify_original_archives
from scripts.m3_12_droplet_teardown import (
    HostAbsence,
    _host_authority,
    reconcile_teardown,
    review_destroy_plan,
)


class Captures(Offline):
    def __init__(self, attempt: Attempt, scope: Document) -> None:
        super().__init__(attempt, scope)
        self.evidence: dict[str, dict[str, str]] = {}

    def readback(self, intent: bytes, allocation: bytes) -> bytes:
        receipt = json.loads(super().readback(intent, allocation))
        if receipt["outcome"] == "committed":
            label = json.loads(intent)["phase"]
            receipt["evidence"].update(self.evidence.get(label, {}))
        return encode(receipt)


def adapter(
    fixture: tuple[Attempt, Document, ReviewedJourney],
    phase: str,
    captures: Captures | None = None,
) -> AdapterInputs:
    attempt, scope, reviewed = fixture
    runner = Captures(attempt, scope) if captures is None else captures
    runner.unknown = phase
    result = run_journey(attempt, encode(scope), reviewed, runner)
    assert result["phases"][phase] == "uncertain"
    path = attempt.directory / f"journey-{phase}-intent.json"
    return AdapterInputs(attempt, encode(scope), reviewed, path.read_bytes())


def allocation(
    scope: Document,
    role: Literal["source", "restore", "fresh"],
) -> ApprovedAllocation:
    host = scope["resources"]["hosts"][role]
    target = host["target"]
    return ApprovedAllocation(
        run_id=scope["runId"],
        role=role,
        state_sha256=target["stateSha256"],
        allocation_sha256=target["allocationSha256"],
        inventory_sha256=target["inventorySha256"],
        transaction_namespace_sha256=target["transactionNamespaceSha256"],
        identity=ProviderIdentity(
            target["droplet"]["projectIdSha256"],
            target["droplet"]["dropletId"],
            host["enrollment"]["ipv4"],
        ),
    )


def endpoint(
    tmp_path: Path, scope: Document, role: Literal["source", "restore", "fresh"]
) -> Endpoint:
    key = tmp_path / f"synthetic-key-{role}"
    key.touch(mode=0o600)
    approved = allocation(scope, role)
    return Endpoint(approved, approved.identity, public_key(role), key)


def test_native_argv_uses_only_the_owned_host_and_denies_unsupported_apply(
    fixture: tuple[Attempt, Document, ReviewedJourney],
    tmp_path: Path,
) -> None:
    attempt, scope, _ = fixture
    prepared = adapter(fixture, "fresh-install")
    fresh = endpoint(tmp_path, scope, "fresh")
    directory = attempt.directory / "install-fresh"
    directory.mkdir(mode=0o700)
    target = scope["resources"]["hosts"]["fresh"]["target"]
    files = {
        "inventory.json": encode(installation_inventory(fresh, directory / "known_hosts")),
        "known_hosts": fresh.provider.ipv4.encode() + b" " + fresh.host_public_key + b"\n",
        "stage.json": encode(
            install_stage(
                attempt.directory,
                "fresh",
                digest(target),
                fresh_artifact=scope["candidate"]["hostAgentSha256"],
                owner=os.geteuid(),
            )
        ),
    }
    for name, raw in files.items():
        path = directory / name
        path.write_bytes(raw)
        path.chmod(0o600)
    publish(
        attempt.directory,
        "droplet-fresh-install-handoff.json",
        {
            "format": "lowerduckpond-m3-12-install-handoff-v1",
            "role": "fresh",
            "targetSha256": digest(target),
            "files": {name: sha256(raw).hexdigest() for name, raw in files.items()},
        },
    )
    commands: list[SitePreview] = []

    def execute(command: SitePreview) -> bytes:
        commands.append(command)
        return b"m312-fresh\n"

    assert preview_site(prepared, fresh, execute) == b"m312-fresh\n"
    argv = commands[0].argv
    assert argv[1:-1] == (
        "--list-hosts",
        "--inventory",
        str(directory / "inventory.json"),
        "--limit",
        "m312-fresh",
        "--extra-vars",
        f"@{directory / 'stage.json'}",
    )
    assert argv[-1].endswith("/config/ansible/playbooks/site.yml")
    result = subprocess.run(  # noqa: S603 - local nonconnecting host listing only
        argv,
        check=True,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "ANSIBLE_CONFIG": str(commands[0].config),
            "ANSIBLE_HOME": str(tmp_path / "ansible"),
        },
    )
    assert "hosts (1)" in result.stdout and "m312-fresh" in result.stdout
    with pytest.raises(ValidationError, match=MUTATING_SITE_UNAVAILABLE):
        preview_site(prepared, fresh, execute, apply=True)
    with pytest.raises(ValidationError, match="droplet-native-host-role-changed"):
        preview_site(prepared, endpoint(tmp_path, scope, "source"), execute)
    alternate = encode({**json.loads(files["stage.json"]), "static_publication_enabled": True})
    (directory / "stage.json").write_bytes(alternate)
    with pytest.raises(ValidationError, match="droplet-native-handoff-changed"):
        preview_site(prepared, fresh, execute)
    # A handoff with a new self-consistent digest still cannot replace the
    # manifest-derived dark stage.
    name = "droplet-fresh-install-handoff.json"
    handoff = read(attempt.directory, name)
    handoff["files"]["stage.json"] = sha256(alternate).hexdigest()
    (attempt.directory / name).write_bytes(encode(handoff))
    with pytest.raises(ValidationError, match="droplet-native-handoff-changed"):
        preview_site(prepared, fresh, execute)
    assert len(commands) == 1

    immutable = build_platform_only_caddy_routes(
        origin_pull_ca_der=(b"synthetic public CA",), origin_pull_required=True
    )
    assert b'"*.lowerduckpond.com"' in encode(immutable.configuration)


def test_pinned_native_read_rejects_a_changed_intent_or_guest_identity(
    fixture: tuple[Attempt, Document, ReviewedJourney],
    tmp_path: Path,
) -> None:
    _, scope, _ = fixture
    prepared = adapter(fixture, "predecessor")
    original = endpoint(tmp_path, scope, "source")
    enrolled = scope["resources"]["hosts"]["source"]["enrollment"]
    response: Document = {
        "format": FORMAT,
        "metadata": {"dropletId": original.provider.droplet_id, "ipv4": original.provider.ipv4},
        "hostIdentity": {
            key: enrolled[key] for key in ("hostKeySha256", "machineSha256", "systemUuidSha256")
        },
        "bootSha256": proof("boot"),
        "state": {"artifactSha256": None, "launchPresent": False, "publication": "absent"},
    }
    calls = []

    def execute(arguments: list[str], **_kwargs: object) -> bytes:
        calls.append(arguments)
        assert arguments[-2:] == [f"ldp-admin@{original.provider.ipv4}", REMOTE_PROBE]
        assert "StrictHostKeyChecking=yes" in arguments and "ForwardAgent=no" in arguments
        return encode(response)

    with pytest.raises(ValidationError, match="droplet-journey-adapter-intent-changed"):
        inspect_host(replace(prepared, intent=b"{}\n"), original, execute)
    with pytest.raises(ValidationError, match="droplet-native-host-binding-changed"):
        foreign = replace(
            original, allocation=replace(original.allocation, state_sha256=proof("other state"))
        )
        inspect_host(prepared, foreign, execute)
    assert calls == []
    assert inspect_host(prepared, original, execute) == response
    response["hostIdentity"]["machineSha256"] = proof("other machine")
    with pytest.raises(ValidationError, match="droplet-native-host-identity-changed"):
        inspect_host(prepared, original, execute)


@pytest.mark.parametrize("enrolled", [True, False])
def test_edge_subjects_and_associations_cannot_cross_the_reviewed_zones(
    fixture: tuple[Attempt, Document, ReviewedJourney], enrolled: bool
) -> None:
    attempt, scope, review = fixture
    tenant = {
        "format": "lowerduckpond-m3-12-edge-tenant-v1",
        "tenantId": "01997763-4600-7000-8000-000000000001",
        "alias": "sample-tenant",
        "unknown": "unissued",
    }
    canonical = "https://t-" + tenant["tenantId"].replace("-", "") + ".source.tenant.example"
    policy = {
        "format": POLICY_FORMAT,
        "runId": scope["runId"],
        "invocationId": scope["invocationId"],
        "platform": "source.platform.example",
        "tenantScope": "source.tenant.example",
        "tenants": [{"tenantId": tenant["tenantId"], "origin": canonical}] if enrolled else [],
    }
    scope["sitePolicySha256"] = digest(policy)
    review = replace(review, manifest_sha256=digest(scope), site_policy_sha256=digest(policy))
    runner = Captures(attempt, scope)
    runner.evidence["functional"] = {"lifecycle": digest(tenant)}
    prepared = adapter((attempt, scope, review), "edge", runner)
    if not enrolled:
        with pytest.raises(ValidationError, match="droplet-edge-tenant-not-enrolled"):
            prepare_edge_proof(prepared, encode(tenant), encode(policy))
        return
    subjects = prepare_edge_proof(prepared, encode(tenant), encode(policy))
    assert subjects.browser.tenant_immutable == canonical
    with pytest.raises(ValidationError, match="droplet-routing-policy-changed"):
        prepare_edge_proof(prepared, encode(tenant), encode({**policy, "tenants": []}))
    assert subjects.browser.platform == "https://source.platform.example"
    assert subjects.browser.tenant_alias == "https://sample-tenant.source.tenant.example"
    assert subjects.browser.tenant_parent_domain == "source.tenant.example"
    assert subjects.certificate_subjects["tenant"] == (
        "source.tenant.example",
        "*.source.tenant.example",
    )
    with pytest.raises(ValidationError, match="droplet-edge-original-fixture-changed"):
        prepare_edge_proof(prepared, encode({**tenant, "alias": "another"}), encode(policy))

    captured: Document = {
        zone: {
            "zoneId": subjects.zone_ids[zone],
            "zoneName": subjects.zone_names[zone],
            "ssl": "strict",
            "alwaysOnline": False,
            "dns": {host: {"origin": subjects.origin_ipv4, "proxied": True} for host in names},
            "originPulls": dict.fromkeys(names, subjects.certificate_ids[zone]["replacement"]),
        }
        for zone, names in subjects.certificate_subjects.items()
    }
    assert prove_edge_associations(subjects, captured, generation="replacement") == digest(captured)
    with pytest.raises(ValidationError, match="droplet-edge-associations-changed"):
        prove_edge_associations(subjects, captured, generation="primary")
    captured["platform"]["dns"]["foreign.example"] = {
        "origin": subjects.origin_ipv4,
        "proxied": True,
    }
    with pytest.raises(ValidationError, match="droplet-edge-associations-changed"):
        prove_edge_associations(subjects, captured, generation="replacement")


class ReadS3:
    def __init__(self, target: StorageTarget, *, foreign: str | None = None) -> None:
        self.target = target
        self.foreign = foreign

    def get_bucket_versioning(self, **kwargs: object) -> Document:
        assert kwargs["Bucket"] == self.target.bucket
        return {"Status": "Enabled"}

    def list_objects_v2(self, **kwargs: object) -> Document:
        assert kwargs["Bucket"] == self.target.bucket and kwargs["Prefix"] == ""
        return {"IsTruncated": False}

    def list_object_versions(self, **kwargs: object) -> Document:
        assert kwargs["Bucket"] == self.target.bucket and kwargs["Prefix"] == ""
        output: Document = {"IsTruncated": False}
        if self.foreign is not None:
            output["DeleteMarkers"] = [{"Key": self.foreign, "VersionId": "opaque-version"}]
        return output

    def list_multipart_uploads(self, **kwargs: object) -> Document:
        assert kwargs["Bucket"] == self.target.bucket and kwargs["Prefix"] == ""
        return {"IsTruncated": False}


def test_storage_uses_whole_owned_buckets_and_original_restore_authority(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, _ = fixture
    original = {"format": "lowerduckpond-m3-12-archive-authority-v1", "archives": []}
    runner = Captures(attempt, scope)
    runner.evidence["backup-fence"] = {"archiveInventory": digest(original)}
    prepared = adapter(fixture, "restore", runner)
    targets: list[StorageTarget] = []

    def open_storage(target: StorageTarget) -> S3Client:
        targets.append(target)
        assert target.endpoint == "https://abc7.digitaloceanspaces.com"
        return cast(S3Client, ReadS3(target))

    with pytest.raises(ValidationError, match="droplet-storage-scope-changed"):
        observe_storage(prepared, "fresh", "restic", open_storage)
    with pytest.raises(ValidationError, match="droplet-storage-archive-original-changed"):
        verify_original_archives(prepared, encode({**original, "archives": [{}]}), open_storage)
    assert targets == []

    assert observe_storage(prepared, "restore", "restic", open_storage)["empty"]
    assert targets[-1].repository.endswith(f"/source-restic/runs/{scope['runId']}")
    proof_row = verify_original_archives(prepared, encode(original), open_storage)
    assert proof_row["archives"] == []
    assert targets[-1].bucket == "source-archive"

    def changed(target: StorageTarget) -> S3Client:
        return cast(S3Client, ReadS3(target, foreign="foreign/key"))

    observed = observe_storage(prepared, "restore", "archive", changed)
    assert observed["outsideNamespace"] == 1 and not observed["empty"]


def test_teardown_retains_unresolved_obligations_until_exact_readback(
    fixture: tuple[Attempt, Document, ReviewedJourney],
) -> None:
    attempt, scope, _ = fixture
    state_json = encode({"format_version": "1.0", "terraform_version": "1.12.6"})
    hosts = {}
    authorized_hosts = {}
    for role in ("source", "restore", "fresh"):
        item = allocation(scope, role)
        original = InitialRetirement(
            item,
            scope["resources"]["hosts"][role]["stateKey"],
            f"firewall-{role}",
            f"do:droplet:{item.identity.droplet_id}",
            (),
        )
        authorized_hosts[role] = _host_authority(scope, role, original)
        hosts[role] = HostAbsence(
            original,
            state_json,
            {
                "stateKey": original.state_key,
                "allocationSha256": item.allocation_sha256,
                "stateSha256": sha256(state_json).hexdigest(),
                "projectIdSha256": item.identity.project_id_sha256,
                "dropletId": item.identity.droplet_id,
                "firewallId": original.firewall_id,
                "projectUrn": original.urn,
                "droplet": "absent",
                "firewall": "absent",
                "projectMembership": "absent",
            },
        )

    def observed(key: str, status: str, *, evidence: str = proof("fresh readback")) -> Document:
        return {"identitySha256": key, "evidenceSha256": evidence, "status": status}

    dns = {
        f"{zone}-{role}": observed(
            digest(
                {
                    "zoneId": row["zoneId"],
                    "zoneName": row["zoneName"],
                    "scope": row[role],
                }
            ),
            "absent",
        )
        for zone, row in scope["resources"]["edge"].items()
        for role in ("source", "fresh")
    }
    storage = {
        f"{role}-{kind}": observed(digest({"role": role, "kind": kind, **value}), "absent")
        for role, locations in scope["resources"]["storage"].items()
        for kind, value in locations.items()
    }
    grant = proof("owned temporary grant")
    protected = storage["source-archive"]["identitySha256"]
    retained = proof("approved original archive custody")
    authority = {
        "format": "lowerduckpond-m3-12-teardown-authority-v1",
        "allocationSha256": digest(scope),
        "hosts": authorized_hosts,
        "grants": [grant],
        "archiveRetentions": {protected: retained},
    }
    runner = Captures(attempt, scope)
    runner.evidence["retain-originals"] = {"cleanupAuthority": digest(authority)}
    prepared = adapter(fixture, "teardown", runner)
    external = {"dns": dns, "storage": storage, "grants": {grant: observed(grant, "active")}}

    def reconcile(capture: Document, raw: bytes = encode(authority)) -> Document:
        return reconcile_teardown(
            prepared, raw, hosts, capture, independently_observed_sha256=digest(capture)
        )

    assert reconcile(external)["outcome"] == "unresolved"
    external["grants"][grant] = observed(grant, "revoked")
    assert reconcile(external)["outcome"] == "unresolved"  # Archive custody is mandatory.
    storage["source-archive"] = observed(protected, "retained", evidence=retained)
    assert reconcile(external)["outcome"] == "reconciled"
    with pytest.raises(ValidationError, match="droplet-teardown-independent-readback-changed"):
        reconcile_teardown(
            prepared,
            encode(authority),
            hosts,
            external,
            independently_observed_sha256=proof("different capture"),
        )
    with pytest.raises(ValidationError, match="droplet-cleanup-original-resource-set-changed"):
        empty_plan = encode({})
        review_destroy_plan(
            prepared,
            encode(authority),
            "source",
            hosts["source"].original,
            empty_plan,
            reviewed_sha256=sha256(empty_plan).hexdigest(),
        )
    changed = deepcopy(external)
    changed["dns"]["platform-source"]["identitySha256"] = proof("foreign scope")
    with pytest.raises(ValidationError, match="droplet-teardown-readback-changed"):
        reconcile(changed)
    with pytest.raises(ValidationError, match="droplet-teardown-original-changed"):
        reconcile(external, encode({**authority, "grants": []}))
    hosts["restore"].readback["firewall"] = "unverified"
    assert reconcile(external)["outcome"] == "unresolved"
