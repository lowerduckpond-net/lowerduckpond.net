"""Manifest-bound native command preparation for the P4 qualification journey."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from lowerduckpond_static_host_agent.durable import DurableDirectory

from scripts.m3_12_contracts import MAX_RECORD_BYTES, Document, decode, digest, encode, require
from scripts.m3_12_diagnostic_store import Attempt, read
from scripts.m3_12_droplet_controller import inspect_restored_host, install_stage
from scripts.m3_12_droplet_journey import PHASES, require_dispatch
from scripts.m3_12_droplet_scope import ReviewedJourney
from scripts.m3_12_droplet_ssh import Endpoint, ReadExecutor, installation_inventory, observe

REPOSITORY = Path(__file__).resolve().parents[1]
INSTALL_PHASES = frozenset({"cold-install", "fresh-install"})
HOST_PHASES = frozenset(phase.name for phase in PHASES if phase.role != "all")
MUTATING_SITE_UNAVAILABLE = "droplet-native-disposable-routing-unavailable"
HANDOFF_FILES = ("inventory.json", "stage.json", "known_hosts")


@dataclass(frozen=True)
class AdapterInputs:
    attempt: Attempt
    allocation: bytes = field(repr=False)
    reviewed: ReviewedJourney = field(repr=False)
    intent: bytes = field(repr=False)

    def open(self, phases: frozenset[str]) -> tuple[Document, Document]:
        return require_dispatch(self.attempt, self.allocation, self.reviewed, self.intent, phases)


def require_endpoint(endpoint: Endpoint, scope: Document, action: Document) -> Document:
    """Compare every native SSH allocation binding before preparing a command."""
    role = endpoint.allocation.role
    _, fingerprint = endpoint.validate()
    hosts = scope["resources"]["hosts"]
    require(role in hosts and role in action["targets"], "droplet-native-host-role-changed")
    host: Document = hosts[role]
    allocation = endpoint.allocation
    target = host["target"]
    enrollment = host["enrollment"]
    provider = endpoint.provider
    require(
        scope["runId"] == allocation.run_id
        and target["allocationSha256"] == allocation.allocation_sha256
        and target["stateSha256"] == allocation.state_sha256
        and target["inventorySha256"] == allocation.inventory_sha256
        and target["transactionNamespaceSha256"] == allocation.transaction_namespace_sha256
        and target["droplet"]["providerIdentitySha256"] == digest(provider.document())
        and enrollment["ipv4"] == provider.ipv4
        and enrollment["hostKeySha256"] == fingerprint
        and action["targets"][role] == digest(target),
        "droplet-native-host-binding-changed",
    )
    return host


def inspect_host(inputs: AdapterInputs, endpoint: Endpoint, execute: ReadExecutor) -> Document:
    """Run only the existing pinned observation and recheck the full local enrollment."""
    scope, action = inputs.open(HOST_PHASES)
    host = require_endpoint(endpoint, scope, action)
    observed = observe(endpoint, executor=execute)
    identity = host["enrollment"]
    require(
        observed["hostIdentity"]
        == {key: identity[key] for key in ("hostKeySha256", "machineSha256", "systemUuidSha256")},
        "droplet-native-host-identity-changed",
    )
    return observed


def inspect_restore(inputs: AdapterInputs, endpoint: Endpoint, execute: ReadExecutor) -> Document:
    scope, action = inputs.open(frozenset({"cold-install", "restore", "restore-reboot"}))
    host = require_endpoint(endpoint, scope, action)
    exclusions = decode(inputs.reviewed.production_exclusions, "droplet-journey-exclusions")
    return inspect_restored_host(
        inputs.attempt,
        endpoint,
        encode(exclusions["hosts"]),
        executor=execute,
        expected_target_sha256=digest(host["target"]),
    )


@dataclass(frozen=True)
class SitePreview:
    argv: tuple[str, ...]
    config: Path
    role: str
    target_sha256: str


def prepare_site_preview(
    inputs: AdapterInputs, endpoint: Endpoint, *, apply: bool = False
) -> SitePreview:
    """Prepare only the native playbook's host listing from the sealed handoff."""
    scope, action = inputs.open(INSTALL_PHASES)
    host = require_endpoint(endpoint, scope, action)
    # The immutable generator and tenant contracts still pin production
    # subjects. The legacy caddy_domain override cannot scope these commands.
    require(not apply, MUTATING_SITE_UNAVAILABLE)
    role = endpoint.allocation.role
    directory = inputs.attempt.directory
    site = directory / f"install-{role}"
    handoff = read(directory, f"droplet-{role}-install-handoff.json")
    require(
        handoff["format"] == "lowerduckpond-m3-12-install-handoff-v1"
        and handoff["role"] == role
        and handoff["targetSha256"] == digest(host["target"])
        and set(handoff["files"]) == set(HANDOFF_FILES),
        "droplet-native-handoff-changed",
    )
    key, _ = endpoint.validate()
    expected_inventory = installation_inventory(endpoint, site / "known_hosts")
    with DurableDirectory.open(
        site, expected_owner=os.geteuid(), expected_directory_mode=0o700
    ) as retained:
        private = {
            name: retained.read_regular(
                (name,),
                expected_owner=os.geteuid(),
                expected_mode=0o600,
                maximum_bytes=MAX_RECORD_BYTES,
            )
            for name in HANDOFF_FILES
        }
    stage = install_stage(
        directory,
        role,
        digest(host["target"]),
        fresh_artifact=scope["candidate"]["hostAgentSha256"],
        owner=os.geteuid(),
    )
    require(
        all(sha256(raw).hexdigest() == handoff["files"][name] for name, raw in private.items())
        and private["stage.json"] == encode(stage)
        and private["inventory.json"] == encode(expected_inventory)
        and private["known_hosts"] == endpoint.provider.ipv4.encode() + b" " + key + b"\n",
        "droplet-native-handoff-changed",
    )
    config = REPOSITORY / "config/ansible/ansible.cfg"
    return SitePreview(
        (
            str(REPOSITORY / ".venv/bin/ansible-playbook"),
            "--list-hosts",
            "--inventory",
            str(site / "inventory.json"),
            "--limit",
            f"m312-{role}",
            "--extra-vars",
            f"@{site / 'stage.json'}",
            str(config.parent / "playbooks/site.yml"),
        ),
        config,
        role,
        digest(host["target"]),
    )


def preview_site(
    inputs: AdapterInputs,
    endpoint: Endpoint,
    execute: Callable[[SitePreview], bytes],
    *,
    apply: bool = False,
) -> bytes:
    return execute(prepare_site_preview(inputs, endpoint, apply=apply))
