"""Bind a public helper/policy profile to an unchanged private cleanup bundle.

Profiles contain no reader or server credentials. The original GitHub secret is
never replaced: only its in-memory configuration gets the two explicit changes.
"""

from __future__ import annotations

import argparse
import copy
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.http import read_only_requests
from scripts.m3_11_unattended.inventory import ConnectInventoryReader
from scripts.m3_11_unattended.journal import ConnectObligations
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle
from scripts.m3_11_unattended.model import (
    LeaseManifest,
    LeasePolicy,
    LifecycleError,
    digest,
    fingerprint,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState
from scripts.production_qualification_inputs import revision

FORMAT = "lowerduckpond-m3-11-existing-connect-profile-v1"
VALIDATION_FORMAT = "lowerduckpond-m3-11-connect-profile-validation-v1"


class ReadOnlyInventory(ConnectInventoryReader):
    def publish(self, _record: dict[str, object]) -> None:
        raise LifecycleError("profile validation cannot publish inventory facts")


def propose(configuration: object, *, base_configuration_sha256: str) -> dict[str, object]:
    """Generate a public proposal, never a claim of observing the installed secret."""
    config = LeaseConfiguration.parse(configuration)
    config.require_issuance(now=datetime.now(UTC))
    return parse(
        {
            "format": FORMAT,
            "base_configuration_sha256": fingerprint(base_configuration_sha256),
            "helper_revision": config.helper_revision,
            "policy": config.policy.document(),
            "approved_policy_sha256": config.approved_policy_sha256,
            "effective_configuration_sha256": digest(projection(config)),
        }
    )


def projection(config: LeaseConfiguration, *, identities: bool = False) -> dict[str, object]:
    """Native cleanup projection, optionally binding each independent identity.

    No credential value, credentials-file hash, private body or native error is in
    this domain. Targets, authority fingerprints/references, migration and complete
    generation metadata remain bound. Shared/independent role equivalence uses the
    same reader-free projection as existing connect_delivery.bundles.
    """
    value = copy.deepcopy(config.document(cleanup_only=True))
    generations = cast(dict[str, dict[str, dict[str, object]]], value["generations"])
    for roles in generations.values():
        reader = roles["cleanup"].pop("reader")
        if identities:
            _, access = reader_access(reader, allow_expired=True)
            roles["cleanup"]["reader_identity"] = access.receipt()
    return value


def parse(raw: object) -> dict[str, object]:
    value = fields(
        raw,
        {
            "format",
            "base_configuration_sha256",
            "helper_revision",
            "policy",
            "approved_policy_sha256",
            "effective_configuration_sha256",
        },
    )
    policy = LeasePolicy.parse(value["policy"])
    if value["format"] != FORMAT or fingerprint(value["approved_policy_sha256"]) != policy.sha256:
        raise LifecycleError("existing Connect profile has no exact approved policy")
    revision(value["helper_revision"])
    fingerprint(value["base_configuration_sha256"])
    fingerprint(value["effective_configuration_sha256"])
    return {**value, "policy": policy.document()}


def require_controller(config: LeaseConfiguration, raw: object) -> dict[str, object]:
    profile = parse(raw)
    if (
        config.mode != "controller"
        or config.helper_revision != profile["helper_revision"]
        or config.policy.document() != profile["policy"]
        or config.approved_policy_sha256 != profile["approved_policy_sha256"]
        or digest(projection(config)) != profile["effective_configuration_sha256"]
    ):
        raise LifecycleError("controller differs from the exact independent profile")
    return profile


def apply(
    raw: object, requested: object, *, helper: str
) -> tuple[dict[str, object], dict[str, object]]:
    from scripts.m3_11_unattended.connect_action import bootstrap  # noqa: PLC0415

    profile = parse(requested)
    original = fields(raw, {"format", "configuration", "server_credentials"})
    old = LeaseConfiguration.parse(original["configuration"])
    # The native parser validates every independent identity, grant and generation
    # before the profile can change anything. No unrecognized base is adopted.
    old, _ = bootstrap(original, helper=old.helper_revision)
    if digest(projection(old, identities=True)) != profile["base_configuration_sha256"]:
        raise LifecycleError("installed Connect base differs from the approved profile")
    if profile["helper_revision"] != revision(helper):
        raise LifecycleError("profile differs from the exact executing helper")
    result = copy.deepcopy(original)
    configuration = cast(dict[str, object], result["configuration"])
    for name in ("helper_revision", "policy", "approved_policy_sha256"):
        configuration[name] = profile[name]
    candidate, _ = bootstrap(result, helper=helper)
    if digest(projection(candidate)) != profile["effective_configuration_sha256"]:
        raise LifecycleError("effective Connect configuration differs from its profile")
    return result, profile


def validate(
    config: LeaseConfiguration, client: Connect, profile: object, *, directory: Path
) -> dict[str, object]:
    """Authenticate first; GET existing providers/journal without cleanup calls.

    This creates no lease confirmation, revokes nothing and cannot supply the
    required pre-CREATE independent manifest observation.
    """
    selected = parse(profile)
    now = datetime.now(UTC)
    with read_only_requests():
        config.policy.require_start(now=now, approved_sha256=config.approved_policy_sha256)
        active = config.generations[config.active_generation]["cleanup"]
        if (
            not instant(active.generation.introduced_at)
            <= now
            < instant(active.generation.rotation_due_at)
        ):
            raise LifecycleError("profile generation is outside its approved rotation month")
        active.generation.require_coverage(
            policy=config.policy, deadline=config.policy.deadline(now)
        )
        active.providers(targets=config.targets, now=now, reader=client)
        legacy = ConnectObligations(
            client,
            config.journal_vault,
            spool=directory / "validation-read-cache",
            expected=config.migration_sha256,
        )
        legacy.records()  # Native minimum inventory and exact migration digest; no reconciliation.
        if legacy.mapping is None:
            raise LifecycleError("profile migration inventory is unavailable")
        inventory = ReadOnlyInventory(client, config.journal_vault)
        records = inventory.records()
        manifests = {
            str(row["lease_id"]): LeaseManifest.parse(row["payload"])
            for row in records
            if row["slot"] == "manifest"
        }
        if any(str(row["lease_id"]) not in manifests for row in records):
            raise LifecycleError("profile inventory has outcomes without a manifest")
        closed = {str(row["lease_id"]) for row in records if row["slot"] == "closed"}
        checked = {config.active_generation}
        for key, manifest in manifests.items():
            if manifest.targets != config.targets:
                raise LifecycleError("profile historical lease targets differ")
            if key in closed:
                continue
            lifecycle = LeaseLifecycle(
                manifest, inventory, LeaseState(directory / "validation-leases" / key), providers={}
            )
            observed = lifecycle.records()
            for intent in manifest.intents:
                generation = lifecycle.cleanup_generation(intent, observed)
                retained = config.generations.get(generation.generation_id, {}).get("cleanup")
                if retained is None or retained.generation != generation:
                    raise LifecycleError("profile omitted required historical cleanup authority")
                if generation.generation_id not in checked:
                    retained.providers(targets=config.targets, now=now, reader=client)
                    checked.add(generation.generation_id)
    return {
        "format": VALIDATION_FORMAT,
        "status": "ready",
        "observed_at": stamp(now),
        "helper_revision": config.helper_revision,
        "profile_sha256": digest(selected),
        "base_configuration_sha256": selected["base_configuration_sha256"],
        "effective_configuration_sha256": selected["effective_configuration_sha256"],
        "policy_sha256": config.approved_policy_sha256,
        "migration_sha256": config.migration_sha256,
        "provider_activity_verified": True,
        "historical_lease_count": len(manifests),
        "historical_closed_count": len(closed),
        "reconciliation_performed": False,
        "manifest_confirmation_published": False,
        "credential_creation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration", type=Path, required=True)
    parser.add_argument("--base-configuration-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        profile = propose(
            read_private(args.configuration),
            base_configuration_sha256=args.base_configuration_sha256,
        )
        write_private(args.output, profile)
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Public profile proposal failed; original access is unchanged.\n")
    print("Public profile proposal staged; sha256=" + digest(profile))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
