"""Explicit synthetic rotation inputs and isolated Connect reader boundaries."""

from __future__ import annotations

import dataclasses
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import setup
from scripts.m3_11_unattended.config import LeaseBootstrap, LeaseConfiguration
from scripts.m3_11_unattended.connect_configuration import PROVIDER_REFERENCES
from scripts.m3_11_unattended.model import (
    MONTHS_PER_YEAR,
    PROVIDERS,
    AuthorityGeneration,
    LeasePolicy,
    LifecycleError,
    digest,
    stamp,
)
from scripts.m3_11_unattended.production import REFERENCES

from .test_m3_11_connect_auth import example, token
from .test_m3_11_lease_inventory import TARGETS

VAULTS = {"provision": "v" * 26, "cleanup": "c" * 26, "production": "p" * 26, "journal": "j" * 26}


def mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def reader_document(
    role: str, *, now: datetime, vaults: dict[str, str] | None = None
) -> dict[str, object]:
    selected_vaults = dict(VAULTS if vaults is None else vaults)
    entry, metadata, payload = example()
    expiry = now + timedelta(days=40)
    native = cast(list[dict[str, object]], metadata["tokens"])[0]
    identifier = {"provision": "T", "cleanup": "U", "production": "V"}[role] * 26
    native.update(id=identifier, created_at=stamp(now), expires_at=stamp(expiry))
    entry.update(expires_at=stamp(expiry))
    payload.update(jti=identifier, iat=int(now.timestamp()), exp=int(expiry.timestamp()))
    grants = {selected_vaults[role]: 48}
    if role != "production":
        grants[selected_vaults["journal"]] = 1008
    native["vaults"] = [
        {
            "id": vault.upper(),
            "acl": ["allow_viewing"]
            + (["allow_editing"] if vault == selected_vaults["journal"] else []),
        }
        for vault in grants
    ]
    payload["1password.com/vts"] = [{"u": vault.upper(), "a": acl} for vault, acl in grants.items()]
    token(entry, payload)
    return {
        "format": "lowerduckpond-connect-reader-v2",
        "approved_expires_at": stamp(expiry),
        "url": "https://connect.example.test",
        "role": role,
        "vaults": selected_vaults,
        "entry": entry,
        "metadata": metadata,
    }


def document() -> dict[str, object]:
    now = datetime.now(UTC).replace(microsecond=0)
    policy = LeasePolicy(
        stamp(now - timedelta(minutes=1)),
        stamp(now + timedelta(hours=1)),
        stamp(now + timedelta(hours=3)),
        7 * 24 * 3600,
        2 * 24 * 3600,
        True,
        "SYNTHETIC-TEST-ONLY-no-live-approval",
    )
    generation_id = str(uuid.uuid7())
    introduced = now.replace(day=1)
    rotation = introduced.replace(
        year=now.year + (now.month == MONTHS_PER_YEAR), month=now.month % MONTHS_PER_YEAR + 1
    )
    roles = {}
    for role in ("cleanup", "provision"):
        generation = AuthorityGeneration(
            generation_id,
            role,
            digest(dataclasses.asdict(TARGETS)),
            {
                "spaces": "synthetic-team-a",
                "cloudflare-account": TARGETS.account_id,
                "cloudflare-user": TARGETS.user_id,
            },
            {kind: digest([role, kind]) for kind in PROVIDERS},
            {kind: stamp(now + timedelta(days=35)) for kind in PROVIDERS},
            stamp(now + timedelta(days=40)),
            stamp(introduced),
            stamp(rotation),
        )
        roles[role] = {
            "format": "lowerduckpond-m3-11-lease-bootstrap-v1",
            "generation": generation.document(),
            "reader": reader_document(role, now=now),
            "references": {
                key: f"op://{VAULTS[role]}/{'i' * 26}/{key}" for key in PROVIDER_REFERENCES
            },
        }
    return {
        "format": "lowerduckpond-m3-11-lease-config-v1",
        "mode": "controller",
        "targets": dataclasses.asdict(TARGETS),
        "journal_vault": VAULTS["journal"],
        "policy": policy.document(),
        "approved_policy_sha256": policy.sha256,
        "active_generation": generation_id,
        "generations": {generation_id: roles},
        "production": {
            "connect": reader_document("production", now=now),
            "references": {
                key: f"op://{VAULTS['production']}/{'i' * 26}/{key}" for key in REFERENCES
            },
        },
        "independent_server_id": "i" * 26,
        "helper_revision": "e" * 40,
        "migration_sha256": "d" * 64,
    }


def test_versioned_cleanup_bundle_contains_no_provisioning_or_production_reader() -> None:
    config = LeaseConfiguration.parse(document())
    cleanup = LeaseConfiguration.parse(config.document(cleanup_only=True))
    assert cleanup.production is None
    assert all(set(roles) == {"cleanup"} for roles in cleanup.generations.values())
    with pytest.raises(LifecycleError, match="cleanup-only"):
        cleanup.require_issuance(now=datetime.now(UTC))


@pytest.mark.parametrize(
    "fault",
    ["same-independent", "different-endpoint", "swapped-production-vault", "policy-approval"],
)
def test_cross_reader_and_policy_binding_rejects_self_consistent_substitution(fault: str) -> None:
    raw = document()
    production = mapping(raw["production"])
    if fault == "same-independent":
        raw["independent_server_id"] = "S" * 26
    elif fault == "different-endpoint":
        mapping(production["connect"])["url"] = "https://other.example.test"
    elif fault == "swapped-production-vault":
        now = datetime.now(UTC).replace(microsecond=0)
        changed = {**VAULTS, "production": VAULTS["provision"], "provision": VAULTS["production"]}
        production["connect"] = reader_document("production", now=now, vaults=changed)
        production["references"] = {
            key: f"op://{changed['production']}/{'i' * 26}/{key}" for key in REFERENCES
        }
    else:
        raw["approved_policy_sha256"] = "0" * 64
    with pytest.raises((LifecycleError, ValueError)):
        LeaseConfiguration.parse(raw)


def test_unavailable_old_reader_is_local_to_that_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = LeaseConfiguration.parse(document())
    bootstrap = config.generations[config.active_generation]["cleanup"]

    def unavailable(_self: LeaseBootstrap) -> None:
        raise LifecycleError("synthetic expired old reader")

    monkeypatch.setattr(LeaseBootstrap, "reader", unavailable)
    providers = bootstrap.providers(
        targets=TARGETS, now=datetime.now(UTC), tolerate_unavailable=True
    )
    assert set(providers) == PROVIDERS
    for provider in providers.values():
        with pytest.raises(LifecycleError):
            provider.inventory()
    with pytest.raises(LifecycleError, match="expired"):
        bootstrap.providers(targets=TARGETS, now=datetime.now(UTC))


def test_digitalocean_attestation_binds_operator_team_and_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = LeaseConfiguration.parse(document())
    bootstrap = config.generations[config.active_generation]["cleanup"]
    secret = "SYNTHETIC-DO-PRINCIPAL-CANARY"  # noqa: S105 - deliberate synthetic canary
    generation = dataclasses.replace(
        bootstrap.generation,
        fingerprints={
            **bootstrap.generation.fingerprints,
            "spaces": hashlib.sha256(secret.encode()).hexdigest(),
        },
    )

    class Reader:
        def read(self, reference: str) -> str:
            assert reference == bootstrap.references["digitalocean"]
            return secret

    monkeypatch.setattr(setup, "reader", lambda _raw: Reader())
    for principal in ("synthetic-other-team", "synthetic-team-a"):
        path = tmp_path / (principal + ".json")
        if principal != "synthetic-team-a":
            with pytest.raises(LifecycleError, match="principal"):
                setup.attest_digitalocean(
                    reference=bootstrap.references["digitalocean"],
                    generation=generation,
                    reader_config=bootstrap.reader_settings,
                    observed_principal=principal,
                    attested_by="synthetic-operator",
                    principal_context="synthetic console team",
                    output=path,
                )
            assert not path.exists()
        else:
            setup.attest_digitalocean(
                reference=bootstrap.references["digitalocean"],
                generation=generation,
                reader_config=bootstrap.reader_settings,
                observed_principal=principal,
                attested_by="synthetic-operator",
                principal_context="synthetic console team",
                output=path,
            )
            result = read_private(path)
            assert result["digitalocean_principal"] == principal
            assert result["generation_id"] == generation.generation_id
            assert result["token_sha256"] == generation.fingerprints["spaces"]
            assert secret not in str(result)
