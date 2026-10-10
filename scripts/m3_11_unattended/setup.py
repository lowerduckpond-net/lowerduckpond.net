"""Explicit versioned Connect setup; no service-account or credential-creation fallback."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended.config import DO_READ_SCOPES, LeaseConfiguration
from scripts.m3_11_unattended.connect_configuration import (
    PROVIDER_REFERENCES,
    reader,
    reader_access,
)
from scripts.m3_11_unattended.model import (
    AuthorityGeneration,
    LeasePolicy,
    LifecycleError,
    Targets,
    instant,
    stamp,
)
from scripts.m3_11_unattended.production import REFERENCES


def template() -> dict[str, object]:
    """Unusable placeholders intentionally require concrete approved policy inputs."""
    reference = "op://<dedicated-vault-id>/<item-id>/<field-id>"
    return {
        "format": "lowerduckpond-m3-11-lease-config-v1",
        "mode": "controller",
        "targets": dict.fromkeys(Targets.__dataclass_fields__, "<approved value>"),
        "journal_vault": "<existing private journal vault ID>",
        "policy": {
            "format": "lowerduckpond-m3-11-lease-policy-v1",
            **dict.fromkeys(LeasePolicy.__dataclass_fields__, "<explicit approved input>"),
        },
        "approved_policy_sha256": "<SHA-256 of the approved policy document>",
        "active_generation": "<approved generation UUIDv7>",
        "generations": {
            "<approved generation UUIDv7>": {
                role: {
                    "format": "lowerduckpond-m3-11-lease-bootstrap-v1",
                    "generation": {
                        "format": "lowerduckpond-m3-11-authority-generation-v1",
                        **dict.fromkeys(
                            AuthorityGeneration.__dataclass_fields__, "<verified generation input>"
                        ),
                        "role": role,
                    },
                    "reader": "<private verified Connect reader v2 document>",
                    "references": dict.fromkeys(sorted(PROVIDER_REFERENCES), reference),
                }
                for role in ("provision", "cleanup")
            }
        },
        "production": {
            "connect": "<separate private production Connect reader v2 document>",
            "references": dict.fromkeys(sorted(REFERENCES), reference),
        },
        "independent_server_id": "<existing independent cleanup Connect identity>",
        "helper_revision": "<approved full helper revision>",
        "migration_sha256": "<reviewed complete legacy obligation mapping digest>",
    }


def validate(configuration: LeaseConfiguration, *, now: datetime) -> None:
    """Read-only capability checks for separately authorized setup or handover.

    Principal equality comes from the bound operator attestation, never from an
    authenticated empty provider list. This check does not grant issuance.
    """
    if configuration.mode == "controller":
        configuration.require_issuance(now=now)
    for roles in configuration.generations.values():
        for bootstrap in roles.values():
            bootstrap.providers(targets=configuration.targets, now=now)
    if configuration.production is not None:
        reader(configuration.production["connect"])


def configure(manifest: Path, output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise LifecycleError("setup refuses to overwrite private configuration")
    configuration = LeaseConfiguration.load(manifest)
    validate(configuration, now=datetime.now(UTC))
    write_private(output, configuration.document())


def attest_digitalocean(  # noqa: PLR0913 - explicitly bound operator attestation
    *,
    reference: str,
    generation: AuthorityGeneration,
    reader_config: object,
    observed_principal: str,
    attested_by: str,
    principal_context: str,
    output: Path,
) -> None:
    """Bind the operator's observed team, scopes and expiry to an approved PAT.

    The operator must inspect those fields in the approved provider context.
    The existing Spaces API does not supply native PAT/team metadata and this
    operation adds no account-read permission or inferred team identity.
    """
    configured, _access = reader_access(reader_config)
    vaults = configured["vaults"]
    if (
        not isinstance(vaults, dict)
        or configured["role"] != generation.role
        or not reference.startswith("op://" + str(vaults[generation.role]) + "/")
        or observed_principal != generation.principals["spaces"]
        or any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 512  # noqa: PLR2004 - bounded attestation label
            or any(ord(char) < 32 for char in value)  # noqa: PLR2004
            for value in (attested_by, principal_context)
        )
    ):
        raise LifecycleError("DigitalOcean attestation principal or approved reader differs")
    now = datetime.now(UTC)
    if instant(generation.expires_at["spaces"]) <= now:
        raise LifecycleError("DigitalOcean generation is already expired")
    secret = reader(configured).read(reference)
    if hashlib.sha256(secret.encode()).hexdigest() != generation.fingerprints["spaces"]:
        raise LifecycleError("DigitalOcean token differs from its approved generation")
    scopes = (
        DO_READ_SCOPES
        | {"spaces_key:delete"}
        | ({"spaces_key:create_credentials"} if generation.role == "provision" else set())
    )
    write_private(
        output,
        {
            "format": "lowerduckpond-digitalocean-bootstrap-v2",
            "generation_id": generation.generation_id,
            "digitalocean_principal": observed_principal,
            "token_sha256": generation.fingerprints["spaces"],
            "expires_at": generation.expires_at["spaces"],
            "scopes": sorted(scopes),
            "verified_at": stamp(now),
            "verified_by": "operator-provider-console",
            "attested_by": attested_by,
            "principal_context": principal_context,
        },
    )
