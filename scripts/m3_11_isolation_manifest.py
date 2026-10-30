"""Public, strictly bounded diagnostic manifest; never a seven-role lease."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from scripts.m3_11_isolation_contract import Intent, Plan, require_agreement
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_auth import identity as connect_identity
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.connect_profile import projection
from scripts.m3_11_unattended.model import (
    AuthorityGeneration,
    digest,
    fingerprint,
    instant,
)

FORMAT = "lowerduckpond-isolated-public-ca-manifest-v1"


@dataclass(frozen=True)
class Manifest:
    intents: tuple[Intent, ...]
    base_configuration_sha256: str
    journal_vault: str
    independent_server_id: str
    independent_access: dict[str, object]
    provision_generation: AuthorityGeneration
    cleanup_generation: AuthorityGeneration

    def __post_init__(self) -> None:
        plan = require_agreement(self.intents)
        fingerprint(self.base_configuration_sha256)
        connect_identity(self.journal_vault)
        connect_identity(self.independent_server_id)
        access = fields(
            self.independent_access,
            {
                "server_sha256",
                "token_id_sha256",
                "expires_at",
                "exact_native_and_signed_policy",
                "signed_grants_by_vault_sha256",
                "authenticated",
                "create_verified",
            },
        )
        fingerprint(access["token_id_sha256"])
        grants = access["signed_grants_by_vault_sha256"]
        if (
            access["server_sha256"]
            != hashlib.sha256(self.independent_server_id.encode()).hexdigest()
            or access["exact_native_and_signed_policy"] is not True
            or access["authenticated"] is not False
            or access["create_verified"] is not False
            or not isinstance(grants, dict)
            or len(grants) != len({"cleanup", "journal"})
            or grants.get(hashlib.sha256(self.journal_vault.encode()).hexdigest())
            not in {496, 1008}
            or sorted(grants.values()) not in ([48, 496], [48, 1008])
        ):
            raise ValueError("isolated independent signed-reader identity differs")
        for value in grants:
            fingerprint(value)
        creator, cleaner = self.provision_generation, self.cleanup_generation
        if (
            creator.role != "provision"
            or cleaner.role != "cleanup"
            or creator.generation_id != cleaner.generation_id
            or creator.targets_sha256 != cleaner.targets_sha256
            or creator.principals != cleaner.principals
            or creator.principals["cloudflare-account"] != plan.account_id
            or creator.fingerprints["cloudflare-account"] != self.intents[0].issuer_authority_sha256
            or cleaner.fingerprints["cloudflare-account"]
            != self.intents[0].cleanup_authority_sha256
        ):
            raise ValueError("isolated authority generations differ from their exact intents")
        minimum = instant(self.intents[0].expires_at) + timedelta(
            seconds=plan.authority_reserve_seconds
        )
        if instant(access["expires_at"]) < minimum:
            raise ValueError("isolated independent reader lacks cleanup coverage")
        for generation in (creator, cleaner):
            if (
                min(
                    instant(generation.expires_at["cloudflare-account"]),
                    instant(generation.connect_expires_at),
                )
                < minimum
            ):
                raise ValueError("isolated authority lacks credential and cleanup coverage")

    @property
    def plan(self) -> Plan:
        return self.intents[0].plan

    @property
    def sha256(self) -> str:
        return digest(self.document())

    def document(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "format": FORMAT,
            "intents": [
                item.document() for item in sorted(self.intents, key=lambda item: item.role)
            ],
            "base_configuration_sha256": self.base_configuration_sha256,
            "journal_vault": self.journal_vault,
            "independent_server_id": self.independent_server_id,
            "independent_access": self.independent_access,
            "provision_generation": self.provision_generation.document(),
            "cleanup_generation": self.cleanup_generation.document(),
        }

    @classmethod
    def parse(cls, raw: object) -> Manifest:
        row = fields(raw, {"format", *cls.__dataclass_fields__})
        if row["format"] != FORMAT or not isinstance(row["intents"], list):
            raise ValueError("isolated manifest format is invalid")
        return cls(
            tuple(Intent.parse(item) for item in row["intents"]),
            fingerprint(row["base_configuration_sha256"]),
            connect_identity(row["journal_vault"]),
            connect_identity(row["independent_server_id"]),
            fields(
                row["independent_access"],
                {
                    "server_sha256",
                    "token_id_sha256",
                    "expires_at",
                    "exact_native_and_signed_policy",
                    "signed_grants_by_vault_sha256",
                    "authenticated",
                    "create_verified",
                },
            ),
            AuthorityGeneration.parse(row["provision_generation"]),
            AuthorityGeneration.parse(row["cleanup_generation"]),
        )

    def require_independent_configuration(self, config: LeaseConfiguration) -> None:
        """Bind the unchanged secret, without rebinding its seven-role policy."""
        cleanup = config.generations[config.active_generation]["cleanup"]
        _, access = reader_access(cleanup.reader_settings, allow_expired=True)
        if (
            config.mode != "cleanup-only"
            or digest(projection(config, identities=True)) != self.base_configuration_sha256
            or config.journal_vault != self.journal_vault
            or config.independent_server_id != self.independent_server_id
            or cleanup.generation != self.cleanup_generation
            or access.receipt() != self.independent_access
            or config.targets.account_id != self.plan.account_id
            or self.plan.zones
            != {
                "lowerduckpond.net": config.targets.zone_id,
                "lowerduckpond.com": config.targets.tenant_zone_id,
            }
        ):
            raise ValueError("isolated manifest differs from the unchanged independent bootstrap")
