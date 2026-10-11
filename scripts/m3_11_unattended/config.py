"""Dedicated 1Password bootstrap roles, kept outside every qualification environment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol

from scripts.check_m3_7_production_edge import validate_account_token_policy
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare, result
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.lifecycle import CreationRecorder, Provider
from scripts.m3_11_unattended.model import (
    PROVIDERS,
    AuthorityGeneration,
    Credential,
    Intent,
    LeasePolicy,
    LifecycleError,
    ProviderKind,
    Targets,
    digest,
    fingerprint,
    identity,
    instant,
    strings,
)
from scripts.m3_11_unattended.spaces import Spaces
from scripts.production_qualification_inputs import revision

DO_READ_SCOPES = frozenset(
    {"spaces_key:read", "spaces:read", "regions:read", "sizes:read", "actions:read"}
)


class Reader(Protocol):
    def read(self, reference: str) -> str: ...


class UnavailableProvider:
    """A failed authority must not stop independent revocation of other providers."""

    def __init__(self, kind: ProviderKind) -> None:
        self.kind = kind
        self.authority_sha256 = "unavailable"

    def inventory(self) -> list[dict[str, object]]:
        raise LifecycleError("provider cleanup authority is unavailable")

    def inspect(self, identifier: str) -> dict[str, object] | None:
        raise LifecycleError("provider cleanup authority is unavailable")

    def delete(self, identifier: str) -> None:
        raise LifecycleError("provider cleanup authority is unavailable")

    def create(self, intent: Intent, *, record: CreationRecorder) -> Credential:
        raise LifecycleError("cleanup cannot provision credentials")

    def verify(self, intent: Intent, credential: Credential, *, now: datetime) -> None:
        raise LifecycleError("provider cleanup authority is unavailable")

    def denied(self, intent: Intent, credential: Credential) -> bool:
        return False


def _cloudflare_authority(
    client: Cloudflare, *, target: Targets, now: datetime
) -> tuple[str, datetime]:
    verification = client.api.request("GET", client.path + "/verify")
    current = result(verification.status, verification.body)
    if (
        not isinstance(current, dict)
        or current.get("status") != "active"
        or not isinstance(current.get("id"), str)
    ):
        raise LifecycleError("cleanup Cloudflare authority is not active")
    selected = current["id"]
    response = client.api.request("GET", client.path + "/" + selected)
    details = result(response.status, response.body)
    if not isinstance(details, dict) or details.get("id") != selected:
        raise LifecycleError("cleanup Cloudflare authority identity is unverified")
    expected_name = (
        "API Tokens Write" if client.kind == "cloudflare-user" else "Account API Tokens Write"
    )
    expected_scope = (
        "com.cloudflare.api.user"
        if client.kind == "cloudflare-user"
        else "com.cloudflare.api.account"
    )
    response = client.api.request("GET", client.path + "/permission_groups")
    groups = result(response.status, response.body)
    if not isinstance(groups, list):
        raise LifecycleError("cleanup Cloudflare authority policy is unavailable")
    matches = [
        group
        for group in groups
        if isinstance(group, dict)
        and group.get("name") == expected_name
        and isinstance(scopes := group.get("scopes"), list)
        and expected_scope in scopes
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("id"), str):
        raise LifecycleError("cleanup Cloudflare authority permission is ambiguous")
    resources = (
        frozenset({f"com.cloudflare.api.user.{target.user_id}"})
        if client.kind == "cloudflare-user"
        else frozenset({f"com.cloudflare.api.account.{target.account_id}"})
    )
    validate_account_token_policy(
        details,
        expected_id=selected,
        expected_permissions={matches[0]["id"]: expected_name},
        expected_resources=resources,
        label="cleanup authority",
    )
    if details.get("condition") not in (None, {}):
        raise LifecycleError("cleanup Cloudflare authority must not have token conditions")
    expiry = instant(details.get("expires_on"))
    if expiry <= now or (details.get("not_before") and instant(details["not_before"]) > now):
        raise LifecycleError("cleanup Cloudflare authority is expired or not yet valid")
    return selected, expiry


@dataclass(frozen=True)
class LeaseBootstrap:
    """A generation's private reader and public authority metadata, without a journal."""

    generation: AuthorityGeneration
    reader_settings: dict[str, object] = field(repr=False)
    references: dict[str, str] = field(repr=False)

    @classmethod
    def parse(cls, raw: object, *, targets: Targets, vault: str) -> LeaseBootstrap:
        from scripts.m3_11_unattended.connect_configuration import (  # noqa: PLC0415
            PROVIDER_REFERENCES,
            reader_access,
        )

        value = fields(raw, {"format", "generation", "reader", "references"})
        if value["format"] != "lowerduckpond-m3-11-lease-bootstrap-v1":
            raise LifecycleError("lease bootstrap format is invalid")
        generation = AuthorityGeneration.parse(value["generation"])
        reader, access = reader_access(value["reader"], allow_expired=True)
        vaults = strings(reader["vaults"])
        references = strings(fields(value["references"], PROVIDER_REFERENCES))
        if (
            reader.get("format") != "lowerduckpond-connect-reader-v2"
            or reader["role"] != generation.role
            or vaults["journal"] != vault
            or generation.targets_sha256 != digest(asdict(targets))
            or generation.principals["cloudflare-account"] != targets.account_id
            or generation.principals["cloudflare-user"] != targets.user_id
            or access.expires_at < instant(generation.connect_expires_at)
            or any(
                not reference.startswith("op://" + vaults[generation.role] + "/")
                for reference in references.values()
            )
        ):
            raise LifecycleError("lease bootstrap reader, principal or lifetime differs")
        return cls(generation, reader, references)

    def document(self) -> dict[str, object]:
        return {
            "format": "lowerduckpond-m3-11-lease-bootstrap-v1",
            "generation": self.generation.document(),
            "reader": self.reader_settings,
            "references": self.references,
        }

    def reader(self) -> Connect:
        from scripts.m3_11_unattended.connect_configuration import reader  # noqa: PLC0415

        return reader(self.reader_settings)

    def providers(
        self,
        *,
        targets: Targets,
        now: datetime,
        tolerate_unavailable: bool = False,
        reader: Reader | None = None,
    ) -> dict[ProviderKind, Provider]:
        try:
            reader = self.reader() if reader is None else reader
        except RuntimeError, ValueError, OSError, KeyError, TypeError:
            if not tolerate_unavailable:
                raise
            return {kind: UnavailableProvider(kind) for kind in PROVIDERS}
        output: dict[ProviderKind, Provider] = {}
        for kind in sorted(PROVIDERS):
            try:
                output[kind] = self._provider(reader, kind, targets=targets, now=now)
            except RuntimeError, ValueError, OSError, KeyError, TypeError:
                if not tolerate_unavailable:
                    raise
                output[kind] = UnavailableProvider(kind)
        return output

    def _provider(
        self, reader: Reader, kind: ProviderKind, *, targets: Targets, now: datetime
    ) -> Provider:
        generation = self.generation
        # reader() validates the actual local Connect lifetime. Independent
        # cleanup authenticates its own fresh client before supplying it here;
        # an expired old host reader must not disable that separate access.
        if instant(generation.expires_at[kind]) <= now:
            raise LifecycleError("authority generation has expired")
        key = {
            "spaces": "digitalocean",
            "cloudflare-account": "cloudflare_account",
            "cloudflare-user": "cloudflare_user",
        }[kind]
        secret = reader.read(self.references[key])
        if hashlib.sha256(secret.encode()).hexdigest() != generation.fingerprints[kind]:
            raise LifecycleError("authority secret differs from the approved generation")
        if kind == "spaces":
            metadata = fields(
                json.loads(reader.read(self.references["digitalocean_metadata"])),
                {
                    "format",
                    "token_sha256",
                    "expires_at",
                    "scopes",
                    "verified_at",
                    "verified_by",
                    "generation_id",
                    "digitalocean_principal",
                    "attested_by",
                    "principal_context",
                },
            )
            expected_scopes = (
                DO_READ_SCOPES
                | {"spaces_key:delete"}
                | ({"spaces_key:create_credentials"} if generation.role == "provision" else set())
            )
            if (
                metadata["format"] != "lowerduckpond-digitalocean-bootstrap-v2"
                or metadata["token_sha256"] != generation.fingerprints[kind]
                or metadata["generation_id"] != generation.generation_id
                or metadata["digitalocean_principal"] != generation.principals[kind]
                or metadata["scopes"] != sorted(expected_scopes)
                or metadata["verified_by"] != "operator-provider-console"
                or instant(metadata["verified_at"]) > now
                or instant(metadata["expires_at"]) != instant(generation.expires_at[kind])
                or any(
                    not isinstance(metadata[name], str)
                    or not 1 <= len(str(metadata[name])) <= 512  # noqa: PLR2004 - bounded attestation label
                    or any(ord(char) < 32 for char in str(metadata[name]))  # noqa: PLR2004
                    for name in ("attested_by", "principal_context")
                )
            ):
                raise LifecycleError("DigitalOcean generation principal or policy is unverified")
            spaces = Spaces(Api("https://api.digitalocean.com", secret))
            spaces.inventory()
            return spaces
        cloudflare = Cloudflare(
            Api(ORIGIN, secret),
            account=targets.account_id if kind == "cloudflare-account" else None,
        )
        _selected, expiry = _cloudflare_authority(cloudflare, target=targets, now=now)
        if expiry != instant(generation.expires_at[kind]):
            raise LifecycleError("Cloudflare authority expiry differs from its generation")
        return cloudflare


@dataclass(frozen=True)
class LeaseConfiguration:
    """Single versioned Connect bundle; cleanup-only bundles cannot enable issuance."""

    targets: Targets
    journal_vault: str
    policy: LeasePolicy
    approved_policy_sha256: str
    active_generation: str
    generations: dict[str, dict[str, LeaseBootstrap]] = field(repr=False)
    production: dict[str, object] | None = field(repr=False)
    independent_server_id: str
    helper_revision: str
    migration_sha256: str
    mode: str

    @classmethod
    def load(cls, path: Path) -> LeaseConfiguration:
        return cls.parse(read_private(path))

    @classmethod
    def parse(cls, raw: object) -> LeaseConfiguration:  # noqa: PLR0912, PLR0915 - explicit role and generation boundaries
        from scripts.m3_11_unattended.connect_auth import (  # noqa: PLC0415
            identity as connect_identity,
        )
        from scripts.m3_11_unattended.connect_configuration import reader_access  # noqa: PLC0415
        from scripts.m3_11_unattended.production import REFERENCES  # noqa: PLC0415

        value = fields(raw, {"format", *cls.__dataclass_fields__})
        text = strings(
            {
                key: value[key]
                for key in (
                    "journal_vault",
                    "approved_policy_sha256",
                    "active_generation",
                    "independent_server_id",
                    "helper_revision",
                    "migration_sha256",
                    "mode",
                )
            }
        )
        if value["format"] != "lowerduckpond-m3-11-lease-config-v1" or text["mode"] not in {
            "controller",
            "cleanup-only",
        }:
            raise LifecycleError("lease configuration format or mode is invalid")
        vault = Connect._identity(text["journal_vault"])
        targets, policy = Targets.parse(value["targets"]), LeasePolicy.parse(value["policy"])
        if fingerprint(text["approved_policy_sha256"]) != policy.sha256:
            raise LifecycleError("lease policy has no matching explicit approval")
        identity(text["active_generation"])
        connect_identity(text["independent_server_id"])
        revision(text["helper_revision"])
        fingerprint(text["migration_sha256"])
        raw_generations = value["generations"]
        if not isinstance(raw_generations, dict) or not raw_generations:
            raise LifecycleError("lease authority generations are missing")
        generations: dict[str, dict[str, LeaseBootstrap]] = {}
        for key, roles in raw_generations.items():
            identity(key)
            selected = fields(
                roles,
                {"cleanup", "provision"}
                if text["mode"] == "controller" and key == text["active_generation"]
                else {"cleanup"},
            )
            generations[key] = {}
            for role, document in selected.items():
                bootstrap = LeaseBootstrap.parse(document, targets=targets, vault=vault)
                if bootstrap.generation.generation_id != key or bootstrap.generation.role != role:
                    raise LifecycleError("lease generation identity or role differs")
                generations[key][role] = bootstrap
        if text["active_generation"] not in generations:
            raise LifecycleError("active lease authority generation is missing")
        active = generations[text["active_generation"]]["cleanup"].generation
        for roles in generations.values():
            roles["cleanup"].generation.require_same_principal(active)
        if "provision" in generations[text["active_generation"]]:
            creator = generations[text["active_generation"]]["provision"].generation
            if creator.principals != active.principals or set(creator.fingerprints.values()) & set(
                active.fingerprints.values()
            ):
                raise LifecycleError("lease provisioning and cleanup authorities are not separated")
        readers = [
            reader_access(bootstrap.reader_settings, allow_expired=True)
            for roles in generations.values()
            for bootstrap in roles.values()
        ]
        production = None
        if text["mode"] == "controller":
            production = fields(value["production"], {"connect", "references"})
            configured, access = reader_access(production["connect"], allow_expired=True)
            references = strings(fields(production["references"], set(REFERENCES)))
            vaults = strings(configured["vaults"])
            if (
                configured.get("format") != "lowerduckpond-connect-reader-v2"
                or configured["role"] != "production"
                or vaults["journal"] != vault
                or any(
                    not ref.startswith("op://" + vaults["production"] + "/")
                    for ref in references.values()
                )
            ):
                raise LifecycleError("production reader escaped its isolated vault")
            readers.append((configured, access))
        elif value["production"] is not None:
            raise LifecycleError("cleanup-only configuration contains production access")
        first_reader, first_access = readers[0]
        token_roles: dict[str, str] = {}
        for configured, access in readers:
            if (
                configured["vaults"] != first_reader["vaults"]
                or configured["url"] != first_reader["url"]
                or access.server_id != first_access.server_id
                or (
                    text["mode"] == "controller"
                    and access.server_id == text["independent_server_id"]
                )
            ):
                raise LifecycleError("lease readers do not share the approved isolated vault map")
            for token in (access.token_id, access.token):
                role = str(configured["role"])
                if token in token_roles and token_roles[token] != role:
                    raise LifecycleError("lease reader role credentials are not separated")
                token_roles[token] = role
        return cls(
            targets=targets, policy=policy, generations=generations, production=production, **text
        )

    def require_issuance(self, *, now: datetime) -> None:
        from scripts.m3_11_unattended.connect_configuration import reader_access  # noqa: PLC0415

        if self.mode != "controller":
            raise LifecycleError("cleanup-only configuration cannot issue credentials")
        self.policy.require_start(now=now, approved_sha256=self.approved_policy_sha256)
        if self.production is None:
            raise LifecycleError("production reader is required before credential issuance")
        _, production = reader_access(self.production["connect"], allow_expired=True)
        if now >= production.expires_at:
            raise LifecycleError("production reader expired before credential issuance")
        for role in ("provision", "cleanup"):
            generation = self.generations[self.active_generation][role].generation
            if not instant(generation.introduced_at) <= now < instant(generation.rotation_due_at):
                raise LifecycleError(
                    "active authority generation is outside its approved rotation month"
                )
            generation.require_coverage(policy=self.policy, deadline=self.policy.deadline(now))

    def document(self, *, cleanup_only: bool = False) -> dict[str, object]:
        return {
            "format": "lowerduckpond-m3-11-lease-config-v1",
            "targets": asdict(self.targets),
            "policy": self.policy.document(),
            "journal_vault": self.journal_vault,
            "approved_policy_sha256": self.approved_policy_sha256,
            "active_generation": self.active_generation,
            "independent_server_id": self.independent_server_id,
            "helper_revision": self.helper_revision,
            "migration_sha256": self.migration_sha256,
            "mode": "cleanup-only" if cleanup_only else self.mode,
            "production": None if cleanup_only else self.production,
            "generations": {
                key: {
                    role: value.document()
                    for role, value in roles.items()
                    if not cleanup_only or role == "cleanup"
                }
                for key, roles in self.generations.items()
            },
        }
