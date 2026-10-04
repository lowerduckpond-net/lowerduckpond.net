"""Dedicated 1Password bootstrap roles, kept outside every qualification environment."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.check_m3_7_production_edge import validate_account_token_policy
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.cloudflare import ORIGIN, Cloudflare, result
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.journal import Journal, OnePassword, OpJournal
from scripts.m3_11_unattended.lifecycle import Provider
from scripts.m3_11_unattended.model import (
    Authority,
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    Targets,
    digest,
    instant,
    strings,
)
from scripts.m3_11_unattended.spaces import Spaces

DO_READ_SCOPES = frozenset(
    {"spaces_key:read", "spaces:read", "regions:read", "sizes:read", "actions:read"}
)
BOOTSTRAP_ROLE_COUNT = 3
BOOTSTRAP_FIELDS = {
    "service_account_token",
    "service_account_expires_at",
    "digitalocean",
    "digitalocean_metadata",
    "cloudflare_account",
    "cloudflare_user",
}


class Reader(Protocol):
    def read(self, reference: str) -> str: ...


@dataclass(frozen=True)
class Bootstrap:
    values: dict[str, str] = field(repr=False)
    connect_settings: dict[str, object] | None = field(default=None, repr=False)

    @classmethod
    def parse(cls, value: object) -> Bootstrap:
        if isinstance(value, dict) and value.get("format") == "lowerduckpond-m3-11-connect-role-v1":
            from scripts.m3_11_unattended.connect_configuration import parse_role  # noqa: PLC0415

            return parse_role(value)
        values = strings(fields(value, BOOTSTRAP_FIELDS))
        instant(values["service_account_expires_at"])
        return cls(values)

    def op(self) -> OnePassword:
        if self.connect_settings is not None:
            raise LifecycleError("Connect inputs cannot fall back to a service account")
        return OnePassword(self.values["service_account_token"])

    def reader(self) -> Reader:
        if self.connect_settings is None:
            return self.op()
        from scripts.m3_11_unattended.connect_configuration import reader  # noqa: PLC0415

        return reader(self.connect_settings["reader"])

    def journal(self, vault: str, *, directory: Path | None = None) -> Journal:
        if self.connect_settings is None:
            return OpJournal(self.op(), vault)
        from scripts.m3_11_unattended.connect_configuration import journal  # noqa: PLC0415

        return journal(self, vault, directory=directory)

    def expires_at(self) -> datetime:
        if self.connect_settings is None:
            return instant(self.values["service_account_expires_at"])
        from scripts.m3_11_unattended.connect_configuration import expires_at  # noqa: PLC0415

        return expires_at(self.connect_settings)

    def document(self) -> dict[str, object]:
        return dict(self.values) if self.connect_settings is None else dict(self.connect_settings)


@dataclass(frozen=True)
class Configuration:
    targets: Targets
    journal_vault: str
    provision: Bootstrap = field(repr=False)
    cleanup: Bootstrap = field(repr=False)
    production: dict[str, object] = field(repr=False)

    @classmethod
    def load(cls, path: Path) -> Configuration:
        value = fields(
            read_private(path),
            {"format", "targets", "journal_vault", "provision", "cleanup", "production"},
        )
        vault = value["journal_vault"]
        if (
            value["format"]
            not in {
                "lowerduckpond-m3-11-controller-config-v1",
                "lowerduckpond-m3-11-controller-connect-v1",
            }
            or not isinstance(vault, str)
            or re.fullmatch(r"[a-z0-9]{26}", vault) is None
        ):
            raise LifecycleError("invalid controller configuration")
        provision, cleanup = Bootstrap.parse(value["provision"]), Bootstrap.parse(value["cleanup"])
        if value["format"] == "lowerduckpond-m3-11-controller-connect-v1":
            from scripts.m3_11_unattended.connect_configuration import (  # noqa: PLC0415
                configuration,
            )

            return configuration(value, provision, cleanup)
        if provision.connect_settings is not None or cleanup.connect_settings is not None:
            raise LifecycleError("controller credential backends are ambiguous")
        production = fields(
            value["production"],
            {"service_account_token", "service_account_expires_at", "references"},
        )
        token = production["service_account_token"]
        if (
            not isinstance(token, str)
            or len(
                {
                    token,
                    provision.values["service_account_token"],
                    cleanup.values["service_account_token"],
                }
            )
            != BOOTSTRAP_ROLE_COUNT
        ):
            raise LifecycleError("1Password bootstrap roles are not separated")
        return cls(Targets.parse(value["targets"]), vault, provision, cleanup, production)

    def cleanup_document(self) -> dict[str, object]:
        from dataclasses import asdict  # noqa: PLC0415 - no production material in cleanup output

        return {
            "format": "lowerduckpond-m3-11-cleanup-config-v1",
            "targets": asdict(self.targets),
            "journal_vault": self.journal_vault,
            "cleanup": self.cleanup.document(),
        }


def cleanup_configuration(path: Path) -> tuple[Targets, str, Bootstrap]:
    value = fields(read_private(path), {"format", "targets", "journal_vault", "cleanup"})
    if value["format"] != "lowerduckpond-m3-11-cleanup-config-v1" or not isinstance(
        value["journal_vault"], str
    ):
        raise LifecycleError("invalid independent cleanup configuration")
    return (
        Targets.parse(value["targets"]),
        value["journal_vault"],
        Bootstrap.parse(value["cleanup"]),
    )


@dataclass(frozen=True)
class Connections:
    journal: Journal
    providers: dict[ProviderKind, Provider]
    authority: Authority


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

    def create(self, intent: Intent) -> Credential:
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


def connect(  # noqa: PLR0913 - authority, target and persistence boundaries are explicit
    bootstrap: Bootstrap,
    *,
    targets: Targets,
    vault: str,
    now: datetime,
    provisioning: bool = False,
    journal_directory: Path | None = None,
) -> Connections:
    op = bootstrap.reader()
    values = {
        key: op.read(bootstrap.values[key])
        for key in (
            "digitalocean",
            "digitalocean_metadata",
            "cloudflare_account",
            "cloudflare_user",
        )
    }
    if len({values[key] for key in ("digitalocean", "cloudflare_account", "cloudflare_user")}) != 3:  # noqa: PLR2004 - three provider authorities
        raise LifecycleError("provider bootstrap identities are not separated")
    # DigitalOcean's public Spaces API does not expose PAT expiry/scopes. The
    # setup ceremony records its exact dashboard metadata in a dedicated item,
    # binding it to this secret's SHA-256. Never claim this is native key expiry.
    metadata = fields(
        json.loads(values["digitalocean_metadata"]),
        {"format", "token_sha256", "expires_at", "scopes", "verified_at", "verified_by"},
    )
    scopes = (
        DO_READ_SCOPES
        | {"spaces_key:delete"}
        | ({"spaces_key:create_credentials"} if provisioning else set())
    )
    if (
        metadata["format"] != "lowerduckpond-digitalocean-bootstrap-v1"
        or metadata["token_sha256"] != hashlib.sha256(values["digitalocean"].encode()).hexdigest()
        or metadata["scopes"] != sorted(scopes)
        or metadata["verified_by"] != "operator-provider-console"
        or instant(metadata["verified_at"]) > now
    ):
        raise LifecycleError("DigitalOcean bootstrap policy metadata is unverified")
    spaces = Spaces(Api("https://api.digitalocean.com", values["digitalocean"]))
    account = Cloudflare(Api(ORIGIN, values["cloudflare_account"]), account=targets.account_id)
    user = Cloudflare(Api(ORIGIN, values["cloudflare_user"]), account=None)
    # A live, complete read proves current authentication; inability to list is
    # never interpreted as absence. No credential is created during setup.
    spaces.inventory()
    account_id, account_expiry = _cloudflare_authority(account, target=targets, now=now)
    user_id, user_expiry = _cloudflare_authority(user, target=targets, now=now)
    authority = Authority(
        digest(
            {
                "digitalocean": metadata["token_sha256"],
                "cloudflare_account": account_id,
                "cloudflare_user": user_id,
                "journal_vault": vault,
            }
        ),
        min(
            account_expiry,
            user_expiry,
            instant(metadata["expires_at"]),
            bootstrap.expires_at(),
        ),
        {
            "spaces": spaces.authority_sha256,
            "cloudflare-account": account.authority_sha256,
            "cloudflare-user": user.authority_sha256,
        },
    )
    providers = cast(
        dict[ProviderKind, Provider],
        {"spaces": spaces, "cloudflare-account": account, "cloudflare-user": user},
    )
    return Connections(bootstrap.journal(vault, directory=journal_directory), providers, authority)
