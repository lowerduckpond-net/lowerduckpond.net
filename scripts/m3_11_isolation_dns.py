"""Read-only three-role authentication and DNS observations for isolation only."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from scripts.check_m3_7_production_edge import (
    CloudflareClient,
    _account_token_details,
    _require_zone_identity,
    _resolve_permission_groups,
)
from scripts.m3_11_dns_witness import DnsWitness
from scripts.m3_11_isolation_contract import (
    PERMISSIONS,
    Intent,
    Plan,
    provider_id,
    require_agreement,
)
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.model import digest, instant


@dataclass(frozen=True)
class Readers:
    audit: str = field(repr=False)
    caddy: str = field(repr=False)
    observer: str = field(repr=False)


def authenticate(
    plan: Plan,
    intents: tuple[Intent, ...],
    readers: Readers,
    *,
    expected_ids: dict[str, str],
    now: datetime,
) -> dict[str, str]:
    """GET-only audit of exact creation IDs, grants, validity and account/zone identity."""
    if require_agreement(intents).sha256 != plan.sha256:
        raise ValueError("isolated authentication plan differs from all three intents")
    by_role = {intent.role: intent for intent in intents}
    if (
        len(intents) != len(PERMISSIONS)
        or set(by_role) != PERMISSIONS.keys()
        or set(expected_ids) != PERMISSIONS.keys()
        or len(set(expected_ids.values())) != len(PERMISSIONS)
    ):
        raise ValueError("isolated authentication requires exactly three roles")
    tokens = {role: getattr(readers, role) for role in PERMISSIONS}
    if any(not token or any(char.isspace() for char in token) for token in tokens.values()) or len(
        set(tokens.values())
    ) != len(PERMISSIONS):
        raise ValueError("isolated authentication requires three distinct private credentials")
    audit = CloudflareClient(readers.audit)
    identities: dict[str, str] = {}
    for role in sorted(PERMISSIONS):
        intent = by_role[role]
        if intent.plan.sha256 != plan.sha256 or not instant(intent.requested_at) <= now < instant(
            intent.expires_at
        ):
            raise ValueError("isolated authentication differs from its bound plan or validity")
        client = CloudflareClient(tokens[role])
        details = _account_token_details(
            audit, client, account_id=plan.account_id, label="isolation"
        )
        selected = intent.require_owned(details)
        if selected != provider_id(expected_ids[role]):
            raise ValueError("isolated credential differs from its creation identity")
        scope = "com.cloudflare.api.account" + ("" if role == "audit" else ".zone")
        resolved = _resolve_permission_groups(
            audit, account_id=plan.account_id, names=PERMISSIONS[role], expected_scope=scope
        )
        if resolved != intent.permission_ids:
            raise ValueError("isolated permission IDs differ from the authoritative registry")
        if role != "audit":
            for domain, zone in plan.zones.items():
                if _require_zone_identity(client, zone, domain) != plan.account_id:
                    raise ValueError("isolated zone belongs to another account")
        identities[role] = provider_id(selected)
    if len(set(identities.values())) != len(PERMISSIONS):
        raise ValueError("isolated credential identities are not separated")
    return identities


class IsolationWitness(DnsWitness):
    """Same bounded record observation, separate context and evidence namespace."""

    def binding_documents(self) -> tuple[Path, Path]:
        return self.directory / "isolation-context.json", self.directory / "isolation-names.json"

    @classmethod
    def open(cls, directory: Path, plan: Plan, readers: Readers) -> IsolationWitness:
        context_path, names_path = (
            directory / "isolation-context.json",
            directory / "isolation-names.json",
        )
        context, names = read_private(context_path), read_private(names_path)
        if context.get("plan_sha256") != plan.sha256 or names != {
            "format": "lowerduckpond-isolated-public-ca-names-v1",
            "plan_sha256": plan.sha256,
            "nonce": plan.nonce,
        }:
            raise ValueError("isolated DNS context differs from its plan")
        observations = directory / "isolation-dns"
        observations.mkdir(mode=0o700)
        result = cls(
            directory,
            CloudflareClient(readers.observer),
            digest(context),
            digest(names),
            tuple(
                (domain, zone, f"_acme-challenge.m3-11-{plan.nonce.replace('-', '')}.{domain}")
                for domain, zone in sorted(plan.zones.items())
            ),
        )
        result.output_directory = observations
        result.require_absent("baseline")
        return result
