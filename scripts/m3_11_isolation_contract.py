"""Separate, three-role contract for an isolated public-CA dependency diagnostic.

This is deliberately not a seven-role LeaseManifest or a qualification receipt.
No function here creates a fixture, publishes a manifest or calls a provider.
The execution adapter must supply actual audited identities and durable evidence.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Literal

from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS

from scripts.check_m3_7_production_edge import validate_account_token_policy
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import digest, fingerprint, identity, instant, strings

FORMAT = "lowerduckpond-isolated-public-ca-plan-v1"
CONTEXT_FORMAT = "lowerduckpond-isolated-public-ca-context-v1"
RESULT_FORMAT = "lowerduckpond-isolated-public-ca-result-v1"
ROLES = frozenset({"audit", "caddy", "observer"})
DOMAINS = frozenset({"lowerduckpond.net", "lowerduckpond.com"})
PERMISSIONS = {
    "audit": frozenset({"Account API Tokens Read"}),
    "caddy": frozenset({"DNS Write", "Zone Read"}),
    "observer": frozenset({"DNS Read", "Zone Read"}),
}
Mode = Literal["authoritative", "recursive-precheck"]


def provider_id(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError("isolation provider identity is invalid")
    return value


@dataclass(frozen=True)
class Network:
    mode: Mode
    resolvers: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> Network:
        row = fields(value, {"mode", "resolvers"})
        resolvers = row["resolvers"]
        if not isinstance(resolvers, list) or any(not isinstance(item, str) for item in resolvers):
            raise ValueError("isolation DNS mode must be explicitly chosen")
        if row["mode"] == "authoritative" and not resolvers:
            return cls("authoritative", ())
        if row["mode"] != "recursive-precheck" or len(resolvers) != 1:
            raise ValueError("isolation DNS mode must be explicitly chosen")
        resolver = str(ipaddress.ip_address(resolvers[0]))
        if resolver != resolvers[0] or ipaddress.ip_address(resolver).is_unspecified:
            raise ValueError("isolation recursive resolver is invalid")
        return cls("recursive-precheck", (resolver,))

    def document(self) -> dict[str, object]:
        # Validate even a directly constructed dataclass; constructors are not
        # a route around the strict external schema.
        value: dict[str, object] = {"mode": self.mode, "resolvers": list(self.resolvers)}
        if Network.parse(value) != self:
            raise ValueError("isolation DNS mode changed")
        return value


@dataclass(frozen=True)
class Plan:
    run_id: str
    nonce: str
    source_revision: str
    controller_sha256: str
    artifact_sha256: str
    caddy_binary_sha256: str
    fixture_image_sha256: str
    archive_image_sha256: str
    account_id: str
    zones: dict[str, str]
    network: Network
    docker_endpoint: str
    daemon_sha256: str
    approved_at: str
    start_before: str
    credential_lifetime_seconds: int
    cleanup_reserve_seconds: int
    authority_reserve_seconds: int
    approval_reference: str
    preparation_sha256: str

    def __post_init__(self) -> None:
        identity(self.run_id)
        identity(self.nonce)
        if self.run_id == self.nonce or re.fullmatch(r"[0-9a-f]{40}", self.source_revision) is None:
            raise ValueError("isolation source or nonce is invalid")
        for value in (
            self.controller_sha256,
            self.artifact_sha256,
            self.caddy_binary_sha256,
            self.fixture_image_sha256,
            self.archive_image_sha256,
            self.daemon_sha256,
            self.preparation_sha256,
        ):
            fingerprint(value)
        provider_id(self.account_id)
        if set(self.zones) != DOMAINS or len(set(self.zones.values())) != len(DOMAINS):
            raise ValueError("isolation requires the two exact, distinct zones")
        for value in self.zones.values():
            provider_id(value)
        self.network.document()
        if (
            not self.docker_endpoint.startswith("unix:///")
            or any(char.isspace() for char in self.docker_endpoint)
            or not instant(self.approved_at) < instant(self.start_before)
            or type(self.credential_lifetime_seconds) is not int
            or type(self.cleanup_reserve_seconds) is not int
            or type(self.authority_reserve_seconds) is not int
            or not 0 < self.authority_reserve_seconds <= 2**31 - 1
            or not 0 < self.cleanup_reserve_seconds <= 2**31 - 1
            or not 0 < self.credential_lifetime_seconds <= 2**31 - 1
            or self.credential_lifetime_seconds < COORDINATOR_SECONDS + self.cleanup_reserve_seconds
            or not isinstance(self.approval_reference, str)
            or not 1 <= len(self.approval_reference) <= 256  # noqa: PLR2004 - bounded reference
            or any(ord(char) < 32 for char in self.approval_reference)  # noqa: PLR2004
        ):
            raise ValueError("isolation plan lacks explicit approved time/runtime bounds")

    @classmethod
    def parse(cls, value: object) -> Plan:
        row = fields(value, {"format", *cls.__dataclass_fields__})
        if row["format"] != FORMAT:
            raise ValueError("isolation plan format is unsupported")
        selected = {
            "network",
            "zones",
            "credential_lifetime_seconds",
            "cleanup_reserve_seconds",
            "authority_reserve_seconds",
        }
        text = strings({key: row[key] for key in cls.__dataclass_fields__ if key not in selected})
        lifetime, reserve = row["credential_lifetime_seconds"], row["cleanup_reserve_seconds"]
        authority_reserve = row["authority_reserve_seconds"]
        if (
            type(lifetime) is not int
            or type(reserve) is not int
            or type(authority_reserve) is not int
        ):
            raise ValueError("isolation timing bounds must be explicit integers")
        return cls(
            **text,
            zones=strings(row["zones"]),
            network=Network.parse(row["network"]),
            credential_lifetime_seconds=lifetime,
            cleanup_reserve_seconds=reserve,
            authority_reserve_seconds=authority_reserve,
        )

    def document(self) -> dict[str, object]:
        self.__post_init__()
        value = asdict(self)
        value["network"] = self.network.document()
        return {"format": FORMAT, **value}

    @property
    def sha256(self) -> str:
        return digest(self.document())

    def token_name(self, role: str) -> str:
        if role not in ROLES:
            raise ValueError("isolation cannot request Spaces or Page Rules credentials")
        return f"ldp-public-ca-{uuid.UUID(self.run_id).hex}-{role}"

    def resources(self, role: str) -> frozenset[str]:
        self.token_name(role)
        return (
            frozenset({f"com.cloudflare.api.account.{self.account_id}"})
            if role == "audit"
            else frozenset(
                f"com.cloudflare.api.account.zone.{value}" for value in self.zones.values()
            )
        )


@dataclass(frozen=True)
class Intent:
    """Exact three-role scope, duration and pre-CREATE inventory, never secrets."""

    plan: Plan
    role: str
    requested_at: str
    create_before: str
    expires_at: str
    permission_ids: dict[str, str]
    baseline_ids: tuple[str, ...]
    issuer_authority_sha256: str
    cleanup_authority_sha256: str
    approval_reference: str

    def __post_init__(self) -> None:
        self.plan.token_name(self.role)
        fingerprint(self.issuer_authority_sha256)
        fingerprint(self.cleanup_authority_sha256)
        if (
            not instant(self.plan.approved_at)
            <= instant(self.requested_at)
            < instant(self.create_before)
            <= instant(self.plan.start_before)
            or not instant(self.create_before) < instant(self.expires_at)
            or instant(self.expires_at) - instant(self.requested_at)
            != timedelta(seconds=self.plan.credential_lifetime_seconds)
            or self.approval_reference != self.plan.approval_reference
            or self.issuer_authority_sha256 == self.cleanup_authority_sha256
            or set(self.permission_ids.values()) != PERMISSIONS[self.role]
            or len(self.permission_ids) != len(PERMISSIONS[self.role])
            or len(set(self.baseline_ids)) != len(self.baseline_ids)
            or not 1 <= len(self.approval_reference) <= 256  # noqa: PLR2004 - bounded reference
            or any(ord(char) < 32 for char in self.approval_reference)  # noqa: PLR2004
        ):
            raise ValueError("isolation intent lacks exact approved scope or time bounds")
        for value in (*self.permission_ids, *self.baseline_ids):
            provider_id(value)

    def document(self) -> dict[str, object]:
        return {
            **asdict(self),
            "format": "lowerduckpond-isolated-public-ca-intent-v1",
            "plan": self.plan.document(),
            "baseline_ids": list(self.baseline_ids),
        }

    @classmethod
    def parse(cls, raw: object) -> Intent:
        row = fields(raw, {"format", *cls.__dataclass_fields__})
        if row["format"] != "lowerduckpond-isolated-public-ca-intent-v1":
            raise ValueError("isolated intent format differs")
        baseline = row["baseline_ids"]
        if not isinstance(baseline, list) or any(not isinstance(item, str) for item in baseline):
            raise ValueError("isolated baseline is invalid")
        excluded = {"plan", "baseline_ids", "permission_ids"}
        text = strings({key: row[key] for key in cls.__dataclass_fields__ if key not in excluded})
        return cls(
            **text,
            plan=Plan.parse(row["plan"]),
            baseline_ids=tuple(baseline),
            permission_ids=strings(row["permission_ids"]),
        )

    @property
    def sha256(self) -> str:
        return digest(self.document())

    def require_owned(self, item: Mapping[str, object], *, active: bool = True) -> str:
        """A name/prefix alone can never authorize token revocation."""
        selected = provider_id(item.get("id"))
        status = item.get("status")
        if (
            selected in self.baseline_ids
            or item.get("name") != self.plan.token_name(self.role)
            or not instant(self.requested_at)
            <= instant(item.get("issued_on"))
            <= instant(self.create_before)
            or instant(item.get("expires_on")) != instant(self.expires_at)
            or instant(item.get("not_before")) != instant(self.requested_at)
            or item.get("condition") not in (None, {})
            or status not in ({"active"} if active else {"active", "disabled", "expired"})
        ):
            raise ValueError("isolation credential ownership is not proven")
        validate_account_token_policy(
            {**item, "status": "active"},
            expected_id=selected,
            expected_permissions=self.permission_ids,
            expected_resources=self.plan.resources(self.role),
            label="isolated public CA",
        )
        return selected


def require_agreement(intents: tuple[Intent, ...]) -> Plan:
    """Immutable three-role agreement, independently of CREATE admission time."""
    if len(intents) != len(ROLES) or {item.role for item in intents} != ROLES:
        raise ValueError("isolated public CA requires exactly three roles")
    first = intents[0]
    for item in intents:
        item.__post_init__()
        if (
            item.plan.sha256 != first.plan.sha256
            or item.requested_at != first.requested_at
            or item.create_before != first.create_before
            or item.expires_at != first.expires_at
            or item.baseline_ids != first.baseline_ids
            or item.cleanup_authority_sha256 != first.cleanup_authority_sha256
            or item.issuer_authority_sha256 != first.issuer_authority_sha256
            or item.approval_reference != first.approval_reference
        ):
            raise ValueError("isolation intent bindings differ")
    return first.plan


def require_three(intents: tuple[Intent, ...], *, now: datetime) -> Plan:
    plan = require_agreement(intents)
    if any(not instant(item.requested_at) <= now < instant(item.create_before) for item in intents):
        raise ValueError("isolation CREATE admission is closed")
    require_public_admission(intents, now=now)
    return plan


def require_public_admission(intents: tuple[Intent, ...], *, now: datetime) -> None:
    require_agreement(intents)
    first = intents[0]
    if not instant(first.requested_at) <= now < instant(first.plan.start_before) or (
        instant(first.expires_at) - now
        < timedelta(seconds=COORDINATOR_SECONDS + first.plan.cleanup_reserve_seconds)
    ):
        # The native phase and explicitly approved cleanup reserve must fit.
        # Fixture convergence precedes issuance rather than consuming this bound.
        raise ValueError("isolation lacks the public phase and cleanup reserve")
