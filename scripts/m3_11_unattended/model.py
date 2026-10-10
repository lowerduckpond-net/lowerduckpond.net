"""Strict, non-secret ownership records shared with independent credential cleanup."""

from __future__ import annotations

import calendar
import hashlib
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.production_qualification_inputs import revision

LIFETIME = timedelta(hours=14)
CREATION_SETTLE = timedelta(minutes=5)
CLEANUP_MARGIN = timedelta(days=2)
ROLES = frozenset({"archive", "backup", "operator", "caddy", "observer", "audit", "page-rules"})
ProviderKind = Literal["spaces", "cloudflare-account", "cloudflare-user"]
PROVIDERS: frozenset[ProviderKind] = frozenset({"spaces", "cloudflare-account", "cloudflare-user"})
LEASE_POLICY_FORMAT = "lowerduckpond-m3-11-lease-policy-v1"
GENERATION_FORMAT = "lowerduckpond-m3-11-authority-generation-v1"
MONTHS_PER_YEAR = 12


class LifecycleError(RuntimeError):
    """Only fixed diagnostics may cross the private controller boundary."""


def instant(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LifecycleError("invalid lifecycle timestamp")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise LifecycleError("invalid lifecycle timestamp") from None
    if result.tzinfo != UTC:
        raise LifecycleError("invalid lifecycle timestamp")
    return result


def stamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise LifecycleError("lifecycle clock must be timezone aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def identity(value: object) -> str:
    if not isinstance(value, str):
        raise LifecycleError("invalid lifecycle identity")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise LifecycleError("invalid lifecycle identity") from None
    if str(parsed) != value or parsed.version != 7:  # noqa: PLR2004 - UUIDv7
        raise LifecycleError("invalid lifecycle identity")
    return value


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strings(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise LifecycleError("invalid lifecycle string mapping")
    return cast(dict[str, str], value)


def fingerprint(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise LifecycleError("invalid lifecycle digest")
    return value


@dataclass(frozen=True)
class LeasePolicy:
    """Explicit approved inputs; there are deliberately no operational defaults.

    Seven days is the reviewed design recommendation, not an implicit live grant.
    Parsing historical policy is independent of current admission or expiry.
    """

    approved_at: str
    start_before: str
    issuance_before: str
    credential_lifetime_seconds: int
    cleanup_reserve_seconds: int
    retain_after_failure: bool
    approval_reference: str

    def __post_init__(self) -> None:
        if (
            not instant(self.approved_at)
            < instant(self.start_before)
            <= instant(self.issuance_before)
            or any(
                type(value) is not int or not 0 < value <= 2**31 - 1
                for value in (self.credential_lifetime_seconds, self.cleanup_reserve_seconds)
            )
            or type(self.retain_after_failure) is not bool
            or not isinstance(self.approval_reference, str)
            or not 1 <= len(self.approval_reference) <= 256  # noqa: PLR2004 - bounded approval label
            or any(ord(char) < 32 for char in self.approval_reference)  # noqa: PLR2004
        ):
            raise LifecycleError("lease policy is missing explicit approved bounds")

    def document(self) -> dict[str, object]:
        return {"format": LEASE_POLICY_FORMAT, **asdict(self)}

    @property
    def sha256(self) -> str:
        return digest(self.document())

    @classmethod
    def parse(cls, value: object) -> LeasePolicy:
        data = fields(value, {"format", *cls.__dataclass_fields__})
        if data["format"] != LEASE_POLICY_FORMAT:
            raise LifecycleError("lease policy format is unsupported")
        texts = strings(
            {
                key: data[key]
                for key in ("approved_at", "start_before", "issuance_before", "approval_reference")
            }
        )
        if (
            any(
                type(data[key]) is not int
                for key in ("credential_lifetime_seconds", "cleanup_reserve_seconds")
            )
            or type(data["retain_after_failure"]) is not bool
        ):
            raise LifecycleError("lease policy bounds have invalid types")
        return cls(
            **texts,
            credential_lifetime_seconds=cast(int, data["credential_lifetime_seconds"]),
            cleanup_reserve_seconds=cast(int, data["cleanup_reserve_seconds"]),
            retain_after_failure=data["retain_after_failure"],
        )

    def deadline(self, requested_at: datetime) -> datetime:
        try:
            return requested_at + timedelta(seconds=self.credential_lifetime_seconds)
        except OverflowError:
            raise LifecycleError("lease deadline exceeds the timestamp range") from None

    def require_start(self, *, now: datetime, approved_sha256: str) -> None:
        if (
            fingerprint(approved_sha256) != self.sha256
            or not instant(self.approved_at) <= now < instant(self.start_before)
            or not now < instant(self.issuance_before) < self.deadline(now)
        ):
            raise LifecycleError("lease policy is unapproved or its start window elapsed")


@dataclass(frozen=True)
class AuthorityGeneration:
    """Non-secret verified metadata for one role of a monthly authority generation."""

    generation_id: str
    role: str
    targets_sha256: str
    principals: dict[str, str]
    fingerprints: dict[str, str]
    expires_at: dict[str, str]
    connect_expires_at: str
    introduced_at: str
    rotation_due_at: str

    def __post_init__(self) -> None:
        identity(self.generation_id)
        fingerprint(self.targets_sha256)
        if self.role not in {"provision", "cleanup"}:
            raise LifecycleError("authority generation role is invalid")
        for values in (self.principals, self.fingerprints, self.expires_at):
            if set(strings(values)) != PROVIDERS:
                raise LifecycleError("authority generation is incomplete")
        for value in self.fingerprints.values():
            fingerprint(value)
        for value in self.expires_at.values():
            instant(value)
        instant(self.connect_expires_at)
        introduced = instant(self.introduced_at)
        year, month = (
            introduced.year + (introduced.month == MONTHS_PER_YEAR),
            introduced.month % MONTHS_PER_YEAR + 1,
        )
        expected_rotation = introduced.replace(
            year=year, month=month, day=min(introduced.day, calendar.monthrange(year, month)[1])
        )
        if instant(self.rotation_due_at) != expected_rotation:
            raise LifecycleError(
                "authority generation must use its explicit calendar-month rotation"
            )
        if any(
            not 1 <= len(value) <= 128  # noqa: PLR2004 - bounded non-secret principal
            or re.fullmatch(r"[A-Za-z0-9_.:@/-]+", value) is None
            for value in self.principals.values()
        ):
            raise LifecycleError("authority generation principal is unestablished")

    def document(self) -> dict[str, object]:
        return {"format": GENERATION_FORMAT, **asdict(self)}

    @classmethod
    def parse(cls, value: object) -> AuthorityGeneration:
        data = fields(value, {"format", *cls.__dataclass_fields__})
        if data["format"] != GENERATION_FORMAT:
            raise LifecycleError("authority generation format is unsupported")
        return cls(
            **strings(
                {
                    key: data[key]
                    for key in (
                        "generation_id",
                        "role",
                        "targets_sha256",
                        "connect_expires_at",
                        "introduced_at",
                        "rotation_due_at",
                    )
                }
            ),
            principals=strings(data["principals"]),
            fingerprints=strings(data["fingerprints"]),
            expires_at=strings(data["expires_at"]),
        )

    def require_coverage(self, *, policy: LeasePolicy, deadline: datetime) -> None:
        reserve = (
            timedelta(seconds=policy.cleanup_reserve_seconds)
            if self.role == "cleanup"
            else timedelta()
        )
        if any(
            instant(value) < deadline + reserve
            for value in (*self.expires_at.values(), self.connect_expires_at)
        ):
            raise LifecycleError("authority generation cannot cover the child deadline")

    def require_same_principal(self, previous: AuthorityGeneration) -> None:
        if (
            self.role != previous.role
            or self.targets_sha256 != previous.targets_sha256
            or self.principals != previous.principals
        ):
            raise LifecycleError("replacement authority principal or targets differ")


@dataclass(frozen=True)
class Targets:
    region: str
    archive_bucket: str
    backup_bucket: str
    account_id: str
    zone_id: str
    tenant_zone_id: str
    user_id: str

    def __post_init__(self) -> None:
        if (
            re.fullmatch(r"[a-z]{3}[1-9][0-9]?", self.region) is None
            or any(
                re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
                for bucket in (self.archive_bucket, self.backup_bucket)
            )
            or self.archive_bucket == self.backup_bucket
            or self.zone_id == self.tenant_zone_id
            or any(
                re.fullmatch(r"[0-9a-f]{32}", item) is None
                for item in (self.account_id, self.zone_id, self.tenant_zone_id, self.user_id)
            )
        ):
            raise LifecycleError("invalid approved qualification targets")

    @classmethod
    def parse(cls, value: object) -> Targets:
        return cls(**strings(fields(value, set(cls.__dataclass_fields__))))

    def environment(self) -> dict[str, str]:
        return {
            "SPACES_REGION": self.region,
            "SPACES_ARCHIVE_BUCKET": self.archive_bucket,
            "SPACES_BACKUP_BUCKET": self.backup_bucket,
            "CLOUDFLARE_ZONE_ID": self.zone_id,
            "CLOUDFLARE_TENANT_ZONE_ID": self.tenant_zone_id,
        }

    @property
    def storage_digest(self) -> str:
        # Preserve ADR 0029's existing target encoding (without the trailing LF).
        values = {
            key: value for key, value in self.environment().items() if key.startswith("SPACES_")
        }
        return hashlib.sha256(canonical_bytes(values).rstrip(b"\n")).hexdigest()

    @property
    def zone_resources(self) -> dict[str, str]:
        return {
            f"com.cloudflare.api.account.zone.{zone}": "*"
            for zone in (self.zone_id, self.tenant_zone_id)
        }


@dataclass(frozen=True)
class Intent:
    run_id: str
    role: str
    source_revision: str
    helper_revision: str
    provider: ProviderKind
    cleanup_authority_sha256: str
    name: str
    requested_at: str
    create_before: str
    deadline: str
    scope: dict[str, object]
    baseline_ids: tuple[str, ...]
    targets: Targets
    policy: LeasePolicy | None = None

    def __post_init__(self) -> None:
        identity(self.run_id)
        revision(self.source_revision)
        revision(self.helper_revision)
        if (
            self.role not in ROLES
            or re.fullmatch(r"[0-9a-f]{64}", self.cleanup_authority_sha256) is None
            or self.provider not in {"spaces", "cloudflare-account", "cloudflare-user"}
            or self.name != f"ldp-m311-{uuid.UUID(self.run_id).hex}-{self.role}"
            or not instant(self.requested_at) < instant(self.create_before) < instant(self.deadline)
            or (
                self.policy is None
                and (
                    instant(self.deadline) - instant(self.requested_at) != LIFETIME
                    or instant(self.create_before) - instant(self.requested_at) != CREATION_SETTLE
                )
            )
            or (
                self.policy is not None
                and (
                    instant(self.deadline) != self.policy.deadline(instant(self.requested_at))
                    or self.create_before != self.policy.issuance_before
                    or not instant(self.policy.approved_at)
                    <= instant(self.requested_at)
                    < instant(self.policy.start_before)
                )
            )
            or len(set(self.baseline_ids)) != len(self.baseline_ids)
            or any(
                re.fullmatch(r"[A-Za-z0-9_-]{8,128}", item) is None for item in self.baseline_ids
            )
        ):
            raise LifecycleError("invalid credential creation intent")

    def document(self) -> dict[str, object]:
        value = asdict(self)
        value["baseline_ids"] = list(self.baseline_ids)
        if self.policy is None:
            del value["policy"]
        else:
            value["policy"] = self.policy.document()
        return value

    @classmethod
    def parse(cls, value: object) -> Intent:
        expected = set(cls.__dataclass_fields__) - {"policy"}
        if isinstance(value, dict) and "policy" in value:
            expected.add("policy")
        data = fields(value, expected)
        names = set(cls.__dataclass_fields__) - {"scope", "baseline_ids", "targets", "policy"}
        text = strings({key: data[key] for key in names})
        scope, baseline = data["scope"], data["baseline_ids"]
        if (
            not isinstance(scope, dict)
            or not isinstance(baseline, list)
            or any(not isinstance(item, str) for item in baseline)
        ):
            raise LifecycleError("invalid credential creation intent")
        return cls(
            run_id=text["run_id"],
            role=text["role"],
            source_revision=text["source_revision"],
            helper_revision=text["helper_revision"],
            provider=cast(ProviderKind, text["provider"]),
            cleanup_authority_sha256=text["cleanup_authority_sha256"],
            name=text["name"],
            requested_at=text["requested_at"],
            create_before=text["create_before"],
            deadline=text["deadline"],
            scope=scope,
            baseline_ids=tuple(baseline),
            targets=Targets.parse(data["targets"]),
            policy=LeasePolicy.parse(data["policy"]) if "policy" in data else None,
        )

    @property
    def sha256(self) -> str:
        return digest(self.document())


@dataclass(frozen=True)
class Credential:
    identifier: str
    secret: str = field(repr=False)
    metadata: dict[str, object] = field(repr=False)


@dataclass(frozen=True)
class Authority:
    """A verified cleanup identity and its conservative available-until boundary."""

    identity_sha256: str
    valid_until: datetime
    providers: dict[ProviderKind, str] = field(default_factory=dict)

    def provider_identity(self, kind: ProviderKind) -> str:
        return self.providers.get(kind, self.identity_sha256)

    def require(self, deadline: datetime) -> None:
        if (
            re.fullmatch(r"[0-9a-f]{64}", self.identity_sha256) is None
            or self.valid_until < deadline + CLEANUP_MARGIN
        ):
            raise LifecycleError("cleanup authority does not outlive the child credential deadline")


@dataclass(frozen=True)
class LeaseManifest:
    """The complete immutable obligation exists off-host before the first CREATE."""

    lease_id: str
    source_revision: str
    helper_revision: str
    created_at: str
    policy: LeasePolicy
    creator: AuthorityGeneration
    cleanup: AuthorityGeneration
    targets: Targets
    intents: tuple[Intent, ...]

    def __post_init__(self) -> None:
        identity(self.lease_id)
        revision(self.source_revision)
        revision(self.helper_revision)
        requested = instant(self.created_at)
        self.policy.require_start(now=requested, approved_sha256=self.policy.sha256)
        target_digest = digest(asdict(self.targets))
        if (
            self.creator.role != "provision"
            or self.cleanup.role != "cleanup"
            or self.creator.generation_id != self.cleanup.generation_id
            or self.creator.principals != self.cleanup.principals
            or any(
                generation.targets_sha256 != target_digest
                or generation.principals["cloudflare-account"] != self.targets.account_id
                or generation.principals["cloudflare-user"] != self.targets.user_id
                for generation in (self.creator, self.cleanup)
            )
            or {intent.role for intent in self.intents} != ROLES
            or len(self.intents) != len(ROLES)
        ):
            raise LifecycleError("lease manifest has incomplete or mismatched authority and roles")
        for generation in (self.creator, self.cleanup):
            generation.require_coverage(
                policy=self.policy, deadline=self.policy.deadline(requested)
            )
        for intent in self.intents:
            provider = (
                "spaces"
                if intent.role in {"archive", "backup", "operator"}
                else "cloudflare-user"
                if intent.role == "page-rules"
                else "cloudflare-account"
            )
            if (
                intent.run_id != self.lease_id
                or intent.source_revision != self.source_revision
                or intent.helper_revision != self.helper_revision
                or intent.requested_at != self.created_at
                or intent.policy != self.policy
                or intent.targets != self.targets
                or intent.provider != provider
                or intent.cleanup_authority_sha256 != self.cleanup.fingerprints[provider]
            ):
                raise LifecycleError("lease manifest child differs from its approved binding")

    def document(self) -> dict[str, object]:
        return {
            "format": "lowerduckpond-m3-11-lease-manifest-v1",
            "lease_id": self.lease_id,
            "source_revision": self.source_revision,
            "helper_revision": self.helper_revision,
            "created_at": self.created_at,
            "policy": self.policy.document(),
            "creator": self.creator.document(),
            "cleanup": self.cleanup.document(),
            "targets": asdict(self.targets),
            "intents": [intent.document() for intent in sorted(self.intents, key=lambda v: v.role)],
        }

    @property
    def sha256(self) -> str:
        return digest(self.document())

    @classmethod
    def parse(cls, value: object) -> LeaseManifest:
        data = fields(value, {"format", *cls.__dataclass_fields__})
        if data["format"] != "lowerduckpond-m3-11-lease-manifest-v1" or not isinstance(
            data["intents"], list
        ):
            raise LifecycleError("lease manifest format is invalid")
        return cls(
            **strings(
                {
                    key: data[key]
                    for key in ("lease_id", "source_revision", "helper_revision", "created_at")
                }
            ),
            policy=LeasePolicy.parse(data["policy"]),
            creator=AuthorityGeneration.parse(data["creator"]),
            cleanup=AuthorityGeneration.parse(data["cleanup"]),
            targets=Targets.parse(data["targets"]),
            intents=tuple(Intent.parse(entry) for entry in data["intents"]),
        )
