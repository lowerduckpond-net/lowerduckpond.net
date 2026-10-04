"""Strict, non-secret ownership records shared with independent credential cleanup."""

from __future__ import annotations

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
            or instant(self.deadline) - instant(self.requested_at) != LIFETIME
            or instant(self.create_before) - instant(self.requested_at) != CREATION_SETTLE
            or len(set(self.baseline_ids)) != len(self.baseline_ids)
            or any(
                re.fullmatch(r"[A-Za-z0-9_-]{8,128}", item) is None for item in self.baseline_ids
            )
        ):
            raise LifecycleError("invalid credential creation intent")

    def document(self) -> dict[str, object]:
        value = asdict(self)
        value["baseline_ids"] = list(self.baseline_ids)
        return value

    @classmethod
    def parse(cls, value: object) -> Intent:
        data = fields(value, set(cls.__dataclass_fields__))
        names = set(cls.__dataclass_fields__) - {"scope", "baseline_ids", "targets"}
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
