"""Select only existing Cloudflare account authority; never load unrelated roots."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta

from scripts.m3_11_isolation_lease import Provider
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.config import LeaseBootstrap, LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import identity as connect_identity
from scripts.m3_11_unattended.connect_configuration import reader, reader_access
from scripts.m3_11_unattended.model import Targets, digest, instant

FORMAT = "lowerduckpond-isolated-public-ca-host-access-v1"


@dataclass(frozen=True)
class HostAccess:
    targets: Targets
    journal_vault: str
    provision: LeaseBootstrap = field(repr=False)
    cleanup: LeaseBootstrap = field(repr=False)

    @classmethod
    def parse(cls, raw: object) -> HostAccess:
        value = fields(raw, {"format", "targets", "journal_vault", "provision", "cleanup"})
        if value["format"] != FORMAT:
            raise ValueError("isolated host access format differs")
        targets = Targets.parse(value["targets"])
        vault = connect_identity(value["journal_vault"])
        result = cls(
            targets,
            vault,
            LeaseBootstrap.parse(value["provision"], targets=targets, vault=vault),
            LeaseBootstrap.parse(value["cleanup"], targets=targets, vault=vault),
        )
        settings = [
            reader_access(item.reader_settings, allow_expired=True)
            for item in (result.provision, result.cleanup)
        ]
        if (
            result.provision.generation.role != "provision"
            or result.cleanup.generation.role != "cleanup"
            or result.provision.generation.principals != result.cleanup.generation.principals
            or settings[0][0]["vaults"] != settings[1][0]["vaults"]
            or settings[0][0]["url"] != settings[1][0]["url"]
            or settings[0][1].server_id != settings[1][1].server_id
            or settings[0][1].token_id == settings[1][1].token_id
            or settings[0][1].token == settings[1][1].token
        ):
            raise ValueError("isolated shared readers or authority roles differ")
        return result

    def require(self, manifest: Manifest) -> None:
        settings = [reader_access(item.reader_settings) for item in (self.provision, self.cleanup)]
        minimum = instant(manifest.intents[0].expires_at) + timedelta(
            seconds=manifest.plan.authority_reserve_seconds
        )
        if (
            self.journal_vault != manifest.journal_vault
            or self.provision.generation != manifest.provision_generation
            or self.cleanup.generation != manifest.cleanup_generation
            or self.targets.account_id != manifest.plan.account_id
            or self.targets.zone_id != manifest.plan.zones["lowerduckpond.net"]
            or self.targets.tenant_zone_id != manifest.plan.zones["lowerduckpond.com"]
            or any(
                access.server_id == manifest.independent_server_id or access.expires_at < minimum
                for _, access in settings
            )
        ):
            raise ValueError("isolated host access differs from its exact manifest")

    def client(self, role: str, manifest: Manifest) -> Connect:
        self.require(manifest)
        if role not in {"provision", "cleanup"}:
            raise ValueError("isolation cannot select a production reader")
        selected = self.provision if role == "provision" else self.cleanup
        return reader(selected.reader_settings)

    def provider(self, role: str, manifest: Manifest, *, client: Connect) -> Provider:
        self.require(manifest)
        selected = (
            self.provision if role == "provision" else self.cleanup if role == "cleanup" else None
        )
        if selected is None:
            raise ValueError("isolated authority role differs")
        now = datetime.now(UTC)
        if role == "provision" and not instant(selected.generation.introduced_at) <= now < instant(
            selected.generation.rotation_due_at
        ):
            raise ValueError("isolated creator generation is outside its admission month")
        return account_provider(selected, self.targets, manifest, client=client, now=now)

    def document(self) -> dict[str, object]:
        return {
            "format": FORMAT,
            "targets": asdict(self.targets),
            "journal_vault": self.journal_vault,
            "provision": self.provision.document(),
            "cleanup": self.cleanup.document(),
        }

    def cleanup_access(self) -> CleanupAccess:
        return CleanupAccess(self.targets, self.journal_vault, self.cleanup)


@dataclass(frozen=True)
class CleanupAccess:
    targets: Targets
    journal_vault: str
    cleanup: LeaseBootstrap = field(repr=False)

    @classmethod
    def parse(cls, raw: object) -> CleanupAccess:
        row = fields(raw, {"format", "targets", "journal_vault", "cleanup"})
        if row["format"] != "lowerduckpond-isolated-public-ca-cleanup-access-v1":
            raise ValueError("isolated cleanup access format differs")
        targets = Targets.parse(row["targets"])
        vault = connect_identity(row["journal_vault"])
        bootstrap = LeaseBootstrap.parse(row["cleanup"], targets=targets, vault=vault)
        if bootstrap.generation.role != "cleanup":
            raise ValueError("isolated cleanup cannot import creator access")
        return cls(targets, vault, bootstrap)

    def require(self, manifest: Manifest) -> None:
        configured, access = reader_access(self.cleanup.reader_settings)
        minimum = instant(manifest.intents[0].expires_at) + timedelta(
            seconds=manifest.plan.authority_reserve_seconds
        )
        if (
            self.cleanup.generation != manifest.cleanup_generation
            or self.journal_vault != manifest.journal_vault
            or self.targets.account_id != manifest.plan.account_id
            or self.targets.zone_id != manifest.plan.zones["lowerduckpond.net"]
            or self.targets.tenant_zone_id != manifest.plan.zones["lowerduckpond.com"]
            or access.server_id == manifest.independent_server_id
            or access.expires_at < minimum
            or configured["role"] != "cleanup"
        ):
            raise ValueError("isolated cleanup differs from its exact shared-reader scope")

    def client(self, manifest: Manifest) -> Connect:
        self.require(manifest)
        return reader(self.cleanup.reader_settings)

    def provider(self, manifest: Manifest, *, client: Connect) -> Provider:
        self.require(manifest)
        return account_provider(
            self.cleanup, self.targets, manifest, client=client, now=datetime.now(UTC)
        )

    def document(self) -> dict[str, object]:
        return {
            "format": "lowerduckpond-isolated-public-ca-cleanup-access-v1",
            "targets": asdict(self.targets),
            "journal_vault": self.journal_vault,
            "cleanup": self.cleanup.document(),
        }


def account_provider(
    bootstrap: LeaseBootstrap,
    targets: Targets,
    manifest: Manifest,
    *,
    client: Connect,
    now: datetime,
) -> Provider:
    expected = (
        manifest.provision_generation
        if bootstrap.generation.role == "provision"
        else manifest.cleanup_generation
    )
    if bootstrap.generation != expected or expected.targets_sha256 != digest(asdict(targets)):
        raise ValueError("isolated account authority generation differs")
    # This existing native method checks activity, exact Account API Tokens
    # Write grant/resources and native expiry. It reads ONLY this reference;
    # providers() would also read DigitalOcean and user-token authority.
    selected = bootstrap._provider(client, "cloudflare-account", targets=targets, now=now)
    if (
        not isinstance(selected, Cloudflare)
        or selected.authority_sha256 != expected.fingerprints["cloudflare-account"]
    ):
        raise ValueError("isolated account authority identity differs")
    return Provider(selected.api, account=manifest.plan.account_id)


def independent(config: LeaseConfiguration, manifest: Manifest) -> LeaseBootstrap:
    manifest.require_independent_configuration(config)
    return config.generations[config.active_generation]["cleanup"]
