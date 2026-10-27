"""Current native authority around terminal historical custody, with no source access."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.m3_11_custody_domain import DomainDocker
from scripts.m3_11_custody_domain import verify as verify_domain
from scripts.m3_11_custody_plan import require
from scripts.m3_11_custody_registry import Registry
from scripts.m3_11_frozen_client import make_client
from scripts.m3_11_frozen_terminal import terminal_facts
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_archive import MAX_VERSIONS, Archives
from scripts.m3_11_retirement_files import digest, record
from scripts.m3_11_unattended import readiness_credentials
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import LEASE_DIRECTORY
from scripts.m3_11_unattended.inventory import (
    ConnectInventoryReader,
    require_clear,
    require_confirmation,
)
from scripts.m3_11_unattended.lifecycle import fixture_scopes
from scripts.m3_11_unattended.model import ROLES, Credential, LeaseManifest, identity, instant
from scripts.m3_11_unattended.state import LeaseState
from scripts.m3_11_unattended.storage_admission import (
    HELPER_SECONDS,
    existing_lock,
    require_remaining,
)

MAX_READS = 80
POST_EFFECT_RESERVE = 1200  # 8 S3 x40 + 2 registry readers x9 x30 + durable reporting.
LOCAL_RESERVE = 180
MAX_JOURNAL_ITEMS = 10000


class NativeCustody:
    def __init__(  # noqa: PLR0913 - separate native, historical and proof trust boundaries
        self,
        *,
        configuration: LeaseConfiguration,
        historical: object,
        invocation: object,
        docker: DomainDocker,
        revalidate_custody_and_cleanup: Callable[[], str],
        require_cleanup_current: Callable[[int], None],
    ) -> None:
        self.config, self.historical, self.invocation = configuration, historical, invocation
        self.docker, self.revalidate, self.cleanup_current = (
            docker,
            revalidate_custody_and_cleanup,
            require_cleanup_current,
        )
        self.root, self.held = Path("/evidence"), False
        self.deletes, self.reads = 0, 0
        self.archives: Archives

    @contextmanager
    def locked(self, approved: dict[str, object]) -> Iterator[None]:
        require(not self.held, "custody retirement already holds native ownership")
        self.plan = approved
        self.lease = LeaseState(self.root / "leases" / identity(approved["current_lease_id"]))
        historical = fields(self.historical, {"manifest", "issuer", "created"})
        self.old_manifest = LeaseManifest.parse(historical["manifest"])
        require(
            self.old_manifest.lease_id == approved["historical_lease_id"]
            and self.old_manifest.sha256 == approved["historical_manifest_sha256"]
            and self.old_manifest.targets == self.config.targets,
            "historical custody lease or target differs",
        )
        require(
            self.config.helper_revision == approved["implementation_revision"],
            "custody retirement helper differs from configured source",
        )
        verify_domain(
            self.docker, approved["runtime"], self.invocation, helper=self.config.helper_revision
        )
        target = {
            "region": self.config.targets.region,
            "archive_bucket": self.config.targets.archive_bucket,
        }
        with ExitStack() as stack:
            stack.enter_context(existing_lock(self.lease.directory / "runtime-use.lock"))
            stack.enter_context(existing_lock(Path(LEASE_DIRECTORY) / (digest(target) + ".lock")))
            # The storage lock serializes all fixtures using the same bucket;
            # the lease lock forbids a concurrent runtime consumer/admission.
            self.manifest = self.lease.manifest()
            require(
                self.manifest.sha256 == approved["current_manifest_sha256"]
                and self.manifest.targets == self.config.targets
                and self.manifest.helper_revision == self.config.helper_revision
                and self.manifest.source_revision == self.config.helper_revision
                and self.manifest.policy.retain_after_failure
                and self.config.mode == "controller"
                and self.manifest.policy.sha256 == self.config.approved_policy_sha256
                and self.manifest.lease_id != self.old_manifest.lease_id
                and self.manifest.policy.deadline(instant(self.manifest.created_at))
                - datetime.now(UTC)
                > timedelta(seconds=HELPER_SECONDS),
                "current retirement lease differs from approved scope or full work budget",
            )
            self.deliveries = {
                intent.role: self.lease.credential(intent) for intent in self.manifest.intents
            }
            require(
                set(self.deliveries) == ROLES and all(self.deliveries.values()),
                "retirement requires all seven current native deliveries",
            )
            archive, operator = (
                cast(Credential, self.deliveries[role]) for role in ("archive", "operator")
            )
            require(
                archive.identifier != operator.identifier and archive.secret != operator.secret,
                "retirement archive principals are not independent",
            )
            bootstraps = self.config.generations[self.config.active_generation]
            require(
                bootstraps["provision"].reader_settings != bootstraps["cleanup"].reader_settings,
                "retirement journal principals are not separate",
            )
            self.held = True
            try:
                with readiness_credentials.read_only_requests(self.guard):
                    self.guard()
                    self.inventory = ConnectInventoryReader(
                        bootstraps["cleanup"].reader(), self.config.journal_vault
                    )
                    self.writer = Registry(
                        bootstraps["provision"].reader(),
                        self.config.journal_vault,
                        guard=self.guard,
                    )
                    self.observer = Registry(
                        bootstraps["cleanup"].reader(), self.config.journal_vault, guard=self.guard
                    )
                    require_clear(self.inventory, current_lease=self.manifest.lease_id)
                    require_confirmation(
                        self.inventory,
                        self.manifest,
                        independent_server_id=self.config.independent_server_id,
                    )
                    self.historical_facts()
                    scopes = fixture_scopes(
                        self.config.targets,
                        bootstraps["cleanup"].providers(
                            targets=self.config.targets, now=datetime.now(UTC)
                        ),
                    )
                    require(
                        all(
                            intent.scope == scopes[intent.role] for intent in self.manifest.intents
                        ),
                        "current retirement lease differs from the native seven-role scope",
                    )
                    self.final_roles = readiness_credentials.validate_all_roles(
                        self.config,
                        self.manifest,
                        self.lease,
                        clock=lambda: datetime.now(UTC),
                        guard=self.guard,
                    )
                self.archives = Archives(
                    self.client("archive"),
                    self.client("operator"),
                    self.config.targets.archive_bucket,
                )
                yield
            finally:
                self.held = False

    def historical_facts(self) -> None:
        value = cast(dict[str, object], self.historical)
        terminal_facts(
            self.inventory.records(),
            self.old_manifest,
            issuer=value["issuer"],
            created=cast(dict[str, object], value["created"]),
        )

    def guard(self) -> None:
        require(self.held, "custody retirement does not hold native ownership")
        require_remaining(LOCAL_RESERVE)
        self.cleanup_current(LOCAL_RESERVE)
        now = datetime.now(UTC)
        require(
            self.lease.manifest().sha256 == self.plan["current_manifest_sha256"]
            and self.manifest.policy.deadline(instant(self.manifest.created_at)) > now
            and all(instant(intent.deadline) > now for intent in self.manifest.intents)
            and not list(self.lease.directory.glob("close-*.json"))
            and not list(self.lease.directory.glob("use-*.json")),
            "current lease changed, expired, is closing or has runtime users",
        )
        stopped = self.lease.issuer_stop()
        require(
            stopped is not None
            and stopped["retained_roles"] == sorted(ROLES)
            and instant(stopped["stopped_at"]) <= now,
            "current issuer is not stopped",
        )
        for intent in self.manifest.intents:
            credential = cast(Credential, self.deliveries[intent.role])
            require(
                self.lease.credential(intent) == credential
                and self.lease.created(intent)
                == {"intent_sha256": intent.sha256, "credential_id": credential.identifier},
                "current retirement credential identity changed",
            )

    def verify_custody(self) -> None:
        require(self.revalidate() == self.plan["custody_sha256"], "preserved custody proof differs")
        self.cleanup_current(POST_EFFECT_RESERVE + 70)
        verify_domain(
            self.docker, self.plan["runtime"], self.invocation, helper=self.config.helper_revision
        )
        self.guard()
        with readiness_credentials.read_only_requests(self.guard):
            self.historical_facts()
            self.final_roles()

    def exclusion(self) -> dict[str, object] | None:
        self.guard()
        first, second = (
            source.selected(str(self.plan["fixture_id"])) for source in (self.writer, self.observer)
        )
        require(first == second, "external custody exclusion principals disagree")
        return first

    def publish_exclusion(self, value: dict[str, object], *, spool: Path) -> None:
        self.guard()
        self.writer.publish_once(value, spool=spool)

    def require_exclusion(self, value: dict[str, object]) -> None:
        require(self.exclusion() == value, "permanent external custody exclusion is not visible")

    @contextmanager
    def submission(self) -> Iterator[None]:
        self.guard()
        verify_domain(
            self.docker, self.plan["runtime"], self.invocation, helper=self.config.helper_revision
        )
        with readiness_credentials.read_only_requests(self.guard):
            self.final_roles()
        self.cleanup_current(POST_EFFECT_RESERVE + 70)
        require_remaining(POST_EFFECT_RESERVE + 40)
        with existing_lock(self.root / ".credential-cleanup.lock"):
            self.guard()
            yield

    def client(self, role: str) -> S3Client:
        credential = cast(Credential, self.deliveries[role])
        selected = cast(dict[str, object], self.plan["archive"])
        require(
            selected["bucket"] == self.config.targets.archive_bucket,
            "retirement archive bucket differs from current and historical authority",
        )

        def parameters(params: dict[str, object], model: object, **_kwargs: object) -> None:
            operation = getattr(model, "name", None)
            allowed = {
                "GetBucketVersioning": {"Bucket": selected["bucket"]},
                "ListObjectsV2": {"Bucket": selected["bucket"], "MaxKeys": MAX_VERSIONS + 1},
                "ListObjectVersions": {"Bucket": selected["bucket"], "MaxKeys": MAX_VERSIONS + 1},
                "ListMultipartUploads": {"Bucket": selected["bucket"], "MaxUploads": 1},
            }
            if operation == "DeleteObject":
                require(
                    role == "archive"
                    and self.deletes == 0
                    and params
                    == {
                        "Bucket": selected["bucket"],
                        "Key": selected["key"],
                        "VersionId": selected["version"],
                    },
                    "custody retirement attempted an unapproved mutation",
                )
                self.deletes += 1
            else:
                require(
                    operation in allowed and params == allowed[operation],
                    "custody retirement attempted an unapproved read",
                )
                self.reads += 1
                require(self.reads <= MAX_READS, "custody retirement exceeded its read budget")
            self.guard()
            require_remaining(40)

        def before_wire(operation: str) -> None:
            self.guard()
            if operation == "DeleteObject":
                self.remote_open()
                self.cleanup_current(POST_EFFECT_RESERVE + 40)
                require_remaining(POST_EFFECT_RESERVE + 40)

        return make_client(
            ArchiveConfiguration(
                self.config.targets.region,
                self.config.targets.archive_bucket,
                credential.identifier,
                credential.secret,
            ),
            parameters,
            before_wire,
        )

    def remote_open(self) -> None:
        """One bounded native close-intent read immediately before the DELETE."""
        require_remaining(POST_EFFECT_RESERVE + 30)
        response = self.inventory.client.request(
            "GET", f"/v1/vaults/{self.config.journal_vault}/items"
        )
        require(
            response.status == HTTPStatus.OK
            and isinstance(response.body, list)
            and len(response.body) <= MAX_JOURNAL_ITEMS,
            "current lease close inventory is unavailable",
        )
        prefix = "m3-11-lease-" + self.manifest.lease_id + "-close"
        require(
            not any(
                not isinstance(row, dict) or str(row.get("title", "")).startswith(prefix)
                for row in cast(list[object], response.body)
            ),
            "current retirement lease is closing remotely",
        )

    def record_completion(self, value: dict[str, object]) -> None:
        self.guard()
        record(
            self.lease.directory / "custody-retirement.json",
            {
                "fixture_id": self.plan["fixture_id"],
                "retirement_sha256": digest(value),
            },
        )
