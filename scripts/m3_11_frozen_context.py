"""Native locked owner for the one frozen-fixture archive transition.

Runs in the existing managed controller. A checksum-bound workstation driver
revalidates the preserved files and both native cleanup proofs while these locks
remain held; its exchange is bound to the exact approved evidence digest. This
class never starts, stops, removes or installs anything on a fixture.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts.m3_11_frozen_client import make_client
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_archive import Archives
from scripts.m3_11_retirement_files import RetirementError, digest, fingerprint, legacy
from scripts.m3_11_unattended import readiness_credentials
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import LEASE_DIRECTORY
from scripts.m3_11_unattended.model import Credential, identity, instant
from scripts.m3_11_unattended.state import LeaseState, RunState, journey_result
from scripts.m3_11_unattended.storage_admission import (
    HELPER_SECONDS,
    ReadOnlyDocker,
    existing_lock,
    require_remaining,
)
from scripts.qualification_context import resource_names
from scripts.qualification_mutation import ownership
from scripts.qualification_restore import environment_for

RETAINED_ROLES = {"archive", "audit", "backup", "caddy", "observer", "operator", "page-rules"}
MAX_READS = 200
POST_EFFECT_RESERVE = 2400


def require(value: object, explanation: str) -> None:
    if not value:
        raise RetirementError(explanation)


def actor(row: dict[str, object]) -> dict[str, object]:
    state = cast(dict[str, object], row["State"])
    host = cast(dict[str, object], row["HostConfig"])
    config = cast(dict[str, object], row["Config"])
    return {
        "id": row["Id"],
        "name": row["Name"],
        "image": row["Image"],
        "running": state["Running"],
        "restart_policy": cast(dict[str, object], host["RestartPolicy"])["Name"],
        "owner": cast(dict[str, object], config["Labels"])["lowerduckpond.qualification.run"],
    }


class NativeFixture:
    helper_seconds = HELPER_SECONDS

    def __init__(  # noqa: PLR0913 - independent native and retained-proof boundaries
        self,
        *,
        configuration: LeaseConfiguration,
        fixture: dict[str, object],
        evidence_root: Path,
        revalidate_copies_and_cleanup: Callable[[], str],
        docker: ReadOnlyDocker,
        require_cleanup_current: Callable[[], None],
        refresh_cleanup: Callable[[], None] | None = None,
        observation_only: bool = False,
    ) -> None:
        self.config, self.fixture, self.root = configuration, fixture, evidence_root
        self.revalidate = revalidate_copies_and_cleanup
        self.docker = docker
        self.cleanup_current = require_cleanup_current
        self.refresh_cleanup = refresh_cleanup
        self.observation_only = observation_only
        self.submitting = False
        self.held = False
        self.archives: Archives
        self.final_roles: Callable[[], None] | None = None
        self.deletes, self.reads = 0, 0

    @contextmanager
    def locked(self, plan: dict[str, object]) -> Iterator[None]:
        require(not self.held, "frozen retirement is already holding ownership")
        fields(
            self.fixture,
            {
                "original_files",
                "consumer_binding",
                "producer_binding",
                "actors",
                "source_incarnation",
            },
        )
        require(digest(self.fixture) == plan["fixture_sha256"], "frozen fixture binding differs")
        self.plan = plan
        self.run = Path(str(plan["original_run"]))
        self.consumer = self.root / "runs" / identity(plan["consumer_attempt"])
        self.producer = self.root / "runs" / identity(plan["producing_attempt"])
        require(
            self.consumer != self.producer, "frozen retirement needs its distinct retained consumer"
        )
        require(
            self.run.parent == self.producer / "qualification"
            and self.run.name.startswith("spaces-"),
            "retirement run is outside its producing managed attempt",
        )
        self.lease = LeaseState(self.root / "leases" / identity(plan["lease_id"]))
        with ExitStack() as stack:
            # Same nonblocking lock order as managed use/admission. Nothing is
            # allocated and no existing pending operation is adopted as a retry.
            for path in (
                self.consumer / "controller.lock",
                self.lease.directory / "runtime-use.lock",
            ):
                stack.enter_context(existing_lock(path))
            self.manifest = self.lease.manifest()
            require(
                self.manifest.sha256 == plan["manifest_sha256"]
                and self.manifest.targets == self.config.targets
                and self.manifest.policy.sha256 == self.config.approved_policy_sha256,
                "retirement lease differs from existing approved scope",
            )
            self.environment = environment_for(self.run)
            self.environment.update(
                {
                    "SPACES_REGION": self.manifest.targets.region,
                    "SPACES_ARCHIVE_BUCKET": self.manifest.targets.archive_bucket,
                    "SPACES_BACKUP_BUCKET": self.manifest.targets.backup_bucket,
                }
            )
            require(
                self.manifest.policy.deadline(instant(self.manifest.created_at)) - datetime.now(UTC)
                > timedelta(seconds=self.helper_seconds)
                and all(
                    instant(intent.deadline) - datetime.now(UTC)
                    > timedelta(seconds=self.helper_seconds)
                    for intent in self.manifest.intents
                ),
                "retirement work budget cannot fit genuine credential validity",
            )
            target = {
                "region": self.manifest.targets.region,
                "archive_bucket": self.manifest.targets.archive_bucket,
            }
            stack.enter_context(existing_lock(Path(LEASE_DIRECTORY) / (digest(target) + ".lock")))
            stack.enter_context(existing_lock(self.run / "run.lock"))
            stack.enter_context(
                ownership(self.run, exclusive=True, create=not self.observation_only)
            )
            self.deliveries = {
                intent.role: self.lease.credential(intent) for intent in self.manifest.intents
            }
            require(
                set(self.deliveries) == RETAINED_ROLES and all(self.deliveries.values()),
                "retirement lacks all seven original private deliveries",
            )
            self.uses = sorted(self.lease.directory.glob("use-*.json"))
            self.uses_digest = digest([read_private(path) for path in self.uses])
            self.storage = LiveStorage._retained(self.environment)
            require(
                self.storage.target.region == self.manifest.targets.region
                and self.storage.target.archive_bucket == self.manifest.targets.archive_bucket
                and self.storage.target.backup_bucket == self.manifest.targets.backup_bucket,
                "frozen fixture storage differs from retained lease targets",
            )
            self.held = True
            try:
                with readiness_credentials.read_only_requests(self.owner):
                    self.owner()
                    self.final_roles = readiness_credentials.validate_all_roles(
                        self.config,
                        self.manifest,
                        self.lease,
                        clock=lambda: datetime.now(UTC),
                        guard=self.owner,
                    )
                    clients = [self.client(role) for role in ("archive", "operator")]
                    require(
                        self.deliveries["archive"] != self.deliveries["operator"],
                        "retirement needs independent principals",
                    )
                    self.archives = Archives(
                        clients[0], clients[1], self.manifest.targets.archive_bucket
                    )
                    self.guard(plan)
                    yield
            finally:
                self.final_roles = None
                self.held = False

    def before_disposition(self) -> None:
        self.owner()
        require_remaining(POST_EFFECT_RESERVE)
        from scripts.m3_11_frozen_envelope import verify  # noqa: PLC0415

        self.closeout_envelope = verify(self)
        require_remaining(POST_EFFECT_RESERVE)

    @contextmanager
    def submission(self) -> Iterator[None]:
        # The global cleanup lock is never held over local revalidation or
        # network readiness. It excludes revocation only for the one request.
        require_remaining(POST_EFFECT_RESERVE)
        self.owner()
        with existing_lock(self.root / ".credential-cleanup.lock"):
            self.submitting = True
            try:
                self.owner()
                yield
            finally:
                self.submitting = False

    def owner(self) -> None:
        require(self.held, "retirement does not hold original ownership")
        require_remaining(120)
        if self.refresh_cleanup is not None and not self.submitting:
            self.refresh_cleanup()
        self.cleanup_current()
        now = datetime.now(UTC)
        require(
            self.manifest.policy.retain_after_failure
            and self.manifest.policy.deadline(instant(self.manifest.created_at)) > now
            and all(instant(intent.deadline) > now for intent in self.manifest.intents),
            "retirement credentials are expired or no longer retained",
        )
        require(
            self.lease.manifest().sha256 == self.plan["manifest_sha256"]
            and not list(self.lease.directory.glob("close-*.json")),
            "retirement lease changed or is closing",
        )
        stopped = self.lease.issuer_stop()
        require(
            stopped is not None
            and stopped["retained_roles"] == sorted(self.deliveries)
            and instant(stopped["stopped_at"]) <= now,
            "retirement lacks the original stopped issuer",
        )
        for intent in self.manifest.intents:
            credential = cast(Credential, self.deliveries[intent.role])
            require(
                self.lease.credential(intent) == credential
                and self.lease.created(intent)
                == {"intent_sha256": intent.sha256, "credential_id": credential.identifier},
                "retirement retained credential changed",
            )
        require(
            sorted(self.lease.directory.glob("use-*.json")) == self.uses
            and digest([read_private(path) for path in self.uses]) == self.uses_digest,
            "retirement runtime users changed",
        )
        current = self.lease.directory / ("use-" + str(self.plan["consumer_attempt"]) + ".json")
        require(current in self.uses, "retirement lacks its original consumer use")
        self.consumer_use(current)
        for path in self.uses:
            use = fields(read_private(path), {"attempt_id", "binding_sha256", "kind"})
            require(
                path.name == "use-" + identity(use["attempt_id"]) + ".json"
                and use["kind"] == "attempt",
                "retirement runtime use identity differs",
            )
            if path != current:
                require(
                    self.lease.released_use(
                        attempt_id=str(use["attempt_id"]), binding_sha256=str(use["binding_sha256"])
                    ),
                    "another retained consumer is still active",
                )
        for path, binding in (
            (self.consumer, self.fixture["consumer_binding"]),
            (self.producer, self.fixture["producer_binding"]),
        ):
            state = RunState(path)
            progress, request, journey = (
                state.status(),
                read_private(path / "request.json"),
                journey_result(path),
            )
            require(
                not state.cancelled
                and not state.stopped
                and progress["phase"] == "finished"
                and progress["qualification"] == "failed"
                and journey["outcome"] == "failed"
                and journey["status"] == progress["exit_status"]
                and instant(journey["observed_at"]) <= now,
                "retirement requires exact terminal failed attempts",
            )
            require(
                request["lease_id"] == self.plan["lease_id"]
                and digest(request["binding"]) == binding
                and request["mode"] == "qualification"
                and read_private(path / "attempt.json")["binding"] == request["binding"]
                and read_private(path / "attempt-started.json")
                == {"binding_sha256": binding, "manifest_sha256": self.plan["manifest_sha256"]}
                and read_private(path / "host-drained.json")
                == {"binding_sha256": binding, "drained": True},
                "retirement managed start/drain bindings differ",
            )
        require(
            read_private(current)
            == {
                "attempt_id": self.plan["consumer_attempt"],
                "binding_sha256": self.fixture["consumer_binding"],
                "kind": "attempt",
            },
            "retirement exclusive consumer binding differs",
        )

    def consumer_use(self, current: Path) -> None:
        require(
            not (
                self.lease.directory / ("released-" + str(self.plan["consumer_attempt"]) + ".json")
            ).exists(),
            "retirement consumer no longer owns its retained lease",
        )

    def client(self, role: str) -> S3Client:
        credential = cast(Credential, self.deliveries[role])
        selected = cast(dict[str, object], self.plan["archive"])

        def parameters(params: dict[str, object], model: object, **_kwargs: object) -> None:
            operation = getattr(model, "name", None)
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
                    "retirement attempted another mutation",
                )
                self.deletes += 1
            elif operation == "GetObject":
                require(
                    role in {"backup", "operator"}
                    and params
                    == {
                        "Bucket": self.storage.target.backup_bucket,
                        "Key": self.storage.target.owner_key,
                        "VersionId": self.storage.owner_version,
                    },
                    "retirement attempted an unbound object body read",
                )
                self.reads += 1
            else:
                require(
                    operation
                    in {
                        "GetBucketVersioning",
                        "ListObjectsV2",
                        "ListObjectVersions",
                        "ListMultipartUploads",
                    }
                    and params.get("Bucket")
                    in {self.manifest.targets.archive_bucket, self.manifest.targets.backup_bucket},
                    "retirement attempted an unapproved provider operation",
                )
                self.reads += 1
            require(self.reads <= MAX_READS, "retirement exceeded its bounded read count")
            self.owner()
            require_remaining(40)

        def before_wire(operation: str) -> None:
            self.owner()
            if operation == "DeleteObject":
                require_remaining(POST_EFFECT_RESERVE)

        return make_client(
            ArchiveConfiguration(
                self.manifest.targets.region,
                self.manifest.targets.archive_bucket,
                credential.identifier,
                credential.secret,
            ),
            parameters,
            before_wire,
        )

    def guard(self, plan: dict[str, object]) -> None:
        self.frozen_state(plan)
        for role in ("backup", "operator"):
            self.storage.target.require_owner(
                self.client(role), self.storage.binding, version=self.storage.owner_version
            )
        self.preserved_evidence(plan)

    def frozen_state(self, plan: dict[str, object]) -> None:
        """Common immutable actor/failure checks; no remote ownership assumption.

        The staged remote owner additionally requires its exact removal journal
        when the original owner object is absent. Ordinary retirement still
        requires the owner object through ``guard`` above.
        """
        require(plan == self.plan, "retirement plan changed during ownership")
        self.owner()
        if self.final_roles is None:
            raise RetirementError("retirement lacks native all-role verification")
        self.final_roles()
        require(
            self.docker.endpoint == self.environment["DOCKER_HOST"]
            and self.docker.info() == read_private(self.consumer / "request.json")["daemon"],
            "retirement daemon differs from its managed consumer",
        )
        originals = self.fixture["original_files"]
        require(
            isinstance(originals, dict)
            and set(originals) == {"failure.json", "failure-exit.json", "source-revision"},
            "retirement lacks exact original failure file bindings",
        )
        for name, expected in cast(dict[str, dict[str, object]], originals).items():
            path = self.run / name
            require(
                path.is_relative_to(self.run)
                and ".." not in Path(name).parts
                and not Path(name).is_absolute(),
                "retirement original path escaped its run",
            )
            require(
                fingerprint(path, 1024 * 1024) == expected,
                "retirement original failure or fixture changed",
            )
        failure = legacy(self.run / "failure-exit.json")
        require(
            failure.get("phase") == "verify"
            and type(failure.get("exit_status")) is int
            and 0 < cast(int, failure["exit_status"]) <= 255,  # noqa: PLR2004 - POSIX exit status
            "retirement does not match the archived qualification failure",
        )
        diagnostic = legacy(self.run / "failure.json")
        require(
            diagnostic.get("phase") == "verify"
            and diagnostic.get("group") == "archive"
            and diagnostic.get("source_revision") == self.storage.binding["source_revision"]
            and diagnostic.get("original_exit_status") == failure["exit_status"],
            "retirement lacks its original archive-phase failure",
        )
        require(
            not (self.run / "qualification.json").exists()
            and not (self.run / "combined.json").exists(),
            "retirement cannot adopt a completed qualification",
        )
        for name in ("owned-teardown", "debug-closeout", "failed-archive-retirement"):
            require(
                not (self.run / name).exists() and not (self.run / name).is_symlink(),
                "retirement conflicts with another disposition",
            )
        require(
            not self.run.with_name(self.run.name + ".debug-closeout.json").exists(),
            "retirement conflicts with pending directory disposal",
        )
        manifest = read_private(self.run / "fixture.json")
        owner = str(manifest["run_id"]).replace("-", "")
        resource_names(owner)
        actors = cast(list[dict[str, object]], self.fixture["actors"])
        require(
            bool(actors)
            and all(
                row["owner"] == owner and row["running"] is False and row["restart_policy"] == "no"
                for row in actors
            ),
            "retirement actor binding is not frozen",
        )
        found = json.loads(self.docker.command("inspect", *(str(row["id"]) for row in actors)))
        require(
            [actor(row) for row in found] == actors, "frozen actor identity or incarnation changed"
        )
        source_actors = [row for row in found if str(row["Name"]).endswith("-host")]
        require(
            len(source_actors) == 1
            and all(row["State"]["Running"] is False and row["State"]["Pid"] == 0 for row in found),
            "retirement has an ambiguous or active frozen source",
        )
        source_row = source_actors[0]
        require(
            {
                "id": source_row["Id"],
                "started": source_row["State"]["StartedAt"],
                "finished": source_row["State"]["FinishedAt"],
                "restarts": source_row["RestartCount"],
            }
            == self.fixture["source_incarnation"],
            "captured source state was restarted after preservation",
        )
        found_ids = (
            self.docker.command(
                "ps",
                "-aq",
                "--no-trunc",
                "--filter",
                "label=lowerduckpond.qualification.run=" + owner,
            )
            .decode()
            .splitlines()
        )
        require(
            set(found_ids) == {row["id"] for row in actors}, "retirement has unknown fixture actors"
        )
        self.storage._require_inputs(self.environment)

    def preserved_evidence(self, plan: dict[str, object]) -> None:
        require(
            self.revalidate() == plan["evidence_sha256"],
            "native preserved-file or cleanup revalidation differs",
        )
        self.owner()
