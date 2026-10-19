"""Concrete remote stage: preserve/retire only the frozen fixture's backup prefix.

No actor is removed, no archive DELETE is available, and no credential is
issued/revoked/released. Original archive uncertainty is retained separately.
Local disposal is a different adapter requiring terminal lease proof.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from lowerduckpond_m3_archive.storage import S3Client
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts import m3_11_frozen_backups as backups
from scripts import m3_11_frozen_capture_resume as capture_resume
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_debug_closeout import dns_absent
from scripts.m3_11_frozen_budget import MAX_REMOTE_BYTES, REMOTE_SECONDS
from scripts.m3_11_frozen_client import make_client
from scripts.m3_11_frozen_context import NativeFixture, require
from scripts.m3_11_frozen_retirement import plan as retirement_plan
from scripts.m3_11_frozen_retirement import require_supported_closeout
from scripts.m3_11_frozen_stage import Effects, authorization, initialize, read_plan
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields, uuid7
from scripts.m3_11_retirement_files import digest, record
from scripts.m3_11_unattended.model import Credential, stamp
from scripts.m3_11_unattended.storage_admission import require_remaining
from scripts.qualification_fence import commit as complete_fence
from scripts.qualification_fence import registry, require_committed

FORMAT = "lowerduckpond-m3-11-frozen-remote-closeout-v1"
MAX_REQUESTS = 10000


class _Writer:
    def __init__(self, client: S3Client, fixture: NativeRemote) -> None:
        self.client, self.fixture = client, fixture

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401 - SDK protocol delegates read methods
        if name == "abort_multipart_upload":
            raise ValueError("remote closeout cannot discard unpreserved multipart data")
        return getattr(self.client, name)

    def delete_object(self, **parameters: object) -> dict[str, object]:
        # Exclude cleanup only during this exact bounded native submission, not
        # throughout potentially long preservation/independent observations.
        with self.fixture.submission():
            return self.fixture.effects.submit(
                "delete-backup-" + digest(parameters),
                parameters,
                lambda: self.client.delete_object(**parameters),
            )


class NativeRemote(NativeFixture):
    helper_seconds = REMOTE_SECONDS
    stage: dict[str, object]
    stage_root: Path
    effects: Effects
    mutation_enabled = False
    normalize_fence = False

    def consumer_use(self, current: Path) -> None:
        # Unlike initial archive retirement, later remote closeout may run
        # after this exact consumer was released. It never re-acquires a use.
        # The base owner still verifies every other use is released; the common
        # storage lock excludes an active successor or new allocation.
        released = self.lease.directory / (
            "released-" + str(self.plan["consumer_attempt"]) + ".json"
        )
        if released.exists() or released.is_symlink():
            original = read_private(current)
            require(
                self.lease.released_use(
                    attempt_id=str(original["attempt_id"]),
                    binding_sha256=str(original["binding_sha256"]),
                ),
                "remote closeout original consumer release is not verified",
            )

    def selected(self, raw: object) -> dict[str, object]:
        value = fields(
            raw,
            {
                "format",
                "implementation_revision",
                "retirement_plan",
                "retirement_authorization_sha256",
                "fixture",
                "backup_inventory",
                "maximum_backup_bytes",
                "maximum_provider_requests",
            },
        )
        require(
            value["format"] == FORMAT
            and re.fullmatch(r"[a-f0-9]{40}", str(value["implementation_revision"])),
            "remote closeout plan format or source differs",
        )
        selected = retirement_plan(value["retirement_plan"])
        require(value["fixture"] == self.fixture, "remote closeout fixture differs")
        require(
            type(value["maximum_backup_bytes"]) is int
            and 0 < value["maximum_backup_bytes"] <= MAX_REMOTE_BYTES
            and type(value["maximum_provider_requests"]) is int
            and 0 < value["maximum_provider_requests"] <= MAX_REQUESTS,
            "remote closeout work bounds are invalid",
        )
        self.stage = value
        from scripts.m3_11_frozen_retirement import fingerprint  # noqa: PLC0415

        fingerprint(value["retirement_authorization_sha256"])
        root = registry(Path(str(selected["original_run"])))
        require(root is not None, "remote closeout requires managed external ownership")
        identity = uuid7(
            read_private(Path(str(selected["original_run"])) / "fixture.json")["run_id"]
        )
        self.stage_root = (
            cast(Path, root)
            / ("identity-" + identity.hex + ".retired")
            / ("remote-" + digest(value))
        )
        self.sent: set[tuple[str, str]] = set()
        return selected

    def fence(self) -> dict[str, object]:
        root = registry(self.run)
        require(root is not None, "remote closeout lost persistent execution exclusion")
        fixture_id = uuid7(read_private(self.run / "fixture.json")["run_id"])
        value = read_private(cast(Path, root) / ("identity-" + fixture_id.hex + ".intent.json"))
        require(
            value.get("original_run") == str(self.run)
            and value.get("plan_sha256") == digest(self.plan)
            and value.get("authorization_sha256") == self.stage["retirement_authorization_sha256"]
            and value.get("fixture_id") == read_private(self.run / "fixture.json")["run_id"],
            "remote closeout execution exclusion differs from its exact retirement",
        )
        if self.normalize_fence:
            complete_fence(
                self.run,
                plan_sha256=digest(self.plan),
                authorization_sha256=str(self.stage["retirement_authorization_sha256"]),
                continuing=True,
            )
        require_committed(self.run, value)
        return value

    def client(self, role: str) -> S3Client:
        credential = cast(Credential, self.deliveries[role])
        expected = cast(dict[str, object], self.stage["backup_inventory"])
        versions = {
            (key, version) for _kind, key, version in cast(list[list[str]], expected["versions"])
        }

        def parameters(params: dict[str, object], model: object, **_kwargs: object) -> None:
            operation = getattr(model, "name", None)
            if operation == "DeleteObject":
                pair = (str(params.get("Key")), str(params.get("VersionId")))
                require(
                    self.mutation_enabled
                    and role == "backup"
                    and pair in versions
                    and pair not in self.sent
                    and params
                    == {
                        "Bucket": self.storage.target.backup_bucket,
                        "Key": pair[0],
                        "VersionId": pair[1],
                    },
                    "remote closeout rejected an unbound or repeated backup mutation",
                )
                self.sent.add(pair)
                self.deletes += 1
            elif operation == "GetObject":
                pair = (str(params.get("Key")), str(params.get("VersionId")))
                require(
                    role in {"backup", "operator"}
                    and pair in versions
                    and params
                    == {
                        "Bucket": self.storage.target.backup_bucket,
                        "Key": pair[0],
                        "VersionId": pair[1],
                    },
                    "remote closeout attempted an unbound body read",
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
                    "remote closeout attempted another provider operation",
                )
                self.reads += 1
            require(
                self.reads + self.deletes <= cast(int, self.stage["maximum_provider_requests"]),
                "remote closeout exceeded its request bound",
            )
            self.owner()
            require_remaining(40)

        def sending(operation: str) -> None:
            self.owner()
            require_remaining(40)
            if operation == "DeleteObject":
                require(
                    self.mutation_enabled and role == "backup",
                    "remote closeout lost exact mutation authority",
                )

        client = make_client(
            ArchiveConfiguration(
                self.manifest.targets.region,
                self.manifest.targets.archive_bucket,
                credential.identifier,
                credential.secret,
            ),
            parameters,
            sending,
        )
        return cast(S3Client, _Writer(client, self)) if role == "backup" else client

    def removal(self) -> Removal:
        removal = Removal(
            self.storage.target,
            self.storage.binding,
            self.storage.owner_version,
            self.client("backup"),
            self.client("operator"),
            self.stage_root / "backup-removal",
            lambda: digest(self.fixture),
            self.owner,
        )
        removal._validate_inventory(cast(dict[str, object], self.stage["backup_inventory"]))
        return removal

    def guard(self, plan: dict[str, object]) -> None:
        self.frozen_state(plan)
        self.fence()
        removal = self.removal()
        if removal.directory.exists():
            # Once owner deletion was submitted, only the exact journal and
            # independent absence may stand in for the now-deleted owner object.
            if removal.is_removed():
                require(
                    self.effects.submitted(
                        "remote-cleanup",
                        {"inventory_sha256": digest(self.stage["backup_inventory"])},
                    ),
                    "removed remote owner lacks original exact submission",
                )
            else:
                removal._owner()
        else:
            removal._owner()
        self.preserved_evidence(plan)

    def execute(self, raw: object, approved: object) -> dict[str, object]:
        require_supported_closeout()
        selected = self.selected(raw)
        approval = authorization(approved, self.stage, stage="remote-cleanup")
        self.normalize_fence = True
        # Read-only guard at lock entry must not depend on creating a journal.
        with self.locked(selected):
            initialize(self.stage_root, self.stage, approval)
            self.effects = Effects(self.stage_root, plan=self.stage, approval=approval)
            removal = self.removal()
            expected = cast(dict[str, object], self.stage["backup_inventory"])
            copies = backups.capture(
                removal,
                expected,
                self.stage_root / "backup-evidence",
                maximum_bytes=cast(int, self.stage["maximum_backup_bytes"]),
                guard=self.owner,
            )
            self.guard(selected)
            require(
                removal._observed() == expected,
                "backup inventory changed after complete preservation",
            )
            archive_before = self.archives.observed()
            archive = cast(dict[str, object], selected["archive"])
            require(
                archive_before in ([], [(str(archive["key"]), str(archive["version"]))]),
                "archive inventory escaped the original exact disposition",
            )
            # This does not claim whole-bucket acceptance when the original
            # version remains after a pre-DELETE failure/uncertain submission.
            dns_absent(self.run, self.environment, self.storage.target)
            identity: dict[str, object] = {"inventory_sha256": digest(expected)}

            def remove() -> dict[str, object]:
                self.mutation_enabled = True
                try:
                    return removal.run()
                finally:
                    self.mutation_enabled = False

            result = self.effects.submit("remote-cleanup", identity, remove)
            return self.complete(approval, copies, archive_before, result)

    def complete(
        self,
        approval: dict[str, object],
        copies: dict[str, object],
        archive_before: list[tuple[str, str]],
        result: dict[str, object],
    ) -> dict[str, object]:
        removal = self.removal()
        self.guard(self.plan)
        # Observe after final potentially slow checks; preserve actual times.
        removal.require_removed()
        backup_observed_at = stamp(datetime.now(UTC))
        archive_after = self.archives.observed()
        archive_observed_at = stamp(datetime.now(UTC))
        require(
            archive_after == archive_before, "archive state changed during remote backup cleanup"
        )
        dns_absent(self.run, self.environment, self.storage.target)
        receipt = {
            "format": FORMAT,
            "plan_sha256": digest(self.stage),
            "authorization_sha256": digest(approval),
            "backup_removal": result,
            "backup_preservation_sha256": digest(copies),
            "archive_versions": archive_after,
            "whole_archive_bucket_empty": archive_after == [],
            "backup_observed_at": backup_observed_at,
            "archive_observed_at": archive_observed_at,
            "dns_observed_at": stamp(datetime.now(UTC)),
            "observed_at": stamp(datetime.now(UTC)),
            "actors_retained": True,
            "archive_delete_submissions": 0,
            "credential_mutations": 0,
            "lease_released": False,
        }
        record(self.stage_root / "completed.json", receipt)
        return receipt

    def continue_unsubmitted(self, raw: object, approved: object) -> dict[str, object]:
        """Explicit next submission for only never-submitted remaining identities."""
        require_supported_closeout()
        selected = self.selected(raw)
        approval = authorization(approved, self.stage, stage="remote-cleanup")
        self.normalize_fence = True
        if self.stage_root.exists() or self.stage_root.is_symlink():
            self.effects = Effects(self.stage_root, plan=self.stage, approval=approval)
        with self.locked(selected):
            initialize(self.stage_root, self.stage, approval, continuing=True)
            self.effects = Effects(self.stage_root, plan=self.stage, approval=approval)
            removal = self.removal()
            expected = cast(dict[str, object], self.stage["backup_inventory"])
            copies = capture_resume.capture(
                self.stage_root / "backup-evidence",
                ledger=self.stage_root,
                verify=lambda: backups.verify(
                    removal,
                    expected,
                    self.stage_root / "backup-evidence",
                    maximum_bytes=cast(int, self.stage["maximum_backup_bytes"]),
                    guard=self.owner,
                ),
                create=lambda: backups.capture(
                    removal,
                    expected,
                    self.stage_root / "backup-evidence",
                    maximum_bytes=cast(int, self.stage["maximum_backup_bytes"]),
                    guard=self.owner,
                ),
                guard=self.owner,
                continuing=True,
            )
            remaining = removal._observed()
            self.remaining(removal, expected, remaining)
            require(bool(remaining["versions"]), "remote resources are absent; reconcile only")
            archive_before = self.archives.observed()
            archive = cast(dict[str, object], selected["archive"])
            require(
                archive_before in ([], [(str(archive["key"]), str(archive["version"]))]),
                "remote continuation archive identity differs",
            )
            dns_absent(self.run, self.environment, self.storage.target)
            batch: dict[str, object] = {"inventory_sha256": digest(expected)}
            name, identity = "remote-cleanup", batch
            if self.effects.submitted(name, identity):
                name, identity = "continue-remote-" + digest(remaining), {"remaining": remaining}

            def remove() -> dict[str, object]:
                self.mutation_enabled = True
                try:
                    return removal.run()
                finally:
                    self.mutation_enabled = False

            result = self.effects.submit(name, identity, remove)
            return self.complete(approval, copies, archive_before, result)

    def remaining(
        self, removal: Removal, expected: dict[str, object], remaining: dict[str, object]
    ) -> None:
        original = {tuple(row) for row in cast(list[list[str]], expected["versions"])}
        present = {tuple(row) for row in cast(list[list[str]], remaining["versions"])}
        require(
            not remaining["uploads"] and present <= original,
            "remote continuation contains new or unpreserved bytes",
        )
        for row in original:
            parameters: dict[str, object] = {
                "Bucket": removal.target.backup_bucket,
                "Key": row[1],
                "VersionId": row[2],
            }
            submitted = self.effects.submitted("delete-backup-" + digest(parameters), parameters)
            require(
                not (row in present and submitted),
                "remote submitted version remains unresolved; no replay",
            )
            require(
                row in present or submitted,
                "remote version disappeared without its original exact submission",
            )

    def reconcile(self, raw: object, approved: object) -> dict[str, object]:
        """Observe the original submitted transition; never call Removal.run."""
        selected = self.selected(raw)
        approval = authorization(approved, self.stage, stage="remote-cleanup")
        self.normalize_fence = False
        self.effects = Effects(self.stage_root, plan=self.stage, approval=approval)
        require(
            read_plan(self.stage_root) == self.stage
            and read_private(self.stage_root / "authorization.json") == approval,
            "remote observation lacks its original exact journal",
        )
        with self.locked(selected):
            removal = self.removal()
            copies = backups.verify(
                removal,
                cast(dict[str, object], self.stage["backup_inventory"]),
                self.stage_root / "backup-evidence",
                maximum_bytes=cast(int, self.stage["maximum_backup_bytes"]),
                guard=self.owner,
            )
            self.guard(selected)
            absent = removal.is_removed()
            observed = self.effects.observe(
                "remote-cleanup",
                {"inventory_sha256": digest(self.stage["backup_inventory"])},
                absent=absent,
            )
            archive_versions = self.archives.observed()
            archive_time = stamp(datetime.now(UTC))
            archive = cast(dict[str, object], selected["archive"])
            require(
                archive_versions in ([], [(str(archive["key"]), str(archive["version"]))]),
                "remote observation found another archive identity",
            )
            dns_absent(self.run, self.environment, self.storage.target)
            return {
                "format": FORMAT,
                "plan_sha256": digest(self.stage),
                "authorization_sha256": digest(approval),
                "observation": observed,
                "backup_preservation_sha256": digest(copies),
                "archive_versions": archive_versions,
                "whole_archive_bucket_empty": archive_versions == [],
                "archive_observed_at": archive_time,
                "dns_observed_at": stamp(datetime.now(UTC)),
                "actors_retained": True,
                "archive_delete_submissions": 0,
                "credential_mutations": 0,
                "lease_released": False,
                "mutation_submissions": 0,
                "no_replay": True,
            }
