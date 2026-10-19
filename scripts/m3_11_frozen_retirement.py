"""One exact archive submission after permanent fixture execution retirement.

The approved plan comes from native frozen-state validation. A pending record
is a consumed submission identity, including a crash before the SDK call. It
never authorizes another mutation. This deliberately does not reuse the older
reconstruction transaction's resumable deletion branch.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields, uuid7
from scripts.m3_11_retirement_archive import Archives, records
from scripts.m3_11_retirement_files import RetirementError, digest, directory, record, sync
from scripts.qualification_disposition import DIRECTORY

FORMAT = "lowerduckpond-m3-11-frozen-archive-retirement-v1"
AUTHORIZATION = "lowerduckpond-m3-11-frozen-archive-authorization-v2"
OBSERVATION = "lowerduckpond-m3-11-frozen-archive-observation-v1"
RETAINED = ["original-failure", "containers", "state", "backup-prefix", "private-copies"]
PLAN_FIELDS = {
    "format",
    "original_run",
    "producing_attempt",
    "consumer_attempt",
    "lease_id",
    "manifest_sha256",
    "implementation_revision",
    "fixture_sha256",
    "evidence_sha256",
    "archive",
    "retained",
}


def require_supported_closeout() -> None:
    """Keep native execution disabled until the narrower exit path is reviewed.

    Transaction primitives remain testable against synthetic stores. Neither
    approval nor a runtime flag may replace the missing staged closeout adapter.
    Removing this blocker requires that adapter, its race/crash regressions and
    a newly reviewed source/program binding, not merely a new approval document.
    """
    raise RetirementError(
        "live retirement unavailable: supported staged closeout is not implemented"
    )


def reserve(path: Path, value: dict[str, object]) -> None:
    """Exclusive, durable reservation. A torn final file still consumes the call.

    Unlike the generic copy helper, this never removes a partial file and never
    republishes a prior reservation. No network mutation happens until both the
    final file and its parent entry have been fsynced successfully.
    """
    if (
        path.with_name(path.name + ".partial").exists()
        or path.with_name(path.name + ".partial").is_symlink()
    ):
        raise RetirementError("ambiguous retirement submission partial; no replay")
    directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical_bytes(value))
        stream.flush()
        os.fsync(stream.fileno())
    sync(path.parent)


def fingerprint(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RetirementError("frozen retirement digest is invalid")
    return value


def plan(value: object) -> dict[str, object]:
    result = fields(value, PLAN_FIELDS)
    archive = fields(result["archive"], {"bucket", "key", "version", "size", "sha256"})
    bucket = archive["bucket"]
    if (
        result["format"] != FORMAT
        or result["retained"] != RETAINED
        or not isinstance(result["original_run"], str)
        or not Path(result["original_run"]).is_absolute()
        or re.fullmatch(r"[0-9a-f]{40}", str(result["implementation_revision"])) is None
        or not isinstance(bucket, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket) is None
    ):
        raise RetirementError("frozen retirement plan is invalid")
    for key in ("producing_attempt", "consumer_attempt", "lease_id"):
        uuid7(result[key])
    for key in ("manifest_sha256", "fixture_sha256", "evidence_sha256"):
        fingerprint(result[key])
    records([{key: archive[key] for key in ("key", "version", "size", "sha256")}])
    return result


class Fixture(Protocol):
    archives: Archives

    def locked(self, approved: dict[str, object]) -> AbstractContextManager[None]:
        """Hold original managed controller, runtime-use, storage and run locks."""
        ...

    def guard(self, approved: dict[str, object]) -> None:
        """Revalidate original failure, stopped actors, native copies and fresh authority."""
        ...

    def submission(self) -> AbstractContextManager[None]:
        """Exclude credential cleanup only around the single bounded mutation."""
        ...

    def before_disposition(self) -> None:
        """Reject an already-insufficient budget before the permanent local effect."""
        ...


class FrozenRetirement:
    def __init__(
        self,
        approved_plan: object,
        fixture: Fixture,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.plan = plan(approved_plan)
        self.run = Path(str(self.plan["original_run"]))
        self.root = self.run / DIRECTORY
        self.fixture, self.clock = fixture, clock

    def _authorization(self, value: object) -> dict[str, object]:
        document = fields(
            value,
            {
                "format",
                "plan_sha256",
                "approved_at",
                "approval_reference_sha256",
                "acknowledge_exact_version_loss",
                "acknowledge_permanent_fixture_retirement",
                "acknowledge_separate_closeout_required",
            },
        )
        if (
            document["format"] != AUTHORIZATION
            or document["plan_sha256"] != digest(self.plan)
            or document["acknowledge_exact_version_loss"] is not True
            or document["acknowledge_permanent_fixture_retirement"] is not True
            or document["acknowledge_separate_closeout_required"] is not True
            or not isinstance(document["approved_at"], str)
        ):
            raise RetirementError(
                "exact version loss, permanent execution retirement and separate closeout "
                "need approval"
            )
        approved = datetime.fromisoformat(document["approved_at"])
        if approved.tzinfo is None or approved > self.clock():
            raise RetirementError("frozen retirement approval time is invalid")
        fingerprint(document["approval_reference_sha256"])
        return document

    def _expected(self) -> list[tuple[str, str]]:
        archive = cast(dict[str, object], self.plan["archive"])
        if self.fixture.archives.bucket != archive["bucket"]:
            raise RetirementError("frozen retirement selected another bucket")
        return [(str(archive["key"]), str(archive["version"]))]

    def _guard(self, authorization: dict[str, object]) -> None:
        directory(self.run)
        directory(self.root)
        if (
            read_private(self.root / "plan.json") != self.plan
            or read_private(self.root / "authorization.json") != authorization
        ):
            raise RetirementError("frozen retirement journal differs from approval")
        self.fixture.guard(self.plan)

    def execute(self, authorization: object, *, reconcile_only: bool = False) -> dict[str, object]:
        approval = self._authorization(authorization)
        with self.fixture.locked(self.plan):
            return self._execute(approval, reconcile_only=reconcile_only)

    def _execute(self, approval: dict[str, object], *, reconcile_only: bool) -> dict[str, object]:  # noqa: PLR0912, PLR0915 - fail-closed journal states
        directory(self.run)
        self.fixture.guard(self.plan)
        expected = self._expected()
        fresh = not self.root.exists() and not self.root.is_symlink()
        if reconcile_only:
            return self._reconcile(approval)
        if not fresh:
            raise RetirementError("retirement already entered; no replay; reconcile only")
        if fresh:
            if self.fixture.archives.observed() != expected:
                raise RetirementError("frozen retirement inventory changed before disposition")
            self.fixture.before_disposition()
            # This directory itself permanently closes every supported mutation
            # consumer. A crash before any following record must stay fail closed.
            self.root.mkdir(mode=0o700)
            sync(self.run)
            record(self.root / "plan.json", self.plan)
            record(self.root / "authorization.json", approval)
        self._guard(approval)
        row = cast(dict[str, object], self.plan["archive"])
        submission = {
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(approval),
            "archive": row,
            "maximum_submissions": 1,
        }
        pending = self.root / "delete-submitted.json"
        absence = self.root / "absence.json"
        partial = pending.with_name(pending.name + ".partial")
        if partial.exists() or partial.is_symlink():
            raise RetirementError("ambiguous retirement submission partial; no replay")
        if pending.exists() or pending.is_symlink():
            if read_private(pending) != submission:
                raise RetirementError("frozen retirement submission identity differs")
            # Even observing the version still present cannot prove that a lost
            # earlier request was not accepted. Reconciliation never calls DELETE.
            if self.fixture.archives.observed():
                raise RetirementError(
                    "consumed deletion remains unresolved; no replay is permitted"
                )
        else:
            if not fresh or reconcile_only:
                raise RetirementError("interrupted retirement has no submission; no replay")
            if any(
                path.exists() or path.is_symlink()
                for name in ("absence.json", "retired.json")
                for path in (self.root / name, self.root / (name + ".partial"))
            ):
                raise RetirementError("frozen retirement lacks its original submission")
            if self.fixture.archives.observed() != expected:
                raise RetirementError("frozen retirement inventory changed before submission")
            self._guard(approval)
            reserve(pending, submission)
            self._guard(approval)
            # Reserved before the last read and network call. Failure at either
            # point consumes the only mutation identity, rather than guessing.
            if self.fixture.archives.observed() != expected:
                raise RetirementError("frozen retirement reserved inventory changed")
            with self.fixture.submission():
                self.fixture.archives.delete(row)
            self._guard(approval)
            if self.fixture.archives.observed():
                raise RetirementError("exact-version absence is not independently proven")
        self._guard(approval)
        # Guarding includes full local/provider checks and may be slow. Never
        # stamp an earlier empty observation with the time after that work.
        if self.fixture.archives.observed():
            raise RetirementError("exact-version absence changed during final guard")
        if not absence.exists():
            record(
                absence,
                {
                    "submission_sha256": digest(submission),
                    "observed_at": self.clock().isoformat(),
                    "independent_inventories": 2,
                },
            )
        result = self._completion(approval, submission)
        record(self.root / "retired.json", result)
        return result

    def _completion(
        self, approval: dict[str, object], submission: dict[str, object]
    ) -> dict[str, object]:
        observed = fields(
            read_private(self.root / "absence.json"),
            {
                "submission_sha256",
                "observed_at",
                "independent_inventories",
            },
        )
        observed_at = datetime.fromisoformat(str(observed["observed_at"]))
        if (
            observed_at.tzinfo is None
            or not datetime.fromisoformat(str(approval["approved_at"]))
            <= observed_at
            <= self.clock()
        ):
            raise RetirementError("frozen retirement absence time is invalid")
        if (
            observed["submission_sha256"] != digest(submission)
            or observed["independent_inventories"] != 2  # noqa: PLR2004 - distinct principals
        ):
            raise RetirementError("frozen retirement absence binding differs")
        return {
            "format": FORMAT,
            "outcome": "exact-version-retired-frozen-fixture-retained",
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(approval),
            "absence_sha256": digest(observed),
            "versions_retired": 1,
            "qualification_authority": "none",
            "fixture_execution": "permanently-excluded",
            "fixture_disposal": "separately-authorized-closeout-required",
            "original_tenant_job_audit_unchanged": True,
            "retained": RETAINED,
            "lease_released": False,
            "credential_cleanup_complete": False,
        }

    def _reconcile(self, approval: dict[str, object]) -> dict[str, object]:
        """Observe the consumed identity without completing or rewriting its journal."""
        self._guard(approval)
        for name in ("delete-submitted.json", "absence.json", "retired.json"):
            partial = self.root / (name + ".partial")
            if partial.exists() or partial.is_symlink():
                raise RetirementError("ambiguous retirement journal; no replay")
        submission = {
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(approval),
            "archive": self.plan["archive"],
            "maximum_submissions": 1,
        }
        if read_private(self.root / "delete-submitted.json") != submission:
            raise RetirementError("retirement observation lacks its consumed submission")
        observed = self.fixture.archives.observed()
        if observed not in ([], self._expected()):
            raise RetirementError("retirement observation found changed inventory")
        recorded = self.root / "retired.json"
        complete = None
        absence = self.root / "absence.json"
        if absence.exists() or absence.is_symlink():
            complete = self._completion(approval, submission)
        recorded_complete = recorded.exists() or recorded.is_symlink()
        if recorded_complete and (
            complete is None or read_private(recorded) != complete or observed
        ):
            raise RetirementError("recorded retirement differs from observed evidence")
        self._guard(approval)
        # Observation timestamps also describe the final fresh inventory, not
        # an inventory from before a potentially lengthy evidence guard.
        observed = self.fixture.archives.observed()
        if observed not in ([], self._expected()) or (recorded_complete and observed):
            raise RetirementError("retirement observation changed during final guard")
        return {
            "format": OBSERVATION,
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(approval),
            "observed_at": self.clock().isoformat(),
            "version_state": "present" if observed else "absent",
            "recorded_retirement": recorded_complete,
            "qualification_authority": "none",
            "lease_released": False,
            "credential_cleanup_complete": False,
        }
