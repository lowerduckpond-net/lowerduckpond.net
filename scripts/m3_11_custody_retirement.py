"""One exact irreversible submission over migrated history and fresh authority."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.m3_11_custody_plan import FORMAT, RETAINED, authorization, local_root, plan, require
from scripts.m3_11_custody_registry import FORMAT as EXCLUSION
from scripts.m3_11_frozen_retirement import reserve
from scripts.m3_11_retirement_archive import Archives
from scripts.m3_11_retirement_files import digest, directory, record, sync
from scripts.m3_11_unattended.model import stamp


class Fixture(Protocol):
    archives: Archives
    root: Path

    def locked(self, approved: dict[str, object]) -> AbstractContextManager[None]: ...
    def guard(self) -> None: ...
    def verify_custody(self) -> None: ...
    def exclusion(self) -> dict[str, object] | None: ...
    def publish_exclusion(self, value: dict[str, object], *, spool: Path) -> None: ...
    def require_exclusion(self, value: dict[str, object]) -> None: ...
    def submission(self) -> AbstractContextManager[None]: ...
    def record_completion(self, value: dict[str, object]) -> None: ...


class CustodyRetirement:
    def __init__(
        self,
        approved: object,
        fixture: Fixture,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.plan, self.fixture, self.clock = plan(approved), fixture, clock
        self.root = local_root(fixture.root, self.plan)

    def expected(self) -> list[tuple[str, str]]:
        archive = cast(dict[str, object], self.plan["archive"])
        return [(str(archive["key"]), str(archive["version"]))]

    def execute(self, approval: object, *, observe_only: bool = False) -> dict[str, object]:
        approved = authorization(approval, self.plan, now=self.clock())
        with self.fixture.locked(self.plan):
            # Always consult the external fixture identity, even with a new plan,
            # new current lease or a completely lost local workspace.
            external = self.fixture.exclusion()
            if observe_only:
                require(external is not None, "observation requires an external consumed attempt")
                return self.observe(approved, cast(dict[str, object], external))
            require(
                external is None and not self.root.exists() and not self.root.is_symlink(),
                "custody retirement is already consumed; observation only, no replay",
            )
            self.fixture.guard()
            require(
                self.fixture.archives.observed() == self.expected(),
                "whole archive inventory differs from the one approved version",
            )
            self.fixture.verify_custody()
            self.fixture.guard()
            parent = self.root.parent
            parent.mkdir(mode=0o700, exist_ok=True)
            directory(parent)
            self.root.mkdir(mode=0o700)
            sync(parent)
            record(self.root / "plan.json", self.plan)
            record(self.root / "authorization.json", approved)
            exclusion = {
                "format": EXCLUSION,
                "fixture_id": self.plan["fixture_id"],
                "plan": self.plan,
                "authorization": approved,
                "reserved_at": stamp(self.clock()),
            }
            # This is deliberately before publication and the final inventory.
            # Any later failure has consumed this invocation, even before DELETE.
            reserve(self.root / "delete-submitted.json", exclusion)
            spool = self.root / "publication"
            spool.mkdir(mode=0o700)
            sync(self.root)
            self.fixture.publish_exclusion(exclusion, spool=spool)
            self.fixture.require_exclusion(exclusion)
            self.fixture.guard()
            require(
                self.fixture.archives.observed() == self.expected(),
                "archive inventory changed after the permanent exclusion",
            )
            self.fixture.require_exclusion(exclusion)
            with self.fixture.submission():
                self.fixture.guard()
                self.fixture.archives.delete(cast(dict[str, object], self.plan["archive"]))
            self.fixture.guard()
            require(
                self.fixture.archives.observed() == [],
                "archive absence is not independently verified",
            )
            self.fixture.require_exclusion(exclusion)
            absence = {
                "plan_sha256": digest(self.plan),
                "authorization_sha256": digest(approved),
                "observed_at": stamp(self.clock()),
                "whole_bucket_empty": True,
                "exclusion_sha256": digest(exclusion),
            }
            record(self.root / "absence.json", absence)
            result = {
                "format": FORMAT,
                "fixture_id": self.plan["fixture_id"],
                "outcome": "exact-version-retired-custody-retained",
                "plan_sha256": digest(self.plan),
                "authorization_sha256": digest(approved),
                "absence_sha256": digest(absence),
                "versions_retired": 1,
                "fixture_execution": "permanently-excluded",
                "qualification_authority": "none",
                "historical_lease_closed": True,
                "current_lease_cleanup_complete": False,
                "retained": RETAINED,
                "source_workspace_changed": False,
            }
            record(self.root / "retired.json", result)
            self.fixture.record_completion(result)
            return result

    def observe(
        self, approved: dict[str, object], external: dict[str, object]
    ) -> dict[str, object]:
        # Observation cannot mint a completion receipt or rewrite the original
        # plan/fact after loss of local state. A fresh plan may supply read access.
        self.fixture.guard()
        current = self.fixture.archives.observed()
        require(
            current in ([], self.expected()), "archive observation contains unexpected versions"
        )
        self.fixture.require_exclusion(external)
        return {
            "format": FORMAT,
            "outcome": "observed-only",
            "plan_sha256": digest(self.plan),
            "authorization_sha256": digest(approved),
            "exclusion_sha256": digest(external),
            "version_state": "absent" if not current else "present",
            "provider_delete_submissions": 0,
            "qualification_authority": "none",
            "historical_lease_closed": True,
            "current_lease_cleanup_complete": False,
        }
