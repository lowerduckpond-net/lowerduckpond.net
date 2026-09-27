"""Immutable preparation, explicit approval, and resumable exact archive deletion."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_archive import Archives, records
from scripts.m3_11_retirement_files import (
    RetirementError,
    digest,
    directory,
    fingerprint,
    record,
    sync,
)
from scripts.m3_11_retirement_receipt import FORMAT, RETAINED, receipt, timestamp


def now() -> str:
    return datetime.now(UTC).isoformat()


class Fixture(Protocol):
    archives: Archives

    def initial(self) -> dict[str, object]: ...
    def freeze(self, root: Path, intent: dict[str, object]) -> None: ...
    def capture(self, root: Path, intent: dict[str, object]) -> dict[str, object]: ...
    def guard(self, root: Path, intent: dict[str, object], capture: dict[str, object]) -> None: ...


class Retirement:
    """Caller holds the storage-target and original-run leases throughout."""

    def __init__(self, run: Path, fixture: Fixture) -> None:
        directory(run)
        self.root = run / "failed-archive-retirement"
        self.fixture = fixture

    def prepare(self) -> dict[str, object]:
        if not (self.root / "preparation.json").exists():
            if self.root.exists():
                directory(self.root)
                if {entry.name for entry in self.root.iterdir()} - {"preparation.json.partial"}:
                    raise RetirementError("incomplete preparation contains unbound evidence")
            initial = self.fixture.initial()
            self.root.mkdir(mode=0o700, exist_ok=True)
            sync(self.root.parent)
            record(self.root / "preparation.json", initial)
        directory(self.root)
        intent = read_private(self.root / "preparation.json")
        if (self.root / "plan.json").exists():
            plan = self.plan()
            self.guard(plan)
            return summary(plan)
        self.fixture.freeze(self.root, intent)
        capture = self.fixture.capture(self.root, intent)
        selected = records(capture.get("archives"))
        self.fixture.guard(self.root, intent, capture)
        expected = [(str(row["key"]), str(row["version"])) for row in selected]
        if self.fixture.archives.observed() != expected:
            raise RetirementError("archive inventory does not match frozen ownership")
        copies = []
        for index, row in enumerate(selected):
            name = f"archive-{index:02d}.bin"
            copies.append({"name": name, **self.fixture.archives.preserve(row, self.root / name)})
        self.fixture.guard(self.root, intent, capture)
        if self.fixture.archives.observed() != expected:
            raise RetirementError("archive inventory changed during evidence preservation")
        plan = {
            "format": FORMAT,
            "stage": "prepared",
            "prepared_at": now(),
            "preparation_sha256": digest(intent),
            "capture": capture,
            "copies": copies,
        }
        record(self.root / "plan.json", plan)
        return summary(plan)

    def plan(self) -> dict[str, object]:
        directory(self.root)
        plan = fields(
            read_private(self.root / "plan.json"),
            {"format", "stage", "prepared_at", "preparation_sha256", "capture", "copies"},
        )
        capture = plan["capture"]
        if plan["format"] != FORMAT or plan["stage"] != "prepared" or not isinstance(capture, dict):
            raise RetirementError("invalid retirement plan")
        timestamp(plan["prepared_at"])
        selected = records(capture.get("archives"))
        copies = plan["copies"]
        if not isinstance(copies, list) or len(copies) != len(selected):
            raise RetirementError("retirement plan lacks preserved archives")
        for index, row in enumerate(selected):
            if copies[index] != {
                "name": f"archive-{index:02d}.bin",
                "size": row["size"],
                "sha256": row["sha256"],
            }:
                raise RetirementError("retirement plan copy identities disagree")
        return plan

    def guard(self, plan: dict[str, object]) -> None:
        if self.plan() != plan:
            raise RetirementError("retirement plan changed")
        intent = read_private(self.root / "preparation.json")
        if digest(intent) != plan["preparation_sha256"]:
            raise RetirementError("retirement preparation changed")
        capture = cast(dict[str, object], plan["capture"])
        self.fixture.guard(self.root, intent, capture)
        for index, row in enumerate(records(capture["archives"])):
            if fingerprint(self.root / f"archive-{index:02d}.bin", cast(int, row["size"])) != {
                "size": row["size"],
                "sha256": row["sha256"],
            }:
                raise RetirementError("preserved archive bytes changed")

    def retire(self, approved: str, *, acknowledge: bool) -> dict[str, object]:  # noqa: PLR0912, PLR0915 - ordered durable deletion transaction
        plan = self.plan()
        if not acknowledge or approved != digest(plan):
            raise RetirementError("explicit approval of this exact retirement plan is required")
        self.guard(plan)
        selected = records(cast(dict[str, object], plan["capture"])["archives"])
        remaining = [(str(row["key"]), str(row["version"])) for row in selected]
        authorization = self.root / "authorization.json"
        if not authorization.exists():
            if self.fixture.archives.observed() != remaining:
                raise RetirementError("archive inventory changed before approval")
            record(
                authorization,
                {
                    "plan_sha256": approved,
                    "approved_at": now(),
                    "failed_run_data_loss_acknowledged": True,
                },
            )
        approval = fields(
            read_private(authorization),
            {"plan_sha256", "approved_at", "failed_run_data_loss_acknowledged"},
        )
        if (
            approval["plan_sha256"] != approved
            or approval["failed_run_data_loss_acknowledged"] is not True
        ):
            raise RetirementError("retirement approval changed")
        authorization_digest = digest(approval)
        timestamp(approval["approved_at"])
        for index, row in enumerate(selected):
            pending = self.root / f"delete-{index:02d}.json"
            done = self.root / f"deleted-{index:02d}.json"
            step: dict[str, object] = {"authorization_sha256": authorization_digest, "archive": row}
            self.guard(plan)
            observed = self.fixture.archives.observed()
            if done.exists():
                if read_private(pending) != step or read_private(done) != step:
                    raise RetirementError("retirement deletion journal changed")
                remaining.pop(0)
                # Later rows may also have durable completed/pending deletions;
                # reconcile the whole prefix once before selecting a new write.
                continue
            if pending.exists():
                if read_private(pending) != step:
                    raise RetirementError("retirement pending deletion changed")
                if observed == remaining[1:]:
                    record(done, step)
                    remaining.pop(0)
                    continue
            if observed != remaining:
                raise RetirementError("retirement inventory has an unauthorized change")
            record(pending, step)
            self.guard(plan)
            if self.fixture.archives.observed() != remaining:
                raise RetirementError("archive inventory changed before exact deletion")
            self.fixture.archives.delete(row)
            if self.fixture.archives.observed() != remaining[1:]:
                raise RetirementError("exact archive deletion is not independently proven")
            record(done, step)
            remaining.pop(0)
        self.guard(plan)
        if self.fixture.archives.observed():
            raise RetirementError("retirement final archive absence is not proven")
        path = self.root / "retired.json"
        if not path.exists():
            record(
                path,
                {
                    "format": FORMAT,
                    "outcome": "archives-retired-fixture-retained",
                    "plan_sha256": approved,
                    "authorization_sha256": authorization_digest,
                    "original_failure_preserved": True,
                    "qualification_authority": "none",
                    "versions_retired": len(selected),
                    "final_absence_at": now(),
                    "retained": RETAINED,
                },
            )
        result = receipt(read_private(path))
        if (
            result.get("plan_sha256") != approved
            or result.get("authorization_sha256") != authorization_digest
            or result["versions_retired"] != len(selected)
        ):
            raise RetirementError("retirement receipt changed")
        return result


def summary(plan: dict[str, object]) -> dict[str, object]:
    selected = records(cast(dict[str, object], plan["capture"])["archives"])
    return {
        "format": FORMAT,
        "stage": "prepared",
        "plan_sha256": digest(plan),
        "archive_versions": len(selected),
        "preserved_archive_bytes": sum(cast(int, row["size"]) for row in selected),
        "original_qualification": "failed",
        "deletion_authorized": False,
        "retained": [
            "stopped-containers",
            "state",
            "backup-prefix",
            "private-copies",
            "original-failure",
        ],
    }
