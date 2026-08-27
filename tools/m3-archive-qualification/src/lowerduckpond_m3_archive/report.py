"""Sanitized M3.1 archive qualification report."""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from lowerduckpond_m3_archive.storage import AcceptanceEvidence

REPORT_SCHEMA: Final = "lowerduckpond.m3-archive-qualification/v1"
SOURCE_REVISION_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_CHECKS: Final = (
    "buckets-versioned",
    "credential-isolation",
    "exact-version-read",
    "delete-marker",
    "forced-pagination",
    "empty-archive-baseline",
    "cleanup-complete",
)
UUID7_VERSION: Final = 7


class UnsafeArchiveReportError(ValueError):
    """Raised when a report could contain unrecognized or unsafe data."""


@dataclass(frozen=True, slots=True)
class ReportCheck:
    check_id: str
    status: str


@dataclass(frozen=True, slots=True)
class ArchiveQualificationReport:
    report_schema: str
    run_id: str
    source_revision: str
    generated_at: str
    environment: str
    checks: tuple[ReportCheck, ...]

    @classmethod
    def create(
        cls, evidence: AcceptanceEvidence, *, source_revision: str
    ) -> ArchiveQualificationReport:
        if not SOURCE_REVISION_PATTERN.fullmatch(source_revision):
            raise UnsafeArchiveReportError("source revision is not a lowercase commit ID")
        evidence_values = asdict(evidence)
        if tuple(evidence_values) != tuple(item.replace("-", "_") for item in EXPECTED_CHECKS):
            raise UnsafeArchiveReportError("acceptance evidence shape is not recognized")
        if not all(value is True for value in evidence_values.values()):
            raise UnsafeArchiveReportError("a passing report requires every acceptance proof")
        return cls(
            report_schema=REPORT_SCHEMA,
            run_id=str(uuid.uuid7()),
            source_revision=source_revision,
            generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            environment="production-spaces",
            checks=tuple(
                ReportCheck(check_id=check_id, status="passed") for check_id in EXPECTED_CHECKS
            ),
        )

    @classmethod
    def from_json(cls, raw: str) -> ArchiveQualificationReport:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {
            "report_schema",
            "run_id",
            "source_revision",
            "generated_at",
            "environment",
            "checks",
        }:
            raise UnsafeArchiveReportError("report shape is not recognized")
        if value["report_schema"] != REPORT_SCHEMA or value["environment"] != "production-spaces":
            raise UnsafeArchiveReportError("report identity is not recognized")
        source_revision = value["source_revision"]
        if not isinstance(source_revision, str) or not SOURCE_REVISION_PATTERN.fullmatch(
            source_revision
        ):
            raise UnsafeArchiveReportError("source revision is not recognized")
        run_id = value["run_id"]
        try:
            parsed_run_id = uuid.UUID(run_id)
        except (AttributeError, ValueError) as error:
            raise UnsafeArchiveReportError("run ID is not a UUID") from error
        if parsed_run_id.version != UUID7_VERSION or str(parsed_run_id) != run_id:
            raise UnsafeArchiveReportError("run ID is not canonical UUIDv7")
        generated_at = value["generated_at"]
        if not isinstance(generated_at, str):
            raise UnsafeArchiveReportError("generated timestamp is not a string")
        try:
            timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise UnsafeArchiveReportError("generated timestamp is invalid") from error
        if timestamp.tzinfo is None:
            raise UnsafeArchiveReportError("generated timestamp has no timezone")
        checks_value = value["checks"]
        if not isinstance(checks_value, list) or len(checks_value) != len(EXPECTED_CHECKS):
            raise UnsafeArchiveReportError("report does not contain the exact check count")
        checks: list[ReportCheck] = []
        for expected_id, check in zip(EXPECTED_CHECKS, checks_value, strict=True):
            if check != {"check_id": expected_id, "status": "passed"}:
                raise UnsafeArchiveReportError("report check is not recognized")
            checks.append(ReportCheck(check_id=expected_id, status="passed"))
        return cls(
            report_schema=REPORT_SCHEMA,
            run_id=run_id,
            source_revision=source_revision,
            generated_at=generated_at,
            environment="production-spaces",
            checks=tuple(checks),
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(self.to_json())
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary_path, path)
            temporary_path.unlink()
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise
