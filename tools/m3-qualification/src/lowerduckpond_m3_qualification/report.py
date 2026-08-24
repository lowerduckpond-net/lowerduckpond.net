"""Strict, allowlisted qualification evidence reports."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal

from lowerduckpond_m3_qualification.checks import EVIDENCE_KEYS_BY_CHECK
from lowerduckpond_m3_qualification.session import (
    UnsafeSessionError,
    validate_run_id,
    validate_source_revision,
)

REPORT_SCHEMA_VERSION: Final = "lowerduckpond.m3-qualification/v2"
MAX_EVIDENCE_FIELDS: Final = 12
MAXIMUM_HANDOFF_MILLISECONDS: Final = 1000
MINIMUM_NAMESERVERS: Final = 2
MAXIMUM_NAMESERVERS: Final = 8
CHECK_ID_PATTERN: Final = re.compile(r"^m3\.0\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
EVIDENCE_KEY_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
SAFE_STRING_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+:/-]{0,159}$")
VERSION_PATTERN: Final = re.compile(r"^[0-9]{1,4}(?:[.+-][A-Za-z0-9]{1,12}){1,5}$")
FORBIDDEN_EVIDENCE_WORDS: Final = frozenset(
    {
        "authorization",
        "body",
        "cookie",
        "credential",
        "header",
        "journal",
        "log",
        "password",
        "secret",
        "stderr",
        "stdout",
        "token",
    }
)
REPORT_ENVIRONMENTS: Final = frozenset(
    {
        "hermetic-ci",
        "live-dual-domain",
        "operator-and-cloudflare",
        "production-equivalent",
        "ubuntu-26.04-disposable",
    }
)
FIXED_STRING_EVIDENCE: Final = {
    "distribution": frozenset({"ubuntu"}),
    "draft": frozenset({"2020-12"}),
    "engine": frozenset({"chromium", "firefox", "webkit"}),
    "filesystem": frozenset({"ext4", "overlay", "tmpfs", "xfs"}),
    "mode": frozenset({"safe-pure"}),
    "release": frozenset({"26.04"}),
}
FIXED_INTEGER_EVIDENCE: Final = {
    "accepted": frozenset({1}),
    "bounded_attempts": frozenset({3}),
    "certificate_paths": frozenset({4}),
    "engines": frozenset({3}),
    "examples": frozenset({100}),
    "inodes": frozenset({4096}),
    "initial_links": frozenset({2}),
    "operations": frozenset({4}),
    "rejected": frozenset({7}),
    "remaining_links": frozenset({1}),
    "route_classes": frozenset({5}),
    "routes_checked": frozenset({5}),
    "size_mib": frozenset({64}),
}

type EvidenceValue = bool | int | str
type Status = Literal["passed", "failed"]


class UnsafeReportError(ValueError):
    """Raised when a report could contain non-allowlisted evidence."""


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One bounded qualification result."""

    check_id: str
    status: Status
    evidence: Mapping[str, EvidenceValue]
    error_code: str | None = None

    def __post_init__(self) -> None:
        _validate_check_id(self.check_id)
        _validate_evidence(self.evidence)
        allowed_evidence = EVIDENCE_KEYS_BY_CHECK.get(self.check_id)
        if allowed_evidence is None or not set(self.evidence).issubset(allowed_evidence):
            raise UnsafeReportError("check evidence is not allowlisted")
        if self.status == "passed" and set(self.evidence) != allowed_evidence:
            raise UnsafeReportError("passed check evidence is incomplete")
        if self.status == "passed" and self.error_code is not None:
            raise UnsafeReportError("passed checks cannot contain an error code")
        if self.status == "failed" and (self.error_code != "probe_failed"):
            raise UnsafeReportError("failed checks require a fixed-format error code")


@dataclass(frozen=True, slots=True)
class QualificationReport:
    """A complete report fragment or assembled M3.0 report."""

    report_schema: str
    run_id: str
    source_revision: str
    generated_at: str
    environment: str
    checks: tuple[CheckResult, ...]

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        source_revision: str,
        environment: str,
        checks: Iterable[CheckResult],
        now: datetime | None = None,
    ) -> QualificationReport:
        try:
            validate_run_id(run_id)
            validate_source_revision(source_revision)
        except UnsafeSessionError as error:
            raise UnsafeReportError("report run identity is not recognized") from error
        if environment not in REPORT_ENVIRONMENTS:
            raise UnsafeReportError("environment is not a safe report label")
        ordered = tuple(sorted(checks, key=lambda item: item.check_id))
        identifiers = [item.check_id for item in ordered]
        if len(identifiers) != len(set(identifiers)):
            raise UnsafeReportError("duplicate check identifiers are not allowed")
        generated_at = (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
        return cls(
            report_schema=REPORT_SCHEMA_VERSION,
            run_id=run_id,
            source_revision=source_revision,
            generated_at=generated_at,
            environment=environment,
            checks=ordered,
        )

    @classmethod
    def from_json(cls, raw: str) -> QualificationReport:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {
            "report_schema",
            "run_id",
            "source_revision",
            "generated_at",
            "environment",
            "checks",
        }:
            raise UnsafeReportError("report shape is not recognized")
        checks_value = value["checks"]
        if not isinstance(checks_value, list):
            raise UnsafeReportError("report checks must be a list")
        checks: list[CheckResult] = []
        for item in checks_value:
            if not isinstance(item, dict) or set(item) != {
                "check_id",
                "status",
                "evidence",
                "error_code",
            }:
                raise UnsafeReportError("check shape is not recognized")
            status = item["status"]
            if status not in {"passed", "failed"}:
                raise UnsafeReportError("check status is not recognized")
            evidence = item["evidence"]
            if not isinstance(evidence, dict):
                raise UnsafeReportError("check evidence must be an object")
            checks.append(
                CheckResult(
                    check_id=_require_string(item["check_id"]),
                    status=status,
                    evidence=evidence,
                    error_code=_require_optional_string(item["error_code"]),
                )
            )
        report = cls.create(
            run_id=_require_string(value["run_id"]),
            source_revision=_require_string(value["source_revision"]),
            environment=_require_string(value["environment"]),
            checks=checks,
        )
        if value["report_schema"] != REPORT_SCHEMA_VERSION:
            raise UnsafeReportError("report schema is not supported")
        generated_at = _require_string(value["generated_at"])
        try:
            parsed_timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise UnsafeReportError("report timestamp is invalid") from error
        if parsed_timestamp.tzinfo is None:
            raise UnsafeReportError("report timestamp must include a timezone")
        return cls(
            report_schema=REPORT_SCHEMA_VERSION,
            run_id=report.run_id,
            source_revision=report.source_revision,
            generated_at=generated_at,
            environment=report.environment,
            checks=report.checks,
        )

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check.status == "passed" for check in self.checks)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(self.to_json())
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.replace(path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise


def combine_reports(
    reports: Iterable[QualificationReport], *, required_check_ids: frozenset[str]
) -> QualificationReport:
    """Combine fragments and require an exact, duplicate-free check set."""
    reports_tuple = tuple(reports)
    if not reports_tuple:
        raise UnsafeReportError("at least one report fragment is required")
    run_ids = {report.run_id for report in reports_tuple}
    source_revisions = {report.source_revision for report in reports_tuple}
    if len(run_ids) != 1 or len(source_revisions) != 1:
        raise UnsafeReportError("report fragments do not belong to one qualification run")
    checks = tuple(check for report in reports_tuple for check in report.checks)
    identifiers = [check.check_id for check in checks]
    if len(identifiers) != len(set(identifiers)):
        raise UnsafeReportError("report fragments contain duplicate checks")
    missing = required_check_ids.difference(identifiers)
    unexpected = set(identifiers).difference(required_check_ids)
    if missing or unexpected:
        raise UnsafeReportError("report fragments do not contain the exact required check set")
    return QualificationReport.create(
        run_id=next(iter(run_ids)),
        source_revision=next(iter(source_revisions)),
        environment="production-equivalent",
        checks=checks,
    )


def _validate_check_id(check_id: str) -> None:
    if not CHECK_ID_PATTERN.fullmatch(check_id):
        raise UnsafeReportError("check identifier is not recognized")


def _validate_evidence(evidence: Mapping[str, EvidenceValue]) -> None:
    if len(evidence) > MAX_EVIDENCE_FIELDS:
        raise UnsafeReportError("check evidence contains too many fields")
    for key, value in evidence.items():
        if not EVIDENCE_KEY_PATTERN.fullmatch(key):
            raise UnsafeReportError("evidence key is not recognized")
        key_words = frozenset(key.split("_"))
        if key_words.intersection(FORBIDDEN_EVIDENCE_WORDS):
            raise UnsafeReportError("evidence key names sensitive data")
        if value.__class__ not in {bool, int, str}:
            raise UnsafeReportError("evidence values must be scalar")
        if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**63:
            raise UnsafeReportError("integer evidence is out of bounds")
        if isinstance(value, str) and not SAFE_STRING_PATTERN.fullmatch(value):
            raise UnsafeReportError("string evidence is not a safe bounded label")
        _validate_evidence_value(key, value)


def _validate_evidence_value(key: str, value: EvidenceValue) -> None:
    if isinstance(value, bool):
        if value is not True:
            raise UnsafeReportError("boolean evidence must record a proven condition")
        return
    if isinstance(value, int):
        if key == "handoff_ms" and 0 <= value < MAXIMUM_HANDOFF_MILLISECONDS:
            return
        if key == "nameservers" and MINIMUM_NAMESERVERS <= value <= MAXIMUM_NAMESERVERS:
            return
        if value not in FIXED_INTEGER_EVIDENCE.get(key, frozenset()):
            raise UnsafeReportError("integer evidence is outside its allowlist")
        return
    if key == "version" and VERSION_PATTERN.fullmatch(value):
        return
    if value not in FIXED_STRING_EVIDENCE.get(key, frozenset()):
        raise UnsafeReportError("string evidence is outside its allowlist")


def _require_string(value: object) -> str:
    if not isinstance(value, str):
        raise UnsafeReportError("expected a string")
    return value


def _require_optional_string(value: object) -> str | None:
    if value is None:
        return None
    return _require_string(value)
