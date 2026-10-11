"""Bind checksum-only repair to retained evidence without recreating a report."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.report import ArchiveQualificationReport

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_recovery_policy import HISTORICAL_SPAN, Window


def modified(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, UTC)


def combined_originals(directory: Path, report: dict[str, object]) -> datetime:
    raw, proof = evidence.read_document(directory / "combined.json")
    context_raw, context = evidence.read_document(directory / "combined-context.json")
    phases = evidence.fields(proof["phases"], set(evidence.PHASE_CHECKS))
    first = evidence.fields(
        phases[next(iter(evidence.PHASE_CHECKS))],
        {"started_at", "completed_at", "checks", "evidence_sha256"},
    )
    last = evidence.fields(
        phases["owned-teardown"], {"started_at", "completed_at", "checks", "evidence_sha256"}
    )
    packaged = evidence.parse_timestamp(report["packaged_at"])
    maximum_age = HISTORICAL_SPAN
    if "finalization_recovery" in report:
        maximum_age = Window.from_evidence(
            cast(dict[str, object], report["managed_credentials"]),
            cast(dict[str, object], report["finalization_recovery"]),
        ).maximum_age
    if any(
        not packaged - maximum_age <= modified(directory / name) <= packaged
        for name in ("combined-context.json", "combined-names.json", "combined.json")
    ):
        raise ValueError("retained combined observation is stale or future-dated at packaging")
    if (
        raw != evidence.canonical_bytes(report["combined"])
        or context_raw != evidence.canonical_bytes(context)
        or context != proof["context"]
        or modified(directory / "combined-context.json")
        > evidence.parse_timestamp(first["started_at"])
        or modified(directory / "combined-names.json")
        > evidence.parse_timestamp(first["started_at"])
        or not evidence.parse_timestamp(last["completed_at"])
        <= modified(directory / "combined.json")
        <= evidence.parse_timestamp(report["completed_at"])
    ):
        raise ValueError("published report differs from retained combined evidence")
    evidence.validate_names(directory / "combined-names.json", context)
    return evidence.parse_timestamp(context["captured_at"])


def verify(
    directory: Path, report: dict[str, object], *, phases: tuple[str, ...], now: datetime
) -> None:
    """Compare original bytes/observations after the report's historical validation."""
    if (directory / "diagnostic-origin.json").exists() or (
        directory / "diagnostic-origin.json"
    ).is_symlink():
        raise ValueError("diagnostic continuation cannot repair qualification evidence")
    raw, _ = evidence.read_document(directory / "storage.json")
    storage = ArchiveQualificationReport.from_json(raw.decode("ascii"))
    _, installed = evidence.read_document(directory / "installed.json")
    accounting = cast(dict[str, object], report["accounting"])
    completed = evidence.parse_timestamp(
        (directory / "final-proof.started-at").read_text(encoding="ascii").strip()
    )
    phase_times = {phase: modified(directory / f"{phase}.passed") for phase in phases}
    if (
        report["source_revision"]
        != (directory / "source-revision").read_text(encoding="ascii").strip()
        or storage.source_revision != report["source_revision"]
        or storage.run_id != report["storage_run_id"]
        or hashlib.sha256(raw).hexdigest() != report["storage_report_sha256"]
        or installed != {"artifact_sha256": report["artifact_sha256"], **accounting}
        or completed != evidence.parse_timestamp(report["completed_at"])
        or not phase_times["verify"] <= completed <= phase_times["destroy"]
        or any(
            (directory / f"{phase}.passed").read_text(encoding="ascii") != "passed\n"
            for phase in phases
        )
    ):
        raise ValueError("published report differs from retained original evidence")
    times = [
        evidence.parse_timestamp(storage.generated_at),
        modified(directory / "installed.json"),
        completed,
        *phase_times.values(),
    ]
    if "input_policy" in report:
        _, captured = evidence.read_document(directory / "qualification-inputs.json")
        if captured != {
            key: report[key]
            for key in (
                "source_revision",
                "input_policy",
                "qualification_inputs_sha256",
                "storage_target_sha256",
            )
        }:
            raise ValueError("published report differs from retained qualification inputs")
    if "combined" in report:
        times.append(combined_originals(directory, report))
        observations = {
            "storage_at": storage.generated_at,
            "installed_at": modified(directory / "installed.json")
            .isoformat()
            .replace("+00:00", "Z"),
            "phases": {
                phase: value.isoformat().replace("+00:00", "Z")
                for phase, value in phase_times.items()
            },
        }
        if report["legacy_observations"] != observations:
            raise ValueError("published report differs from retained observation timestamps")
    times.extend(managed_originals(directory, report))
    if min(times) != evidence.parse_timestamp(report["oldest_evidence_at"]):
        raise ValueError("published report differs from retained oldest evidence time")
    if "packaged_at" not in report:
        # M3.10 did not record its packaging instant. Require a feasible original
        # 24-hour window, preserving its explicit five-minute future tolerance.
        earliest_package = max(times) - timedelta(minutes=5)
        if earliest_package > min(times) + HISTORICAL_SPAN or earliest_package > now:
            raise ValueError("retained original evidence has no valid historical packaging window")
    if "finalization_recovery" in report:
        recovery = cast(dict[str, object], report["finalization_recovery"])
        if not any(
            read_private(path) == recovery["final_observation"]
            for path in directory.glob("*/final-observation.json")
        ):
            raise ValueError("published report differs from retained final observations")


def managed_originals(directory: Path, report: dict[str, object]) -> list[datetime]:
    times = []
    managed = directory / "managed-credentials.json"
    if "managed_credentials" in report or managed.exists() or managed.is_symlink():
        _, credential = evidence.read_document(managed)
        if report.get("managed_credentials") != credential:
            raise ValueError("published report differs from retained credential receipts")
        receipts = evidence.fields(credential["receipts"], {"fixture", "production"})
        for value in receipts.values():
            if not isinstance(value, dict):
                raise ValueError("retained credential receipt is invalid")
            times.append(evidence.parse_timestamp(value["started_at"]))
    return times
