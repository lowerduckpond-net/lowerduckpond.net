"""Create and verify milestone-specific secure-workstation evidence envelopes."""

from __future__ import annotations

import argparse
import hashlib
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lowerduckpond_m3_archive.report import ArchiveQualificationReport

from scripts import m3_11_qualification_evidence as combined
from scripts.production_qualification_inputs import (
    POLICY,
    ROOT,
    assert_not_revoked,
    candidate_inputs,
    current_candidate,
    fingerprint,
    git,
    revision,
    storage_target_digest,
)

FORMAT = "lowerduckpond-m3-10-installed-spaces-v1"
INPUT_BOUND_FORMAT = "lowerduckpond-m3-10-installed-spaces-v2"
PROVIDER_EVIDENCE_MAX_AGE = timedelta(days=7)
PHASES = ("create", "prepare", "converge", "idempotence", "verify", "destroy")
EMPTY_ACCOUNTING = {
    "pending_intents": 0,
    "pending_intake": 0,
    "pending_exports": 0,
    "pending_staging": 0,
    "quarantine": False,
    "remote_versions_and_markers": 0,
    "remote_multipart_uploads": 0,
}


def verify_report(  # noqa: PLR0913 - candidate bindings plus explicit milestone selection
    path: Path,
    *,
    source: str,
    artifact: str,
    repository: Path | None = None,
    storage_target: str | None = None,
    milestone: str = "3.10",
) -> None:
    formats = _formats(milestone)
    raw, report = combined.read_document(path)
    if not isinstance(report.get("format"), str):
        raise ValueError("qualification report format is invalid")
    input_bound = report.get("format") in {INPUT_BOUND_FORMAT, combined.REPORT_FORMAT}
    expected_fields = {
        "format",
        "source_revision",
        "artifact_sha256",
        "completed_at",
        "oldest_evidence_at",
        "environment",
        "storage_report_sha256",
        "storage_run_id",
        "phases",
        "accounting",
    }
    expected_fields |= (
        {"input_policy", "qualification_inputs_sha256", "storage_target_sha256"}
        if input_bound
        else set()
    )
    expected_fields |= (
        {"combined", "combined_report_sha256", "packaged_at", "legacy_observations"}
        if milestone == "3.11"
        else set()
    )
    if (
        not isinstance(report, dict)
        or set(report) != expected_fields
        or report["format"] not in formats
        or report["environment"] != "secure-workstation-installed-production-spaces"
        or (not input_bound and report["source_revision"] != source)
        or re.fullmatch(r"[0-9a-f]{40}", source) is None
        or report["artifact_sha256"] != artifact
        or re.fullmatch(r"[0-9a-f]{64}", artifact) is None
        or report["phases"] != dict.fromkeys(PHASES, "passed")
        or report["accounting"] != EMPTY_ACCOUNTING
    ):
        raise ValueError("qualification report does not bind this source and artifact")
    _empty_accounting(report["accounting"])
    maximum_age = PROVIDER_EVIDENCE_MAX_AGE if input_bound else timedelta(hours=24)
    completed = _fresh_timestamp(report["completed_at"], maximum_age=maximum_age)
    oldest = _fresh_timestamp(report["oldest_evidence_at"], maximum_age=maximum_age)
    if oldest > completed:
        raise ValueError("qualification evidence chronology is invalid")
    if milestone == "3.11":
        if raw != combined.canonical_bytes(report):
            raise ValueError("M3.11 qualification envelope must be canonical")
        _verify_combined(report, maximum_age=maximum_age)
    if (
        not isinstance(report["storage_report_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", report["storage_report_sha256"]) is None
    ):
        raise ValueError("storage evidence digest is invalid")
    run_id = report["storage_run_id"]
    if not isinstance(run_id, str) or str(uuid.UUID(run_id, version=7)) != run_id:
        raise ValueError("storage evidence run identity is invalid")
    if input_bound and repository is None:
        raise ValueError("input-bound qualification requires its Git repository")
    if repository is not None:
        inputs = candidate_inputs(repository, source, artifact)
        original = revision(report["source_revision"])
        assert_not_revoked(
            current_candidate(repository, source),
            source=original,
            artifact=artifact,
            inputs=inputs,
            report=raw,
        )
        if input_bound:
            git(repository, "merge-base", "--is-ancestor", original, source)
            if (
                report["input_policy"] != POLICY
                or report["qualification_inputs_sha256"] != inputs
                or fingerprint(repository, original) != inputs
                or storage_target is None
                or re.fullmatch(r"[0-9a-f]{64}", storage_target) is None
                or report["storage_target_sha256"] != storage_target
            ):
                raise ValueError("qualification inputs or storage target changed")


def _formats(milestone: str) -> set[str]:
    if milestone == "3.10":
        return {FORMAT, INPUT_BOUND_FORMAT}
    if milestone == "3.11":
        return {combined.REPORT_FORMAT}
    raise ValueError("unknown qualification milestone")


def _empty_accounting(value: object) -> None:
    accounting = combined.fields(value, set(EMPTY_ACCOUNTING))
    for key, expected in EMPTY_ACCOUNTING.items():
        if type(accounting[key]) is not type(expected) or accounting[key] != expected:
            raise ValueError("installed accounting is unresolved")


def _verify_combined(report: dict[str, object], *, maximum_age: timedelta) -> None:
    times = combined.validate(report["combined"], binding=report, maximum_age=maximum_age)
    if (
        report["combined_report_sha256"]
        != hashlib.sha256(combined.canonical_bytes(report["combined"])).hexdigest()
    ):
        raise ValueError("combined qualification receipt digest changed")
    now = datetime.now(UTC)
    oldest, completed, packaged = (
        combined.timestamp(report[key], now=now, maximum_age=maximum_age)
        for key in ("oldest_evidence_at", "completed_at", "packaged_at")
    )
    if (
        not oldest
        <= times.captured_at
        <= times.started_at
        <= times.completed_at
        <= completed
        <= packaged
    ):
        raise ValueError("combined qualification envelope chronology is invalid")
    if packaged - oldest > timedelta(hours=24):
        raise ValueError("combined qualification exceeded the packaging window")
    _verify_legacy_observations(report, times, maximum_age=maximum_age)


def _verify_legacy_observations(
    report: dict[str, object], times: combined.EvidenceTimes, *, maximum_age: timedelta
) -> None:
    observations = combined.fields(
        report["legacy_observations"], {"storage_at", "installed_at", "phases"}
    )
    phases = combined.fields(observations["phases"], set(PHASES))
    now = datetime.now(UTC)
    phase_times = {
        key: combined.timestamp(phases[key], now=now, maximum_age=maximum_age) for key in PHASES
    }
    storage, installed = (
        combined.timestamp(observations[key], now=now, maximum_age=maximum_age)
        for key in ("storage_at", "installed_at")
    )
    oldest, completed, packaged = (
        combined.timestamp(report[key], now=now, maximum_age=maximum_age)
        for key in ("oldest_evidence_at", "completed_at", "packaged_at")
    )
    ordered = [
        oldest,
        storage,
        *(phase_times[key] for key in PHASES[:-1]),
        completed,
        phase_times["destroy"],
        packaged,
    ]
    if (
        ordered != sorted(ordered)
        or not phase_times["idempotence"] <= installed <= phase_times["verify"]
        or not phase_times["idempotence"]
        <= times.started_at
        <= times.completed_at
        <= phase_times["verify"]
    ):
        raise ValueError("combined qualification legacy observation chronology is invalid")


def _fresh_timestamp(value: object, *, maximum_age: timedelta = timedelta(hours=24)) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("qualification report timestamp is invalid")
    timestamp = datetime.fromisoformat(value)
    age = datetime.now(UTC) - timestamp
    if not -timedelta(minutes=5) <= age <= maximum_age:
        raise ValueError("qualification report is stale or future-dated")
    return timestamp


def _evidence_time(path: Path) -> datetime:
    return _fresh_timestamp(
        datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat().replace("+00:00", "Z")
    )


def create_report(
    directory: Path,
    *,
    repository: Path | None = None,
    storage_target: str | None = None,
    milestone: str = "3.10",
) -> dict[str, object]:
    _formats(milestone)
    if milestone == "3.11" and repository is None:
        raise ValueError("M3.11 qualification requires its Git inputs and storage target")
    source = revision((directory / "source-revision").read_text(encoding="ascii").strip())
    storage_raw, _ = combined.read_document(directory / "storage.json")
    storage = ArchiveQualificationReport.from_json(storage_raw.decode("ascii"))
    if storage.source_revision != source:
        raise ValueError("storage qualification used another source revision")
    evidence_times = [_fresh_timestamp(storage.generated_at)]
    for phase in PHASES:
        if (directory / f"{phase}.passed").read_text(encoding="ascii") != "passed\n":
            raise ValueError("an installed qualification phase did not pass")
        evidence_times.append(_evidence_time(directory / f"{phase}.passed"))
    _, installed = combined.read_document(directory / "installed.json")
    evidence_times.append(_evidence_time(directory / "installed.json"))
    # Captured immediately before the final independent proof, never when the
    # envelope happens to be packaged after destruction or a suspended process.
    completed = _fresh_timestamp(
        (directory / "final-proof.started-at").read_text(encoding="ascii").strip()
    )
    if (
        _evidence_time(directory / "verify.passed") > completed
        or _evidence_time(directory / "destroy.passed") < completed
    ):
        raise ValueError("qualification final proof chronology is invalid")
    if not isinstance(installed, dict) or set(installed) != {"artifact_sha256", *EMPTY_ACCOUNTING}:
        raise ValueError("installed accounting report has unknown fields")
    _empty_accounting({key: installed[key] for key in EMPTY_ACCOUNTING})
    digest = installed["artifact_sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("installed artifact identity is invalid")
    report: dict[str, object] = {
        "format": FORMAT,
        "source_revision": source,
        "artifact_sha256": digest,
        "completed_at": completed.isoformat().replace("+00:00", "Z"),
        "oldest_evidence_at": min(*evidence_times, completed).isoformat().replace("+00:00", "Z"),
        "environment": "secure-workstation-installed-production-spaces",
        "storage_report_sha256": hashlib.sha256(storage_raw).hexdigest(),
        "storage_run_id": storage.run_id,
        "phases": dict.fromkeys(PHASES, "passed"),
        "accounting": EMPTY_ACCOUNTING,
    }
    if repository is not None:
        if storage_target is None or re.fullmatch(r"[0-9a-f]{64}", storage_target) is None:
            raise ValueError("qualification storage target is unavailable")
        _, captured = combined.read_document(directory / "qualification-inputs.json")
        expected_inputs = {
            "source_revision": source,
            "input_policy": POLICY,
            "qualification_inputs_sha256": candidate_inputs(repository, source, digest),
            "storage_target_sha256": storage_target,
        }
        if captured != expected_inputs:
            raise ValueError("qualification inputs changed since the run started")
        report.update(format=INPUT_BOUND_FORMAT, **expected_inputs)
    if milestone == "3.11":
        _add_combined(report, directory)
    return report


def _add_combined(report: dict[str, object], directory: Path) -> None:
    raw, proof = combined.read_document(directory / "combined.json")
    times = combined.validate(proof, binding=report, maximum_age=timedelta(hours=24))
    context_raw, context = combined.read_document(directory / "combined-context.json")
    if (
        raw != combined.canonical_bytes(proof)
        or context_raw != combined.canonical_bytes(context)
        or context != proof["context"]
        or _evidence_time(directory / "combined-context.json") > times.started_at
        or _evidence_time(directory / "combined-names.json") > times.started_at
        or not times.completed_at
        <= _evidence_time(directory / "combined.json")
        <= _fresh_timestamp(report["completed_at"])
    ):
        raise ValueError("combined qualification did not retain its original context and proof")
    combined.validate_names(directory / "combined-names.json", context)
    # Preserve every legacy observation so consumption can recheck chronology
    # without consulting private files or refreshing their original timestamps.
    _, storage = combined.read_document(directory / "storage.json")
    observations: dict[str, object] = {
        "storage_at": storage["generated_at"],
        "installed_at": _evidence_time(directory / "installed.json")
        .isoformat()
        .replace("+00:00", "Z"),
        "phases": {
            phase: _evidence_time(directory / f"{phase}.passed").isoformat().replace("+00:00", "Z")
            for phase in PHASES
        },
    }
    report.update(
        format=combined.REPORT_FORMAT,
        combined=proof,
        combined_report_sha256=hashlib.sha256(raw).hexdigest(),
        packaged_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        legacy_observations=observations,
        oldest_evidence_at=min(_fresh_timestamp(report["oldest_evidence_at"]), times.captured_at)
        .isoformat()
        .replace("+00:00", "Z"),
    )
    _verify_combined(report, maximum_age=timedelta(hours=24))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--source")
    parser.add_argument("--artifact")
    parser.add_argument("--milestone", choices=("3.10", "3.11"), default="3.10")
    arguments = parser.parse_args()
    try:
        if arguments.verify:
            if not arguments.source or not arguments.artifact:
                raise ValueError("source and artifact are required")
            verify_report(
                arguments.path,
                source=arguments.source,
                artifact=arguments.artifact,
                repository=ROOT,
                storage_target=storage_target_digest(),
                milestone=arguments.milestone,
            )
            print(
                f"M{arguments.milestone} live qualification binds this candidate "
                "and its original evidence."
            )
            return 0
        if arguments.source or arguments.artifact:
            raise ValueError("unexpected evidence creation options")
        report = create_report(
            arguments.path,
            repository=ROOT,
            storage_target=storage_target_digest(),
            milestone=arguments.milestone,
        )
        raw = combined.canonical_bytes(report)
        with (arguments.path / "qualification.json").open("xb") as stream:
            stream.write(raw)
        with (arguments.path / "qualification.sha256").open("x", encoding="ascii") as stream:
            stream.write(hashlib.sha256(raw).hexdigest() + "  qualification.json\n")
    except ValueError, OSError, TypeError, AttributeError, RecursionError:
        parser.exit(1, f"M{arguments.milestone} qualification evidence is incomplete or invalid.\n")
    print(f"Sanitized M{arguments.milestone} installed Spaces qualification report created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
