"""Create and verify milestone-specific secure-workstation evidence envelopes."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lowerduckpond_m3_archive.report import ArchiveQualificationReport

from scripts import m3_11_qualification_evidence as combined
from scripts.m3_11_private_inputs import publish_bytes, read_private, read_private_bytes
from scripts.m3_11_recovery_policy import HISTORICAL_SPAN, SUMMARY_FIELDS, Window
from scripts.m3_11_unattended import inputs as managed_inputs
from scripts.m3_11_unattended.model import digest as managed_digest
from scripts.m3_11_unattended.model import instant
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
MANAGED_FORMAT = "lowerduckpond-m3-11-installed-spaces-managed-v1"
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


def verify_report(  # noqa: PLR0913 - explicit candidate bindings
    path: Path,
    *,
    source: str,
    artifact: str,
    repository: Path | None = None,
    storage_target: str | None = None,
    milestone: str = "3.10",
    managed_binding: dict[str, object] | None = None,
) -> bytes:
    return _verify_report(
        path,
        source=source,
        artifact=artifact,
        repository=repository,
        storage_target=storage_target,
        milestone=milestone,
        managed_binding=managed_binding,
        now=datetime.now(UTC),
    )


def _verify_report(  # noqa: PLR0912, PLR0913, PLR0915 - original publication and current consumption clocks
    path: Path,
    *,
    source: str,
    artifact: str,
    repository: Path | None,
    storage_target: str | None,
    milestone: str,
    managed_binding: dict[str, object] | None,
    now: datetime,
) -> bytes:
    """Return the exact report bytes accepted by every gate below.

    A rollout must retain and hash this result rather than reread ``path``:
    its directory entry may change while Git/input/revocation checks run.
    No report is reserialized or returned before those checks succeed.
    """
    formats = _formats(milestone)
    raw, report = combined.read_document(path)
    if not isinstance(report.get("format"), str):
        raise ValueError("qualification report format is invalid")
    managed = report.get("format") == MANAGED_FORMAT
    if managed_binding is not None and not managed:
        raise ValueError("managed qualification requires its credential receipts")
    input_bound = report.get("format") in {
        INPUT_BOUND_FORMAT,
        combined.REPORT_FORMAT,
        MANAGED_FORMAT,
    }
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
    expected_fields |= {"managed_credentials"} if managed else set()
    if milestone == "3.11" and "finalization_recovery" in report:
        expected_fields.add("finalization_recovery")
    expected_fields |= (
        {"combined", "combined_report_sha256", "packaged_at", "legacy_observations"}
        if milestone == "3.11"
        else set()
    )
    if (
        not isinstance(report, dict)
        or set(report) != expected_fields
        or report["format"] not in formats
        or report["environment"]
        != (
            "trusted-controller-installed-production-spaces"
            if managed
            else "secure-workstation-installed-production-spaces"
        )
        or (not input_bound and report["source_revision"] != source)
        or re.fullmatch(r"[0-9a-f]{40}", source) is None
        or report["artifact_sha256"] != artifact
        or re.fullmatch(r"[0-9a-f]{64}", artifact) is None
        or report["phases"] != dict.fromkeys(PHASES, "passed")
        or report["accounting"] != EMPTY_ACCOUNTING
    ):
        raise ValueError("qualification report does not bind this source and artifact")
    _empty_accounting(report["accounting"])
    window = None
    evidence_now = now
    maximum_age = PROVIDER_EVIDENCE_MAX_AGE if input_bound else timedelta(hours=24)
    if "finalization_recovery" in report:
        if not managed:
            raise ValueError("recovery report requires managed lease evidence")
        window = Window.from_evidence(
            combined.fields(
                report["managed_credentials"],
                managed_inputs.BINDING | {"format", "receipts", "receipts_sha256"},
            ),
            combined.fields(
                report["finalization_recovery"], SUMMARY_FIELDS | {"final_observation"}
            ),
        )
        evidence_now = combined.parse_timestamp(report["packaged_at"])
        if evidence_now > now:
            raise ValueError("qualification package is future-dated")
        maximum_age = window.maximum_age
        window.validate(report, now=now, freshness=PROVIDER_EVIDENCE_MAX_AGE)
    completed = _fresh_timestamp(report["completed_at"], maximum_age=maximum_age, now=evidence_now)
    oldest = _fresh_timestamp(
        report["oldest_evidence_at"], maximum_age=maximum_age, now=evidence_now
    )
    if oldest > completed:
        raise ValueError("qualification evidence chronology is invalid")
    if milestone == "3.11":
        if raw != combined.canonical_bytes(report):
            raise ValueError("M3.11 qualification envelope must be canonical")
        _verify_combined(report, maximum_age=maximum_age, now=evidence_now, window=window)
        if managed:
            _verify_managed(
                report,
                maximum_age=maximum_age,
                binding=managed_binding,
                now=evidence_now,
                historical_at=window.functional_at if window else None,
            )
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
    return raw


def _formats(milestone: str) -> set[str]:
    if milestone == "3.10":
        return {FORMAT, INPUT_BOUND_FORMAT}
    if milestone == "3.11":
        return {combined.REPORT_FORMAT, MANAGED_FORMAT}
    raise ValueError("unknown qualification milestone")


def _empty_accounting(value: object) -> None:
    accounting = combined.fields(value, set(EMPTY_ACCOUNTING))
    for key, expected in EMPTY_ACCOUNTING.items():
        if type(accounting[key]) is not type(expected) or accounting[key] != expected:
            raise ValueError("installed accounting is unresolved")


def _verify_combined(
    report: dict[str, object],
    *,
    maximum_age: timedelta,
    now: datetime | None = None,
    window: Window | None = None,
) -> None:
    now = now or datetime.now(UTC)
    times = combined.validate(report["combined"], binding=report, maximum_age=maximum_age, now=now)
    if (
        report["combined_report_sha256"]
        != hashlib.sha256(combined.canonical_bytes(report["combined"])).hexdigest()
    ):
        raise ValueError("combined qualification receipt digest changed")
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
    if window is None and packaged - oldest > timedelta(hours=24):
        raise ValueError("combined qualification exceeded the packaging window")
    _verify_legacy_observations(report, times, maximum_age=maximum_age, now=now)


def _verify_legacy_observations(
    report: dict[str, object],
    times: combined.EvidenceTimes,
    *,
    maximum_age: timedelta,
    now: datetime | None = None,
) -> None:
    observations = combined.fields(
        report["legacy_observations"], {"storage_at", "installed_at", "phases"}
    )
    phases = combined.fields(observations["phases"], set(PHASES))
    now = now or datetime.now(UTC)
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


def _fresh_timestamp(
    value: object,
    *,
    maximum_age: timedelta = timedelta(hours=24),
    now: datetime | None = None,
) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("qualification report timestamp is invalid")
    timestamp = datetime.fromisoformat(value)
    age = (now or datetime.now(UTC)) - timestamp
    if not -timedelta(minutes=5) <= age <= maximum_age:
        raise ValueError("qualification report is stale or future-dated")
    return timestamp


def _evidence_time(
    path: Path,
    *,
    maximum_age: timedelta = timedelta(hours=24),
    now: datetime | None = None,
) -> datetime:
    return _fresh_timestamp(
        datetime.fromtimestamp(path.stat().st_mtime, UTC).isoformat().replace("+00:00", "Z"),
        maximum_age=maximum_age,
        now=now,
    )


def create_report(  # noqa: PLR0912, PLR0915 - legacy, managed, and recovered evidence gates
    directory: Path,
    *,
    repository: Path | None = None,
    storage_target: str | None = None,
    milestone: str = "3.10",
    recovery_observation: Path | None = None,
) -> dict[str, object]:
    if (directory / "diagnostic-origin.json").exists() or (
        directory / "diagnostic-origin.json"
    ).is_symlink():
        raise ValueError("diagnostic continuation cannot produce qualification evidence")
    _formats(milestone)
    if milestone == "3.11" and repository is None:
        raise ValueError("M3.11 qualification requires its Git inputs and storage target")
    now = datetime.now(UTC)
    window = None
    recovery = None
    maximum_age = HISTORICAL_SPAN
    if milestone == "3.11" and (directory / "finalization-recovery.json").exists():
        if recovery_observation is None:
            raise ValueError(
                "recovery packaging requires this invocation's fresh final observations"
            )
        recovery = {
            **recovery_summary(directory),
            "final_observation": read_private(recovery_observation),
        }
        window = Window.from_evidence(
            read_private(directory / "managed-credentials.json"), recovery
        )
        if now >= window.deadline:
            raise ValueError("recovery packaging exceeded original credential expiry")
        maximum_age = window.maximum_age
    source = revision((directory / "source-revision").read_text(encoding="ascii").strip())
    storage_raw, _ = combined.read_document(directory / "storage.json")
    storage = ArchiveQualificationReport.from_json(storage_raw.decode("ascii"))
    if storage.source_revision != source:
        raise ValueError("storage qualification used another source revision")
    evidence_times = [_fresh_timestamp(storage.generated_at, maximum_age=maximum_age, now=now)]
    for phase in PHASES:
        if (directory / f"{phase}.passed").read_text(encoding="ascii") != "passed\n":
            raise ValueError("an installed qualification phase did not pass")
        evidence_times.append(
            _evidence_time(directory / f"{phase}.passed", maximum_age=maximum_age, now=now)
        )
    _, installed = combined.read_document(directory / "installed.json")
    evidence_times.append(
        _evidence_time(directory / "installed.json", maximum_age=maximum_age, now=now)
    )
    # Captured immediately before the final independent proof, never when the
    # envelope happens to be packaged after destruction or a suspended process.
    completed = _fresh_timestamp(
        (directory / "final-proof.started-at").read_text(encoding="ascii").strip(),
        maximum_age=maximum_age,
        now=now,
    )
    if (
        _evidence_time(directory / "verify.passed", maximum_age=maximum_age, now=now) > completed
        or _evidence_time(directory / "destroy.passed", maximum_age=maximum_age, now=now)
        < completed
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
        if recovery is not None:
            report["finalization_recovery"] = recovery
        _add_combined(report, directory, maximum_age=maximum_age, now=now, window=window)
        _add_managed(report, directory, maximum_age=maximum_age, now=now, window=window)
        if window:
            window.validate(report, now=now, freshness=HISTORICAL_SPAN)
    return report


def recovery_summary(directory: Path) -> dict[str, object]:
    """Retain the original recovery time, but reject stale original-evidence bindings."""
    value = read_private(directory / "finalization-recovery.json")
    checkpoint = read_private(directory / "functional-completion.json")
    original = read_private(directory.parent.parent / "journey-result.json")
    if value != {
        "functional_completed_at": checkpoint["completed_at"],
        "completed_at": value.get("completed_at"),
        "original_outcome": original["outcome"],
        "original_result_sha256": managed_digest(original),
        "checkpoint_sha256": managed_digest(checkpoint),
    }:
        raise ValueError("finalization recovery lost its original evidence binding")
    return value


def write_once(path: Path, raw: bytes, *, before_publish: Callable[[], None] | None = None) -> None:
    """Retry only missing output; never replace conflicting or partial bytes."""
    if path.exists() or path.is_symlink():
        if read_private_bytes(path) != raw:
            raise ValueError("existing qualification output differs from original evidence")
        return
    publish_bytes(path, raw, before_publish=before_publish)


def publish_report(  # noqa: PLR0913 - explicit candidate and recovery publication guards
    directory: Path,
    *,
    repository: Path,
    storage_target: str,
    milestone: str,
    recovery_observation: Path | None = None,
    guard: Callable[[], None] | None = None,
) -> None:
    path = directory / "qualification.json"
    if path.exists() or path.is_symlink():
        original = read_private(path)
        if "finalization_recovery" in original:
            recovery = combined.fields(
                original["finalization_recovery"], SUMMARY_FIELDS | {"final_observation"}
            )
            if {key: recovery[key] for key in SUMMARY_FIELDS} != recovery_summary(directory):
                raise ValueError("published recovery lost its original evidence binding")
        # Repair publication, not qualification. Validate the ORIGINAL chronology
        # at its original packaging time, keeping current input/revocation checks.
        packaged = combined.parse_timestamp(original.get("packaged_at", original["completed_at"]))
        if packaged > datetime.now(UTC):
            raise ValueError("original qualification package is future-dated")
        raw = _verify_report(
            path,
            source=revision((directory / "source-revision").read_text(encoding="ascii").strip()),
            artifact=str(original["artifact_sha256"]),
            repository=repository,
            storage_target=storage_target,
            milestone=milestone,
            managed_binding=None,
            now=packaged,
        )
        if raw != combined.canonical_bytes(original):
            raise ValueError("qualification report changed during publication repair")
    else:
        report = create_report(
            directory,
            repository=repository,
            storage_target=storage_target,
            milestone=milestone,
            recovery_observation=recovery_observation,
        )
        raw = combined.canonical_bytes(report)
        if "finalization_recovery" in report:

            def require_publication() -> None:
                if guard is not None:
                    guard()
                managed = report["managed_credentials"]
                recovery = report["finalization_recovery"]
                if not isinstance(managed, dict) or not isinstance(recovery, dict):
                    raise ValueError("recovery evidence is invalid")
                if datetime.now(UTC) >= Window.from_evidence(managed, recovery).deadline:
                    raise ValueError("recovery publication exceeded original credential expiry")

            write_once(path, raw, before_publish=require_publication)
        else:
            write_once(path, raw)
    write_once(
        directory / "qualification.sha256",
        (hashlib.sha256(raw).hexdigest() + "  qualification.json\n").encode("ascii"),
    )


def freshness_start(report: dict[str, object]) -> object:
    """Freshness basis for an already validated, immutable report."""
    if "finalization_recovery" not in report:
        return report["oldest_evidence_at"]
    recovery = combined.fields(
        report["finalization_recovery"], SUMMARY_FIELDS | {"final_observation"}
    )
    observation = recovery["final_observation"]
    if not isinstance(observation, dict):
        raise ValueError("recovery final observation is invalid")
    return observation["started_at"]


def _add_managed(
    report: dict[str, object],
    directory: Path,
    *,
    maximum_age: timedelta = HISTORICAL_SPAN,
    now: datetime | None = None,
    window: Window | None = None,
) -> None:
    path = directory / "managed-credentials.json"
    if not path.exists() and not path.is_symlink():
        if os.environ.get(managed_inputs.MANAGED_ENV):
            raise ValueError("managed qualification omitted its production and fixture receipts")
        return
    _, receipt = combined.read_document(path)
    report.update(
        format=MANAGED_FORMAT,
        environment="trusted-controller-installed-production-spaces",
        managed_credentials=receipt,
    )
    receipts = combined.fields(receipt.get("receipts"), {"production", "fixture"})
    times = [_fresh_timestamp(report["oldest_evidence_at"], maximum_age=maximum_age, now=now)]
    for value in receipts.values():
        if not isinstance(value, dict):
            raise ValueError("managed credential receipt is invalid")
        times.append(_fresh_timestamp(value.get("started_at"), maximum_age=maximum_age, now=now))
    report["oldest_evidence_at"] = min(times).isoformat().replace("+00:00", "Z")
    _verify_managed(
        report,
        maximum_age=maximum_age,
        now=now,
        historical_at=window.functional_at if window else None,
    )
    _verify_combined(report, maximum_age=maximum_age, now=now, window=window)


def _verify_managed(
    report: dict[str, object],
    *,
    maximum_age: timedelta,
    binding: dict[str, object] | None = None,
    now: datetime | None = None,
    historical_at: datetime | None = None,
) -> None:
    credential = combined.fields(
        report["managed_credentials"],
        managed_inputs.BINDING | {"format", "receipts", "receipts_sha256"},
    )
    if binding is not None and combined.fields(binding, managed_inputs.BINDING) != {
        key: credential[key] for key in managed_inputs.BINDING
    }:
        raise ValueError("managed credential evidence belongs to another controller attempt")
    if (
        credential["format"] != "lowerduckpond-m3-11-managed-credentials-v1"
        or any(
            credential[key] != report[key]
            for key in managed_inputs.BINDING - {"managed_run_id", "helper_revision"}
        )
        or credential["receipts_sha256"] != managed_digest(credential["receipts"])
    ):
        raise ValueError("managed credential evidence does not bind the qualification")
    receipts = managed_inputs.receipt_pair(
        credential["receipts"],
        binding=credential,
        now=historical_at or now or datetime.now(UTC),
        maximum_age=HISTORICAL_SPAN if historical_at else maximum_age,
    )
    legacy = combined.fields(
        report["legacy_observations"], {"storage_at", "installed_at", "phases"}
    )
    storage = _fresh_timestamp(legacy["storage_at"], maximum_age=maximum_age, now=now)
    oldest = _fresh_timestamp(report["oldest_evidence_at"], maximum_age=maximum_age, now=now)
    for value in receipts.values():
        if not isinstance(value, dict):
            raise ValueError("managed credential receipt is invalid")
        if not oldest <= instant(value["started_at"]) <= instant(value["completed_at"]) <= storage:
            raise ValueError("managed credential evidence chronology is invalid")


def _add_combined(
    report: dict[str, object],
    directory: Path,
    *,
    maximum_age: timedelta = HISTORICAL_SPAN,
    now: datetime | None = None,
    window: Window | None = None,
) -> None:
    now = now or datetime.now(UTC)
    raw, proof = combined.read_document(directory / "combined.json")
    times = combined.validate(proof, binding=report, maximum_age=maximum_age, now=now)
    context_raw, context = combined.read_document(directory / "combined-context.json")
    if (
        raw != combined.canonical_bytes(proof)
        or context_raw != combined.canonical_bytes(context)
        or context != proof["context"]
        or _evidence_time(directory / "combined-context.json", maximum_age=maximum_age, now=now)
        > times.started_at
        or _evidence_time(directory / "combined-names.json", maximum_age=maximum_age, now=now)
        > times.started_at
        or not times.completed_at
        <= _evidence_time(directory / "combined.json", maximum_age=maximum_age, now=now)
        <= _fresh_timestamp(report["completed_at"], maximum_age=maximum_age, now=now)
    ):
        raise ValueError("combined qualification did not retain its original context and proof")
    combined.validate_names(directory / "combined-names.json", context)
    # Preserve every legacy observation so consumption can recheck chronology
    # without consulting private files or refreshing their original timestamps.
    _, storage = combined.read_document(directory / "storage.json")
    observations: dict[str, object] = {
        "storage_at": storage["generated_at"],
        "installed_at": _evidence_time(
            directory / "installed.json", maximum_age=maximum_age, now=now
        )
        .isoformat()
        .replace("+00:00", "Z"),
        "phases": {
            phase: _evidence_time(directory / f"{phase}.passed", maximum_age=maximum_age, now=now)
            .isoformat()
            .replace("+00:00", "Z")
            for phase in PHASES
        },
    }
    report.update(
        format=combined.REPORT_FORMAT,
        combined=proof,
        combined_report_sha256=hashlib.sha256(raw).hexdigest(),
        packaged_at=now.isoformat().replace("+00:00", "Z"),
        legacy_observations=observations,
        oldest_evidence_at=min(
            _fresh_timestamp(report["oldest_evidence_at"], maximum_age=maximum_age, now=now),
            times.captured_at,
        )
        .isoformat()
        .replace("+00:00", "Z"),
    )
    _verify_combined(report, maximum_age=maximum_age, now=now, window=window)


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
        publish_report(
            arguments.path,
            repository=ROOT,
            storage_target=storage_target_digest(),
            milestone=arguments.milestone,
        )
    except ValueError, OSError, TypeError, AttributeError, RecursionError:
        parser.exit(1, f"M{arguments.milestone} qualification evidence is incomplete or invalid.\n")
    print(f"Sanitized M{arguments.milestone} installed Spaces qualification report created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
