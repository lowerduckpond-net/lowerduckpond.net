"""Create and verify the allowlisted M3.10 secure-workstation evidence envelope."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from lowerduckpond_m3_archive.report import ArchiveQualificationReport

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


def verify_report(
    path: Path,
    *,
    source: str,
    artifact: str,
    repository: Path | None = None,
    storage_target: str | None = None,
) -> None:
    raw = path.read_bytes()
    report = json.loads(raw)
    input_bound = isinstance(report, dict) and report.get("format") == INPUT_BOUND_FORMAT
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
    if input_bound:
        expected_fields |= {"input_policy", "qualification_inputs_sha256", "storage_target_sha256"}
    if (
        not isinstance(report, dict)
        or set(report) != expected_fields
        or report["format"] not in {FORMAT, INPUT_BOUND_FORMAT}
        or report["environment"] != "secure-workstation-installed-production-spaces"
        or (not input_bound and report["source_revision"] != source)
        or re.fullmatch(r"[0-9a-f]{40}", source) is None
        or report["artifact_sha256"] != artifact
        or re.fullmatch(r"[0-9a-f]{64}", artifact) is None
        or report["phases"] != dict.fromkeys(PHASES, "passed")
        or report["accounting"] != EMPTY_ACCOUNTING
    ):
        raise ValueError("qualification report does not bind this source and artifact")
    for key, expected in EMPTY_ACCOUNTING.items():
        if type(report["accounting"][key]) is not type(expected):
            raise ValueError("qualification accounting types are invalid")
    maximum_age = PROVIDER_EVIDENCE_MAX_AGE if input_bound else timedelta(hours=24)
    completed = _fresh_timestamp(report["completed_at"], maximum_age=maximum_age)
    oldest = _fresh_timestamp(report["oldest_evidence_at"], maximum_age=maximum_age)
    if oldest > completed:
        raise ValueError("qualification evidence chronology is invalid")
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
    directory: Path, *, repository: Path | None = None, storage_target: str | None = None
) -> dict[str, object]:
    source = (directory / "source-revision").read_text(encoding="ascii").strip()
    if re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise ValueError("qualification source identity is invalid")
    storage_raw = (directory / "storage.json").read_bytes()
    storage = ArchiveQualificationReport.from_json(storage_raw.decode("ascii"))
    if storage.source_revision != source:
        raise ValueError("storage qualification used another source revision")
    evidence_times = [_fresh_timestamp(storage.generated_at)]
    for phase in PHASES:
        if (directory / f"{phase}.passed").read_text(encoding="ascii") != "passed\n":
            raise ValueError("an installed qualification phase did not pass")
        evidence_times.append(_evidence_time(directory / f"{phase}.passed"))
    installed = json.loads((directory / "installed.json").read_text(encoding="ascii"))
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
    for key, expected in EMPTY_ACCOUNTING.items():
        if type(installed[key]) is not type(expected) or installed[key] != expected:
            raise ValueError("installed accounting is unresolved")
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
        captured = json.loads((directory / "qualification-inputs.json").read_bytes())
        expected_inputs = {
            "source_revision": source,
            "input_policy": POLICY,
            "qualification_inputs_sha256": candidate_inputs(repository, source, digest),
            "storage_target_sha256": storage_target,
        }
        if captured != expected_inputs:
            raise ValueError("qualification inputs changed since the run started")
        report.update(format=INPUT_BOUND_FORMAT, **expected_inputs)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--source")
    parser.add_argument("--artifact")
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
            )
            print("M3.10 live qualification binds this candidate and its original evidence.")
            return 0
        if arguments.source or arguments.artifact:
            raise ValueError("unexpected evidence creation options")
        report = create_report(
            arguments.path, repository=ROOT, storage_target=storage_target_digest()
        )
        raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        with (arguments.path / "qualification.json").open("xb") as stream:
            stream.write(raw)
        with (arguments.path / "qualification.sha256").open("x", encoding="ascii") as stream:
            stream.write(hashlib.sha256(raw).hexdigest() + "  qualification.json\n")
    except ValueError, OSError, TypeError, AttributeError:
        parser.exit(1, "M3.10 qualification evidence is incomplete or invalid.\n")
    print("Sanitized M3.10 installed Spaces qualification report created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
