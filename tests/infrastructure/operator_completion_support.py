"""Explicitly modeled installed observations through actual completion/report producers."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from pathlib import Path

from lowerduckpond_m3_archive.report import ArchiveQualificationReport
from lowerduckpond_m3_archive.storage import AcceptanceEvidence

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_functional_completion as functional
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_owned_teardown import nodes
from scripts.m3_11_phase_receipts import Recorder
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_recovery_policy import CHECKS
from scripts.m3_11_unattended.model import stamp
from scripts.production_qualification_inputs import POLICY
from scripts.qualification_group_runner import Completion


class Observations:
    def __init__(self, directory: Path, environment: dict[str, str]) -> None:
        self.directory = directory
        self.environment = environment
        managed = read_private(directory / "managed-credentials.json")
        source = str(managed["source_revision"])
        bound = {
            key: managed[key]
            for key in (
                "source_revision",
                "artifact_sha256",
                "qualification_inputs_sha256",
                "storage_target_sha256",
            )
        }
        write_private(
            directory / "qualification-inputs.json",
            {
                key: value
                for key, value in {**bound, "input_policy": POLICY}.items()
                if key != "artifact_sha256"
            },
        )
        (directory / "source-revision").write_text(source + "\n")
        storage = ArchiveQualificationReport.create(
            AcceptanceEvidence(True, True, True, True, True, True, True), source_revision=source
        )
        storage.write(directory / "storage.json")
        for phase in ("create", "prepare", "converge", "idempotence"):
            (directory / (phase + ".passed")).write_text("passed\n")
        write_private(
            directory / "installed.json",
            {"artifact_sha256": managed["artifact_sha256"], **reports.EMPTY_ACCOUNTING},
        )
        nonce = str(uuid.uuid7())
        context = {
            "format": evidence.CONTEXT_FORMAT,
            "run_id": read_private(directory / "fixture.json")["run_id"],
            "captured_at": stamp(datetime.now(UTC)),
            **bound,
            "input_policy": POLICY,
            "storage_run_id": storage.run_id,
            "storage_report_sha256": hashlib.sha256(
                (directory / "storage.json").read_bytes()
            ).hexdigest(),
            **{key: hashlib.sha256(key.encode()).hexdigest() for key in evidence.IDENTITY_FIELDS},
            "subject_set_sha256": evidence.subject_digest(nonce),
        }
        write_private(directory / "combined-context.json", context)
        write_private(
            directory / "combined-names.json",
            {
                "format": evidence.NAMES_FORMAT,
                "run_id": context["run_id"],
                "nonce": nonce,
                "subjects": evidence.subjects(nonce),
            },
        )
        self.proof: dict[str, object] = {
            "format": evidence.FORMAT,
            "environment": evidence.ENVIRONMENT,
            "context": context,
            "recovery": {
                **dict.fromkeys(evidence.RECOVERY_FIELDS, "d" * 64),
                "protected_segments": 2,
                "retained_releases": 4,
                "tenant_states": dict.fromkeys(
                    ("active", "suspended", "archived", "undeployed"), 1
                ),
            },
            "public_ca": {
                "issuer": evidence.ISSUER,
                "trust": "system-public-roots",
                "subject_count": 4,
                "zone_count": 2,
                "certificates_sha256": "e" * 64,
            },
            "accounting": {
                **dict.fromkeys(evidence.ZERO_ACCOUNTING, 0),
                "source_state": "fenced",
                "source_fence_sha256": "f" * 64,
                "source_pending_inputs_sha256": "a" * 64,
                "destination_quarantine": False,
            },
            "teardown": dict.fromkeys(evidence.ZERO_TEARDOWN, 0),
        }
        write_private(
            directory / "combined-assertions.json",
            {key: self.proof[key] for key in ("recovery", "public_ca", "accounting")},
        )
        for name in ("combined.started.json", "paired-accounting.json", "live-storage.json"):
            write_private(directory / name, {"synthetic_external_observation": name})
        self.recorder = Recorder(directory, context)
        for name in functional.PHASES:
            with self.recorder.phase(name) as observed:
                observed["synthetic_external_observation"] = name
        for name in functional.FILES:
            (directory / name).chmod(0o600)
        # The modeled journey process reports the exact installed test set. The
        # Completion object and immutable save/load checks run unchanged.
        completion = Completion(nodes(environment))
        completion.collected = list(completion.expected)
        completion.reports = {
            node: [(stage, "passed", False) for stage in ("setup", "call", "teardown")]
            for node in completion.expected
        }
        functional.save(directory, completion, 0, environment)
        assert functional.load(directory, environment)[0].passed(0)

    def finish(self, *, recovery: bool = False) -> Path:
        started = stamp(datetime.now(UTC))
        with self.recorder.phase("owned-teardown") as observed:
            observed["teardown"] = self.proof["teardown"]
        self.proof["phases"] = self.recorder.receipts()
        write_private(self.directory / "combined.json", self.proof)
        (self.directory / "verify.passed").write_text("passed\n")
        (self.directory / "final-proof.started-at").write_text(stamp(datetime.now(UTC)))
        (self.directory / "destroy.passed").write_text("passed\n")
        context = read_private(self.directory / "combined-context.json")
        observation = None
        if recovery:
            checkpoint = read_private(self.directory / "functional-completion.json")
            original = read_private(self.directory.parent.parent / "journey-result.json")
            completed = stamp(datetime.now(UTC))
            write_private(
                self.directory / "finalization-recovery.json",
                {
                    "functional_completed_at": checkpoint["completed_at"],
                    "completed_at": completed,
                    "original_outcome": original["outcome"],
                    "original_result_sha256": functional.digest(original),
                    "checkpoint_sha256": functional.digest(checkpoint),
                },
            )
            observation = self.directory / "synthetic-final-observation.json"
            write_private(
                observation,
                {
                    "started_at": started,
                    "cleanup_completed_at": completed,
                    "storage_started_at": completed,
                    "storage_completed_at": completed,
                    "completed_at": completed,
                    "checks": CHECKS,
                    "combined_sha256": functional.digest(self.proof),
                    "context_sha256": functional.digest(context),
                    "checkpoint_sha256": functional.digest(checkpoint),
                    "dns_sha256": "a" * 64,
                },
            )
        report = reports.create_report(
            self.directory,
            repository=Path.cwd(),
            storage_target=str(context["storage_target_sha256"]),
            milestone="3.11",
            recovery_observation=observation,
        )
        path = self.directory / "qualification.json"
        write_private(path, report)
        reports.verify_report(
            path,
            source=str(context["source_revision"]),
            artifact=str(context["artifact_sha256"]),
            repository=Path.cwd(),
            storage_target=str(context["storage_target_sha256"]),
            milestone="3.11",
            managed_binding={
                key: read_private(self.directory / "managed-credentials.json")[key]
                for key in (
                    "managed_run_id",
                    "source_revision",
                    "helper_revision",
                    "artifact_sha256",
                    "qualification_inputs_sha256",
                    "storage_target_sha256",
                )
            },
        )
        return path
