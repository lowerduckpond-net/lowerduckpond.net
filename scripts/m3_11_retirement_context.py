"""Original private attempt bindings for failed archive retirement."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

from lowerduckpond_m3_archive.report import ArchiveQualificationReport

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_combined_inputs import environment_for
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_phase_receipts import FORMAT as PHASE_FORMAT
from scripts.m3_11_private_inputs import read_private, read_private_bytes
from scripts.m3_11_retirement_files import RetirementError, directory, fingerprint, legacy
from scripts.m3_11_retirement_receipt import timestamp

FILES = (
    "fixture.json",
    "source-revision",
    "qualification-inputs.json",
    "storage.json",
    "installed.json",
    "live-storage.json",
    "combined-context.json",
    "combined-names.json",
    "destination-reservation.json",
    "combined.started.json",
    "failure-exit.json",
    "failure.json",
    "restore/source.json",
    "restore/destination.json",
    "restore/acme.json",
    "public-inputs/original.json",
    "combined-phases/backup-mutation-overlap.started.json",
    "combined-phases/backup-mutation-overlap.json",
    "combined-phases/protected-rotation.started.json",
    "combined-phases/protected-rotation.json",
    "combined-phases/reconstruction.started.json",
)


class Context:
    def __init__(self, run: Path, ambient: Mapping[str, str]) -> None:
        self.run = run
        manifest = read_private(run / "fixture.json")
        values = manifest.get("environment")
        if not isinstance(values, dict):
            raise RetirementError("retirement fixture lacks its saved environment")
        endpoint = values.get("DOCKER_HOST")
        if not isinstance(endpoint, str) or (
            ambient.get("DOCKER_HOST") and ambient["DOCKER_HOST"] != endpoint
        ):
            raise RetirementError("retirement Docker endpoint differs from the original attempt")
        self.environment = environment_for(run, {**ambient, "DOCKER_HOST": endpoint})
        # This reads local bindings only. The caller separately verifies the exact
        # original owner through bounded backup/operator clients before stopping.
        self.storage = LiveStorage._retained(self.environment)
        self.context = read_private(run / "combined-context.json")

    def original(self) -> dict[str, object]:  # noqa: PLR0912 - fixed historical prerequisites
        for path in (
            "combined.json",
            "combined-assertions.json",
            "qualification.json",
            "owned-teardown",
            "public-dns",
        ):
            if (self.run / path).exists() or (self.run / path).is_symlink():
                raise RetirementError("retirement cannot adopt successful or public-CA progress")
        root = self.run / "combined-phases"
        directory(root)
        expected = {Path(name).name for name in FILES if name.startswith("combined-phases/")}
        observed = set()
        for entry in root.iterdir():
            observed.add(entry.name)
            if entry.name not in expected or len(observed) > len(expected):
                raise RetirementError("retirement has unexpected reconstruction progress")
        if observed != expected:
            raise RetirementError("retirement requires exactly the interrupted reconstruction")
        hashes = {name: fingerprint(self.run / name, evidence.MAX_BYTES) for name in FILES}
        context = evidence.fields(
            self.context,
            {
                "format",
                "run_id",
                "captured_at",
                *evidence.BINDING_FIELDS,
                *evidence.IDENTITY_FIELDS,
            },
        )
        if (
            read_private(self.run / "combined-context.json") != context
            or context["format"] != evidence.CONTEXT_FORMAT
            or context["run_id"] != self.storage.target.run_id
            or context["backup_repository_sha256"]
            != hashlib.sha256(self.storage.target.repository.encode()).hexdigest()
            or any(context[key] != value for key, value in self.storage.binding.items())
            or read_private_bytes(self.run / "source-revision").decode().strip()
            != context["source_revision"]
        ):
            raise RetirementError("retirement context differs from original inputs")
        evidence.validate_names(self.run / "combined-names.json", context)
        captured = legacy(self.run / "qualification-inputs.json")
        if (
            captured
            != {
                key: context[key]
                for key in (
                    "source_revision",
                    "input_policy",
                    "qualification_inputs_sha256",
                    "storage_target_sha256",
                )
            }
            or hashes["storage.json"]["sha256"] != context["storage_report_sha256"]
        ):
            raise RetirementError("retirement original qualification bindings disagree")
        storage = ArchiveQualificationReport.from_json(
            read_private_bytes(self.run / "storage.json").decode()
        )
        if (
            storage.source_revision != context["source_revision"]
            or storage.run_id != context["storage_run_id"]
        ):
            raise RetirementError("retirement original storage report changed")
        original = legacy(self.run / "failure-exit.json")
        status = original.get("exit_status")
        if (
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 1 <= status <= 255  # noqa: PLR2004 - process exit status
            or original.get("phase") != "verify"
        ):
            raise RetirementError("retirement lacks its original failed verification")
        context_digest = hashlib.sha256(evidence.canonical_bytes(context)).hexdigest()
        if read_private(self.run / "combined.started.json") != {
            "context_sha256": context_digest,
            "installed_sha256": hashes["installed.json"]["sha256"],
        }:
            raise RetirementError("retirement combined attempt differs from its original start")
        timestamp(context["captured_at"])
        for name in FILES:
            if name.startswith("combined-phases/"):
                phase = read_private(self.run / name)
                started = name.endswith(".started.json")
                phase_name = Path(name).name.removesuffix(".json").removesuffix(".started")
                evidence.fields(
                    phase,
                    {"format", "context_sha256", "phase", "started_at"}
                    | (set() if started else {"completed_at", "observations"}),
                )
                if (
                    phase["context_sha256"] != context_digest
                    or phase["format"] != PHASE_FORMAT
                    or phase["phase"] != phase_name
                ):
                    raise RetirementError("retirement phase belongs to a different attempt")
                timestamp(phase["started_at"])
                if not started:
                    timestamp(phase["completed_at"])
                    if not isinstance(phase["observations"], dict) or not phase["observations"]:
                        raise RetirementError(
                            "retirement prior phase lacks its original observations"
                        )
        return {
            "files": hashes,
            "context_sha256": context_digest,
            "original_exit_status": original["exit_status"],
        }
