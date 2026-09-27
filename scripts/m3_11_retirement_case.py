"""Diagnostic completion for the fixed native case that intentionally retains failure."""

from __future__ import annotations

import hashlib
from pathlib import Path

from scripts import qualification_restore as owned
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import digest, fields
from scripts.m3_11_retirement_files import legacy
from scripts.m3_11_retirement_receipt import receipt
from scripts.qualification_context import ARTIFACT_ENV, RUN_ENV, host_name
from scripts.qualification_groups import GROUP_REPORT_FORMAT
from scripts.qualification_groups import RETAINED_FAILURE_CASE as CASE
from scripts.qualification_groups import RETAINED_FAILURE_DISPOSITION as DISPOSITION


def completion(directory: Path, environment: dict[str, str]) -> int:
    host_name(environment)
    if environment.get("M3_10_ARCHIVE_BACKEND") != "minio" or environment.get(
        "M3_10_INSTALLED_REPORT"
    ):
        raise ValueError("retirement installed receipt requires its local fixed case")
    owned.require_source_idempotence(environment, archived_prefix=True)
    value = fields(
        read_private(directory / "case-retirement.json"),
        {
            "run_id",
            "artifact_sha256",
            "receipt",
            "protected_backup_sha256",
            "source_state_sha256",
            "destination_state_sha256",
        },
    )
    if (
        value["run_id"] != environment[RUN_ENV]
        or value["artifact_sha256"]
        != hashlib.sha256(Path(environment[ARTIFACT_ENV]).read_bytes()).hexdigest()
    ):
        raise ValueError("retirement installed receipt belongs to another fixture")
    for key in ("protected_backup_sha256", "source_state_sha256", "destination_state_sha256"):
        digest(value[key])
    result = receipt(value["receipt"])
    if read_private(directory / "failed-archive-retirement/retired.json") != result:
        raise ValueError("retirement installed transaction changed")
    for kind in ("source", "destination", "acme"):
        saved = legacy(directory / f"restore/{kind}.json")
        current = owned.inspect(environment, str(saved["id"]))
        if current["running"] is not False or any(
            current[key] != saved[key] for key in ("id", "name", "owner", "image")
        ):
            raise ValueError("retained failed fixture restarted or changed")
    write_private(
        directory / "case.json",
        {
            "format": GROUP_REPORT_FORMAT,
            "authority": "diagnostic-only",
            "case": CASE,
            "run_id": environment[RUN_ENV],
            "backend": "minio",
            "status": "passed",
            **DISPOSITION,
        },
    )
    print(f"Installed failure-retention case passed: {directory / 'case.json'}", flush=True)
    return 0
