"""Run one fresh installed archive diagnostic, retaining every unsuccessful fixture."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV, host_name, run_lease
from scripts.qualification_failure import record_phase
from scripts.qualification_probe import bounded_command, document

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "lowerduckpond-full-size-archive-diagnostic-v1"
INSTALLED_FORMAT = "lowerduckpond-full-size-archive-installed-v1"
CONTENT_BYTES = 100 * 1024 * 1024
ENTRY_COUNT = 5000


def owned_containers(environment: dict[str, str]) -> dict[str, str]:
    host_name(environment)  # Reject partial or mixed ownership before querying Docker.
    identities = {}
    for key in (HOST_ENV, ARCHIVE_ENV):
        output = bounded_command(
            [
                "docker",
                "inspect",
                "--format",
                '{"id":{{json .Id}},"owner":'
                '{{json (index .Config.Labels "lowerduckpond.qualification.run")}}}',
                environment[key],
            ],
            environment=environment,
        )
        if output is None:
            raise ValueError("owned fixture is unavailable")
        data = json.loads(output)
        if (
            not isinstance(data.get("id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", data["id"]) is None
            or data.get("owner") != environment[RUN_ENV]
        ):
            raise ValueError("fixture ownership changed")
        identities[key] = data["id"]
    return identities


def independent_storage_absence(environment: dict[str, str], archive_id: str) -> None:
    """Use the fixture's root identity, independently of the installed runtime key."""
    for bucket in ("molecule-tenant-archives", "molecule-platform-backup"):
        for mode in ("--versions", "--incomplete"):
            output = bounded_command(
                [
                    "docker",
                    "exec",
                    archive_id,
                    "mc",
                    "--config-dir",
                    "/root/.mc",
                    "--json",
                    "ls",
                    mode,
                    "--recursive",
                    f"m310/{bucket}",
                ],
                timeout=15,
                environment=environment,
            )
            if output is None or output.strip():
                raise ValueError("independent whole-bucket absence did not pass")


def installed_receipt(directory: Path, environment: dict[str, str]) -> dict[str, object]:
    receipt = document(directory / "case-installed.json")
    if (
        set(receipt)
        != {"format", "run_id", "artifact_sha256", "content_sha256", "entries", "bytes"}
        or receipt.get("format") != INSTALLED_FORMAT
        or receipt.get("run_id") != environment[RUN_ENV]
        or receipt.get("entries") != ENTRY_COUNT
        or receipt.get("bytes") != CONTENT_BYTES
        or any(
            not isinstance(receipt.get(key), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(receipt[key])) is None
            for key in ("artifact_sha256", "content_sha256")
        )
    ):
        raise ValueError("the installed case did not produce this run's complete receipt")
    return receipt


def phase(directory: Path, environment: dict[str, str], uv: str, name: str) -> int:
    print(f"Independent full-size archive: {name}", flush=True)
    with (directory / f"{name}.log").open("xb") as stream:
        result = subprocess.run(  # noqa: S603 - fixed phase command and owned private context
            [
                uv,
                "run",
                "--frozen",
                "molecule",
                "--base-config",
                str(directory / "case-base.yml"),
                name,
                "--scenario-name",
                "m3_8",
            ],
            env=environment,
            cwd=ROOT / "config/ansible",
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


def run_full_size(directory: Path, environment: dict[str, str], uv: str) -> int:
    with run_lease(directory, create=True):
        return _run_full_size(directory, environment, uv)


def _run_full_size(directory: Path, environment: dict[str, str], uv: str) -> int:
    """Only this named case's completed tests and fresh storage proof permit teardown."""
    # Retirement shares these case primitives; defer the import to avoid a cycle.
    from scripts.qualification_retirement import local_proof  # noqa: PLC0415

    environment = {
        **environment,
        "NO_COLOR": "1",
        "PY_COLORS": "0",
        "ANSIBLE_FORCE_COLOR": "0",
        "ANSIBLE_NOCOLOR": "1",
    }
    base = {
        "scenario": {"create_sequence": ["dependency", "create"]},
        "ansible": {
            "playbooks": {
                "verify": str(ROOT / "config/ansible/molecule/m3_8/verify_full_size_archive.yml")
            }
        },
    }
    with (directory / "case-base.yml").open("x", encoding="ascii") as stream:
        # JSON is also valid YAML and avoids introducing a controller dependency.
        json.dump(base, stream)
    identities: dict[str, str] = {}
    for name in ("create", "prepare", "converge", "idempotence", "verify"):
        status = phase(directory, environment, uv, name)
        if status:
            return status
        if name == "create":
            identities = owned_containers(environment)
            with (directory / "case-containers.json").open("x", encoding="ascii") as stream:
                json.dump(identities, stream)
    record_phase("final-accounting")
    receipt = installed_receipt(directory, environment)
    if owned_containers(environment) != identities:
        raise ValueError("fixture identity changed before final storage proof")
    if local_proof(environment, identities[HOST_ENV]) != "quiescent-installed":
        raise ValueError("installed case accounting is incomplete")
    record_phase("final-storage-proof")
    print("Independent full-size archive: final storage proof", flush=True)
    independent_storage_absence(environment, identities[ARCHIVE_ENV])
    record_phase("final-accounting")
    if (
        owned_containers(environment) != identities
        or local_proof(environment, identities[HOST_ENV]) != "quiescent-installed"
    ):
        raise ValueError("fixture changed before teardown")
    status = phase(directory, environment, uv, "destroy")
    if status:
        return status
    with (directory / "case.json").open("x", encoding="ascii") as stream:
        json.dump(
            {
                "format": FORMAT,
                "authority": "diagnostic-only",
                "case": "full-size-archive",
                "installed": receipt,
                "backend": "minio",
                "status": "passed",
                "local_accounting": "passed",
                "independent_storage_absence": "passed",
                "destroy": "passed",
            },
            stream,
            sort_keys=True,
        )
        stream.write("\n")
    print(f"Full-size archive diagnostic passed: {directory / 'case.json'}", flush=True)
    return 0
