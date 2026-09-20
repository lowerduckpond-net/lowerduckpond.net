"""Shared phase, ownership and storage proofs for owned installed cases."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, IMAGE_ENV, RUN_ENV, host_name
from scripts.qualification_probe import bounded_command, document

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "lowerduckpond-full-size-archive-diagnostic-v1"
INSTALLED_FORMAT = "lowerduckpond-full-size-archive-installed-v1"
CONTENT_BYTES = 100 * 1024 * 1024
ENTRY_COUNT = 5000


def private_document(directory: Path, name: str, value: object) -> None:
    """Durably replace one controller-owned receipt while its run lease is held."""
    descriptor, temporary = tempfile.mkstemp(prefix=".fixture-", dir=directory)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(directory / name)
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def owned_containers(environment: dict[str, str], *, allow_missing: bool = False) -> dict[str, str]:
    host_name(environment)  # Reject partial or mixed ownership before querying Docker.
    identities = {}
    for key in (HOST_ENV, ARCHIVE_ENV):
        found: str | None = None
        if allow_missing:
            inventory = bounded_command(
                [
                    "docker",
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    f"name=^/{environment[key]}$",
                    "--format",
                    "{{.ID}}",
                ],
                environment=environment,
            )
            if inventory is None:
                raise ValueError("owned fixture inventory is unavailable")
            found = inventory.decode("ascii").strip()
            if not found:
                continue
            if re.fullmatch(r"[0-9a-f]{64}", found) is None:
                raise ValueError("owned fixture inventory is invalid")
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
            or (found is not None and data["id"] != found)
        ):
            raise ValueError("fixture ownership changed")
        identities[key] = data["id"]
    return identities


def record_created_containers(
    directory: Path, environment: dict[str, str], status: int
) -> dict[str, str]:
    private_document(directory, "case-create.json", {"exit_status": status})
    identities = owned_containers(environment, allow_missing=True)
    private_document(directory, "case-containers.json", identities)
    if status == 0 and set(identities) != {HOST_ENV, ARCHIVE_ENV}:
        raise ValueError("successful creation did not produce both owned containers")
    return identities


def remove_owned_image(environment: dict[str, str]) -> None:
    """Untag only this run's Molecule build after its containers are absent."""
    host_name(environment)
    if not environment.get(RUN_ENV):
        raise ValueError("image cleanup requires an owned qualification")
    if owned_containers(environment, allow_missing=True):
        raise ValueError("owned containers remain before image cleanup")
    reference = f"molecule_local/{environment[IMAGE_ENV]}"

    def present() -> bool:
        output = bounded_command(
            [
                "docker",
                "image",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"reference={reference}",
                "--format",
                "{{.ID}}",
            ],
            environment=environment,
        )
        if output is None:
            raise ValueError("owned build image inventory is unavailable")
        identity = output.decode("ascii").strip()
        if identity and re.fullmatch(r"sha256:[0-9a-f]{64}", identity) is None:
            raise ValueError("owned build image inventory is invalid")
        return bool(identity)

    if not present():
        return
    # A tag, never an image ID, --force, or a daemon-wide prune. Shared layers
    # and other runs' tags remain protected by Docker's normal reference checks.
    bounded_command(["docker", "image", "rm", reference], timeout=40, environment=environment)
    if present():
        raise ValueError("owned build image cleanup did not complete")


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
    return validate_installed_receipt(
        document(directory / "case-installed.json"), environment[RUN_ENV]
    )


def validate_installed_receipt(receipt: dict[str, object], run_id: str) -> dict[str, object]:
    if (
        set(receipt)
        != {"format", "run_id", "artifact_sha256", "content_sha256", "entries", "bytes"}
        or receipt.get("format") != INSTALLED_FORMAT
        or receipt.get("run_id") != run_id
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
    print(f"Owned installed fixture: {name}", flush=True)
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
