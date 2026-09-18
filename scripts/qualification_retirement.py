"""Explicitly retire an inactive owned archive fixture after fresh independent proofs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

from scripts.qualification_case import independent_storage_absence, owned_containers
from scripts.qualification_context import (
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    RESOURCE_ENV,
    resource_names,
    run_lease,
)
from scripts.qualification_local import FORMAT as FIXTURE_FORMAT
from scripts.qualification_local import docker_endpoint
from scripts.qualification_probe import bounded_command, document

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "lowerduckpond-local-fixture-retirement-v1"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024


def artifact_digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError("invalid retained artifact")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        current = os.fstat(descriptor)
        if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise ValueError("retained artifact changed during verification")
        return digest
    finally:
        os.close(descriptor)


def environment_for(directory: Path) -> dict[str, str]:
    manifest = document(directory / "fixture.json")
    if manifest.get("format") != FIXTURE_FORMAT or not isinstance(manifest.get("run_id"), str):
        raise ValueError("invalid owned fixture manifest")
    expected = resource_names(str(manifest["run_id"]))
    expected[ARTIFACT_ENV] = str(directory / "fixture/static-host-agent.tar")
    expected["MOLECULE_EPHEMERAL_DIRECTORY"] = str(directory / "fixture/molecule")
    if (
        manifest.get("environment") != expected
        or manifest.get("host") != expected[HOST_ENV]
        or manifest.get("archive") != expected[ARCHIVE_ENV]
    ):
        raise ValueError("owned fixture paths or names changed")
    endpoint = manifest.get("docker_endpoint")
    if not isinstance(endpoint, str):
        raise ValueError("missing original Docker endpoint")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in RESOURCE_ENV
        and not key.startswith(
            ("SPACES_", "CLOUDFLARE_", "M3_8_", "MOLECULE_", "LDP_QUALIFICATION_")
        )
        and key not in {"DOCKER_CONTEXT", "M3_10_INSTALLED_REPORT"}
    }
    environment.update(expected)
    environment["DOCKER_HOST"] = docker_endpoint({"DOCKER_HOST": endpoint})
    environment["M3_10_ARCHIVE_BACKEND"] = "minio"
    return environment


def local_proof(environment: dict[str, str], host_id: str) -> str:
    output = bounded_command(
        ["docker", "exec", "--interactive", host_id, "/usr/bin/python3", "-I", "-B", "-"],
        timeout=40,
        environment=environment,
        stdin=(ROOT / "scripts/qualification_retirement_probe.py").read_bytes(),
    )
    if output is None:
        raise ValueError("local accounting is not proven quiescent")
    proof = json.loads(output)
    if proof == {"state": "empty-before-installation"}:
        return "empty-before-installation"
    if not isinstance(proof, dict) or proof.get("state") != "quiescent-installed":
        raise ValueError("unknown local accounting proof")
    digest = artifact_digest(Path(environment[ARTIFACT_ENV]))
    if proof.get("artifact_sha256") != digest:
        raise ValueError("selected artifact differs from the retained run's artifact")
    return "quiescent-installed"


def uninstalled_storage_absence(environment: dict[str, str], archive_id: str) -> None:
    # Before converge, the owned pinned fixture has no TLS configuration/buckets.
    # These are its fixed disposable root credentials, never production inputs.
    endpoint = "http://molecule-m3-10-root:molecule-m3-10-disposable-root-secret@127.0.0.1:443"
    output = bounded_command(
        [
            "docker",
            "exec",
            "--env",
            f"MC_HOST_m310={endpoint}",
            archive_id,
            "mc",
            "--json",
            "ls",
            "m310/",
        ],
        timeout=15,
        environment=environment,
    )
    if output is None or output.strip():
        raise ValueError("pre-installation storage absence is not proven")


def retire(directory: Path) -> Path:
    directory = directory.resolve(strict=True)
    with run_lease(directory):
        print("Owned fixture retirement: verify ownership", flush=True)
        environment = environment_for(directory)
        bound = document(directory / "case-containers.json")
        if set(bound) != {HOST_ENV, ARCHIVE_ENV} or owned_containers(environment) != bound:
            raise ValueError("retained container identities changed")
        host_id, archive_id = str(bound[HOST_ENV]), str(bound[ARCHIVE_ENV])
        print("Owned fixture retirement: fresh local accounting", flush=True)
        state = local_proof(environment, host_id)
        print("Owned fixture retirement: independent storage absence", flush=True)
        if state == "empty-before-installation":
            try:
                independent_storage_absence(environment, archive_id)
            except ValueError:
                uninstalled_storage_absence(environment, archive_id)
        else:
            independent_storage_absence(environment, archive_id)
        # Recheck both ownership and local obligations after the independent read.
        print("Owned fixture retirement: recheck ownership and local accounting", flush=True)
        if owned_containers(environment) != bound or local_proof(environment, host_id) != state:
            raise ValueError("fixture changed during retirement checks")
        docker = shutil.which("docker")
        if docker is None:
            raise ValueError("Docker is unavailable")
        print("Owned fixture retirement: remove the bound container pair", flush=True)
        for identity in (host_id, archive_id):
            subprocess.run(  # noqa: S603 - only exact IDs bound to this verified owned run
                [docker, "stop", "--time", "30", identity],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=40,
            )
            subprocess.run(  # noqa: S603 - no name lookup, pruning, or unrelated resources
                [docker, "rm", "--volumes", identity],
                env=environment,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
        destination = directory / "retirement.json"
        with destination.open("x", encoding="ascii") as stream:
            json.dump(
                {
                    "format": FORMAT,
                    "authority": "diagnostic-only",
                    "outcome": "retired",
                    "local_accounting": state,
                    "independent_storage_absence": "passed",
                },
                stream,
                sort_keys=True,
            )
            stream.write("\n")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        destination = retire(args.directory)
    except Exception:
        print("Fixture retirement did not complete; private evidence remains in the run directory.")
        return 2
    print(f"Owned fixture retired; private evidence retained at {destination.parent}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
