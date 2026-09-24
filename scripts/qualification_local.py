"""Allocate owned resources for the existing local MinIO qualification sequence."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.qualification_case import remove_owned_image  # noqa: E402
from scripts.qualification_context import (  # noqa: E402 - standalone controller entry point
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    RESOURCE_ENV,
    RUN_ENV,
    resource_names,
    run_lease,
)
from scripts.qualification_failure import (  # noqa: E402
    record_controller_failure,
    record_controller_stage,
    record_phase,
)
from scripts.qualification_groups import GROUPS  # noqa: E402
from scripts.qualification_minio import ensure_image  # noqa: E402
from scripts.qualification_probe import bounded_command  # noqa: E402

FORMAT = "lowerduckpond-local-qualification-fixture-v1"


def docker_endpoint(environment: dict[str, str]) -> str:
    context = environment.get("DOCKER_CONTEXT")
    if context or not environment.get("DOCKER_HOST"):
        arguments = ["docker", "context", "inspect"]
        if context:
            arguments.append(context)
        arguments.extend(("--format", "{{.Endpoints.docker.Host}}"))
        output = bounded_command(arguments, check=True)
        assert output is not None  # noqa: S101 - checked mode returns bytes or raises
        endpoint = output.decode("ascii").strip()
    else:
        endpoint = environment["DOCKER_HOST"]
    if not endpoint.startswith(("unix:///", "tcp://", "ssh://", "https://")):
        raise ValueError("unsupported Docker endpoint")
    return endpoint


def create_environment(directory: Path) -> dict[str, str]:
    """Create one exclusive run; no resource names can be inherited from another."""
    if os.environ.get("M3_10_ARCHIVE_BACKEND", "minio") != "minio":
        raise ValueError("use the secure-workstation workflow for live Spaces")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in RESOURCE_ENV
        and not key.startswith(("SPACES_", "CLOUDFLARE_", "M3_8_"))
        and key not in {"MOLECULE_EPHEMERAL_DIRECTORY", "M3_10_INSTALLED_REPORT"}
    }
    endpoint = docker_endpoint(environment)
    environment.pop("DOCKER_CONTEXT", None)
    environment["DOCKER_HOST"] = endpoint
    directory = directory.resolve(strict=True)
    owned = directory / "fixture"
    owned.mkdir(mode=0o700)  # An existing run is never reused or cleaned implicitly.
    names = resource_names(uuid.uuid7().hex)
    environment.update(names)
    environment.update(
        {
            ARTIFACT_ENV: str(owned / "static-host-agent.tar"),
            "MOLECULE_EPHEMERAL_DIRECTORY": str(owned / "molecule"),
            "M3_10_ARCHIVE_BACKEND": "minio",
            "M3_8_STATIC_PUBLICATION_ENABLED": "false",
            "M3_11_BACKUP_RECOVERY_ENABLED": "false",
            "M3_11_AUDIT_ROTATION_ENABLED": "false",
        }
    )
    manifest = {
        "format": FORMAT,
        "run_id": names[RUN_ENV],
        "host": names[HOST_ENV],
        "archive": names[ARCHIVE_ENV],
        "docker_endpoint": endpoint,
        "environment": {
            key: environment[key] for key in (*names, ARTIFACT_ENV, "MOLECULE_EPHEMERAL_DIRECTORY")
        },
    }
    descriptor = os.open(directory / "fixture.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        json.dump(manifest, stream, sort_keys=True)
        stream.write("\n")
    return environment


def run(directory: Path, *, create_only: bool = False, case: str = "complete") -> int:
    if case not in {"complete", "baseline", *GROUPS} or (create_only and case != "complete"):
        raise ValueError("unsupported qualification case")
    record_phase("dependencies")
    try:
        record_controller_stage("docker-endpoint")
        environment = create_environment(directory)
        record_controller_stage("dependencies")
        docker = shutil.which("docker")
        uv = shutil.which("uv")
        if docker is None:
            raise FileNotFoundError("docker")
        if uv is None:
            raise FileNotFoundError("uv")
        record_controller_stage("docker-daemon")
        # Query the daemon without running unrelated client plugins via docker info.
        subprocess.run(  # noqa: S603 - checked Docker endpoint; fixed read-only check
            [docker, "version", "--format", "{{.Server.Version}}"],
            env=environment,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        record_controller_stage("resource-collision")
        for key in (HOST_ENV, ARCHIVE_ENV):
            existing = subprocess.run(  # noqa: S603 - generated name, fixed metadata query
                [docker, "inspect", environment[key]],
                env=environment,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if existing.returncode == 0:
                raise ValueError("generated qualification name already exists")
        if case != "baseline":
            record_controller_stage("fixture-image")
            ensure_image(environment)
    except Exception as error:
        record_controller_failure(error)
        raise
    print(f"Owned local fixture: {environment[HOST_ENV]}", flush=True)
    if case in GROUPS:
        from scripts.qualification_group_case import run_group  # noqa: PLC0415

        return run_group(directory, environment, uv, case)
    command = [
        uv,
        "run",
        "--frozen",
        "molecule",
        "create" if create_only else "test",
        "--scenario-name",
        "default" if case == "baseline" else "m3_8",
    ]
    with run_lease(directory, create=True):
        status = subprocess.call(  # noqa: S603 - same fixed qualification, with owned resources
            command,
            env=environment,
            cwd=ROOT / "config/ansible",
        )
        if not create_only:
            try:
                remove_owned_image(environment)
            except Exception:
                if status == 0:
                    raise
                # Failed Molecule tests may retain their containers. Never mask
                # the original failure or remove a retained fixture's image.
                print("Owned build image retained after unsuccessful qualification.", flush=True)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-only", action="store_true")
    parser.add_argument("--case", choices=("complete", "baseline", *GROUPS), default="complete")
    args = parser.parse_args()
    try:
        events = os.environ.get("LDP_QUALIFICATION_TIMING_EVENTS")
        os.umask(0o077)
        if events:
            directory = Path(events).parent
        else:
            root = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
            root = root / "lowerduckpond.net/m3-10"
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory = Path(tempfile.mkdtemp(prefix="local-", dir=root))
        print(f"Private local qualification run: {directory}", flush=True)
        return run(directory, create_only=args.create_only, case=args.case)
    except Exception:
        print(
            "Owned local qualification did not complete; private run context retained.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
