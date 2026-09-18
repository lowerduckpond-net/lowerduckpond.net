"""Allocate owned resources for the existing local MinIO qualification sequence."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.qualification_context import (  # noqa: E402 - standalone controller entry point
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    RESOURCE_ENV,
    RUN_ENV,
    resource_names,
)
from scripts.qualification_probe import bounded_command  # noqa: E402

FORMAT = "lowerduckpond-local-qualification-fixture-v1"


def docker_endpoint(environment: dict[str, str]) -> str:
    context = environment.get("DOCKER_CONTEXT")
    if context or not environment.get("DOCKER_HOST"):
        arguments = ["docker", "context", "inspect"]
        if context:
            arguments.append(context)
        arguments.extend(("--format", "{{.Endpoints.docker.Host}}"))
        output = bounded_command(arguments)
        if output is None:
            raise ValueError("Docker context is unavailable")
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


def run(directory: Path, *, create_only: bool = False) -> int:
    environment = create_environment(directory)
    docker = shutil.which("docker")
    uv = shutil.which("uv")
    if docker is None or uv is None:
        raise ValueError("local qualification tools are unavailable")
    subprocess.run(  # noqa: S603 - checked Docker endpoint; fixed read-only check
        [docker, "info"],
        env=environment,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    for key in (HOST_ENV, ARCHIVE_ENV):
        existing = subprocess.run(  # noqa: S603 - generated owned name, fixed metadata query
            [docker, "inspect", environment[key]],
            env=environment,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        if existing.returncode == 0:
            raise ValueError("generated qualification name already exists")
    print(f"Owned local fixture: {environment[HOST_ENV]}", flush=True)
    command = [
        uv,
        "run",
        "--frozen",
        "molecule",
        "create" if create_only else "test",
        "--scenario-name",
        "m3_8",
    ]
    return subprocess.call(  # noqa: S603 - same fixed qualification, with owned resources
        command,
        env=environment,
        cwd=ROOT / "config/ansible",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--create-only", action="store_true")
    args = parser.parse_args()
    try:
        events = os.environ.get("LDP_QUALIFICATION_TIMING_EVENTS")
        if not events:
            raise ValueError("use the qualification timing entry point")
        os.umask(0o077)
        return run(Path(events).parent, create_only=args.create_only)
    except Exception:
        print(
            "Owned local qualification could not start; private run context retained.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
