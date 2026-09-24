"""Build the pinned local storage fixture after upstream retired its images."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "config/ansible/molecule/m3_8/Dockerfile.minio.j2"
LABEL = "net.lowerduckpond.fixture.minio-recipe"


def image_reference() -> str:
    return "ldp-minio-fixture:" + hashlib.sha256(RECIPE.read_bytes()).hexdigest()


def ensure_image(environment: dict[str, str] | None = None) -> str:
    """Reuse only the matching build; no registry fallback or foreign image removal."""
    reference = image_reference()
    digest = reference.split(":", 1)[1]
    environment = dict(os.environ) if environment is None else environment
    docker = shutil.which("docker")
    if docker is None:
        raise FileNotFoundError("docker")
    inspect = [
        docker,
        "image",
        "inspect",
        "--format",
        '{{json (index .Config.Labels "' + LABEL + '")}}',
        reference,
    ]

    def recipe() -> str | None:
        result = subprocess.run(  # noqa: S603 - fixed read-only metadata and derived image name
            inspect, env=environment, capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode:
            return None
        value = json.loads(result.stdout)
        if value != digest:
            raise ValueError("local MinIO fixture image does not match the pinned recipe")
        return digest

    if recipe() is None:
        subprocess.run(  # noqa: S603 - repository recipe with pinned public source revisions
            [
                docker,
                "build",
                "--tag",
                reference,
                "--label",
                f"{LABEL}={digest}",
                "-",
            ],
            input=RECIPE.read_bytes(),
            env=environment,
            stdout=sys.stderr,
            check=True,
            timeout=600,
        )
        if recipe() is None:
            raise ValueError("local MinIO fixture build did not produce its image")
    return reference


if __name__ == "__main__":
    print(ensure_image())
