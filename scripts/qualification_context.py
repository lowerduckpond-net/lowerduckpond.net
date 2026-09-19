"""Names shared by one owned local qualification and its child processes."""

from __future__ import annotations

import fcntl
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

RUN_ENV = "LDP_QUALIFICATION_RUN_ID"
HOST_ENV = "LDP_QUALIFICATION_HOST"
ARCHIVE_ENV = "LDP_QUALIFICATION_ARCHIVE"
IMAGE_ENV = "LDP_QUALIFICATION_IMAGE"
PORT_ENV = "LDP_QUALIFICATION_SSH_PORT"
ARTIFACT_ENV = "LDP_QUALIFICATION_ARTIFACT"
RESOURCE_ENV = frozenset({RUN_ENV, HOST_ENV, ARCHIVE_ENV, IMAGE_ENV, PORT_ENV, ARTIFACT_ENV})
LEGACY_HOST = "lowerduckpond-ubuntu-2604"
LEGACY_ARCHIVE = "lowerduckpond-m3-10-minio"
RUN_PATTERN = re.compile(r"[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}")


def resource_names(run_id: str) -> dict[str, str]:
    if RUN_PATTERN.fullmatch(run_id) is None:
        raise ValueError("invalid qualification run identity")
    prefix = f"ldp-m3-{run_id}"
    return {
        RUN_ENV: run_id,
        HOST_ENV: f"{prefix}-host",
        ARCHIVE_ENV: f"{prefix}-archive",
        IMAGE_ENV: f"{prefix}:ubuntu-2604",
        PORT_ENV: "0",
    }


def host_name(environment: Mapping[str, str] | None = None) -> str:
    values = os.environ if environment is None else environment
    run_id = values.get(RUN_ENV)
    if run_id:
        expected = resource_names(run_id)
        if any(values.get(key) != value for key, value in expected.items()):
            raise ValueError("qualification resource names disagree with their owner")
        return expected[HOST_ENV]
    if any(key in values for key in RESOURCE_ENV):
        raise ValueError("qualification resource overrides require an owned run")
    return LEGACY_HOST


def reapply_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Discard Molecule's child exports while preserving the owned state directory."""
    host_name(environment)
    result = {key: value for key, value in environment.items() if not key.startswith("MOLECULE_")}
    if environment.get(RUN_ENV):
        artifact = Path(environment[ARTIFACT_ENV])
        if not artifact.is_absolute() or artifact.name != "static-host-agent.tar":
            raise ValueError("invalid owned artifact location")
        result["MOLECULE_EPHEMERAL_DIRECTORY"] = str(artifact.parent / "molecule")
    return result


@contextmanager
def run_lease(directory: Path, *, create: bool = False) -> Iterator[None]:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    descriptor = os.open(directory / "run.lock", flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError("invalid local run lease")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)
