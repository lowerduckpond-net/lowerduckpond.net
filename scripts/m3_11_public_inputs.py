"""Retain clean public trust/DNS bytes before any controlled-CA fixture setup."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_combined_inputs import environment_for
from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_public_inputs_probe import CHUNK_BYTES, FILES, MAXIMUM_BYTES
from scripts.qualification_context import HOST_ENV, RUN_ENV

FORMAT = "lowerduckpond-m3-11-original-public-inputs-v1"


def _probe(environment: dict[str, str], identity: str, *arguments: str) -> object:
    return json.loads(
        owned.command(
            environment,
            "docker",
            "exec",
            "--interactive",
            identity,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-",
            *arguments,
            stdin=Path(__file__).with_name("m3_11_public_inputs_probe.py").read_bytes(),
        )
    )


def _fingerprints(environment: dict[str, str], identity: str) -> dict[str, object]:
    return evidence.fields(_probe(environment, identity), set(FILES))


def _copy(environment: dict[str, str], identity: str, local: Path, fingerprint: object) -> None:
    expected = evidence.fields(fingerprint, {"sha256", "identity"})
    metadata = expected["identity"]
    if not isinstance(metadata, list) or len(metadata) != 5:  # noqa: PLR2004 - stat identity fields
        raise ValueError("public dependency file identity is malformed")
    size = metadata[2]
    evidence.count(size, minimum=1, maximum=MAXIMUM_BYTES)
    assert isinstance(size, int)  # noqa: S101 - count rejects every non-int
    descriptor = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        for offset in range(0, size, CHUNK_BYTES):
            value = evidence.fields(
                _probe(environment, identity, local.name, str(offset)), {"fingerprint", "content"}
            )
            encoded = value["content"]
            if value["fingerprint"] != expected or not isinstance(encoded, str):
                raise ValueError("public dependency changed during its bounded copy")
            raw = base64.b64decode(encoded, validate=True)
            if len(raw) != min(CHUNK_BYTES, size - offset):
                raise ValueError("public dependency copy is incomplete")
            stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if (
        hashlib.sha256(read_private_bytes(local, maximum=MAXIMUM_BYTES)).hexdigest()
        != expected["sha256"]
    ):
        raise ValueError("public dependency copy differs from its original source")


def _identity(value: dict[str, object]) -> dict[str, object]:
    return {key: value[key] for key in ("id", "name", "owner", "image")}


def capture(directory: Path, ambient: dict[str, str]) -> None:
    """Called immediately after source creation and before Molecule prepare."""
    environment = environment_for(directory, ambient)
    source = owned.inspect(environment, environment[HOST_ENV])
    if source.get("running") is not True or source.get("name") != "/" + environment[HOST_ENV]:
        raise ValueError("public inputs require the original running source fixture")
    destination = directory / "public-inputs"
    destination.mkdir(mode=0o700)  # Failure/partial capture is never replaced.
    started = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    identity = str(source["id"])
    before = _fingerprints(environment, identity)
    for name in FILES:
        # Read through the running fixture. Docker's archive API itself changes
        # ctime on bind-mounted hosts/resolv.conf; using it would defeat the
        # strict before/after identity comparison. Each chunk stays below the
        # existing command-output bound and rechecks the entire original file.
        _copy(environment, identity, destination / name, before[name])
    if before != _fingerprints(environment, identity) or source != owned.inspect(
        environment, identity
    ):
        raise ValueError("public dependency source changed during capture")
    write_private(
        destination / "original.json",
        {
            "format": FORMAT,
            "run_id": environment[RUN_ENV],
            "source": _identity(source),
            "started_at": started,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "files": before,
        },
    )


def require_original(directory: Path, context: dict[str, object]) -> dict[str, Path]:
    """Bind later TLS verification to the original fresh-image trust, never the restored bundle."""
    destination = directory / "public-inputs"
    original = evidence.fields(
        read_private(destination / "original.json"),
        {"format", "run_id", "source", "started_at", "completed_at", "files"},
    )
    if (
        original["format"] != FORMAT
        or original["run_id"] != evidence.uuid7(context["run_id"]).hex
        or hashlib.sha256(evidence.canonical_bytes(original["source"])).hexdigest()
        != context["source_fixture_sha256"]
    ):
        raise ValueError("public dependency inputs belong to another source fixture")
    now = datetime.now(UTC)
    times = tuple(
        evidence.timestamp(value, now=now, maximum_age=timedelta(hours=24))
        for value in (original["started_at"], original["completed_at"], context["captured_at"])
    )
    if not times[0] <= times[1] <= times[2]:
        raise ValueError("public dependency inputs were not captured before the combined context")
    fingerprints = evidence.fields(original["files"], set(FILES))
    for name in FILES:
        expected = evidence.fields(fingerprints[name], {"sha256", "identity"})
        if (
            hashlib.sha256(
                read_private_bytes(destination / name, maximum=MAXIMUM_BYTES)
            ).hexdigest()
            != expected["sha256"]
        ):
            raise ValueError("original public dependency bytes changed")
    return {name: destination / name for name in FILES}
