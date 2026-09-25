"""Reserve an empty destination identity; start it only after source fencing."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from scripts import qualification_restore as owned
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.qualification_context import HOST_ENV, RUN_ENV

FORMAT = "lowerduckpond-m3-11-stopped-destination-v1"
IDENTITY_FIELDS = {"id", "name", "owner", "image"}


def _identity(
    value: dict[str, object], environment: dict[str, str], name: str
) -> dict[str, object]:
    result = {key: value[key] for key in IDENTITY_FIELDS}
    if (
        result["name"] != "/" + name
        or result["owner"] != environment[RUN_ENV]
        or re.fullmatch(r"[0-9a-f]{64}", str(result["id"])) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(result["image"])) is None
    ):
        raise ValueError("combined destination reservation identity changed")
    return result


def _path(environment: dict[str, str]) -> Path:
    return owned.directory(environment).parent / "destination-reservation.json"


def _binding(storage: LiveStorage) -> dict[str, object]:
    return {
        "format": FORMAT,
        "run_id": storage.target.run_id,
        "artifact_sha256": storage.binding["artifact_sha256"],
        "backup_repository_sha256": hashlib.sha256(storage.target.repository.encode()).hexdigest(),
    }


def reserve(storage: LiveStorage) -> dict[str, object]:
    """The caller holds the run lease; no process or recovery input is installed."""
    environment = dict(storage.environment)
    storage.require_source(environment)
    path = _path(environment)
    if path.exists() or path.is_symlink():
        raise ValueError("combined destination already has its original reservation")
    source = _identity(
        owned.inspect(environment, environment[HOST_ENV]), environment, environment[HOST_ENV]
    )
    current = owned.create_stopped(environment, "destination")
    destination = _identity(current, environment, f"ldp-m3-{environment[RUN_ENV]}-destination")
    if destination["id"] == source["id"] or destination["image"] != source["image"]:
        raise ValueError("combined destination is not a distinct empty source image")
    receipt = {**_binding(storage), "source": source, "destination": destination}
    write_private(path, receipt)
    return receipt


def adopt(storage: LiveStorage) -> str:
    """Recheck the original stopped identity and source fence before any startup."""
    environment = dict(storage.environment)
    storage.require_source(environment)
    receipt = fields(
        read_private(_path(environment)), {*_binding(storage), "source", "destination"}
    )
    if any(receipt[key] != value for key, value in _binding(storage).items()):
        raise ValueError("combined destination reservation belongs to another run")
    source = _identity(
        owned.inspect(environment, environment[HOST_ENV]), environment, environment[HOST_ENV]
    )
    expected = fields(receipt["destination"], IDENTITY_FIELDS)
    current = owned.inspect(environment, str(expected["id"]))
    destination = _identity(current, environment, f"ldp-m3-{environment[RUN_ENV]}-destination")
    if (
        source != receipt["source"]
        or destination != expected
        or destination["image"] != source["image"]
        or destination["id"] == source["id"]
        or current.get("running") is not False
    ):
        raise ValueError("combined destination reservation is no longer its empty stopped fixture")
    owned.source_fenced(environment)
    write_private(owned.directory(environment) / "destination.json", current)
    identity = str(destination["id"])
    owned.command(environment, "docker", "start", identity)
    return identity
