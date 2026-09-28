"""Reattach existing test helpers to saved IDs; never create a replacement host."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

import testinfra  # type: ignore[import-untyped]

from scripts import qualification_restore as owned
from scripts.m3_11_combined_inputs import environment_for
from scripts.m3_11_debug_files import MARKER, require_original_unchanged
from scripts.m3_11_debug_types import Fixture
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_context import HOST_ENV
from scripts.qualification_probe import document

TESTS = Path(__file__).resolve().parents[1] / "config/ansible/molecule/m3_8/tests"


def inputs(root: Path) -> tuple[dict[str, str], LiveStorage]:
    require_original_unchanged(root)
    saved = cast("dict[str, str]", read_private(root / "fixture.json")["environment"])
    ambient = dict(os.environ)
    ambient.pop("DOCKER_CONTEXT", None)
    environment = environment_for(root, {**ambient, "DOCKER_HOST": saved["DOCKER_HOST"]})
    storage = LiveStorage.load(environment)
    if (environment.get("SPACES_REGION"), environment.get("SPACES_ARCHIVE_BUCKET")) != (
        storage.target.region,
        storage.target.archive_bucket,
    ):
        raise ValueError("diagnostic storage lease differs from the original archive target")
    original = read_private(root / MARKER)
    if original["qualification_authority"] != "none":
        raise ValueError("diagnostic workspace gained qualification authority")
    context = read_private(root / "combined-context.json")
    for kind in ("source", "destination", "acme"):
        receipt = document(root / "restore" / (kind + ".json"))
        actual = owned.inspect(environment, str(receipt["id"]))
        fields = ("id", "name", "owner", "image")
        if any(actual[key] != receipt[key] for key in fields) or not actual["running"]:
            raise ValueError("diagnostic fixture identity changed or stopped")
        if kind in {"source", "destination"}:
            digest = hashlib.sha256(
                json.dumps(
                    {key: actual[key] for key in fields}, sort_keys=True, separators=(",", ":")
                ).encode()
                + b"\n"
            ).hexdigest()
            if digest != context[kind + "_fixture_sha256"]:
                raise ValueError("diagnostic fixture differs from its original context")
    owned.source_fenced(environment)
    return environment, storage


def attach(root: Path) -> Fixture:
    environment, storage = inputs(root)
    os.environ.update(environment)
    sys.path.insert(0, str(TESTS))
    module = importlib.import_module("restore_fixture")
    fixture = cast("Fixture", module.Fixture.__new__(module.Fixture))
    fixture.environment, fixture.live_storage = environment, storage

    def command(*args: str, timeout: int = 60, stdin: bytes = b"") -> bytes:
        result = subprocess.run(  # noqa: S603 - fixture helper commands, private stage log
            args, env=environment, input=stdin, capture_output=True, timeout=timeout, check=False
        )
        if result.returncode:
            sys.stderr.buffer.write(result.stdout + result.stderr)
            raise ValueError(f"diagnostic fixture command failed with status {result.returncode}")
        return result.stdout

    fixture.command = command  # type: ignore[method-assign]  # diagnostic transport retains stderr
    fixture.root = root / "restore"
    fixture.inputs = fixture.root / "inputs"
    fixture.target = read_private(fixture.inputs / "target.json")
    fixture.restore_id = str(fixture.target["restoreId"])
    fixture.binary = str(cast("dict[str, object]", fixture.target["caddy"])["binaryPath"])
    fixture.snapshot = str(fixture.target["snapshotId"])
    fixture.transport = fixture.root / "operator-transport.json"
    fixture.ephemeral = Path(environment["MOLECULE_EPHEMERAL_DIRECTORY"])
    fixture.source_id = str(owned.inspect(environment, environment[HOST_ENV])["id"])
    identities = owned.identities(environment)
    fixture.destination_id, fixture.acme_id = identities["destination"], identities["acme"]
    for kind in ("source", "destination", "acme"):
        setattr(fixture, kind, testinfra.get_host("docker://" + getattr(fixture, kind + "_id")))
    fixture.fence = fixture.source.file(
        f"/var/lib/lowerduckpond/recovery/source-fence-{fixture.restore_id}.json"
    ).content
    if (
        hashlib.sha256(fixture.source.file(owned.GATE).content).hexdigest()
        != document(fixture.root / "source.json")["gateSha256"]
    ):
        raise ValueError("diagnostic source gate changed")
    return fixture


def history(root: Path, fixture: Fixture) -> dict[str, object]:
    path = root / "diagnostic-history.json"
    if path.exists():
        return read_private(path)
    module = importlib.import_module("test_export_import")
    source = Path(__file__).with_name("m3_11_debug_history.py").read_text()
    body = f"exec(compile({source!r}, 'm3_11_debug_history.py', 'exec'))"
    raw = fixture.source.run("python3 -I -B -c %s", module._selected_python(fixture.source, body))
    if raw.rc:
        print(raw.stdout, raw.stderr, file=sys.stderr)
        raise ValueError("original source diagnostic replay inputs are unavailable")
    value = json.loads(raw.stdout)
    descriptor = json.loads(
        fixture.destination.file("/var/lib/lowerduckpond/recovery/backup-descriptor.json").content
    )
    if {row["tenantId"] for row in descriptor["tenants"]} != set(value["tenants"]):
        raise ValueError("diagnostic tenant history differs from original snapshot")
    value["replay"]["descriptor"] = descriptor
    write_private(path, value)
    return cast("dict[str, object]", value)
