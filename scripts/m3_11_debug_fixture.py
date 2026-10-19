"""Reattach existing test helpers to saved IDs; never create a replacement host."""

from __future__ import annotations

import atexit
import hashlib
import importlib
import json
import os
import subprocess
import sys
from contextlib import ExitStack
from datetime import UTC, datetime
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
from scripts.qualification_disposition import require_available
from scripts.qualification_mutation import ownership
from scripts.qualification_probe import document

_LEASE_SESSION = ExitStack()
atexit.register(_LEASE_SESSION.close)


def lease_use(root: Path) -> None:
    """An attached diagnostic holds the same exclusive owner until process exit."""
    from scripts.m3_11_unattended.model import digest, identity, instant  # noqa: PLC0415
    from scripts.m3_11_unattended.state import LeaseState, RunState  # noqa: PLC0415

    marker = read_private(root / MARKER)
    require_available(root)
    original = Path(str(marker["original_run"]))
    attempt = original.parent.parent
    request_path = attempt / "request.json"
    if not request_path.exists():
        if attempt.parent.name == "runs" and (attempt / "attempt.json").exists():
            raise ValueError("managed fixture request is unavailable")
        return  # Older manually supplied fixtures retain their existing gates.
    request = read_private(request_path)
    if request.get("format") != "lowerduckpond-m3-11-unattended-request-v2":
        raise ValueError("obsolete managed fixture cannot reacquire runtime access")
    lease = LeaseState(attempt.parent.parent / "leases" / identity(request["lease_id"]))
    with ExitStack() as pending:
        pending.enter_context(RunState(attempt).lock())
        pending.enter_context(lease.use_lock())
        require_available(root)
        run_id = identity(attempt.name)
        manifest = lease.manifest()
        use = read_private(lease.directory / ("use-" + run_id + ".json"))
        if (
            use["attempt_id"] != run_id
            or use["binding_sha256"] != digest(request["binding"])
            or (lease.directory / ("released-" + run_id + ".json")).exists()
            or any(lease.directory.glob("close-*.json"))
            or datetime.now(UTC) >= manifest.policy.deadline(instant(manifest.created_at))
            or RunState(attempt).status()["qualification"] not in {"failed", "interrupted"}
        ):
            raise ValueError("diagnostic fixture does not hold exclusive lease use")
        lease.retain(
            "diagnostic-" + run_id + ".json",
            {
                "use_sha256": digest(use),
                "workspace_sha256": digest(str(root)),
            },
        )
        _LEASE_SESSION.enter_context(pending.pop_all())


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
    lease_use(root)
    environment, storage = inputs(root)
    os.environ.update(environment)
    sys.path.insert(0, str(TESTS))
    module = importlib.import_module("restore_fixture")
    fixture = cast("Fixture", module.Fixture.__new__(module.Fixture))
    fixture.environment, fixture.live_storage = environment, storage

    def command(*args: str, timeout: int = 60, stdin: bytes = b"") -> bytes:
        require_available(root)
        with ownership(root):
            result = subprocess.run(  # noqa: S603 - fixture helper commands, private stage log
                args,
                env=environment,
                input=stdin,
                capture_output=True,
                timeout=timeout,
                check=False,
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
