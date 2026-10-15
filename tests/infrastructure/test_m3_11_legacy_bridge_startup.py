"""Actual host CLI and Node action against the unchanged pinned helper checkout.

Only subprocess HTTP, Docker and artifact transports are controlled. Selection,
authentication, configuration parsing, dispatch, encrypted checkpoint recovery,
ledger construction and compatible records() all execute their pinned code.
These synthetic regressions make no live authentication or CREATE assertion.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import legacy_import_reader as bridge
from scripts.m3_11_unattended.journal import TAG, event, record_title
from scripts.m3_11_unattended.model import digest, stamp

from .test_m3_11_legacy_import_reader import native
from .test_m3_11_unattended_lifecycle import TARGETS

Row = dict[str, Any]
ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "lowerduckpond-net/lowerduckpond.net"
WORKFLOW = "m3-11-credential-cleanup.yml"
VAULTS = {"provision": "v" * 26, "cleanup": "c" * 26, "production": "p" * 26, "journal": "j" * 26}


def command(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:  # noqa: ANN401 - subprocess keyword forwarding
    return subprocess.run(arguments, capture_output=True, check=True, timeout=30, **kwargs)  # noqa: S603 - fixed local fixture commands


@pytest.fixture(scope="module")
def pinned(tmp_path_factory: pytest.TempPathFactory) -> Path:
    # A disposable test fixture, not a development worktree. Real git validation
    # in connect_action.main must see the clean full pinned candidate history.
    root = tmp_path_factory.mktemp("legacy-bridge") / "helper"
    command(["git", "clone", "--shared", "--no-checkout", str(ROOT), str(root)])
    command(["git", "-C", str(root), "checkout", "--detach", bridge.LEGACY_REVISION])
    (root / ".venv").mkdir()
    (root / ".venv/bin").symlink_to(Path(sys.executable).parent, target_is_directory=True)
    (root / ".venv/lib").symlink_to(
        Path(sys.executable).parent.parent / "lib", target_is_directory=True
    )
    shutil.copyfile(Path(sys.executable).parent.parent / "pyvenv.cfg", root / ".venv/pyvenv.cfg")
    for name, expected in (
        ("connect_auth", bridge.INSPECTOR_SHA256),
        ("connect_ledger", bridge.LEDGER_SHA256),
    ):
        assert (
            hashlib.sha256((root / f"scripts/m3_11_unattended/{name}.py").read_bytes()).hexdigest()
            == expected
        )
    return root


def token(payload: Row) -> str:
    def part(value: Row) -> str:
        return base64.urlsafe_b64encode(canonical_bytes(value)).decode().rstrip("=")

    return ".".join(
        (
            part({"alg": "ES256", "typ": "JWT"}),
            part(payload),
            base64.urlsafe_b64encode(b"x" * 64).decode().rstrip("="),
        )
    )


def inputs(actor: str, *, fault: str, expiry_delta: float = 1) -> Row:  # noqa: PLR0912, PLR0915 - complete synthetic legacy contract
    now = datetime.now(UTC).replace(microsecond=0)
    expiry = now + timedelta(days=1)
    issued = now - timedelta(days=6)
    server = ("S" if actor == "watchdog" else "I") * 26
    payload: Row = {
        "jti": "T" * 26,
        "sub": server,
        "iss": "synthetic-issuer",
        "aud": ["synthetic-audience"],
        "iat": int(issued.timestamp()),
        "exp": int(expiry.timestamp()),
        "1password.com/auuid": "A" * 26,
        "1password.com/fts": ["vaultaccess"],
        "1password.com/vts": [
            {"u": VAULTS["cleanup"], "a": 48},
            {"u": VAULTS["journal"], "a": 496},
        ],
    }
    native_token: Row = {
        "id": "T" * 26,
        "integration_id": server,
        "state": "ACTIVE",
        "name": "synthetic-cleanup",
        "issuer": "synthetic-issuer",
        "audience": "synthetic-audience",
        "features": ["vaultaccess"],
        "created_at": stamp(issued),
        "expires_at": stamp(expiry + timedelta(seconds=expiry_delta)),
        "vaults": [
            {"id": VAULTS["cleanup"], "acl": ["allow_viewing"]},
            {"id": VAULTS["journal"], "acl": ["allow_viewing", "allow_editing"]},
        ],
    }
    if fault == "expired":
        expiry = now - timedelta(seconds=1)
        payload["exp"] = int(expiry.timestamp())
        native_token["expires_at"] = stamp(expiry + timedelta(seconds=expiry_delta))
    elif fault == "extra-audience":
        payload["aud"] = ["synthetic-audience", "other"]
    elif fault == "duplicate-audience":
        payload["aud"] = ["synthetic-audience", "synthetic-audience"]
    elif fault == "wrong-audience":
        payload["aud"] = ["other"]
    elif fault == "scalar-audience":
        payload["aud"] = "synthetic-audience"
    elif fault == "identity":
        native_token["integration_id"] = "X" * 26
    elif fault == "grant":
        payload["1password.com/vts"][1]["a"] = 1008
    elif fault == "extra-grant":
        payload["1password.com/vts"].append({"u": "x" * 26, "a": 48})
    elif fault == "lifetime":
        payload["iat"] = int((now - timedelta(days=8)).timestamp())
        native_token["created_at"] = stamp(now - timedelta(days=8))
    entry: Row = {
        "token": token(payload),
        "server": server,
        "name": "synthetic-cleanup",
        "expires_at": stamp(expiry),
    }
    if fault == "declared-expiry":
        entry["expires_at"] = native_token["expires_at"]
    reader = {
        "role": "cleanup",
        "url": "https://connect.example.test",
        "vaults": VAULTS,
        "entry": entry,
        "metadata": {"server": {"id": server, "state": "ACTIVE"}, "tokens": [native_token]},
    }
    epoch = str(uuid.uuid7())
    probe_format = "lowerduckpond-m3-11-connect-provenance-v1"
    anchor = event("run", epoch, {"synthetic": True})
    shared = event("run", epoch, {"format": probe_format, "epoch": epoch, "actor": "shared"})
    forged = event(
        "run",
        epoch,
        {
            "format": probe_format,
            "epoch": epoch,
            "actor": "shared-forgery",
            "claimed_author": "R" * 26,
        },
    )
    independent = event(
        "run", epoch, {"format": probe_format, "epoch": epoch, "actor": "independent"}
    )
    records = [anchor, shared, forged, independent]
    initial = {row["event_id"]: digest(row) for row in records}
    checkpoint = {
        "format": "lowerduckpond-m3-11-connect-checkpoint-v1",
        "epoch": epoch,
        "sequence": 1,
        "previous": None,
        "records": records,
    }
    pointer = {"identity": 1, "sha256": digest(checkpoint)}
    targets = dataclasses.asdict(TARGETS)
    request = {
        "format": "lowerduckpond-m3-11-connect-genesis-request-v1",
        "epoch": epoch,
        "helper_revision": bridge.LEGACY_REVISION,
        "registry_revision": "b" * 40,
        "vaults": VAULTS,
        "anchor": "a" * 26,
        "anchor_sha256": digest(anchor),
        "initial": {row["event_id"]: digest(row) for row in records[:-1]},
        "shared_server": "S" * 26,
        "shared_author": "A" * 26,
        "shared_probe": shared,
        "shared_forgery_probe": forged,
        "independent_probe": independent,
        "targets_sha256": digest(targets),
    }
    genesis: Row = {
        "format": "lowerduckpond-m3-11-connect-genesis-receipt-v1",
        "request_sha256": digest(request),
        "epoch": epoch,
        "helper_revision": bridge.LEGACY_REVISION,
        "registry_revision": "b" * 40,
        "initial": initial,
        "genesis": pointer,
        "independent_server": "I" * 26,
        "independent_author": "R" * 26,
        "shared_author": "A" * 26,
        "authority_sha256": "d" * 64,
        "authority_expires_at": stamp(expiry),
        "observed_at": stamp(now),
        "forged_author_ignored": True,
        "shared_forged_author_ignored": True,
        "provider_children_created": False,
    }
    references = {
        key: f"op://{VAULTS['cleanup']}/{'z' * 26}/{key}"
        for key in (
            "digitalocean",
            "digitalocean_metadata",
            "cloudflare_account",
            "cloudflare_user",
        )
    }
    configuration = {
        "format": "lowerduckpond-m3-11-cleanup-config-v1",
        "targets": targets,
        "journal_vault": VAULTS["journal"],
        "cleanup": {
            "format": "lowerduckpond-m3-11-connect-role-v1",
            "values": references,
            "reader": reader,
            "witness": {
                "epoch": epoch,
                "helper": bridge.LEGACY_REVISION,
                "active_helper": bridge.LEGACY_REVISION,
                "server": "I" * 26,
                "author": "R" * 26,
                "genesis_id": "1",
                "genesis_sha256": digest(checkpoint),
            },
            "initial": initial,
            "anchor": "a" * 26,
            "anchor_sha256": digest(anchor),
            "independent_expires_at": stamp(expiry),
        },
    }
    # A separate retained encryption token proves checkpoint continuity survives
    # the active client's audience/expiry adaptation. It is never used for HTTP.
    previous_token = token(
        {**payload, "jti": "K" * 26, "exp": int((now - timedelta(days=1)).timestamp())}
    )
    bootstrap = {
        "format": "lowerduckpond-m3-11-connect-bootstrap-v1",
        "targets": targets,
        "journal_vault": VAULTS["journal"],
        "cleanup": {**references, "service_account_expires_at": stamp(expiry)},
        "token": entry,
        "server_credentials": {"synthetic": True},
        "provider_metadata": reader["metadata"],
        "checkpoint_token": previous_token,
    }
    if fault == "checkpoint-key":
        bootstrap["checkpoint_token"] = token({**payload, "sub": "X" * 26})
    elif fault == "checkpoint-current-key":
        bootstrap["checkpoint_token"] = entry["token"]
    if fault == "checkpoint-digest":
        genesis["genesis"]["sha256"] = "0" * 64
    selection = {
        "format": "lowerduckpond-m3-11-connect-independent-v1",
        "stage": "active",
        "active_helper": bridge.LEGACY_REVISION,
        "request": request,
        "receipt": genesis,
    }
    if fault == "dispatch":
        selection["stage"] = "genesis"
    mapping = {"format": "lowerduckpond-m3-11-legacy-import-v2", "synthetic": True}
    items = {
        letter * 26: native(letter * 26, record_title(row), TAG, row)
        for letter, row in zip("abcd", records, strict=True)
    }
    items["i" * 26] = native(
        "i" * 26, "m3-11-import-" + digest(mapping), bridge.IMPORT_TAG, mapping
    )
    return {
        "fault": fault,
        "token": entry["token"],
        "configuration": configuration,
        "bootstrap": bootstrap,
        "selection": selection,
        "items": items,
        "migration": digest(mapping),
        "signed_expiry": stamp(expiry),
        "artifact_responses": artifacts(checkpoint, previous_token, fault=fault),
    }


def artifacts(checkpoint: Row, key: str, *, fault: str) -> dict[str, str]:
    context = ("lowerduckpond-m3-11-journal-cache-v1:connect:" + checkpoint["epoch"]).encode()
    nonce = b"n" * 12
    encrypted = AESGCM(hashlib.sha256(context + b"\0" + key.encode()).digest()).encrypt(
        nonce, canonical_bytes(checkpoint), context
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "checkpoint.json",
            json.dumps({"ciphertext": base64.b64encode(nonce + encrypted).decode()}),
        )
    raw = output.getvalue()
    prefix = "repos/" + REPOSITORY
    responses = {
        prefix + "/commits/" + "b" * 40 + "/statuses?per_page=100&page=1": [
            {
                "id": 1,
                "context": "m3-11/connect-checkpoint/" + checkpoint["epoch"],
                "state": "success",
                "creator": {"id": 41898282, "type": "Bot"},
                "description": "sha256:" + digest(checkpoint),
                "target_url": f"https://github.com/{REPOSITORY}/actions/runs/10/artifacts/1",
            }
        ],
        prefix + "/actions/artifacts/1": {
            "id": 1,
            "name": "m311-connect-"
            + uuid.UUID(checkpoint["epoch"]).hex
            + "-"
            + digest(checkpoint)
            + "-"
            + "f" * 32,
            "expired": False,
            "workflow_run": {"id": 10, "head_branch": "main"},
            "size_in_bytes": len(raw),
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        },
        prefix + "/actions/runs/10": {
            "id": 10,
            "workflow_id": 374497951,
            "path": ".github/workflows/" + WORKFLOW,
            "head_branch": "main",
            "event": "schedule",
            "repository": {"full_name": REPOSITORY},
            "head_repository": {"full_name": REPOSITORY},
        },
    }
    if fault == "checkpoint-ciphertext":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    return {
        **{
            path: base64.b64encode(json.dumps(value).encode()).decode()
            for path, value in responses.items()
        },
        prefix + "/actions/artifacts/1/zip": base64.b64encode(raw).decode(),
    }


def execute(
    root: Path, directory: Path, actor: str, fixture: Row, *, watch: bool = False
) -> tuple[Path, list[Row]]:
    directory.chmod(0o700)
    config = directory / "configuration.json"
    config.write_bytes(canonical_bytes(fixture["configuration"]))
    config.chmod(0o600)
    fixture_path = directory / "fixture.json"
    fixture_path.write_text(json.dumps(fixture))
    hook = directory / "hooks"
    hook.mkdir()
    shutil.copyfile(
        Path(__file__).parent / "fixtures/m3_11_legacy_bridge_transport.py.txt",
        hook / "sitecustomize.py",
    )
    # Only these test executables resolve, even when Docker/gh are not installed.
    for name in ("docker", "gh"):
        executable = hook / name
        executable.write_text("#!/bin/sh\nexit 99\n")
        executable.chmod(0o700)
    receipt = directory / (
        "m3-11-import-reader/observation.json" if actor == "github" else "observation.json"
    )
    trace = directory / "trace.jsonl"
    environment = {
        "PATH": str(hook) + os.pathsep + os.environ["PATH"],
        "HOME": str(directory),
        "PYTHONPATH": str(hook),
        "PYTHONDONTWRITEBYTECODE": "1",
        "BRIDGE_FIXTURE": str(fixture_path),
        "BRIDGE_TRACE": str(trace),
        "BRIDGE_RECEIPT": str(receipt),
        "RUNNER_TEMP": str(directory),
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main",
        "GITHUB_RUN_ID": "20",
        "GITHUB_RUN_ATTEMPT": "1",
        "M3_11_HELPER_REVISION": bridge.LEGACY_REVISION,
    }
    if actor == "watchdog":
        arguments = [
            str(root / ".venv/bin/python"),
            str(ROOT / "scripts/m3_11_unattended/legacy_import_reader.py"),
            "--legacy-root",
            str(root),
            "--journal-vault",
            VAULTS["journal"],
            "--migration-sha256",
            fixture["migration"],
            "--actor",
            actor,
            "--receipt",
            str(receipt),
            "--",
            "--config",
            str(config),
            "--actor",
            actor,
        ]
    else:
        environment.update(
            M3_11_LEGACY_ROOT=str(root),
            M3_11_BRIDGE_VAULT=VAULTS["journal"],
            M3_11_BRIDGE_MIGRATION=fixture["migration"],
            M3_11_CONNECT_OPERATION="reconcile",
            M3_11_CONNECT_BOOTSTRAP=json.dumps(fixture["bootstrap"]),
            M3_11_CONNECT_CONFIGURATION=json.dumps(fixture["selection"]),
        )
        arguments = ["node", str(ROOT / ".github/actions/m3-11-legacy-import-bridge/index.js")]
    if watch:
        assert actor == "watchdog"
        runs = directory / "runs"
        runs.mkdir(mode=0o700)
        arguments += ["--watch", "--runs", str(runs)]
    result = subprocess.run(  # noqa: S603 - actual local bridge entrypoints, transport fenced
        arguments, env=environment, capture_output=True, check=False, timeout=15
    )
    # No simulated ready result: transport stops after the actual reader receipt.
    assert result.returncode != 0
    assert fixture["token"].encode() not in result.stdout + result.stderr
    (directory / "process-output.txt").write_bytes(result.stdout + result.stderr)
    return receipt, [
        json.loads(line) for line in trace.read_text().splitlines()
    ] if trace.exists() else []


@pytest.mark.parametrize("actor", ["watchdog", "github"])
@pytest.mark.parametrize("expiry_delta", [0, 1])
@pytest.mark.parametrize("audience", ["singleton", "scalar-audience"])
def test_actual_entrypoints_reach_compatible_reader(
    pinned: Path, tmp_path: Path, actor: str, expiry_delta: int, audience: str
) -> None:
    fixture = inputs(actor, fault=audience, expiry_delta=expiry_delta)
    receipt, trace = execute(pinned, tmp_path, actor, fixture)
    assert receipt.exists(), trace
    # A later deliberately aborted snapshot can overwrite the diagnostic with
    # unresolved. Assert the actual completed receipt observed at the boundary.
    observed = next(row["receipt"] for row in trace if row["transport"] == "observation")
    assert observed["status"] == "snapshot-verified"
    assert observed["import_visible"] is True
    assert observed["physical_items"] == len(fixture["items"])
    assert observed["legacy_records"] == len(fixture["items"]) - 1
    assert not any(row.get("method") == "POST" for row in trace)
    assert {row["path"] for row in trace if row["transport"] == "http"} >= {
        "/v1/vaults/" + VAULTS[role] for role in ("production", "provision")
    }
    if actor == "github":
        assert any(row["transport"] == "artifact" and row["path"].endswith("/zip") for row in trace)
        assert sum(row.get("operation", [None, None])[1] == "rm" for row in trace) == 6  # noqa: PLR2004 - three containers, two volumes, one network


def test_actual_persistent_watchdog_startup_and_cleanup_lock(pinned: Path, tmp_path: Path) -> None:
    fixture = inputs("watchdog", fault="none")
    receipt, trace = execute(pinned, tmp_path, "watchdog", fixture, watch=True)
    assert receipt.exists()
    observed = next(row["receipt"] for row in trace if row["transport"] == "observation")
    assert observed["status"] == "snapshot-verified" and observed["import_visible"] is True
    assert any(row["transport"] == "docker" for row in trace)
    assert not any(row.get("method") == "POST" for row in trace)


@pytest.mark.parametrize("actor", ["watchdog", "github"])
@pytest.mark.parametrize(
    "fault",
    [
        "expired",
        "extra-audience",
        "duplicate-audience",
        "wrong-audience",
        "identity",
        "grant",
        "extra-grant",
        "lifetime",
        "declared-expiry",
    ],
)
def test_actual_entrypoints_reject_invalid_client_before_transport(
    pinned: Path, tmp_path: Path, actor: str, fault: str
) -> None:
    receipt, trace = execute(pinned, tmp_path, actor, inputs(actor, fault=fault))
    assert not receipt.exists()
    assert trace == []


@pytest.mark.parametrize("actor", ["watchdog", "github"])
@pytest.mark.parametrize("delta", [-1, 0.5, 1.5, 2, 3600])
def test_actual_entrypoints_reject_other_native_expiry_offsets(
    pinned: Path, tmp_path: Path, actor: str, delta: float
) -> None:
    receipt, trace = execute(
        pinned, tmp_path, actor, inputs(actor, fault="none", expiry_delta=delta)
    )
    assert not receipt.exists()
    assert trace == []


@pytest.mark.parametrize("actor", ["watchdog", "github"])
@pytest.mark.parametrize("fault", ["forbidden", "extra-visible"])
def test_actual_authentication_isolation_failure_never_reaches_reader(
    pinned: Path, tmp_path: Path, actor: str, fault: str
) -> None:
    receipt, trace = execute(pinned, tmp_path, actor, inputs(actor, fault=fault))
    assert not receipt.exists()
    assert any(row["transport"] == "http" for row in trace)
    assert not any("/items" in row.get("path", "") for row in trace)


@pytest.mark.parametrize(
    "fault",
    [
        "dispatch",
        "checkpoint-key",
        "checkpoint-current-key",
        "checkpoint-digest",
        "checkpoint-ciphertext",
    ],
)
def test_actual_github_dispatch_and_checkpoint_gates_remain(
    pinned: Path, tmp_path: Path, fault: str
) -> None:
    receipt, trace = execute(pinned, tmp_path, "github", inputs("github", fault=fault))
    assert not receipt.exists()
    if fault in {"dispatch", "checkpoint-key"}:
        assert trace == []
    else:
        assert any(row["transport"] == "artifact" for row in trace)
        assert not any("/items" in row.get("path", "") for row in trace)


def test_backport_keeps_legacy_contract_and_signed_deadline(pinned: Path) -> None:
    script = """
import importlib.util
import json
import sys
from datetime import UTC, datetime
from scripts.m3_11_unattended import connect_auth as auth
from scripts.m3_11_unattended.model import LifecycleError, instant, stamp
spec = importlib.util.spec_from_file_location("bridge", sys.argv[1])
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
before = dict(vars(auth))
bridge.install_authentication(auth)
assert {key for key in before if before[key] is not vars(auth)[key]} == {"inspect"}
assert auth.READ_WRITE == 496 and auth.MAX_LIFETIME.days == 7
fixture = json.load(sys.stdin)
reader = fixture["configuration"]["cleanup"]["reader"]
arguments = (reader["entry"], reader["metadata"])
expected = {"c" * 26: 48, "j" * 26: 496}
access = auth.inspect(*arguments, expected=expected, now=datetime.now(UTC))
assert access.grants == expected
assert stamp(access.expires_at) == fixture["signed_expiry"]
# At signed expiry, the +1s native display cannot keep this credential usable.
try:
    auth.inspect(*arguments, expected=expected, now=instant(fixture["signed_expiry"]))
except LifecycleError:
    pass
else:
    raise AssertionError("native expiry extended runtime access")
try:
    bridge.install_authentication(auth)
except ValueError:
    pass
else:
    raise AssertionError("duplicate adaptation accepted")
print("legacy-contract-and-signed-deadline-verified")
"""
    result = command(
        [
            sys.executable,
            "-c",
            script,
            str(ROOT / "scripts/m3_11_unattended/legacy_import_reader.py"),
        ],
        cwd=pinned,
        input=canonical_bytes(inputs("watchdog", fault="none")),
    )
    assert result.stdout.strip() == b"legacy-contract-and-signed-deadline-verified"
