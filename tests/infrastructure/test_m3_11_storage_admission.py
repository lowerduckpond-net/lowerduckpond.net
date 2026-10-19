"""Released runtimes with retained objects must not consume another attempt."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import signal
import sys
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import production_qualification_inputs
from scripts import provider_preflight_diagnostics as diagnostics
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import __main__ as cli
from scripts.m3_11_unattended import approval, docker, storage_admission
from scripts.m3_11_unattended import connect_activate as activation
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import LifecycleError, digest, instant, stamp
from scripts.m3_11_unattended.state import LeaseState, RunState
from scripts.m3_11_unattended.watchdog import quiesce_runtime

from .test_m3_10_production_gate import Storage
from .test_m3_11_lease_runtime import RuntimeDocker, runtime
from .test_m3_11_unattended_admission import Daemon
from .test_m3_11_unattended_controller import DAEMON, configuration

EXISTING_DAEMON_SECONDS = 1200


class Inventory(Storage):
    def __init__(self) -> None:
        super().__init__()
        self.guard: Callable[..., None] = lambda **_kwargs: None
        self.meta = SimpleNamespace(events=SimpleNamespace(register=self.register))

    def register(self, event: str, callback: Callable[..., None]) -> None:
        assert event == "request-created.s3"
        self.guard = callback

    def __getattr__(self, name: str) -> object:
        original = cast(Callable[..., object], super().__getattr__(name))

        def operation(**arguments: object) -> object:
            assert arguments["Bucket"] == "test-archive"
            self.guard(request=object(), operation_name=name)
            return original(**{**arguments, "Bucket": "archive-fixture"})

        return operation


def prepared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, LeaseState, RuntimeDocker, LeaseConfiguration, Inventory]:
    directory, lease, daemon = runtime(tmp_path, monkeypatch)
    quiesce_runtime(directory, daemon)
    RunState(directory).update("finished", cleanup="pending")
    daemon.mutations.clear()
    manifest = lease.manifest()
    lease.claim_issuer(writer_sha256="a" * 64)
    for intent in manifest.intents:
        lease.remember(intent, "synthetic-" + intent.role, "synthetic-secret-" + intent.role)
    lease.finish_issuer(writer_sha256="a" * 64, stopped_at=manifest.created_at)
    config = dataclasses.replace(
        configuration(),
        targets=manifest.targets,
        policy=manifest.policy,
        approved_policy_sha256=manifest.policy.sha256,
    )
    root = tmp_path / "storage-leases"
    root.mkdir(mode=0o700)
    lock = root / (
        hashlib.sha256(
            canonical_bytes(
                {
                    "region": manifest.targets.region,
                    "archive_bucket": manifest.targets.archive_bucket,
                }
            )
        ).hexdigest()
        + ".lock"
    )
    lock.write_bytes(b"")
    lock.chmod(0o600)
    monkeypatch.setattr(storage_admission, "LEASE_DIRECTORY", str(root))
    inventory = Inventory()
    monkeypatch.setattr(storage_admission, "make_policy_client", lambda _config: inventory)
    monkeypatch.setattr(
        storage_admission, "_deadline", time.monotonic() + storage_admission.HELPER_SECONDS
    )
    return directory, lease, daemon, config, inventory


@pytest.mark.parametrize("kind", ["current", "version", "marker", "multipart", "malformed"])
def test_released_fixture_is_not_empty_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    directory, lease, daemon, config, inventory = prepared(tmp_path, monkeypatch)
    operation, result = {
        "current": ("list_objects_v2", {"Contents": [{"Key": "owned-retained"}]}),
        "version": (
            "list_object_versions",
            {"Versions": [{"Key": "owned-retained", "VersionId": "v1"}]},
        ),
        "marker": (
            "list_object_versions",
            {"DeleteMarkers": [{"Key": "owned-retained", "VersionId": "v1"}]},
        ),
        "multipart": (
            "list_multipart_uploads",
            {"Uploads": [{"Key": "owned-retained", "UploadId": "u1"}]},
        ),
        "malformed": ("list_objects_v2", {"IsTruncated": "no"}),
    }[kind]
    inventory.responses[operation] = {"IsTruncated": False, **cast(dict[str, object], result)}
    before = {path: path.read_bytes() for path in lease.directory.rglob("*") if path.is_file()}
    result = storage_admission.observe(
        config,
        lease_id=lease.manifest().lease_id,
        manifest_sha256=lease.manifest().sha256,
        evidence_root=directory.parent.parent,
        docker=daemon,
        clock=lambda: instant(lease.manifest().created_at) + timedelta(minutes=1),
    )
    assert result["whole_bucket_empty"] is False
    assert diagnostics.verified(result["failure"])["phase"] == "storage"
    assert daemon.mutations == []
    assert before == {
        path: path.read_bytes() for path in lease.directory.rglob("*") if path.is_file()
    }


@pytest.mark.parametrize(
    "fault", ["none", "unreleased", "closing", "credential", "resumed", "manifest", "deadline"]
)
def test_readiness_requires_original_released_lease_and_unchanged_provider_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    directory, lease, daemon, config, inventory = prepared(tmp_path, monkeypatch)
    manifest = lease.manifest()
    if fault == "unreleased":
        (lease.directory / ("released-" + directory.name + ".json")).unlink()
    elif fault == "closing":
        write_private(lease.directory / "close-cancelled.json", {})
    elif fault == "credential":
        (lease.directory / "credential-operator.json").unlink()
    elif fault == "resumed":
        cast(dict[str, object], daemon.rows["1" * 64]["State"])["Running"] = True
    now = instant(manifest.created_at) + timedelta(minutes=1)
    if fault == "deadline":
        now = manifest.policy.deadline(instant(manifest.created_at)) - timedelta(hours=1)
    parameters = {
        "lease_id": manifest.lease_id,
        "manifest_sha256": "0" * 64 if fault == "manifest" else manifest.sha256,
        "evidence_root": directory.parent.parent,
        "docker": daemon,
        "clock": lambda: now,
    }
    if fault == "none":
        result = storage_admission.observe(config, **parameters)  # type: ignore[arg-type]
        assert result["whole_bucket_empty"] is True
        assert inventory.calls == list(inventory.responses)
        assert result["manifest_sha256"] == manifest.sha256
    else:
        with pytest.raises((LifecycleError, OSError)):
            storage_admission.observe(config, **parameters)  # type: ignore[arg-type]
        assert inventory.calls == []
    assert daemon.mutations == []


@pytest.mark.parametrize("malformed", [False, True])
def test_launch_blocks_nonempty_reuse_before_allocating_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    malformed: bool,
) -> None:
    daemon = Daemon()
    config = configuration()
    source = config.helper_revision
    now = instant(config.policy.approved_at) + timedelta(minutes=1)
    previous = "019b8e10-4ef0-7000-8000-000000000001"
    daemon.controllers.append(docker.controller_name(previous))
    approved = {
        "format": approval.FORMAT,
        "prepared": {
            "source_revision": source,
            "helper_revision": source,
            "controller_image": "sha256:" + "b" * 64,
            "artifact_sha256": "c" * 64,
            "daemon": DAEMON,
        },
        "targets": dataclasses.asdict(config.targets),
        "qualification_inputs_sha256": "d" * 64,
        "modes": ["qualification"],
        "approved_at": stamp(now - timedelta(seconds=1)),
        "expires_at": stamp(now + timedelta(hours=1)),
        "policy_sha256": config.policy.sha256,
        "lease_id": previous,
        "approval_reference": "SYNTHETIC storage admission test",
    }
    monkeypatch.setattr(cli, "datetime", SimpleNamespace(now=lambda _zone: now))
    monkeypatch.setattr(cli, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(cli, "fingerprint", lambda *_args: "d" * 64)
    monkeypatch.setattr(LeaseConfiguration, "load", lambda _path: config)
    monkeypatch.setattr(cli, "require_current_watchdogs", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        cli,
        "operate",
        lambda *_args: json.dumps(
            {
                "status": {"phase": "finished", "qualification": "failed"},
                "lease": {
                    "lease_id": previous,
                    "policy_sha256": config.policy.sha256,
                    "manifest_sha256": "a" * 64,
                    "use_released": True,
                },
            }
        ).encode(),
    )

    def readiness(*_args: object, **kwargs: object) -> dict[str, object]:
        assert daemon.reserved
        assert kwargs["operation"] == "storage-admission"
        failure = diagnostics.document(
            ValueError("private-sentinel"), phase="storage", started=time.monotonic()
        )
        if malformed:
            failure["elapsed_seconds"] = 10**1000
        return {
            "format": storage_admission.FORMAT,
            "lease_id": previous,
            "manifest_sha256": "a" * 64,
            "policy_sha256": config.policy.sha256,
            "storage_target_sha256": config.targets.storage_digest,
            "helper_revision": source,
            "whole_bucket_empty": False,
            "failure": failure,
        }

    monkeypatch.setattr(cli, "utility", readiness)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("failed storage readiness allocated or launched an attempt")

    monkeypatch.setattr(cli, "initialize_run", forbidden)
    monkeypatch.setattr(cli, "launch", forbidden)
    monkeypatch.setattr(cli, "Docker", lambda: daemon)
    monkeypatch.setattr(cli, "read_private", lambda _path: approved)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "unattended",
            "start",
            source,
            "--approval",
            "unused",
            "--config",
            "unused",
            "--mode",
            "qualification",
            "--daemon-socket",
            docker.SOCKET,
        ],
    )
    with pytest.raises(SystemExit) as exited:
        cli.main()
    assert exited.value.code == 1
    error = capsys.readouterr().err
    assert "private-sentinel" not in error
    if malformed:
        assert "Operation incomplete" in error
    else:
        assert diagnostics.verified(json.loads(error.splitlines()[0]))["phase"] == "storage"
        assert "no attempt allocated" in error
    assert not daemon.reserved
    assert daemon.controllers == [docker.controller_name(previous)]


def test_remaining_budget_rejects_before_read_without_clipping_inner_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: current[0])
    monkeypatch.setattr(storage_admission, "_deadline", storage_admission.HELPER_SECONDS)
    calls = []

    def command(_self: object, *args: object, **kwargs: object) -> bytes:
        calls.append((args, kwargs))
        return b"ok"

    monkeypatch.setattr(docker.Docker, "command", command)
    client = object.__new__(storage_admission.ReadOnlyDocker)
    assert client.command("inspect", "synthetic") == b"ok"
    assert calls[0][1]["timeout"] == EXISTING_DAEMON_SECONDS
    current[0] = storage_admission.HELPER_SECONDS - EXISTING_DAEMON_SECONDS
    with pytest.raises(LifecycleError, match="next complete read"):
        client.command("inspect", "synthetic")
    assert len(calls) == 1
    with pytest.raises(LifecycleError, match="non-read"):
        client.command("restart", "synthetic")
    assert len(calls) == 1


def test_provider_read_cannot_start_without_its_complete_allowance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory, lease, daemon, config, inventory = prepared(tmp_path, monkeypatch)
    monkeypatch.setattr(
        storage_admission, "_deadline", time.monotonic() + storage_admission.PROVIDER_SECONDS
    )
    result = storage_admission.observe(
        config,
        lease_id=lease.manifest().lease_id,
        manifest_sha256=lease.manifest().sha256,
        evidence_root=directory.parent.parent,
        docker=daemon,
        clock=lambda: instant(lease.manifest().created_at) + timedelta(minutes=1),
    )
    assert result["whole_bucket_empty"] is False
    assert result["provider_read_count"] == 0
    assert inventory.calls == []


def test_helper_clock_is_shared_not_renewed_and_restores_source_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: current[0])
    timers = []
    monkeypatch.setattr(signal, "setitimer", lambda *args: timers.append(args))
    original = production_qualification_inputs.git
    with storage_admission.bounded_helper():
        assert production_qualification_inputs.git is storage_admission.bounded_git
        storage_admission.require_remaining(storage_admission.GIT_SECONDS)
        current[0] = storage_admission.HELPER_SECONDS - storage_admission.GIT_SECONDS
        with pytest.raises(LifecycleError, match="next complete read"):
            storage_admission.require_remaining(storage_admission.GIT_SECONDS)
        with pytest.raises(LifecycleError, match="nonrenewing"), storage_admission.bounded_helper():
            pytest.fail("nested helper renewed its deadline")
    assert production_qualification_inputs.git is original
    assert timers == [
        (signal.ITIMER_REAL, storage_admission.HELPER_SECONDS),
        (signal.ITIMER_REAL, 0),
    ]


def test_actual_daemon_entry_preserves_nonempty_diagnostic_and_source_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory, lease, daemon, config, inventory = prepared(tmp_path, monkeypatch)
    root = directory.parent.parent
    artifact = root / "prepared" / config.helper_revision / "static-host-agent.tar"
    artifact.parent.mkdir(parents=True, mode=0o700)
    artifact.write_bytes(b"synthetic-artifact")
    inputs = {
        "source_revision": config.helper_revision,
        "helper_revision": config.helper_revision,
        "controller_image": "sha256:" + "b" * 64,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "daemon": daemon.info(),
    }
    checked = []
    monkeypatch.setattr(
        production_qualification_inputs,
        "current_candidate",
        lambda root, source: checked.append((root, source)),
    )
    monkeypatch.setattr(storage_admission, "ReadOnlyDocker", lambda: daemon)
    monkeypatch.setattr(storage_admission, "_deadline", None)
    monkeypatch.setattr(
        storage_admission,
        "datetime",
        SimpleNamespace(
            now=lambda _zone: instant(lease.manifest().created_at) + timedelta(minutes=1)
        ),
    )
    inventory.responses["list_objects_v2"] = {
        "IsTruncated": False,
        "Contents": [{"Key": "retained-private-sentinel"}],
    }
    envelope = {
        "format": activation.UTILITY_FORMAT,
        "prepared": inputs,
        "operation": "storage-admission",
        "payload": {
            "configuration": config.document(cleanup_only=True),
            "lease_id": lease.manifest().lease_id,
            "manifest_sha256": lease.manifest().sha256,
        },
    }
    result = activation.daemon_utility(envelope, evidence_root=root)
    assert checked == [(docker.ROOT, config.helper_revision)]
    assert result["whole_bucket_empty"] is False
    failure = diagnostics.verified(result["failure"])
    nodes = cast(dict[str, list[dict[str, object]]], failure["exception_chain"])["nodes"]
    assert nodes[0]["reason"] == "current-objects-present"
    assert "retained-private-sentinel" not in json.dumps(result)
    assert daemon.mutations == []
    artifact.write_bytes(b"changed-artifact")
    inventory.calls.clear()
    with pytest.raises(LifecycleError, match="exact prepared inputs"):
        activation.daemon_utility(envelope, evidence_root=root)
    assert inventory.calls == []


@pytest.mark.parametrize("operation", ["admission", "storage-admission"])
def test_native_utility_encloses_new_helper_without_changing_existing_bounds(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    inputs = {
        "source_revision": "a" * 40,
        "helper_revision": "a" * 40,
        "controller_image": "sha256:" + "b" * 64,
        "artifact_sha256": "c" * 64,
        "daemon": DAEMON,
    }
    calls = []

    def command(_self: object, *args: str, stdin: bytes, timeout: int) -> bytes:
        calls.append((args, timeout))
        envelope = json.loads(stdin)
        return canonical_bytes(
            {
                "format": activation.UTILITY_FORMAT,
                "input_sha256": digest(envelope),
                "result": {"verified": True},
            }
        )

    monkeypatch.setattr(docker.Docker, "command", command)
    monkeypatch.setattr(docker.Docker, "info", lambda _self: DAEMON)
    result = docker.utility(
        object.__new__(docker.Docker),
        prepared=inputs,
        operation=operation,
        payload={},
        daemon_socket=docker.SOCKET,
    )
    assert result == {"verified": True}
    arguments, timeout = calls[0]
    if operation == "storage-admission":
        assert timeout == storage_admission.CALLER_SECONDS
        assert timeout > storage_admission.HELPER_SECONDS
        assert (
            f"type=volume,source={docker.LEASE_VOLUME},target={docker.LEASE_DIRECTORY},readonly"
            in arguments
        )
    else:
        assert timeout == EXISTING_DAEMON_SECONDS
