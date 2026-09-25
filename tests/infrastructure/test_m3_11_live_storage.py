"""Live credentials require an explicit owned pair, artifact and provider lease."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import uuid
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_restore_reservation as reservation
from scripts import qualification_restore as owned
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_live_storage import LiveStorage, main
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.production_qualification_inputs import POLICY
from scripts.qualification_context import ARTIFACT_ENV, HOST_ENV, RUN_ENV, resource_names


@pytest.fixture
def storage(tmp_path: Path) -> LiveStorage:
    run_id = uuid.uuid7()
    target = Target(str(run_id), "ams3", "fixture-backups", "fixture-archives")
    artifact = tmp_path / "fixture/static-host-agent.tar"
    artifact.parent.mkdir()
    artifact.write_bytes(b"selected fixture artifact")
    binding: dict[str, object] = {
        "source_revision": "a" * 40,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "input_policy": POLICY,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": target.storage_target_sha256,
        "storage_run_id": str(uuid.uuid7()),
        "storage_report_sha256": "d" * 64,
    }
    environment = {
        **resource_names(run_id.hex),
        ARTIFACT_ENV: str(artifact),
        "M3_10_INSTALLED_REPORT": str(tmp_path / "installed.json"),
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "M3_10_ARCHIVE_BACKEND": "spaces",
        "M3_11_COMBINED_BACKEND": "spaces",
        "SPACES_REGION": "ams3",
        "SPACES_BACKUP_BUCKET": target.backup_bucket,
        "SPACES_ARCHIVE_BUCKET": target.archive_bucket,
        "SPACES_BACKUP_ACCESS_KEY_ID": "fixture-backup-key",
        "SPACES_BACKUP_SECRET_ACCESS_KEY": "fixture-backup-secret",
        "SPACES_ARCHIVE_ACCESS_KEY_ID": "fixture-archive-key",
        "SPACES_ARCHIVE_SECRET_ACCESS_KEY": "fixture-archive-secret",
        "SPACES_ACCESS_KEY_ID": "fixture-observer-key",
        "SPACES_SECRET_ACCESS_KEY": "fixture-observer-secret",
        "RESTIC_PASSWORD": "fixture-production-password",
    }
    return LiveStorage(target, binding, "original-owner-version", environment, "c" * 64)


@pytest.mark.parametrize(
    "key,value",
    [
        (RUN_ENV, uuid.uuid7().hex),
        (HOST_ENV, "production-host"),
        ("M3_10_ARCHIVE_BACKEND", "minio"),
        ("M3_11_COMBINED_BACKEND", ""),
        ("DOCKER_HOST", "ssh://production-host"),
        ("DOCKER_HOST", "tcp://127.0.0.1:2375"),
        ("DOCKER_HOST", ""),
        ("DOCKER_CONTEXT", "remote"),
        ("M3_10_INSTALLED_REPORT", "/foreign/installed.json"),
        ("M3_10_INSTALLED_REPORT", ""),
        (ARTIFACT_ENV, "fixture/static-host-agent.tar"),
    ],
)
def test_mixed_or_remote_fixture_never_reaches_provider(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch, key: str, value: str
) -> None:
    owner = Mock(side_effect=AssertionError("provider must not be consulted"))
    monkeypatch.setattr(LiveStorage, "require_owner", owner)
    with pytest.raises(ValueError):
        storage.require_source({**storage.environment, key: value})
    owner.assert_not_called()


@pytest.mark.parametrize("fault", ["changed-artifact", "reused-password", "missing-binding"])
def test_changed_inputs_never_attach_live_credentials(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    owner = Mock(side_effect=AssertionError("provider must not be consulted"))
    monkeypatch.setattr(LiveStorage, "require_owner", owner)
    if fault == "changed-artifact":
        Path(storage.environment[ARTIFACT_ENV]).write_bytes(b"replacement artifact")
    elif fault == "reused-password":
        storage = replace(storage, environment={**storage.environment, "RESTIC_PASSWORD": "c" * 64})
    else:
        storage = replace(storage, binding={})
    with pytest.raises(ValueError):
        storage.require_source(storage.environment)
    owner.assert_not_called()


def test_original_owner_is_rechecked_by_both_independent_principals(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    clients = (object(), object())
    monkeypatch.setattr(Target, "clients", Mock(return_value=clients))
    owner = Mock()
    monkeypatch.setattr(Target, "require_owner", owner)
    storage.require_source(storage.environment)
    assert owner.call_args_list == [
        ((client, storage.binding), {"version": "original-owner-version"}) for client in clients
    ]


def test_retained_inputs_after_owner_deletion_are_available_only_to_cleanup(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = Mock()
    monkeypatch.setattr(LiveStorage, "require_owner", owner)
    storage.save()
    owner.side_effect = ValueError("original owner has been removed")
    with pytest.raises(ValueError, match="owner has been removed"):
        LiveStorage.load(storage.environment)
    retained = LiveStorage._retained(storage.environment)
    assert retained == storage
    with pytest.raises(ValueError, match="owner has been removed"):
        retained.variables()
    Path(storage.environment[ARTIFACT_ENV]).write_bytes(b"replacement artifact")
    with pytest.raises(ValueError, match="inputs changed"):
        LiveStorage._retained(storage.environment)


def test_source_and_destination_share_owned_repository_and_distinct_service_credentials(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = Mock()
    monkeypatch.setattr(LiveStorage, "require_owner", owner)
    variables = storage.variables()
    owner.assert_called_once_with()
    assert variables["backup_repository"] == storage.target.repository
    assert variables["backup_restic_password"] == storage.restic_password
    assert variables["backup_spaces_access_key_id"] == "fixture-backup-key"
    archive = variables["static_host_agent_archive_configuration"]
    assert isinstance(archive, dict)
    assert archive["bucket"] == storage.target.archive_bucket
    assert archive["accessKeyId"] == "fixture-archive-key"
    assert "fixture-observer" not in repr(variables)
    assert "fixture-production-password" not in repr(variables)
    assert "fixture-backup-secret" not in repr(storage)
    assert storage.restic_password not in repr(storage)


@pytest.mark.parametrize("reuse", ["fixture-backup-key", "fixture-observer-key", ""])
def test_archive_key_cannot_be_another_principal_or_missing(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch, reuse: str
) -> None:
    monkeypatch.setattr(LiveStorage, "require_owner", Mock())
    storage = replace(
        storage, environment={**storage.environment, "SPACES_ARCHIVE_ACCESS_KEY_ID": reuse}
    )
    with pytest.raises(ValueError):
        storage.variables()


def test_lost_owner_prevents_credential_materialization(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(LiveStorage, "require_owner", Mock(side_effect=ValueError("lost owner")))
    with pytest.raises(ValueError, match="lost owner"):
        storage.variables()


def test_private_record_preserves_original_owner_and_password_and_cannot_be_overwritten(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(LiveStorage, "require_owner", Mock())
    storage.save()
    path = Path(storage.environment[ARTIFACT_ENV]).parent.parent / "live-storage.json"
    original = path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600  # noqa: PLR2004 - private secret record
    assert LiveStorage.load(storage.environment) == storage
    with pytest.raises(FileExistsError):
        storage.save()
    assert path.read_bytes() == original
    assert "fixture-backup-secret" not in original.decode()
    assert "fixture-observer-secret" not in original.decode()


@pytest.mark.parametrize(
    "fault",
    [
        "public-file",
        "public-directory",
        "symlink",
        "hardlink",
        "oversize",
        "duplicate",
        "unknown",
        "wrong-run",
        "wrong-version-type",
        "missing-binding",
        "replaced-artifact",
    ],
)
def test_unsafe_private_inputs_fail_before_remote_observation(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    owner = Mock()
    monkeypatch.setattr(LiveStorage, "require_owner", owner)
    storage.save()
    owner.reset_mock()
    root = Path(storage.environment[ARTIFACT_ENV]).parent.parent
    path = root / "live-storage.json"
    raw = path.read_bytes()
    document = json.loads(raw)
    if fault == "public-file":
        path.chmod(0o644)
    elif fault == "public-directory":
        root.chmod(0o755)
    elif fault == "symlink":
        path.rename(root / "original.json")
        path.symlink_to(root / "original.json")
    elif fault == "hardlink":
        os.link(path, root / "another-name.json")
    elif fault == "oversize":
        path.write_bytes(b" " * (257 * 1024))
    elif fault == "duplicate":
        path.write_bytes(b'{"format":"ambiguous",' + raw[1:])
    elif fault == "replaced-artifact":
        Path(storage.environment[ARTIFACT_ENV]).write_bytes(b"another artifact")
    else:
        if fault == "missing-binding":
            del document["binding"]
        else:
            changes = {
                "unknown": {"unrecognized": "private-canary"},
                "wrong-run": {"run_id": str(uuid.uuid7())},
                "wrong-version-type": {"owner_version": True},
            }
            document.update(changes[fault])
        path.write_bytes(canonical_bytes(document))
    try:
        with pytest.raises((ValueError, OSError)):
            LiveStorage.load(storage.environment)
        owner.assert_not_called()
    finally:
        root.chmod(0o700)


def test_private_cli_failure_cannot_print_private_record(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["m3_11_live_storage", "--variables"])
    monkeypatch.setattr(LiveStorage, "load", Mock(side_effect=ValueError("secret-canary")))
    assert main() == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert "secret-canary" not in captured.err


@pytest.fixture
def reserved_pair(
    storage: LiveStorage, monkeypatch: pytest.MonkeyPatch
) -> tuple[dict[str, dict[str, object]], list[str]]:
    monkeypatch.setattr(LiveStorage, "require_owner", Mock())
    source: dict[str, object] = {
        "id": "1" * 64,
        "name": "/" + storage.environment[HOST_ENV],
        "owner": storage.environment[RUN_ENV],
        "image": "sha256:" + "3" * 64,
        "running": True,
    }
    destination = {
        **source,
        "id": "2" * 64,
        "name": f"/ldp-m3-{storage.environment[RUN_ENV]}-destination",
        "running": False,
    }
    objects = {storage.environment[HOST_ENV]: source, "2" * 64: destination}
    events: list[str] = []
    monkeypatch.setattr(owned, "inspect", lambda env, name: dict(objects[name]))

    def create(environment: dict[str, str], kind: str) -> dict[str, object]:
        assert environment == storage.environment and kind == "destination"
        events.append("create-stopped")
        return dict(destination)

    def start(environment: dict[str, str], *args: str) -> bytes:
        assert args == ("docker", "start", "2" * 64)
        receipt = owned.directory(environment) / "destination.json"
        assert json.loads(receipt.read_bytes()) == destination
        events.append("start")
        return b""

    monkeypatch.setattr(owned, "create_stopped", create)
    monkeypatch.setattr(owned, "source_fenced", lambda _: events.append("fence"))
    monkeypatch.setattr(owned, "command", start)
    reservation.reserve(storage)
    owned.directory(dict(storage.environment)).mkdir(mode=0o700)
    return objects, events


def test_destination_is_reserved_before_capture_and_started_only_after_fence(
    storage: LiveStorage, reserved_pair: tuple[dict[str, dict[str, object]], list[str]]
) -> None:
    _, events = reserved_pair
    root = Path(storage.environment[ARTIFACT_ENV]).parent.parent
    original = (root / "destination-reservation.json").read_bytes()
    assert events == ["create-stopped"]
    with pytest.raises(ValueError, match="original reservation"):
        reservation.reserve(storage)
    assert reservation.adopt(storage) == "2" * 64
    assert events == ["create-stopped", "fence", "start"]
    assert (root / "destination-reservation.json").read_bytes() == original
    with pytest.raises(FileExistsError):
        reservation.adopt(storage)
    assert events.count("start") == 1


@pytest.mark.parametrize(
    "fault", ["running", "source-replaced", "image-replaced", "foreign-run", "missing", "unfenced"]
)
def test_changed_reservation_or_missing_fence_cannot_start_destination(
    storage: LiveStorage,
    reserved_pair: tuple[dict[str, dict[str, object]], list[str]],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    objects, events = reserved_pair
    root = Path(storage.environment[ARTIFACT_ENV]).parent.parent
    path = root / "destination-reservation.json"
    if fault == "running":
        objects["2" * 64]["running"] = True
    elif fault == "source-replaced":
        objects[storage.environment[HOST_ENV]]["id"] = "4" * 64
    elif fault == "image-replaced":
        objects["2" * 64]["image"] = "sha256:" + "4" * 64
    elif fault == "foreign-run":
        document = json.loads(path.read_bytes())
        document["run_id"] = str(uuid.uuid7())
        path.write_bytes(canonical_bytes(document))
    elif fault == "missing":
        path.unlink()
    else:
        monkeypatch.setattr(
            owned, "source_fenced", Mock(side_effect=ValueError("source not fenced"))
        )
    with pytest.raises((ValueError, FileNotFoundError)):
        reservation.adopt(storage)
    assert events == ["create-stopped"]
    assert not (root / "restore/destination.json").exists()
