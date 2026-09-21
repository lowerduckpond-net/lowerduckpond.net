from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from typing import cast

import pytest
from lowerduckpond_static_host_agent import backup_restic as restic
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError

ENVIRONMENT = {
    "RESTIC_REPOSITORY": "s3:https://nyc3.example.test/backups/m3",
    "LOWERDUCKPOND_BACKUP_NODE_NAME": "node",
}


def _responses(
    monkeypatch: pytest.MonkeyPatch, *, config: bytes | None = None, snapshots: bytes = b"[]"
) -> None:
    def metadata(arguments: tuple[str, ...], _environment: Mapping[str, str], _limit: int) -> bytes:
        if arguments == ("cat", "config"):
            return (
                config
                if config is not None
                else json.dumps({"version": 2, "id": "a" * 64}).encode()
            )
        assert arguments == ("snapshots", "--json")
        return snapshots

    monkeypatch.setattr(restic, "restic_metadata", metadata)


def test_discovery_binds_full_config_id_but_not_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _responses(
        monkeypatch,
        snapshots=json.dumps(
            [{"id": "b" * 64, "hostname": "node", "tags": ["scheduled"]}]
        ).encode(),
    )
    identity, tags = restic.discover_repository(ENVIRONMENT)
    assert identity.config_id == "a" * 64
    assert tags == (("node", ("scheduled",)),)
    changed, _ = restic.discover_repository(
        {**ENVIRONMENT, "RESTIC_PASSWORD": "fake-other-password", "AWS_ACCESS_KEY_ID": "fake-key"}
    )
    assert identity.binding() == changed.binding()


@pytest.mark.parametrize(
    "config",
    [
        b"{}",
        b'{"version":true,"id":"aaaaaaaa"}',
        b'{"version":1,"id":"aaaaaaaa"}',
        b'{"id":"short","id":"other"}',
        b'{"id":null}',
        b"[]",
    ],
)
def test_invalid_or_unsupported_repository_config_fails_closed(
    monkeypatch: pytest.MonkeyPatch, config: bytes
) -> None:
    _responses(monkeypatch, config=config)
    with pytest.raises(BackupIdentityError):
        restic.discover_repository(ENVIRONMENT)


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "a" * 8),
        ("id", "A" * 64),
        ("id", None),
        ("hostname", None),
        ("tags", [1]),
        ("tags", ["scheduled", "scheduled"]),
        ("tags", "scheduled"),
        ("tags", ["x" * 257]),
    ],
)
def test_invalid_snapshot_metadata_is_not_silently_skipped(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    entry: dict[str, object] = {"id": "b" * 64, "hostname": "node", "tags": []}
    entry[field] = value
    _responses(monkeypatch, snapshots=json.dumps([entry]).encode())
    with pytest.raises(BackupIdentityError):
        restic.discover_repository(ENVIRONMENT)


def test_duplicate_snapshot_ids_and_bounded_inventory_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = {"id": "b" * 64, "hostname": "node"}
    _responses(monkeypatch, snapshots=json.dumps([entry, entry]).encode())
    with pytest.raises(BackupIdentityError):
        restic.discover_repository(ENVIRONMENT)
    _responses(monkeypatch, snapshots=b"[" + b"{}," * restic.MAX_SNAPSHOTS + b"{}]")
    with pytest.raises(BackupIdentityError, match="exceeds its bound"):
        restic.discover_repository(ENVIRONMENT)


@pytest.mark.parametrize("raw", [b'[],"extra":true', b"{}", b"null", b"[] []"])
def test_snapshot_output_must_be_one_complete_array(
    monkeypatch: pytest.MonkeyPatch, raw: bytes
) -> None:
    _responses(monkeypatch, snapshots=raw)
    with pytest.raises(BackupIdentityError):
        restic.discover_repository(ENVIRONMENT)


@pytest.mark.parametrize("mode", ["success", "overflow", "deadline", "failure"])
def test_real_child_output_deadline_and_failure_are_bounded(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    spawn = subprocess.Popen
    code = {
        "success": "print('{}')",
        "overflow": "import os; os.write(1, b'x' * 100000)",
        "deadline": "import time; time.sleep(30)",
        "failure": "import sys; print('secret-provider-error', file=sys.stderr); sys.exit(1)",
    }[mode]
    children: list[subprocess.Popen[bytes]] = []

    def process(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        # Real child I/O, with a fixed Python producer in place of Restic.
        child = cast("subprocess.Popen[bytes]", spawn([sys.executable, "-I", "-c", code], **kwargs))  # type: ignore[call-overload]
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", process)
    if mode == "deadline":
        monkeypatch.setattr(restic, "METADATA_TIMEOUT_SECONDS", 0.2)
    if mode == "success":
        assert restic.restic_metadata(("cat", "config"), ENVIRONMENT, 4096) == b"{}\n"
    else:
        with pytest.raises(BackupIdentityError) as result:
            restic.restic_metadata(("cat", "config"), ENVIRONMENT, 4096)
        assert "secret-provider-error" not in str(result.value)
    assert len(children) == 1 and children[0].poll() is not None
