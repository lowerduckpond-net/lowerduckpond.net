from __future__ import annotations

import hashlib
import os
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, framed_digest
from lowerduckpond_static_host_agent.host_restore_inputs import (
    INPUT_SCHEMA,
    ISSUER,
    SUBJECTS,
    RestoreInputs,
    file_sha256,
    local_machine_id,
)
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from test_backup_inventory import _fixture
from test_host_restore_journal import RESTORE


@pytest.fixture
def configuration() -> dict[str, object]:
    return {
        "schema": INPUT_SCHEMA,
        "restoreId": RESTORE,
        "snapshotId": "d" * 64,
        "repositoryBinding": framed_digest(
            "lowerduckpond-backup-repository-binding-v1", b"repository"
        ),
        "originalArtifactSha256": "b" * 64,
        "sourceMachineId": "a" * 32,
        "destinationMachineId": "b" * 32,
        "sourceFenceDigest": framed_digest("lowerduckpond-host-restore-source-fence-v1", b"fence"),
        "namespace": _fixture("platform-namespace"),
        "launch": None,
        "archiveTarget": {"region": "sfo3", "bucket": "owned-test-archive"},
        "caddy": {
            "binaryPath": "/usr/local/lib/lowerduckpond/caddy-owned-pinned-binary",
            "binarySha256": "c" * 64,
            "environmentSha256": "d" * 64,
            "originPullCaSha256": ["e" * 64],
            "originalOriginPullCaSha256": ["f" * 64],
            "originPullRequired": True,
            "issuer": ISSUER,
            "subjects": list(SUBJECTS),
            "trustBundleSha256": "0" * 64,
        },
        "publicationEnabled": False,
        "auditRotationEnabled": False,
    }


def test_private_canonical_inputs_pin_a_distinct_destination_and_exact_original_artifact(
    configuration: dict[str, object],
    tmp_path: Path,
) -> None:
    root = tmp_path / "inputs"
    root.mkdir(mode=0o700)
    raw = canonical_json_bytes(configuration)
    path = root / "target.json"
    path.write_bytes(raw)
    path.chmod(0o600)
    inputs = RestoreInputs.load(root, owner=os.geteuid())
    assert inputs.digest == framed_digest(INPUT_SCHEMA, raw)
    inputs.require_destination("b" * 32, "b" * 64, "d" * 64)
    for machine, artifact, snapshot in (
        ("a" * 32, "b" * 64, "d" * 64),
        ("b" * 32, "c" * 64, "d" * 64),
        ("b" * 32, "b" * 64, "e" * 64),
    ):
        with pytest.raises(HostRestoreError):
            inputs.require_destination(machine, artifact, snapshot)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "same-host",
        "short-id",
        "coercion",
        "internal-issuer",
        "subjects",
        "origin-pull",
        "binary-path",
        "noncanonical",
    ],
)
def test_ambiguous_or_weakened_trusted_policy_never_reaches_restore(
    configuration: dict[str, object],
    fault: str,
) -> None:
    value = deepcopy(configuration)
    caddy = value["caddy"]
    assert type(caddy) is dict
    if fault == "unknown":
        value["command"] = "/bin/sh"
    elif fault == "same-host":
        value["destinationMachineId"] = value["sourceMachineId"]
    elif fault == "short-id":
        value["snapshotId"] = "ddd"
    elif fault == "coercion":
        value["publicationEnabled"] = 1
    elif fault == "internal-issuer":
        caddy["issuer"] = "internal"
    elif fault == "subjects":
        caddy["subjects"] = ["lowerduckpond.net"]
    elif fault == "origin-pull":
        caddy["originPullRequired"] = False
    elif fault == "binary-path":
        caddy["binaryPath"] = "/untrusted/caddy"
    raw = canonical_json_bytes(value)
    if fault == "noncanonical":
        raw = b" " + raw
    with pytest.raises((HostRestoreError, BackupIdentityError)):
        RestoreInputs.from_bytes(raw)


def test_host_identity_and_trusted_file_hashes_reject_aliases_and_unsafe_modes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "machine-id"
    path.write_bytes(b"a" * 32 + b"\n")
    path.chmod(0o444)
    assert local_machine_id(path, owner=os.geteuid()) == "a" * 32
    assert (
        file_sha256(path, owner=os.geteuid(), group=os.getegid(), mode=0o444, maximum=64)
        == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        local_machine_id(alias, owner=os.geteuid())
    path.chmod(0o666)
    with pytest.raises(HostRestoreError):
        local_machine_id(path, owner=os.geteuid())
    with pytest.raises(HostRestoreError):
        file_sha256(path, owner=os.geteuid(), group=os.getegid(), mode=0o444, maximum=64)
