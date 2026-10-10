"""Versioned private staging requires explicit policy and isolated native readers."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import connect_setup as setup
from scripts.m3_11_unattended.connect_action import INDEPENDENT_ORIGIN
from scripts.m3_11_unattended.connect_auth import claims
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_connect_auth import token
from .test_m3_11_lease_configuration import document, mapping, reader_document

CANARY = "connect-setup-secret-canary"


def independent_reader(server: str) -> dict[str, object]:
    value = reader_document("cleanup", now=datetime.now(UTC).replace(microsecond=0))
    entry, metadata = mapping(value["entry"]), mapping(value["metadata"])
    payload = claims(str(entry["token"]))
    entry["server"] = server
    mapping(metadata["server"])["id"] = server
    native = cast(list[dict[str, object]], metadata["tokens"])[0]
    native.update(integration_id=server, id="G" * 26)
    payload.update(sub=server, jti="G" * 26)
    token(entry, payload)
    value["url"] = INDEPENDENT_ORIGIN
    return value


def run(root: Path, *, approved: dict[str, object] | None = None) -> None:
    value = document() if approved is None else approved
    setup.prepare(
        value,
        independent_reader(str(value["independent_server_id"])),
        {"server-secret": CANARY},
        output=root,
    )
    # Endpoint tests test the delivery boundary independently of live preflight.
    write_private(
        root / "activation.json",
        {
            "format": "lowerduckpond-m3-11-lease-activation-v1",
            "status": "ready",
            "controller_sha256": hashlib.sha256(
                (root / "controller-connect.json").read_bytes()
            ).hexdigest(),
            "independent_sha256": hashlib.sha256(
                (root / "github-connect.json").read_bytes()
            ).hexdigest(),
        },
    )


def test_stage_separates_native_master_and_production_access(tmp_path: Path) -> None:
    run(tmp_path)
    controller = read_private(tmp_path / "controller-connect.json")
    independent = read_private(tmp_path / "github-connect.json")
    assert CANARY not in json.dumps(controller)
    config = mapping(independent["configuration"])
    assert config["mode"] == "cleanup-only" and config["production"] is None
    assert all(
        set(mapping(roles)) == {"cleanup"} for roles in mapping(config["generations"]).values()
    )
    assert "OPENTOFU_ENCRYPTION_PASSPHRASE" not in json.dumps(independent)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in tmp_path.glob("*.json"))  # noqa: PLR2004


def test_staging_is_idempotent_and_changed_inputs_do_not_replace_private_outputs(
    tmp_path: Path,
) -> None:
    approved = document()
    independent = independent_reader(str(approved["independent_server_id"]))
    setup.prepare(approved, independent, {"secret": CANARY}, output=tmp_path)
    before = {path: path.read_bytes() for path in tmp_path.glob("*.json")}
    setup.prepare(approved, independent, {"secret": CANARY}, output=tmp_path)
    with pytest.raises(LifecycleError, match="original bundle"):
        setup.prepare(approved, independent, {"secret": "changed"}, output=tmp_path)
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("fault", ["expiry", "server", "vault", "endpoint", "policy"])
def test_stage_rejects_mismatched_independent_access_or_missing_policy(
    tmp_path: Path, fault: str
) -> None:
    approved = document()
    independent = independent_reader(str(approved["independent_server_id"]))
    if fault == "expiry":
        independent.pop("approved_expires_at")
    elif fault == "server":
        approved["independent_server_id"] = "Z" * 26
    elif fault == "vault":
        mapping(independent["vaults"])["cleanup"] = "x" * 26
    elif fault == "endpoint":
        independent["url"] = "https://shared.example.test"
    else:
        mapping(approved["policy"]).pop("cleanup_reserve_seconds")
    with pytest.raises((ValueError, LifecycleError)):
        setup.prepare(approved, independent, {"secret": CANARY}, output=tmp_path)
    assert not list(tmp_path.glob("*.json"))
