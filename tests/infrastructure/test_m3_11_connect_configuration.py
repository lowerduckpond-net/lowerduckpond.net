"""Private Connect role selection, production isolation and ambiguous-input rejection."""

from __future__ import annotations

import copy
import dataclasses
import json
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import connect_configuration as backend
from scripts.m3_11_unattended import production
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import READ, READ_WRITE, claims
from scripts.m3_11_unattended.model import LifecycleError, stamp

from .test_m3_11_connect_auth import CANARY, Endpoint, example, token
from .test_m3_11_unattended_lifecycle import TARGETS

VAULTS = {"provision": "v" * 26, "cleanup": "c" * 26, "production": "p" * 26, "journal": "j" * 26}


def mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def reader_config(role: str) -> dict[str, object]:
    entry, metadata, payload = example()
    now = datetime.now(UTC).replace(microsecond=0)
    expires = now + timedelta(days=7)
    native = cast(list[dict[str, object]], metadata["tokens"])[0]
    identifier = {"provision": "T", "cleanup": "U", "production": "V"}[role] * 26
    native.update(id=identifier, created_at=stamp(now), expires_at=stamp(expires))
    entry.update(expires_at=stamp(expires))
    payload.update(jti=identifier, iat=int(now.timestamp()), exp=int(expires.timestamp()))
    grants = {VAULTS[role]: READ}
    if role != "production":
        grants[VAULTS["journal"]] = READ_WRITE
    native["vaults"] = [
        {
            "id": vault.upper(),
            "acl": ["allow_viewing"] + (["allow_editing"] if acl == READ_WRITE else []),
        }
        for vault, acl in grants.items()
    ]
    payload["1password.com/vts"] = [{"u": vault.upper(), "a": acl} for vault, acl in grants.items()]
    token(entry, payload)
    return {
        "url": "https://connect.example.test",
        "role": role,
        "vaults": VAULTS,
        "entry": entry,
        "metadata": metadata,
    }


def document() -> dict[str, object]:
    witness = {
        "epoch": str(uuid.uuid7()),
        "helper": "e" * 40,
        "active_helper": "e" * 40,
        "server": "I" * 26,
        "author": "R" * 26,
        "genesis_id": "1",
        "genesis_sha256": "d" * 64,
    }
    common = {
        "format": backend.ROLE_FORMAT,
        "witness": witness,
        "initial": {str(uuid.uuid7()): "d" * 64},
        "anchor": "a" * 26,
        "anchor_sha256": "b" * 64,
        "independent_expires_at": stamp(datetime.now(UTC) + timedelta(days=5)),
    }
    result: dict[str, object] = {
        "format": "lowerduckpond-m3-11-controller-connect-v1",
        "targets": dataclasses.asdict(TARGETS),
        "journal_vault": VAULTS["journal"],
    }
    for role in ("provision", "cleanup"):
        result[role] = {
            **copy.deepcopy(common),
            "reader": reader_config(role),
            "values": {
                key: f"op://{VAULTS[role]}/{'i' * 26}/{key}" for key in backend.PROVIDER_REFERENCES
            },
        }
    result["production"] = {
        "connect": reader_config("production"),
        "references": {
            key: f"op://{VAULTS['production']}/{'i' * 26}/{key}" for key in production.REFERENCES
        },
    }
    return result


def load(tmp_path: Path, value: dict[str, object]) -> Configuration:
    path = tmp_path / "controller.json"
    write_private(path, value)
    return Configuration.load(path)


def test_explicit_backend_retains_only_cleanup_authority_in_watchdog_document(
    tmp_path: Path,
) -> None:
    value = document()
    configured = load(tmp_path, value)
    assert configured.provision.connect_settings is not None
    with pytest.raises(LifecycleError, match="fall back"):
        configured.provision.op()
    assert CANARY not in repr(configured)
    exported = json.dumps(configured.cleanup_document())
    for role in ("provision", "production"):
        selected = mapping(value[role])
        entry = mapping(mapping(selected["reader" if role == "provision" else "connect"])["entry"])
        assert str(entry["token"]) not in exported
    assert configured.cleanup.expires_at() < datetime.now(UTC) + timedelta(days=6)
    with pytest.raises(LifecycleError, match="persistent private"):
        configured.cleanup.journal(configured.journal_vault)


@pytest.mark.parametrize(
    "fault",
    [
        "missing-role",
        "swapped-role",
        "mixed-backend",
        "wrong-format",
        "production-reference",
        "duplicate-vault",
        "witness",
        "shared-witness",
        "native-policy",
        "http",
        "unexpected-secret",
    ],
)
def test_ambiguous_or_broader_inputs_never_fall_back(
    tmp_path: Path,
    fault: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    provision = mapping(value["provision"])
    selected = mapping(provision["reader"])
    if fault == "missing-role":
        del value["cleanup"]
    elif fault == "swapped-role":
        value["cleanup"] = copy.deepcopy(provision)
    elif fault == "mixed-backend":
        value["cleanup"] = {"service_account_token": CANARY}
    elif fault == "wrong-format":
        value["format"] = "lowerduckpond-m3-11-controller-config-v1"
    elif fault == "production-reference":
        mapping(mapping(value["production"])["references"])["OPENTOFU_ENCRYPTION_PASSPHRASE"] = (
            f"op://{VAULTS['provision']}/{'i' * 26}/secret"
        )
    elif fault == "duplicate-vault":
        selected["vaults"] = {**VAULTS, "production": VAULTS["provision"]}
    elif fault == "witness":
        mapping(mapping(value["cleanup"])["witness"])["helper"] = "f" * 40
    elif fault == "shared-witness":
        mapping(provision["witness"])["server"] = "S" * 26
    elif fault == "native-policy":
        native = cast(list[dict[str, object]], mapping(selected["metadata"])["tokens"])[0]
        native["vaults"] = []
    elif fault == "http":
        selected["url"] = "http://127.0.0.1:8080"
    else:
        provision["service_account_token"] = CANARY
    monkeypatch.setattr(
        "scripts.m3_11_unattended.config.OnePassword",
        lambda *_args: pytest.fail("no native fallback"),
    )
    with pytest.raises((ValueError, LifecycleError)) as error:
        load(tmp_path, value)
    assert CANARY not in str(error.value)


def test_connect_production_reader_and_bootstrap_are_confined_to_short_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = document()
    configured = load(tmp_path, value)

    def endpoint(_url: str, credential: str) -> Connect:
        client = Endpoint(credential)
        grants = cast(list[dict[str, object]], claims(credential)["1password.com/vts"])
        client.visible = {str(row["u"]).lower() for row in grants}
        return client

    monkeypatch.setattr(backend, "Connect", endpoint)
    monkeypatch.setattr(
        Endpoint, "read", lambda _self, reference: CANARY + reference.rsplit("/", 1)[-1]
    )
    monkeypatch.setattr(production, "OnePassword", lambda *_args: pytest.fail("no service account"))
    observed: dict[str, object] = {}

    def execute(command: list[str], **arguments: object) -> SimpleNamespace:
        assert command[:3] == ["/bin/bash", "--noprofile", "--norc"]
        observed.update(arguments)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", execute)
    request = {
        **configured.production,
        "targets": dataclasses.asdict(TARGETS),
        "binding": {},
        "output": str(tmp_path / "receipt.json"),
        "fixture": {
            key: "fixture-" + key
            for key in ("audit", "observer", "archive_id", "backup_id", "caddy_id")
        },
    }
    assert production.bootstrap(request, tmp_path) == 0
    environment = mapping(observed["env"])
    assert (
        environment["OPENTOFU_ENCRYPTION_PASSPHRASE"] == CANARY + "OPENTOFU_ENCRYPTION_PASSPHRASE"
    )
    assert not any("CONNECT" in key or "SERVICE_ACCOUNT" in key for key in environment)
    entry = mapping(mapping(configured.production["connect"])["entry"])
    assert entry["token"] not in environment.values()
    assert CANARY.encode() not in cast(bytes, observed["input"])
    assert b"op://" not in cast(bytes, observed["input"])
