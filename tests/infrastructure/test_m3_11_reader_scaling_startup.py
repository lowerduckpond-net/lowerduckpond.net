"""Both real successor entrypoints at journal scale, with synthetic external services.

These regressions establish integration and request counts, not live readiness,
actual authentication signatures, or tested CREATE permission.
"""

from __future__ import annotations

import base64
import json
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import connect_action, connect_activate, operator_publish
from scripts.m3_11_unattended.journal import (
    MIGRATION_FORMAT,
    MIGRATION_TAG,
    TAG,
    event,
    record_title,
)
from scripts.m3_11_unattended.model import LifecycleError, digest, stamp

from .operator_flow_support import SOURCE, Services
from .operator_provider_support import Cloud
from .test_m3_11_connect_host import DockerDouble
from .test_m3_11_lease_configuration import mapping

ITEM_COUNT = 2276


def stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Services, Path, DockerDouble]:
    services = Services(monkeypatch)
    for raw in mapping(services.manifest["clients"]).values():
        client = mapping(raw)
        reference = str(client["reference"])
        header, encoded, _ = services.operator.secrets[reference].split(".")
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        claims["aud"] = [claims["aud"]]
        claims["exp"] -= 1
        client["expires_at"] = stamp(datetime.fromtimestamp(claims["exp"], UTC))
        for grant in claims["1password.com/vts"]:
            if grant["a"] == 1008:  # noqa: PLR2004 - observed journal grant representation
                grant["a"] = 496
        encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(b"s" * 64).decode().rstrip("=")
        services.operator.secrets[reference] = header + "." + encoded + "." + signature
    imported: dict[str, object] = {
        "format": MIGRATION_FORMAT,
        "records": {},
        "obligations": {},
        "retained_files": {},
        "expiry_updates": [],
        "issuers": [],
        "approved_at": stamp(datetime.now(UTC)),
        "approval_reference": "SYNTHETIC-EMPTY-IMPORT",
    }
    services.manifest["migration_sha256"] = digest(imported)
    manifest, staged, expected = services.stage(tmp_path)
    proposal = operator_publish.run(
        manifest=manifest,
        directory=staged,
        expected=expected,
        state=tmp_path / "metadata",
        apply=False,
    )
    operator_publish.run(
        manifest=manifest,
        directory=staged,
        expected=expected,
        state=tmp_path / "metadata",
        apply=True,
        expected_proposal=digest(proposal),
    )
    Cloud(services, monkeypatch)
    vault = str(read_private(staged / "controller-connect.json")["journal_vault"])
    run = str(uuid.uuid7())
    for number in range(ITEM_COUNT):
        value = imported if number == 0 else event("heartbeat", run, {"synthetic_sequence": number})
        identity = f"{number:026d}"
        services.items[vault, identity] = {
            "id": identity,
            "vault": {"id": vault},
            "title": "m3-11-import-" + digest(imported) if number == 0 else record_title(value),
            "category": "SECURE_NOTE",
            "version": 1,
            "tags": [MIGRATION_TAG if number == 0 else TAG],
            "fields": [
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "value": canonical_bytes(value).decode(),
                }
            ],
        }
    original = services.connect

    def connect(request: dict[str, object]) -> dict[str, object]:
        assert request["method"] == "GET"
        response = original(request)
        if str(request["url"]).endswith("/items") and response["status"] == 200:  # noqa: PLR2004
            response["body"] = [
                {key: value for key, value in item.items() if key != "fields"}
                for item in cast(list[dict[str, object]], response["body"])
            ]
        return response

    monkeypatch.setattr(services, "connect", connect)
    docker = DockerDouble()

    def docker_transport(args: list[str], stdin: bytes | None) -> bytes:
        if args[:2] == ["context", "inspect"]:
            return b"unix:///synthetic/docker.sock\n"
        return docker.command(*args, stdin=stdin, timeout=120)

    services.docker_handler = docker_transport
    services.exchanges.clear()
    return services, staged, docker


def test_both_actual_startup_paths_fetch_each_body_once_per_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services, staged, docker = stage(tmp_path, monkeypatch)
    assert connect_activate.activate(staged)["status"] == "ready"
    directory = tmp_path / "independent"
    directory.mkdir(mode=0o700)
    result = connect_action.execute(
        {"bootstrap": read_private(staged / "github-connect.json"), "operation": "cleanup"},
        directory=directory,
        helper=SOURCE,
    )
    assert result["status"] == "ready"
    assert not docker.objects
    vault = str(read_private(staged / "controller-connect.json")["journal_vault"])
    counts: Counter[str] = Counter()
    lists: Counter[str] = Counter()
    for request in services.exchanges:
        url = urlsplit(str(request["url"]))
        identity = "independent" if url.hostname == "127.0.0.1" else "shared"
        if url.path.startswith("/v1/vaults/" + vault + "/items/"):
            counts[identity] += 1
        if url.path == "/v1/vaults/" + vault + "/items":
            lists[identity] += 1
        assert request["method"] == "GET"
    assert counts == {"shared": ITEM_COUNT, "independent": ITEM_COUNT}
    assert lists["shared"] > 1 and lists["independent"] > 1
    authentication = read_private(directory / "authentication.json")
    assert authentication["authenticated"] is True
    assert authentication["create_verified"] is False


def test_independent_permission_failure_cannot_reuse_shared_activation_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services, staged, docker = stage(tmp_path, monkeypatch)
    assert connect_activate.activate(staged)["status"] == "ready"
    original = services.connect

    def denied(request: dict[str, object]) -> dict[str, object]:
        if str(request["url"]).startswith("http://127.0.0.1"):
            services.exchanges.append(request)
            return {"status": 403, "body": None}
        return original(request)

    monkeypatch.setattr(services, "connect", denied)
    monkeypatch.setattr(connect_action, "SYNC_SECONDS", 0)
    directory = tmp_path / "independent"
    directory.mkdir(mode=0o700)
    with pytest.raises(LifecycleError):
        connect_action.execute(
            {"bootstrap": read_private(staged / "github-connect.json"), "operation": "cleanup"},
            directory=directory,
            helper=SOURCE,
        )
    assert not (directory / "cleanup.json").exists()
    assert not docker.objects
    assert all(request["method"] == "GET" for request in services.exchanges)
