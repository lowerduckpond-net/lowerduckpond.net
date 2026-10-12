"""Pinned vendor HTTP schemas plus synthetic subprocess contract checks; entirely offline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import jsonschema
import pytest
import yaml  # type: ignore[import-untyped]

from scripts.m3_11_unattended import connect_host, operator_publish
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.model import digest

from .operator_flow_support import Services

FIXTURES = Path(__file__).parent / "fixtures/onepassword"
SPEC_URI = "https://synthetic-contract.invalid/connect-api-1.8.1"


def validate(schema: dict[str, object], value: object) -> None:
    specification = yaml.safe_load((FIXTURES / "connect-api-1.8.1.yaml").read_bytes())
    jsonschema.Draft7Validator({**schema, "components": specification["components"]}).validate(
        value
    )


def test_pinned_schema_provenance_distinguishes_images_and_synthetic_native_dependencies() -> None:
    provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
    assert (
        hashlib.sha256((FIXTURES / "connect-api-1.8.1.yaml").read_bytes()).hexdigest()
        == provenance["schema"]["sha256"]
    )
    assert provenance["connect_images"] == {
        "api": connect_host.API_IMAGE,
        "sync": connect_host.SYNC_IMAGE,
    }
    assert provenance["cli_version"] == operator_publish.CLI_VERSION
    assert provenance["genuine_response_captures"] == []


def test_actual_http_serializers_and_responses_match_pinned_vendor_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    services = Services(monkeypatch)
    manifest, staged, expected = services.stage(tmp_path)
    proposal = operator_publish.run(
        manifest=manifest,
        directory=staged,
        expected=expected,
        state=tmp_path / "state",
        apply=False,
    )
    operator_publish.run(
        manifest=manifest,
        directory=staged,
        expected=expected,
        state=tmp_path / "state",
        apply=True,
        expected_proposal=digest(proposal),
    )
    # Validate actual application-produced requests, not an independently hand-written note.
    import uuid  # noqa: PLC0415

    from scripts.m3_11_unattended.config import LeaseConfiguration  # noqa: PLC0415
    from scripts.m3_11_unattended.connect_activate import publish_original  # noqa: PLC0415
    from scripts.m3_11_unattended.journal import ConnectObligations, event  # noqa: PLC0415

    config = LeaseConfiguration.load(staged / "controller-connect.json")
    client = config.generations[config.active_generation]["cleanup"].reader()
    journal = ConnectObligations(
        client, config.journal_vault, spool=tmp_path / "pending", expected=config.migration_sha256
    )
    publish_original(journal, event("heartbeat", str(uuid.uuid7()), {"synthetic": True}))
    spec = yaml.safe_load((FIXTURES / "connect-api-1.8.1.yaml").read_bytes())
    operation = spec["paths"]["/vaults/{vaultUuid}/items"]["post"]
    requests = [value for value in services.exchanges if value["method"] == "POST"]
    assert len(requests) == 1
    validate(operation["requestBody"]["content"]["application/json"]["schema"], requests[0]["body"])
    response = next(
        row for (vault, _identifier), row in services.items.items() if vault == config.journal_vault
    )
    validate(operation["responses"]["200"]["content"]["application/json"]["schema"], response)
    for item in services.items.values():
        validate({"$ref": "#/components/schemas/FullItem"}, item)
    with pytest.raises(jsonschema.ValidationError):
        validate(
            {"$ref": "#/components/schemas/FullItem"}, {**response, "category": "not-a-category"}
        )
    with pytest.raises(jsonschema.ValidationError):
        validate(
            {"$ref": "#/components/schemas/FullItem"},
            {**response, "fields": [{"id": "field", "type": "UNKNOWN"}]},
        )


@pytest.mark.parametrize("status", [200, 201, 401, 403, 404, 429, 500])
def test_real_transport_status_contract_and_sanitized_failures(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    import subprocess  # noqa: PLC0415

    from scripts.m3_11_unattended.model import LifecycleError  # noqa: PLC0415

    def response(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        request = json.loads(cast(bytes, kwargs["input"]))
        assert request["method"] == "GET" and "SYNTHETIC-CONNECT-TOKEN" not in arguments
        return subprocess.CompletedProcess(
            arguments,
            0,
            json.dumps({"status": status, "body": []}).encode(),
            b"SYNTHETIC-SENSITIVE-STDERR",
        )

    monkeypatch.setattr(subprocess, "run", response)
    client = Connect("https://example.test", "SYNTHETIC-CONNECT-TOKEN")
    if status in {429, 500}:
        with pytest.raises(LifecycleError) as error:
            client.request("GET", "/v1/vaults")
        assert "SYNTHETIC" not in str(error.value)
    else:
        assert client.request("GET", "/v1/vaults").status == status
