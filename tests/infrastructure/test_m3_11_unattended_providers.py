"""Real provider adapters, exact token policies and lost journal responses."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts import check_m3_10_provider as production
from scripts import m3_11_fixture_tokens as fixture
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import cloudflare
from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.journal import OnePassword, OpJournal, event
from scripts.m3_11_unattended.model import ROLES, Credential, LifecycleError, stamp
from scripts.m3_11_unattended.spaces import Spaces

from .test_m3_10_runtime_token import _ACCOUNT, _AUDIT, _RUNTIME, _SECRETS, _ZONES, TokenFixture
from .test_m3_11_unattended_lifecycle import CANARY, Case


class Responses:
    def __init__(self, *values: Response) -> None:
        self.values = list(values)
        self.calls: list[tuple[str, str, dict[str, object] | None]] = []

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        self.calls.append((method, path, body))
        return self.values.pop(0)

    def api(self) -> Api:
        return cast(Api, self)


@pytest.mark.parametrize("defect", ["unauthenticated", "missing-total", "short-page", "duplicate"])
def test_spaces_inventory_never_turns_failed_or_partial_reads_into_absence(defect: str) -> None:
    item = {
        "access_key": "credential00001",
        "name": "fixture",
        "created_at": stamp(datetime.now(UTC)),
        "grants": [],
    }
    body: dict[str, object] = {"meta": {"total": 1}, "keys": [item]}
    status = 200
    if defect == "unauthenticated":
        status = 403
    elif defect == "missing-total":
        body["meta"] = {}
    elif defect == "short-page":
        body["keys"] = []
    else:
        body.update(meta={"total": 2}, keys=[item, item])
    provider = Spaces(Responses(Response(status, body)).api())
    with pytest.raises(LifecycleError):
        provider.inspect("credential00001")


def test_spaces_deletion_requires_explicit_provider_acknowledgement() -> None:
    provider = Spaces(Responses(Response(403, {})).api())
    with pytest.raises(LifecycleError):
        provider.delete("credential00001")


def test_page_rules_provisioning_audits_complete_permission_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = Case(tmp_path)
    original, _ = case.create()
    permission = "4" * 32
    expected: dict[str, object] = {
        "permissions": {permission: "Page Rules Read"},
        "resources": original.targets.zone_resources,
    }
    intent = dataclasses.replace(
        original,
        role="page-rules",
        provider="cloudflare-user",
        name=original.name.removesuffix("archive") + "page-rules",
        scope=expected,
    )
    token = {
        "id": "f" * 32,
        "name": intent.name,
        "issued_on": intent.requested_at,
        "expires_on": intent.deadline,
        "status": "active",
        "policies": [
            {
                "effect": "allow",
                "resources": original.targets.zone_resources,
                "permission_groups": [{"id": permission, "name": "Page Rules Read"}],
            }
        ],
    }
    verifier = Responses(
        Response(200, {"success": True, "result": {"id": "f" * 32, "status": "active"}})
    )
    monkeypatch.setattr(cloudflare, "Api", lambda *_args: verifier.api())
    client = Cloudflare(
        Responses(Response(200, {"success": True, "result": token})).api(), account=None
    )
    client.verify(intent, Credential("f" * 32, CANARY, {}), now=case.now)
    assert verifier.calls == [("GET", "/user/tokens/verify", None)]
    broadened = copy.deepcopy(token)
    policies = broadened["policies"]
    assert isinstance(policies, list) and isinstance(policies[0], dict)
    policies[0]["permission_groups"].append({"id": "5" * 32, "name": "Page Rules Write"})
    client = Cloudflare(
        Responses(Response(200, {"success": True, "result": broadened})).api(), account=None
    )
    with pytest.raises(LifecycleError, match="policy"):
        client.verify(intent, Credential("f" * 32, CANARY, {}), now=case.now)


@pytest.mark.parametrize("status", [401, 403, 404, 200])
def test_cloudflare_negative_authentication_is_not_a_missing_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    result = {"success": True, "result": {"id": credential.identifier, "status": "active"}}
    verifier = Responses(Response(status, result))
    monkeypatch.setattr(cloudflare, "Api", lambda *_args: verifier.api())
    client = Cloudflare(Responses().api(), account=None)
    assert client.denied(intent, credential) == (status in {401, 403})


class JournalCli:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, object]] = {}
        self.creates = 0
        self.lose_response = False

    def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
        assert CANARY not in " ".join(arguments)
        if arguments[:2] == ("item", "create"):
            assert stdin is not None
            self.creates += 1
            item = json.loads(stdin)
            selected = str(self.creates).zfill(26)
            item["id"], item["version"] = selected, 1
            self.items[selected] = item
            if self.lose_response:
                raise LifecycleError("lost creation response")
            return json.dumps(item).encode()
        if arguments[:2] == ("item", "get"):
            return json.dumps(self.items[arguments[2]]).encode()
        assert arguments[:2] == ("item", "list")
        return json.dumps(
            [
                {key: value for key, value in item.items() if key != "fields"}
                for item in self.items.values()
            ]
        ).encode()


def test_lost_op_item_creation_is_reconciled_once_and_edits_fail_closed(tmp_path: Path) -> None:
    cli = JournalCli()
    cli.lose_response = True
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    record = event("result", Case(tmp_path).run_id, {"test": "safe"})
    journal.append(record)
    assert cli.creates == 1
    assert journal.records() == [record]
    journal.refresh()
    assert journal.records() == [record]
    next(iter(cli.items.values()))["version"] = 2
    journal.refresh()
    with pytest.raises(LifecycleError, match="edited"):
        journal.records()


class FixtureTokens(TokenFixture):
    def __init__(self, now: datetime) -> None:
        super().__init__(None)
        self.now = now

    def response(self, role: str, path: str, query: dict[str, str] | None) -> object:
        if role == "edge" and path.startswith("/zones/"):
            return super().response("caddy", path, query)
        if role == "edge" and path.endswith("/verify"):
            return {"id": "9" * 32, "status": "active"}
        if path.endswith("/permission_groups") and query == {"name": "DNS Read"}:
            return [
                {"id": "4" * 32, "name": "DNS Read", "scopes": ["com.cloudflare.api.account.zone"]}
            ]
        if path.endswith("/" + "9" * 32):
            return {
                "id": "9" * 32,
                "status": "active",
                "issued_on": stamp(self.now - timedelta(days=1)),
                "expires_on": stamp(self.now + timedelta(hours=14)),
                "policies": [
                    {
                        "effect": "allow",
                        "resources": {
                            f"com.cloudflare.api.account.zone.{zone}": "*" for zone in _ZONES
                        },
                        "permission_groups": [
                            {"id": "1" * 32, "name": "Zone Read"},
                            {"id": "4" * 32, "name": "DNS Read"},
                        ],
                    }
                ],
            }
        value = super().response(role, path, query)
        if isinstance(value, dict) and "expires_on" in value:
            value["expires_on"] = stamp(self.now + timedelta(hours=14))
        return value


def test_expiring_caddy_passes_only_fixture_validator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    responses = FixtureTokens(now)
    monkeypatch.setattr(fixture, "CloudflareClient", responses.client)
    monkeypatch.setattr(production, "CloudflareClient", responses.client)
    identities = dict.fromkeys(ROLES, "0" * 64)
    identities.update(
        {
            role: hashlib.sha256(value.encode()).hexdigest()
            for role, value in {
                "audit": _AUDIT,
                "caddy": _RUNTIME,
                "observer": "9" * 32,
                "page-rules": "f" * 32,
            }.items()
        }
    )
    path = tmp_path / "managed.json"
    write_private(
        path, {"receipts": {"production": {}, "fixture": {"identities_sha256": identities}}}
    )
    environment = {
        "CLOUDFLARE_API_TOKEN": _SECRETS["edge"],
        "CADDY_CLOUDFLARE_API_TOKEN": _SECRETS["caddy"],
        "M3_10_TOKEN_AUDIT_TOKEN": _SECRETS["audit"],
        "M3_10_PAGE_RULES_TOKEN": _SECRETS["pages"],
        "CLOUDFLARE_ZONE_ID": "b" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "c" * 32,
        "LDP_M3_11_MANAGED_INPUTS": str(path),
    }
    fixture.check_fixture_tokens(
        environment, account_id=_ACCOUNT, now=now, minimum_remaining=timedelta(hours=12)
    )
    with pytest.raises(ProductionEdgePreflightError):
        production.check_caddy_token(environment, account_id=_ACCOUNT, now=now)
