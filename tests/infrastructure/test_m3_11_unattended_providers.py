"""Real provider adapters, exact token policies and lost journal responses."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]

from scripts import check_m3_10_provider as production
from scripts import m3_11_fixture_tokens as fixture
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import cloudflare, config, connect_configuration
from scripts.m3_11_unattended import production as isolated
from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.journal import _note_content
from scripts.m3_11_unattended.model import ROLES, Credential, LifecycleError, stamp
from scripts.m3_11_unattended.spaces import Spaces

from .test_m3_10_runtime_token import _ACCOUNT, _AUDIT, _RUNTIME, _SECRETS, _ZONES, TokenFixture
from .test_m3_11_lease_configuration import reader_document
from .test_m3_11_unattended_lifecycle import CANARY, TARGETS, Case


class Responses:
    credential_sha256 = "d" * 64

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


@pytest.mark.parametrize(
    ("code", "status", "denied"),
    [
        ("InvalidAccessKeyId", 403, True),
        ("InvalidAccessKeyId", 401, True),
        ("InvalidAccessKeyId", 503, False),
        ("AccessDenied", 403, False),
        ("SignatureDoesNotMatch", 403, False),
        ("NoSuchBucket", 404, False),
    ],
)
def test_spaces_revocation_requires_invalid_authentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str, status: int, denied: bool
) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    provider = Spaces(Responses().api())

    def probe(*_args: object) -> None:
        raise ClientError(
            {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
            "ListObjectsV2",
        )

    monkeypatch.setattr(provider, "_probe", probe)
    assert provider.denied(intent, credential) is denied
    # Even authenticated inventory absence cannot close a cleanup obligation
    # while the retained key only demonstrates loss of bucket authorization.
    monkeypatch.setattr(case.provider, "denied", provider.denied)
    case.lifecycle.request_revocation(case.run_id)
    result = case.lifecycle.sweep({intent.sha256: credential})[0]
    assert result.status == ("verified" if denied else "unresolved")


@pytest.mark.parametrize("account", [True, False])
@pytest.mark.parametrize("condition", [None, {}, {"request_ip": {"in": ["192.0.2.0/24"]}}, [], ""])
def test_cloudflare_authority_rejects_conditions_outside_its_expiry_boundary(
    account: bool, condition: object
) -> None:
    now = datetime.now(UTC)
    selected, permission = "f" * 32, "e" * 32
    name = "Account API Tokens Write" if account else "API Tokens Write"
    scope = "com.cloudflare.api.account" if account else "com.cloudflare.api.user"
    expiry = now + timedelta(days=7)
    details = {
        "id": selected,
        "status": "active",
        "expires_on": stamp(expiry),
        "condition": condition,
        "policies": [
            {
                "effect": "allow",
                "resources": {
                    scope + "." + (TARGETS.account_id if account else TARGETS.user_id): "*"
                },
                "permission_groups": [{"id": permission, "name": name}],
            }
        ],
    }
    api = Responses(
        *(
            Response(200, {"success": True, "result": value})
            for value in (
                {"id": selected, "status": "active"},
                details,
                [{"id": permission, "name": name, "scopes": [scope]}],
            )
        )
    )
    client = Cloudflare(api.api(), account=TARGETS.account_id if account else None)
    if condition in (None, {}):
        assert config._cloudflare_authority(client, target=TARGETS, now=now) == (
            selected,
            expiry,
        )
    else:
        with pytest.raises(LifecycleError, match="conditions"):
            config._cloudflare_authority(client, target=TARGETS, now=now)


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


@pytest.mark.parametrize("blank", [None, ""])
@pytest.mark.parametrize("reverse", [False, True])
def test_legacy_duplicate_builtin_note_remains_readable(blank: str | None, reverse: bool) -> None:
    fields = [
        {"id": "notesPlain", "type": "STRING", "purpose": "NOTES", "value": blank},
        {"id": "notesPlain", "type": "STRING", "value": "original-obligation"},
    ]
    if reverse:
        fields.reverse()
    original = copy.deepcopy(fields)
    assert _note_content(fields) == "original-obligation"
    assert fields == original


@pytest.mark.parametrize("defect", ["value", "purpose", "type", "section", "duplicate"])
def test_legacy_note_ambiguity_remains_rejected(defect: str) -> None:
    blank: dict[str, object] = {"id": "notesPlain", "type": "STRING", "purpose": "NOTES"}
    custom: dict[str, object] = {"id": "notesPlain", "type": "STRING", "value": "original"}
    fields = [blank, custom]
    if defect == "duplicate":
        fields.append(copy.deepcopy(custom))
    else:
        blank[defect] = "changed"
    with pytest.raises(LifecycleError, match="content"):
        _note_content(fields)


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


def test_production_bootstrap_and_state_passphrase_stay_in_the_short_check_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Reader:
        def read(self, reference: str) -> str:
            return CANARY + reference

    observed: dict[str, object] = {}

    def execute(command: list[str], **arguments: object) -> SimpleNamespace:
        observed.update(arguments)
        assert command[:3] == ["/bin/bash", "--noprofile", "--norc"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(connect_configuration, "reader", lambda _value: Reader())
    monkeypatch.setattr(subprocess, "run", execute)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", CANARY + "ambient")
    request: dict[str, object] = {
        "connect": reader_document("production", now=datetime.now(UTC).replace(microsecond=0)),
        "references": dict(zip(isolated.REFERENCES, isolated.REFERENCES, strict=True)),
        "targets": dataclasses.asdict(TARGETS),
        "binding": {},
        "output": str(tmp_path / "receipt.json"),
        "fixture": {
            key: "fixture-" + key
            for key in ("audit", "observer", "archive_id", "backup_id", "caddy_id")
        },
    }
    repository = tmp_path / "source"
    repository.mkdir()
    assert isolated.bootstrap(request, repository) == 0
    environment = observed["env"]
    assert isinstance(environment, dict)
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in environment
    assert CANARY + "service-account" not in environment.values()
    assert (
        environment["OPENTOFU_ENCRYPTION_PASSPHRASE"] == CANARY + "OPENTOFU_ENCRYPTION_PASSPHRASE"
    )
    assert CANARY.encode() not in cast(bytes, observed["input"])


def test_production_storage_probe_receives_only_actual_storage_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "source"
    repository.mkdir()
    output = tmp_path / "production.json"
    case = Case(tmp_path / "journal")
    binding = {
        "managed_run_id": case.run_id,
        "source_revision": "e" * 40,
        "helper_revision": "f" * 40,
        "artifact_sha256": "a" * 64,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": TARGETS.storage_digest,
    }
    for key, value in {
        **TARGETS.environment(),
        "OPENTOFU_ENCRYPTION_PASSPHRASE": CANARY,
        "OPENTOFU_STATE_SECRET_ACCESS_KEY": CANARY,
        "CADDY_CLOUDFLARE_API_TOKEN": CANARY,
        "SPACES_ARCHIVE_ACCESS_KEY_ID": "actual-archive",
        "SPACES_BACKUP_ACCESS_KEY_ID": "actual-backup",
        "SPACES_ARCHIVE_SECRET_ACCESS_KEY": "actual-archive-secret",
        "SPACES_BACKUP_SECRET_ACCESS_KEY": "actual-backup-secret",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(isolated, "current_candidate", lambda *_args: repository)
    monkeypatch.setattr(isolated, "fingerprint", lambda *_args: "b" * 64)
    monkeypatch.setattr(isolated, "check_caddy_token", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        isolated, "verify_active_account_token", lambda *_args, **_kwargs: "actual-caddy"
    )

    def execute(command: list[str], **arguments: object) -> SimpleNamespace:
        assert "credential-check" in command
        environment = arguments["env"]
        assert isinstance(environment, dict) and CANARY not in environment.values()
        assert not any(
            key.startswith(("OP_", "OPENTOFU_", "TF_VAR_", "AWS_")) for key in environment
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", execute)
    isolated.validate(
        {
            "targets": dataclasses.asdict(TARGETS),
            "binding": binding,
            "fixture_ids": {key: "fixture-" + key for key in ("archive", "backup", "caddy")},
            "started_at": stamp(datetime.now(UTC)),
            "output": str(output),
        },
        repository,
    )
    assert CANARY not in output.read_text()
    assert "actual-archive-secret" not in output.read_text()
