"""Real provider adapters, exact token policies and lost journal responses."""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import subprocess
import sys
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
from scripts.m3_11_unattended import cleanup, cloudflare, config
from scripts.m3_11_unattended import production as isolated
from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.config import Bootstrap
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.journal import OnePassword, OpJournal, event
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import ROLES, Credential, LifecycleError, stamp
from scripts.m3_11_unattended.spaces import Spaces

from .test_m3_10_runtime_token import _ACCOUNT, _AUDIT, _RUNTIME, _SECRETS, _ZONES, TokenFixture
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
            # op 2.33 adds its empty built-in note when the template only
            # supplies a custom field, even when both IDs are notesPlain.
            if not any(field.get("purpose") == "NOTES" for field in item["fields"]):
                item["fields"].insert(
                    0,
                    {
                        "id": "notesPlain",
                        "type": "STRING",
                        "purpose": "NOTES",
                        "label": "notesPlain",
                    },
                )
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


def test_journal_creation_populates_the_builtin_note(tmp_path: Path) -> None:
    cli = JournalCli()
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    record = event("result", Case(tmp_path).run_id, {"setup": "independent-journal-read-write"})
    journal.append(record)
    assert journal.records() == [record]
    fields = next(iter(cli.items.values()))["fields"]
    assert isinstance(fields, list) and len(fields) == 1
    assert fields[0]["purpose"] == "NOTES"


@pytest.mark.parametrize("blank_value", [None, ""])
@pytest.mark.parametrize("reverse", [False, True])
def test_old_journal_notes_remain_readable_without_rewriting(
    tmp_path: Path, blank_value: str | None, reverse: bool
) -> None:
    cli = JournalCli()
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    record = event("result", Case(tmp_path).run_id, {"setup": "independent-journal-read-write"})
    # Preserve the exact old writer input and the real CLI's synthesized field.
    item = {
        "title": journal._title(record),
        "category": "SECURE_NOTE",
        "vault": {"id": "a" * 26},
        "tags": ["ldp-m3-11-credential-obligations-v1"],
        "fields": [
            {
                "id": "notesPlain",
                "type": "STRING",
                "label": "notesPlain",
                "value": json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            }
        ],
    }
    cli.command("item", "create", stdin=json.dumps(item).encode())
    stored = next(iter(cli.items.values()))
    fields = cast(list[dict[str, object]], stored["fields"])
    if blank_value is not None:
        fields[0]["value"] = blank_value
    if reverse:
        fields.reverse()
    original = copy.deepcopy(cli.items)
    assert journal.records() == [record]
    journal.refresh()
    assert journal.records() == [record]
    assert cli.items == original
    assert cli.creates == 1


@pytest.mark.parametrize(
    "defect",
    ["two-values", "same-value", "two-custom", "two-default", "whitespace", "wrong-purpose"],
)
def test_journal_duplicate_note_ambiguity_still_fails_closed(tmp_path: Path, defect: str) -> None:
    cli = JournalCli()
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    record = event("result", Case(tmp_path).run_id, {"test": "safe"})
    journal.append(record)
    item = next(iter(cli.items.values()))
    fields = cast(list[dict[str, object]], item["fields"])
    payload = fields[0]
    payload.pop("purpose")
    extra: dict[str, object] = {"id": "notesPlain", "type": "STRING", "purpose": "NOTES"}
    if defect == "two-values":
        extra["value"] = '{"another":"obligation"}\n'
    elif defect == "same-value":
        extra["value"] = cast(str, payload["value"])
    elif defect == "two-custom":
        extra.pop("purpose")
    elif defect == "two-default":
        payload["purpose"] = "NOTES"
    elif defect == "whitespace":
        extra["value"] = " "
    else:
        extra["purpose"] = "USERNAME"
    fields.insert(0, extra)
    with pytest.raises(LifecycleError, match="content"):
        journal.records()


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


def test_actual_independent_cleanup_entrypoint_recovers_after_failure_without_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = Case(tmp_path)
    journal = OpJournal(cast(OnePassword, JournalCli()), "a" * 26)
    case.lifecycle = Lifecycle(journal, {"spaces": case.provider}, clock=lambda: case.now)
    case.create()
    case.lifecycle.request_revocation(case.run_id)
    case.provider.fail_delete = True
    monkeypatch.setattr(
        cleanup, "cleanup_configuration", lambda _path: (TARGETS, "a" * 26, Bootstrap({}))
    )
    monkeypatch.setattr(cleanup, "connect_cleanup", lambda *_args, **_kwargs: case.lifecycle)
    monkeypatch.setattr(
        sys, "argv", ["cleanup", "--actor", "github", "--config", "/unused/private.json"]
    )
    for key, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "lowerduckpond-net/lowerduckpond.net",
    }.items():
        monkeypatch.setenv(key, value)
    assert cleanup.main() == 1
    assert CANARY not in capsys.readouterr().out
    case.provider.fail_delete = False
    assert cleanup.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert output["results"][0]["status"] == "verified"
    assert output["results"][0]["negative_authentication"] == "unavailable"
    assert not case.provider.items
    monkeypatch.setenv("GITHUB_REF", "refs/heads/untrusted")
    with pytest.raises(SystemExit) as stopped:
        cleanup.main()
    assert stopped.value.code == 1


def test_production_bootstrap_and_state_passphrase_stay_in_the_short_check_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Reader:
        def __init__(self, token: str) -> None:
            assert token == CANARY + "service-account"

        def read(self, reference: str) -> str:
            return CANARY + reference

    observed: dict[str, object] = {}

    def execute(command: list[str], **arguments: object) -> SimpleNamespace:
        observed.update(arguments)
        assert command[:3] == ["/bin/bash", "--noprofile", "--norc"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(isolated, "OnePassword", Reader)
    monkeypatch.setattr(subprocess, "run", execute)
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", CANARY + "ambient")
    request: dict[str, object] = {
        "service_account": CANARY + "service-account",
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
