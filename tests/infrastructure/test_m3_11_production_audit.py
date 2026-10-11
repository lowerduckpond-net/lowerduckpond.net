"""Exercise the worker's private production boundary with real token validators."""

from __future__ import annotations

import dataclasses
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import check_m3_10_provider as provider
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError
from scripts.m3_11_unattended import cleanup, connect_configuration, inputs, production, worker
from scripts.m3_11_unattended.config import LeaseBootstrap
from scripts.m3_11_unattended.inventory import ConnectInventory
from scripts.m3_11_unattended.model import ROLES, Credential, LeasePolicy, LifecycleError, instant

from .test_m3_10_runtime_token import _AUDIT, _SECRETS, TokenFixture
from .test_m3_11_connect_action import Case, attempt
from .test_m3_11_lease_inventory import ConnectDouble
from .test_m3_11_unattended_providers import audit_lease_receipt


def controller(
    root: Path, monkeypatch: pytest.MonkeyPatch, *, reuse: bool = False
) -> tuple[worker.Worker, dict[str, Credential], dict[str, object]]:
    case = Case(root, monkeypatch)
    directory, binding = attempt(case)
    issued = datetime.now(UTC) - timedelta(days=2) if reuse else None
    lease = audit_lease_receipt(binding, issued=issued)
    receipt = cast(dict[str, object], lease["receipt"])
    policy = LeasePolicy.parse(receipt["lease_policy"])
    config = dataclasses.replace(case.config, policy=policy, approved_policy_sha256=policy.sha256)
    selected = worker.Worker(directory, config, root / "source")
    credentials = {
        role: Credential(
            _AUDIT if role == "audit" else "fixture-" + role,
            _SECRETS["audit"] if role == "audit" else _SECRETS["edge"],
            {},
        )
        for role in ROLES
    }
    return selected, credentials, receipt


def transport(
    selected: worker.Worker,
    monkeypatch: pytest.MonkeyPatch,
    tokens: TokenFixture,
) -> list[str]:
    """Replace external I/O only; execute both production entrypoints and all token checks."""
    stages: list[str] = []

    class Reader:
        def read(self, reference: str) -> str:
            stages.append("production-read")
            name = reference.rsplit("/", 1)[-1]
            return _SECRETS["caddy"] if name == "CADDY_CLOUDFLARE_API_TOKEN" else "test-" + name

    def command(_command: list[str], *, log: str, stdin: bytes) -> None:
        assert log == "production-check.log"
        production.bootstrap(json.loads(stdin), selected.source)

    def execute(command: list[str], **arguments: object) -> SimpleNamespace:
        if command[0] == "/bin/bash":
            stages.append("state-reader")
            environment = cast(dict[str, str], arguments["env"])
            assert not any(key.startswith(("OP_", "LDP_BOOTSTRAP_")) for key in environment)
            with monkeypatch.context() as child:
                for key, value in environment.items():
                    child.setenv(key, value)
                for role in ("ARCHIVE", "BACKUP"):
                    child.setenv(f"SPACES_{role}_ACCESS_KEY_ID", "production-" + role)
                    child.setenv(f"SPACES_{role}_SECRET_ACCESS_KEY", "test-secret-" + role)
                production.validate(json.loads(cast(bytes, arguments["input"])), selected.source)
        else:
            assert "credential-check" in command
            stages.append("storage-probe")
            environment = cast(dict[str, str], arguments["env"])
            assert not any(key.startswith(("OP_", "OPENTOFU_")) for key in environment)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(selected, "_command", command)
    monkeypatch.setattr(connect_configuration, "reader", lambda _value: Reader())
    monkeypatch.setattr(production, "current_candidate", lambda *_args: selected.source)
    monkeypatch.setattr(production, "fingerprint", lambda *_args: "b" * 64)
    monkeypatch.setattr(production, "CloudflareClient", tokens.client)
    monkeypatch.setattr(provider, "CloudflareClient", tokens.client)
    monkeypatch.setattr(subprocess, "run", execute)
    return stages


@pytest.mark.parametrize("reuse", [False, True])
def test_worker_production_accepts_approved_fourteen_day_audit_and_retained_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reuse: bool
) -> None:
    selected, credentials, receipt = controller(tmp_path, monkeypatch, reuse=reuse)
    tokens = TokenFixture(None, audit_overrides={"expires_on": receipt["deadline"]})
    stages = transport(selected, monkeypatch, tokens)
    result = selected._production(credentials, receipt)
    assert result["checks"] == inputs.PRODUCTION_RESULT
    assert result["source_revision"] == selected.binding["source_revision"]
    assert result["managed_run_id"] == selected.run_id
    assert stages[-1] == "storage-probe"
    assert (
        "audit",
        f"/accounts/{selected.config.targets.account_id}/tokens/{_AUDIT}",
    ) in tokens.calls
    assert selected.config.policy.cleanup_reserve_seconds == 7 * 24 * 3600
    if reuse:
        assert instant(selected.config.policy.issuance_before) < datetime.now(UTC)
        assert result["helper_revision"] == selected.binding["helper_revision"]


@pytest.mark.parametrize("fault", ["unapproved", "deadline", "old-attempt", "legacy"])
def test_invalid_lease_receipt_cannot_read_production_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    selected, credentials, receipt = controller(tmp_path, monkeypatch)
    stages = transport(selected, monkeypatch, TokenFixture(None))
    if fault == "unapproved":
        selected.config = dataclasses.replace(selected.config, approved_policy_sha256="0" * 64)
    elif fault == "deadline":
        receipt["deadline"] = receipt["completed_at"]
    elif fault == "old-attempt":
        receipt["source_revision"] = "0" * 40
    else:
        receipt["format"] = "lowerduckpond-m3-11-fixture-credentials-v1"
    with pytest.raises((LifecycleError, ValueError)):
        selected._production(credentials, receipt)
    assert stages == []


@pytest.mark.parametrize(
    "fault",
    [
        "expiry-shorter",
        "expiry-longer",
        "identity",
        "not-yet-valid",
        "caddy-expiring",
        "caddy-scope",
    ],
)
def test_approved_lease_still_rejects_wrong_native_audit_or_production_caddy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    selected, credentials, receipt = controller(tmp_path, monkeypatch)
    expiry = instant(receipt["deadline"])
    overrides: dict[str, object] = {"expires_on": receipt["deadline"]}
    defect = None
    if fault.startswith("expiry-"):
        overrides["expires_on"] = (
            expiry + timedelta(seconds=1 if fault == "expiry-longer" else -1)
        ).isoformat()
    elif fault == "identity":
        cast(dict[str, str], receipt["identities_sha256"])["audit"] = "0" * 64
    elif fault == "not-yet-valid":
        overrides["not_before"] = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    else:
        defect = "runtime-expiry" if fault == "caddy-expiring" else "excess-permission"
    stages = transport(selected, monkeypatch, TokenFixture(defect, audit_overrides=overrides))
    with pytest.raises(ProductionEdgePreflightError):
        selected._production(credentials, receipt)
    assert "state-reader" in stages
    assert "storage-probe" not in stages


def test_unapproved_policy_is_rejected_before_any_provider_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected, _credentials, _receipt = controller(tmp_path, monkeypatch)
    selected.config = dataclasses.replace(selected.config, approved_policy_sha256="0" * 64)
    selected.lease_id = selected.run_id
    inventory = ConnectInventory(
        ConnectDouble(selected.config.journal_vault),
        selected.config.journal_vault,
        spool=tmp_path / "pending",
    )
    monkeypatch.setattr(selected, "_inventory", lambda: inventory)
    monkeypatch.setattr(cleanup, "sweep_legacy", lambda *_args, **_kwargs: {"status": "ready"})
    provider_access = []

    def providers(_self: LeaseBootstrap, **_kwargs: object) -> dict[str, object]:
        provider_access.append(True)
        pytest.fail("unapproved issuance reached a provider")

    monkeypatch.setattr(LeaseBootstrap, "providers", providers)
    with pytest.raises(LifecycleError, match="unapproved"):
        selected._provision()
    assert provider_access == []
    assert inventory.records() == []
