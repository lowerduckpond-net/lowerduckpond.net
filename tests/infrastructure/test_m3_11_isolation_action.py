"""Protected diagnostic action reuses the actual native independent session."""

from __future__ import annotations

import io
import json
import os
import signal
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import m3_11_isolation_action as action
from scripts.m3_11_isolation_contract import Intent
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.connect_profile import projection
from scripts.m3_11_unattended.http import Api
from scripts.m3_11_unattended.model import digest

from .test_m3_11_connect_action import Case
from .test_m3_11_public_isolation import intents as intents  # noqa: PLC0414 - pytest fixture export
from .test_m3_11_public_isolation import plan as plan  # noqa: PLC0414 - pytest fixture export


def binding(case: Case, intents: tuple[Intent, ...]) -> Manifest:
    config = LeaseConfiguration.parse(case.bundle["configuration"])
    cleanup = config.generations[config.active_generation]["cleanup"].generation
    provision = case.config.generations[case.config.active_generation]["provision"].generation
    selected = replace(
        intents[0].plan,
        account_id=config.targets.account_id,
        zones={
            "lowerduckpond.net": config.targets.zone_id,
            "lowerduckpond.com": config.targets.tenant_zone_id,
        },
    )
    selected_intents = tuple(
        replace(
            item,
            plan=selected,
            issuer_authority_sha256=provision.fingerprints["cloudflare-account"],
            cleanup_authority_sha256=cleanup.fingerprints["cloudflare-account"],
        )
        for item in intents
    )
    _, access = reader_access(
        config.generations[config.active_generation]["cleanup"].reader_settings
    )
    return Manifest(
        selected_intents,
        digest(projection(config, identities=True)),
        config.journal_vault,
        config.independent_server_id,
        access.receipt(),
        provision,
        cleanup,
    )


def test_validation_is_get_only_preserves_existing_secret_and_historical_leases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, intents: tuple[Intent, ...]
) -> None:
    case = Case(tmp_path, monkeypatch)
    manifest = binding(case, intents)
    original = json.dumps(case.bundle, sort_keys=True)
    directory = tmp_path / "diagnostic"
    directory.mkdir(mode=0o700)
    posts = case.client.posts

    def account(*args: object, **kwargs: object) -> object:
        with pytest.raises(RuntimeError, match="read-only"):
            Api("https://api.cloudflare.com/client/v4", "synthetic").request(
                "POST", "/accounts/forbidden/tokens", {}
            )
        return object()

    monkeypatch.setattr(action, "account_provider", account)
    result = action.execute(
        {"bootstrap": case.bundle, "manifest": manifest.document(), "operation": "validate"},
        directory=directory,
        actor={"run_id": 12, "run_attempt": 1, "event": "workflow_dispatch"},
    )
    assert result["status"] == "ready" and result["temporary_runtime_closed"] is True
    assert result["journal_mutations"] is False
    assert case.client.posts == posts
    assert original == json.dumps(case.bundle, sort_keys=True)
    assert case.server_active is False
    assert "server_credentials" not in json.dumps(result)


def test_profile_mismatch_fails_before_starting_independent_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, intents: tuple[Intent, ...]
) -> None:
    case = Case(tmp_path, monkeypatch)
    manifest = replace(binding(case, intents), base_configuration_sha256="0" * 64)
    with pytest.raises(ValueError):
        action.execute(
            {"bootstrap": case.bundle, "manifest": manifest.document(), "operation": "validate"},
            directory=tmp_path,
            actor={"run_id": 12, "run_attempt": 1, "event": "workflow_dispatch"},
        )
    assert case.auth_attempts == 0 and not case.server_active


def test_sigterm_unwinds_native_connect_and_cannot_emit_closed_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, intents: tuple[Intent, ...]
) -> None:
    case = Case(tmp_path, monkeypatch)
    manifest = binding(case, intents)
    for key, value in {
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": action.REPOSITORY,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": action.REPOSITORY
        + "/.github/workflows/"
        + action.WORKFLOW
        + "@refs/heads/main",
        "M3_11_HELPER_REVISION": manifest.plan.source_revision,
        "GITHUB_RUN_ID": "12",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(action, "current_candidate", lambda *args: None)

    def cancel(*args: object, **kwargs: object) -> object:
        assert case.server_active
        os.kill(os.getpid(), signal.SIGTERM)
        raise AssertionError("signal handler did not interrupt")

    monkeypatch.setattr(action, "account_provider", cancel)
    raw = {"bootstrap": case.bundle, "manifest": manifest.document(), "operation": "validate"}
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(json.dumps(raw).encode())))
    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
    try:
        assert action.main() == 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    assert not case.server_active
    receipt = read_private(tmp_path / "m3-11-public-ca/receipt.json")
    assert receipt["status"] == "unresolved" and "temporary_runtime_closed" not in receipt


def test_action_transport_keeps_bootstrap_off_argv_env_and_logs(tmp_path: Path) -> None:
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    node = shutil.which("node")
    assert node is not None
    receiver = tmp_path / ".venv/bin/python"
    receiver.parent.mkdir(parents=True)
    canary = "synthetic-isolation-private-canary"
    receiver.write_text(f"""#!{sys.executable}
import json,os,sys
from pathlib import Path
value=json.load(sys.stdin)
Path('delivery.json').write_text(json.dumps({{
 'stdin':value['bootstrap']=={{'private':'{canary}'}},
 'environment':all(key not in os.environ for key in (
    'M3_11_CONNECT_BOOTSTRAP','M3_11_PUBLIC_CA_MANIFEST',
    'GH_TOKEN','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN')),
 'argv':'{canary}' not in str(sys.argv)
}}))
print('{canary}')
print('{canary}',file=sys.stderr)
""")
    receiver.chmod(0o700)
    environment = {
        **os.environ,
        "M3_11_CONNECT_BOOTSTRAP": json.dumps({"private": canary}),
        "M3_11_PUBLIC_CA_MANIFEST": "{}",
        "M3_11_PUBLIC_CA_OPERATION": "validate",
        "GH_TOKEN": canary,
        "GITHUB_TOKEN": canary,
        "ACTIONS_RUNTIME_TOKEN": canary,
    }
    source = Path(__file__).resolve().parents[2] / ".github/actions/m3-11-public-ca/index.js"
    result = subprocess.run(  # noqa: S603 - fixed local synthetic receiver
        [node, str(source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert all(json.loads((tmp_path / "delivery.json").read_bytes()).values())
    assert canary.encode() not in result.stdout + result.stderr
