"""Protected cleanup selection, real protocol integration and sanitized delivery."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_connect_admission import Case as AdmissionCase
from infrastructure.test_m3_11_connect_genesis import Case as GenesisCase
from infrastructure.test_m3_11_connect_journal import sync
from infrastructure.test_m3_11_connect_ledger import REMOTE_AUTHOR, REMOTE_SERVER
from infrastructure.test_m3_11_unattended_lifecycle import CANARY, TARGETS, ProviderDouble
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_genesis as genesis
from scripts.m3_11_unattended.config import Connections
from scripts.m3_11_unattended.connect_admission import run_digest
from scripts.m3_11_unattended.connect_auth import Access
from scripts.m3_11_unattended.github_checkpoint import (
    MINIMUM_START_CAPACITY,
    REPOSITORY,
    WORKFLOW,
    GitHubArtifacts,
)
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import Authority, LifecycleError, digest


def selected(case: GenesisCase) -> dict[str, object]:
    return {
        "format": action.FORMAT,
        "stage": "active",
        "request": case.approved,
        "receipt": case.initialize(),
    }


def test_discovery_shared_forgery_genesis_and_recovery_use_real_adapters(tmp_path: Path) -> None:
    case = GenesisCase(tmp_path)
    forged = cast(dict[str, object], case.approved["shared_forgery_probe"])
    # Remove the pre-staged forgery to exercise the actual required order.
    for replica in (case.journal.shared, case.journal.remote):
        for key, item in list(replica.items.items()):
            if str(forged["event_id"]) in json.dumps(item):
                del replica.items[key]
                replica.version += 1
    initial = cast(dict[str, str], case.approved["initial"])
    initial.pop(str(forged["event_id"]))
    request = {key: value for key, value in case.approved.items() if key != "shared_forgery_probe"}
    request["format"] = genesis.DISCOVERY_FORMAT
    discovery = genesis.discover(
        case.ledger,
        request,
        helper=case.journal.witness.helper,
        server=REMOTE_SERVER,
        now=case.now,
    )
    assert discovery["independent_author"] == REMOTE_AUTHOR
    sync(case.journal.remote, case.journal.shared)
    local = case.journal.local()
    forged = event(
        "run",
        case.epoch,
        {
            "format": genesis.PROBE_FORMAT,
            "epoch": case.epoch,
            "actor": "shared-forgery",
            "claimed_author": discovery["independent_author"],
        },
    )
    local.ledger.stage(forged, claimed_author=str(discovery["independent_author"]))
    sync(case.journal.shared, case.journal.remote)
    case.approved["shared_forgery_probe"] = forged
    initial[str(forged["event_id"])] = digest(forged)
    value = selected(case)
    assert action.selection(value, helper=case.journal.witness.helper) == value
    access = Access(REMOTE_SERVER, "T" * 26, "A" * 26, case.now + timedelta(days=7), {}, CANARY)
    store = cast(GitHubArtifacts, case.store)
    store.remaining_capacity = lambda: MINIMUM_START_CAPACITY + 10  # type: ignore[method-assign]
    journal = action.restore(case.ledger, store, value, access)
    receipt = cast(dict[str, object], value["receipt"])
    assert journal.checkpoint.records.keys() == cast(dict[str, str], receipt["initial"]).keys()


@pytest.mark.parametrize(
    "fault", ["subset", "author", "shared-forgery", "request", "helper", "mixed-stage"]
)
def test_activation_requires_exact_complete_genesis_and_both_provenance_probes(
    tmp_path: Path,
    fault: str,
) -> None:
    case = GenesisCase(tmp_path)
    value = selected(case)
    receipt = cast(dict[str, object], value["receipt"])
    if fault == "subset":
        cast(dict[str, str], receipt["initial"]).popitem()
    elif fault == "author":
        receipt["independent_author"] = receipt["shared_author"]
    elif fault == "shared-forgery":
        receipt["shared_forged_author_ignored"] = False
    elif fault == "request":
        receipt["request_sha256"] = "0" * 64
    elif fault == "helper":
        receipt["helper_revision"] = "0" * 40
    else:
        value["stage"] = "genesis"
    with pytest.raises(LifecycleError):
        action.selection(value, helper=case.journal.witness.helper)


def reconcile(
    case: AdmissionCase, provider: ProviderDouble, *, expected: str = "", fail: bool = False
) -> dict[str, object]:
    def connections() -> Connections:
        if fail:
            raise LifecycleError(CANARY)
        return Connections(case.journal.github, {"spaces": provider}, case.authority)

    return action.reconcile(
        case.journal.github,
        connections,
        targets=TARGETS,
        request_sha256=expected,
        run_id=50,
        attempt=1,
        fallback=lambda: Lifecycle(case.journal.github, {"spaces": provider}),
    )


def test_protected_witness_reserves_and_acknowledges_only_the_dispatched_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = AdmissionCase(tmp_path)
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    provider = ProviderDouble()
    result = reconcile(case, provider, expected=run_digest(case.run_id, case.payload))
    sync(case.journal.remote, case.journal.shared)
    assert result["status"] == "ready" and case.journal.controller.confirmed(case.run)
    assert provider.creates == 0
    ready = [
        r
        for r in case.journal.controller.records()
        if cast(dict[str, object], r["payload"]).get("format") == action.READY_FORMAT
    ]
    assert len(ready) == 1 and case.journal.controller.confirmed(ready[0])


def test_reconciliation_without_dispatch_cannot_admit_creation(tmp_path: Path) -> None:
    case = AdmissionCase(tmp_path)
    result = reconcile(case, ProviderDouble())
    sync(case.journal.remote, case.journal.shared)
    assert result["status"] == "ready" and not case.journal.controller.confirmed(case.run)


def test_unresolved_existing_intent_blocks_new_reservation_before_any_creation_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = AdmissionCase(tmp_path)
    case.intent()
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    with pytest.raises(LifecycleError, match="outstanding credential obligations"):
        reconcile(case, ProviderDouble(), expected=run_digest(case.run_id, case.payload))
    sync(case.journal.remote, case.journal.shared)
    assert not case.journal.controller.confirmed(case.run)


@pytest.mark.parametrize("fault", ["policy-unavailable", "expires-soon"])
def test_unverified_authority_keeps_cleanup_available_but_disallows_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    case = AdmissionCase(tmp_path)
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    if fault == "expires-soon":
        case.authority = Authority("d" * 64, datetime.now(UTC) + timedelta(hours=14))
    result = reconcile(
        case,
        ProviderDouble(),
        expected=run_digest(case.run_id, case.payload),
        fail=fault == "policy-unavailable",
    )
    sync(case.journal.remote, case.journal.shared)
    assert result["status"] == "unresolved"
    assert not case.journal.controller.confirmed(case.run)
    assert CANARY not in json.dumps(result)


def test_failed_provider_read_and_expired_bootstrap_never_erase_cleanup_obligation(
    tmp_path: Path,
) -> None:
    case = AdmissionCase(tmp_path)
    intent = case.intent()
    provider = ProviderDouble()
    provider.fail_read = True
    result = reconcile(case, provider, fail=True)
    assert result["status"] == "unresolved"
    assert intent in case.journal.github.checkpoint.records.values()
    assert CANARY not in json.dumps(result)


def test_secret_canary_cannot_escape_the_action_error_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main",
    )
    monkeypatch.setenv("M3_11_HELPER_REVISION", "a" * 40)

    def fail(*_args: object) -> None:
        raise ValueError(CANARY)

    monkeypatch.setattr(action, "current_candidate", fail)
    assert action.main() == 1
    receipt = read_private(tmp_path / "m3-11-connect/receipt.json")
    assert receipt["status"] == "unresolved"
    captured = capsys.readouterr()
    assert CANARY not in json.dumps(receipt) + captured.out + captured.err


@pytest.mark.parametrize("fail", [False, True])
def test_real_main_atomically_replaces_progress_and_final_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail: bool,
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPOSITORY)
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF", f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main"
    )
    monkeypatch.setenv("M3_11_HELPER_REVISION", "a" * 40)
    monkeypatch.setattr(action, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"{}")))

    def execute(
        _payload: object,
        *,
        directory: Path,
        helper: str,
        progress: Callable[[str], None],
    ) -> dict[str, object]:
        for phase in (
            "start-independent-connect",
            "authenticate-independent-connect",
            "reconcile-and-witness",
        ):
            progress(phase)
            assert read_private(directory / "receipt.json")["phase"] == phase
        if fail:
            raise ValueError(CANARY)
        return {"format": action.RECEIPT_FORMAT, "status": "ready", "helper_revision": helper}

    monkeypatch.setattr(action, "execute", execute)
    assert action.main() == int(fail)
    final = read_private(tmp_path / "m3-11-connect/receipt.json")
    assert final["status"] == ("unresolved" if fail else "ready")
    assert CANARY not in json.dumps(final)


def test_javascript_action_delivers_stdin_without_bootstrap_in_child_environment_or_logs(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    assert node is not None
    receiver = tmp_path / ".venv/bin/python"
    receiver.parent.mkdir(parents=True)
    receiver.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
value = json.load(sys.stdin)
Path("delivery.json").write_text(json.dumps({{
    "received": value["bootstrap"] == {{"token": "{CANARY}"}},
    "environment_clean": all(key not in os.environ for key in (
        "M3_11_CONNECT_BOOTSTRAP", "M3_11_CONNECT_CONFIGURATION")),
    "runtime_available": os.environ.get("ACTIONS_RUNTIME_TOKEN") == "runtime-canary",
    "argv_clean": "{CANARY}" not in str(sys.argv),
}}))
print("{CANARY}")
print("{CANARY}", file=sys.stderr)
''')
    receiver.chmod(0o700)
    environment = {
        **os.environ,
        "M3_11_CONNECT_BOOTSTRAP": json.dumps({"token": CANARY}),
        "M3_11_CONNECT_CONFIGURATION": "{}",
        "M3_11_CONNECT_OPERATION": "reconcile",
        "ACTIONS_RUNTIME_TOKEN": "runtime-canary",
    }
    source = Path(__file__).resolve().parents[2] / ".github/actions/m3-11-connect/index.js"
    result = subprocess.run(  # noqa: S603 - committed action with private provider-double receiver
        [node, str(source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert all(json.loads((tmp_path / "delivery.json").read_text()).values())
    assert CANARY not in result.stdout + result.stderr
