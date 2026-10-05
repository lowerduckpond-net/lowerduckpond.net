"""Protected cleanup selection, real protocol integration and sanitized delivery."""

from __future__ import annotations

import copy
import dataclasses
import io
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_connect_admission import Case as AdmissionCase
from infrastructure.test_m3_11_connect_configuration import VAULTS, reader_config
from infrastructure.test_m3_11_connect_genesis import Case as GenesisCase
from infrastructure.test_m3_11_connect_journal import sync
from infrastructure.test_m3_11_connect_ledger import REMOTE_AUTHOR, REMOTE_SERVER
from infrastructure.test_m3_11_unattended_lifecycle import CANARY, TARGETS, ProviderDouble
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_diagnostics as diagnostics
from scripts.m3_11_unattended import connect_genesis as genesis
from scripts.m3_11_unattended.cleanup import require_independent_ready
from scripts.m3_11_unattended.config import Connections
from scripts.m3_11_unattended.connect_admission import Admission, run_digest
from scripts.m3_11_unattended.connect_auth import Access
from scripts.m3_11_unattended.connect_configuration import PROVIDER_REFERENCES
from scripts.m3_11_unattended.github_checkpoint import (
    MINIMUM_START_CAPACITY,
    REPOSITORY,
    WORKFLOW,
    GitHubArtifacts,
)
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import Authority, Intent, LifecycleError, digest, instant


@pytest.fixture(autouse=True)
def restore_process_umask() -> Iterator[None]:
    # CLI entry points restrict their own process. Direct calls in these tests
    # must not change how unrelated tests create deliberately unsafe files.
    previous = os.umask(0o077)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


def selected(case: GenesisCase) -> dict[str, object]:
    return {
        "format": action.FORMAT,
        "stage": "active",
        "active_helper": case.journal.witness.helper,
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


def test_cleanup_bootstrap_binds_cloudflare_targets_as_well_as_storage() -> None:
    configured = reader_config("cleanup")
    targets = dataclasses.asdict(TARGETS)
    bundle: dict[str, object] = {
        "format": "lowerduckpond-m3-11-connect-bootstrap-v1",
        "targets": targets,
        "journal_vault": VAULTS["journal"],
        "cleanup": {
            **{key: f"op://{VAULTS['cleanup']}/{'i' * 26}/{key}" for key in PROVIDER_REFERENCES},
            "service_account_expires_at": "2026-10-10T00:00:00Z",
        },
        "token": configured["entry"],
        "provider_metadata": configured["metadata"],
        "server_credentials": {"private": CANARY},
    }
    approved: dict[str, object] = {
        "vaults": VAULTS,
        "targets_sha256": digest(targets),
        "shared_server": "Q" * 26,
    }
    _private, _access, actual, _references = action.bootstrap(bundle, approved)
    assert actual == TARGETS
    bundle["targets"] = dataclasses.asdict(dataclasses.replace(TARGETS, zone_id="f" * 32))
    with pytest.raises(LifecycleError, match="targets differ"):
        action.bootstrap(bundle, approved)


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


def test_lost_heartbeat_post_does_not_strand_future_cleanup_after_process_restart(
    tmp_path: Path,
) -> None:
    case = AdmissionCase(tmp_path)
    case.journal.remote.fail = "before"
    with pytest.raises(LifecycleError):
        reconcile(case, ProviderDouble())
    missing = [
        row
        for row in case.journal.github.checkpoint.records.values()
        if row["kind"] == "heartbeat"
        and cast(dict[str, object], row["payload"]).get("actor") == "github"
    ]
    assert not missing
    case.journal.remote.fail = ""
    case.journal.github = case.journal.independent(directory="fresh-worker")
    case.journal.github.capacity = lambda: MINIMUM_START_CAPACITY + 10
    assert reconcile(case, ProviderDouble())["status"] == "ready"
    assert case.journal.github.cache_complete


def test_a_forged_checkpoint_only_receipt_cannot_be_republished_as_independent(
    tmp_path: Path,
) -> None:
    case = AdmissionCase(tmp_path)
    forged = event("heartbeat", case.run_id, {"actor": "github", "forged": True})
    case.journal.controller.append(forged)
    sync(case.journal.shared, case.journal.remote)
    case.journal.github.persist(forged)
    with pytest.raises(LifecycleError, match="native author"):
        case.journal.github.append(forged)
    assert not case.journal.github.ledger.authored(forged, case.journal.witness.author)


def test_cold_replica_waits_for_complete_items_after_vault_authentication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = AdmissionCase(tmp_path)
    case.journal.github.acknowledge(run_id=50, attempt=1, allow=lambda _record: False)
    for key, item in list(case.journal.remote.items.items()):
        if str(case.run["event_id"]) in json.dumps(item):
            del case.journal.remote.items[key]
            case.journal.remote.version += 1
    cold = case.journal.independent(directory="cold-replica")

    def ready() -> bool:
        cold.records()
        return cold.cache_complete

    assert not ready()
    monkeypatch.setattr(
        time, "sleep", lambda _seconds: sync(case.journal.shared, case.journal.remote)
    )
    assert action.synchronize(ready) and cold.cache_complete
    assert not case.journal.controller.confirmed(case.run)


def test_cold_replica_wait_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(action, "SYNC_SECONDS", 0)
    assert not action.synchronize(lambda: False)


def test_reviewed_successor_helper_preserves_original_genesis(tmp_path: Path) -> None:
    case = GenesisCase(tmp_path)
    value = selected(case)
    original = copy.deepcopy(value)
    value["active_helper"] = "f" * 40
    with pytest.raises(LifecycleError, match="installed revision"):
        action.selection(value, helper=case.journal.witness.helper)
    assert action.selection(value, helper="f" * 40) == value
    assert value["request"] == original["request"] and value["receipt"] == original["receipt"]


def test_successor_helper_requires_its_own_fresh_independent_readiness(tmp_path: Path) -> None:
    case = AdmissionCase(tmp_path)
    assert reconcile(case, ProviderDouble())["status"] == "ready"
    sync(case.journal.remote, case.journal.shared)
    case.journal.witness = dataclasses.replace(case.journal.witness, active_helper="f" * 40)
    case.journal.controller = case.journal.local()
    case.journal.github = case.journal.independent(directory="successor")
    case.journal.github.capacity = lambda: MINIMUM_START_CAPACITY + 10
    with pytest.raises(LifecycleError, match="another helper"):
        require_independent_ready(case.journal.controller, helper="f" * 40, now=datetime.now(UTC))
    assert reconcile(case, ProviderDouble())["status"] == "ready"
    sync(case.journal.remote, case.journal.shared)
    require_independent_ready(case.journal.controller, helper="f" * 40, now=datetime.now(UTC))


def test_successor_attempt_cannot_start_until_historical_credentials_are_reconciled(
    tmp_path: Path,
) -> None:
    case = AdmissionCase(tmp_path)
    case.acknowledge(case.reserve())
    intent_record = case.intent()
    case.acknowledge(case.admission())
    intent = Intent.parse(intent_record["payload"])
    provider = ProviderDouble()
    credential = provider.create(intent)
    created = event(
        "created",
        case.run_id,
        {
            "intent_sha256": intent.sha256,
            "credential_id": credential.identifier,
        },
    )
    failed = event(
        "result", case.run_id, {"qualification": "failed", "credential_cleanup": "pending"}
    )
    for record in (created, failed):
        case.journal.controller.append(record)
    case.journal.witness_once()
    original_genesis = case.journal.witness.genesis
    original_binding = case.journal.witness.binding()
    case.journal.witness = dataclasses.replace(case.journal.witness, active_helper="f" * 40)
    case.journal.github = case.journal.independent(directory="reviewed-successor")
    case.journal.github.capacity = lambda: MINIMUM_START_CAPACITY + 10
    case.journal.controller = case.journal.local()
    assert case.journal.controller.confirmed(case.run)
    assert case.journal.witness.binding() == original_binding

    new_id = str(uuid.uuid7())
    payload = copy.deepcopy(case.payload)
    cast(dict[str, str], payload["binding"]).update(
        managed_run_id=new_id,
        source_revision="f" * 40,
        helper_revision="f" * 40,
    )
    new_run = event("run", new_id, payload)
    case.journal.controller.append(new_run)
    sync(case.journal.shared, case.journal.remote)
    cleaner = Lifecycle(case.journal.github, {"spaces": provider})

    def reserve() -> Admission:
        admission = Admission(case.journal.github, targets=TARGETS, now=datetime.now(UTC))
        admission.reserve(
            run_digest(new_id, payload), case.authority, require_clear=cleaner.require_clear
        )
        return admission

    with pytest.raises(LifecycleError, match="outstanding credential obligations"):
        reserve()
    assert not case.journal.controller.confirmed(new_run)
    cleaner.request_revocation(case.run_id)
    assert cleaner.reconcile(intent, credential).status == "verified"
    admission = reserve()
    assert not admission.allow(case.run) and not admission.allow(intent_record)
    case.journal.github.acknowledge(run_id=51, attempt=1, allow=admission.allow)
    sync(case.journal.remote, case.journal.shared)
    assert case.journal.controller.confirmed(new_run)
    assert case.journal.witness.genesis == original_genesis
    assert failed in case.journal.github.checkpoint.records.values()
    assert provider.creates == 1 and provider.deletes == [credential.identifier]


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


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (LifecycleError(CANARY), "lifecycle"),
        (ValueError(CANARY), "input"),
        (KeyError(CANARY), "input"),
        (OSError(1, CANARY, CANARY), "io"),
        (subprocess.CalledProcessError(1, CANARY, output=CANARY, stderr=CANARY), "subprocess"),
        (type("PRIVATE_DYNAMIC_CLASS_CANARY", (Exception,), {})(CANARY), "unexpected"),
    ],
)
def test_failure_diagnostics_export_only_closed_categories(error: Exception, category: str) -> None:
    try:
        raise error
    except Exception as caught:
        value = diagnostics.failure(caught)
    assert value == {"category": category, "origin": None}
    assert CANARY not in json.dumps(value)
    assert "PRIVATE_DYNAMIC_CLASS_CANARY" not in json.dumps(value)


def test_failure_location_comes_only_from_the_pinned_source_ast() -> None:
    try:
        instant(CANARY)
    except LifecycleError as error:
        value = diagnostics.failure(error)
    origin = cast(dict[str, object], value["origin"])
    assert origin["path"] == "scripts/m3_11_unattended/model.py"
    assert origin["function"] == "instant" and type(origin["line"]) is int
    assert CANARY not in json.dumps(value)


@pytest.mark.parametrize("spoof_path", [False, True])
def test_dynamic_traceback_filenames_and_function_names_cannot_be_exported(
    spoof_path: bool,
) -> None:
    code = "def PRIVATE_FUNCTION_CANARY():\n    raise ValueError(secret)\nPRIVATE_FUNCTION_CANARY()"
    filename = str(diagnostics.ROOT / diagnostics.SOURCES[0]) if spoof_path else CANARY
    try:
        exec(compile(code, filename, "exec"), {"secret": CANARY})  # noqa: S102 - static canary fixture
    except ValueError as error:
        value = diagnostics.failure(error)
    assert value == {"category": "input", "origin": None}


def test_unavailable_diagnostic_source_keeps_unresolved_output_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_path: Path) -> str:
        raise OSError(CANARY)

    monkeypatch.setattr(Path, "read_text", unavailable)
    try:
        instant(CANARY)
    except LifecycleError as error:
        value = diagnostics.failure(error)
    assert value == {"category": "lifecycle", "origin": None}


def test_broken_diagnostic_reporter_cannot_suppress_the_unresolved_action_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ACTIONS", "false")

    def broken(_error: Exception) -> dict[str, object]:
        raise ValueError(CANARY)

    monkeypatch.setattr(action, "failure", broken)
    assert action.main() == 1
    value = read_private(tmp_path / "m3-11-connect/receipt.json")
    assert value == {
        "format": action.RECEIPT_FORMAT,
        "status": "unresolved",
        "phase": "validate-protected-execution",
    }
    captured = capsys.readouterr()
    assert CANARY not in json.dumps(value) + captured.out + captured.err


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
