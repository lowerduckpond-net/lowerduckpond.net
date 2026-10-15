"""One complete independent confirmation, cold cleanup and sanitized transport."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import cleanup, connect_auth, worker
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended.config import LeaseBootstrap, LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import Access
from scripts.m3_11_unattended.connect_configuration import reader_access
from scripts.m3_11_unattended.connect_setup import assemble
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.inventory import ConnectInventory, fact, require_confirmation
from scripts.m3_11_unattended.journal import MIGRATION_FORMAT, MIGRATION_TAG
from scripts.m3_11_unattended.lifecycle import LeaseLifecycle, Provider, lease_manifest
from scripts.m3_11_unattended.model import (
    PROVIDERS,
    ROLES,
    LifecycleError,
    ProviderKind,
    digest,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState, RunState
from scripts.m3_11_unattended.watchdog import prepare_lease_cleanup

from .test_m3_11_connect_auth import Endpoint
from .test_m3_11_connect_configuration import journal_grant
from .test_m3_11_connect_setup import CANARY, independent_reader
from .test_m3_11_lease_configuration import document
from .test_m3_11_lease_inventory import ConnectDouble, LeaseProviderDouble
from .test_m3_11_lease_migration import note


class Case:
    """Real entrypoints with only the native server and provider transport doubled."""

    def __init__(  # noqa: PLR0915 - one complete staged independent action fixture
        self, root: Path, monkeypatch: pytest.MonkeyPatch, *, journal_permission: int = 1008
    ) -> None:
        self.root = root
        raw = document()
        self.mapping: dict[str, object] = {
            "format": MIGRATION_FORMAT,
            "records": {},
            "obligations": {},
            "retained_files": {},
            "expiry_updates": [],
            "issuers": [],
            "approved_at": stamp(datetime.now(UTC)),
            "approval_reference": "SYNTHETIC-EMPTY-MIGRATION",
        }
        raw["migration_sha256"] = digest(self.mapping)
        # Native IDs are commonly uppercase; preserve exact independent identity.
        raw["independent_server_id"] = "I" * 26
        self.config = LeaseConfiguration.parse(raw)
        self.client = ConnectDouble(self.config.journal_vault)
        note(
            self.client,
            self.mapping,
            tag=MIGRATION_TAG,
            title="m3-11-import-" + digest(self.mapping),
        )
        self.inventory = ConnectInventory(
            self.client, self.client.vault, spool=root / "host-pending"
        )
        self.providers: dict[str, dict[ProviderKind, LeaseProviderDouble]] = {}
        for role in ("provision", "cleanup"):
            gen = self.config.generations[self.config.active_generation][role].generation
            self.providers[role] = {
                kind: LeaseProviderDouble(kind, gen.fingerprints[kind]) for kind in PROVIDERS
            }
        for kind in PROVIDERS:
            self.providers["cleanup"][kind].items = self.providers["provision"][kind].items
        self.server_active = False
        self.teardown_failure = False
        self.auth_attempts = 0
        self.auth_failures = 0

        def providers(bootstrap: LeaseBootstrap, **_kwargs: object) -> dict[ProviderKind, Provider]:
            return dict(self.providers[bootstrap.generation.role])

        @contextmanager
        def server(_docker: object, credentials: object) -> Iterator[str]:
            assert credentials == {"synthetic": CANARY}
            self.server_active = True
            try:
                yield "http://127.0.0.1:9999"
            finally:
                self.server_active = False
                if self.teardown_failure:
                    raise LifecycleError(CANARY)

        def authenticate(
            _client: Connect, access: Access, *, forbidden: set[str]
        ) -> dict[str, object]:
            assert self.server_active
            assert access.server_id == self.config.independent_server_id
            assert self.config.journal_vault in access.grants
            assert forbidden.isdisjoint(access.grants)
            self.auth_attempts += 1
            if self.auth_attempts <= self.auth_failures:
                raise LifecycleError(CANARY)
            return {
                **access.receipt(),
                "authenticated": True,
                "forbidden_vaults_denied": len(forbidden),
            }

        monkeypatch.setattr(LeaseBootstrap, "providers", providers)
        monkeypatch.setattr(LeaseBootstrap, "reader", lambda _self: self.client)
        monkeypatch.setattr(action, "Docker", object)
        monkeypatch.setattr(action, "independent_server", server)
        monkeypatch.setattr(action, "Connect", lambda *_args, **_kwargs: self.client)
        monkeypatch.setattr(action, "authenticate", authenticate)
        monkeypatch.setenv("GITHUB_RUN_ID", "12345")
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
        independent = independent_reader(self.config.independent_server_id)
        journal_grant(independent, journal_permission)
        _, self.bundle = assemble(raw, independent, {"synthetic": CANARY})
        self.manifest = lease_manifest(
            lease_id=str(uuid.uuid7()),
            source="f" * 40,
            helper=self.config.helper_revision,
            targets=self.config.targets,
            policy=self.config.policy,
            approved_policy_sha256=self.config.approved_policy_sha256,
            creator=self.config.generations[self.config.active_generation]["provision"].generation,
            cleanup=self.config.generations[self.config.active_generation]["cleanup"].generation,
            providers=self.providers["provision"],
            cleanup_providers=self.providers["cleanup"],
            scopes={role: {"synthetic_role": role} for role in ROLES},
            now=datetime.now(UTC),
        )
        self.state = LeaseState(root / "host/leases" / self.manifest.lease_id)
        self.lifecycle = LeaseLifecycle(
            self.manifest, self.inventory, self.state, providers=self.providers["provision"]
        )
        self.lifecycle.prepare()

    def execute(
        self, operation: str = "confirm", *, directory: Path | None = None
    ) -> dict[str, object]:
        target = directory or self.root / "independent"
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        return action.execute(
            {"bootstrap": self.bundle, "operation": operation},
            directory=target,
            helper=self.config.helper_revision,
        )

    def issue(self) -> None:
        self.lifecycle.issue(
            writer_sha256="a" * 64,
            approved_policy_sha256=self.config.approved_policy_sha256,
            independent_server_id=self.config.independent_server_id,
        )


@pytest.fixture(autouse=True)
def restore_process_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    os.umask(previous)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.mark.parametrize("journal_permission", [496, 1008])
def test_real_action_confirms_once_before_original_issuer_can_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, journal_permission: int
) -> None:
    case = Case(tmp_path, monkeypatch, journal_permission=journal_permission)
    with pytest.raises(LifecycleError, match="confirmation"):
        case.issue()
    assert case.execute()["status"] == "ready"
    authentication = read_private(tmp_path / "independent/authentication.json")
    assert authentication["authenticated"] is True
    assert authentication["create_verified"] is False  # Authentication never attests publication.
    require_confirmation(
        case.inventory, case.manifest, independent_server_id=case.config.independent_server_id
    )
    count = case.client.posts
    assert case.execute()["status"] == "ready"
    assert case.client.posts == count
    assert all(provider.creates == 0 for provider in case.providers["provision"].values())
    case.issue()
    assert sum(provider.creates for provider in case.providers["provision"].values()) == len(ROLES)
    assert CANARY not in json.dumps(case.inventory.records())


@pytest.mark.parametrize("fault", ["rejected", "extra-vault", "missing-vault", "forbidden"])
def test_496_independent_authentication_and_isolation_precede_all_journal_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch, journal_permission=496)
    config, _ = action.bootstrap(case.bundle, helper=case.config.helper_revision)
    _, access = reader_access(
        config.generations[config.active_generation]["cleanup"].reader_settings
    )
    endpoint = Endpoint(access.token)
    endpoint.visible = set(access.grants)
    if fault == "rejected":
        endpoint.accepted = False
    elif fault == "extra-vault":
        endpoint.visible.add("x" * 26)
    elif fault == "missing-vault":
        endpoint.visible.remove(config.journal_vault)
    else:
        endpoint.denial = 200
    monkeypatch.setattr(action, "authenticate", connect_auth.authenticate)
    monkeypatch.setattr(action, "Connect", lambda *_args, **_kwargs: endpoint)
    monkeypatch.setattr(action, "SYNC_SECONDS", 0)

    def unavailable(*_args: object, **_kwargs: object) -> None:
        pytest.fail("journal or provider work reached before authenticated isolation")

    monkeypatch.setattr(action, "ConnectInventory", unavailable)
    monkeypatch.setattr(cleanup, "sweep_leases", unavailable)
    before = case.client.posts
    with pytest.raises(LifecycleError):
        case.execute()
    assert case.client.posts == before
    assert not case.server_active
    receipt = read_private(tmp_path / "independent/authentication.json")
    assert receipt["authenticated"] is False and receipt["create_verified"] is False
    assert not (tmp_path / "independent/cleanup.json").exists()


def test_cold_independent_cleanup_deletes_but_preserves_retained_negative_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    case.lifecycle.request_close("finish")
    result = case.execute("cleanup")
    assert result["status"] == "unresolved"
    assert sum(len(provider.deletes) for provider in case.providers["cleanup"].values()) == len(
        ROLES
    )
    assert all(not provider.items for provider in case.providers["cleanup"].values())
    assert all(
        row.status == "verified" for row in case.lifecycle.reconcile(case.providers["cleanup"])
    )
    assert case.execute("cleanup")["status"] == "ready"
    assert any(row["slot"] == "closed" for row in case.inventory.records())
    assert CANARY not in json.dumps(result)


def test_496_acceptance_cannot_confirm_a_lease_with_unresolved_legacy_obligations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch, journal_permission=496)
    monkeypatch.setattr(
        cleanup,
        "sweep_legacy",
        lambda *_args, **_kwargs: {
            "migration_sha256": case.config.migration_sha256,
            "status": "unresolved",
        },
    )
    before = case.client.posts
    result = case.execute()
    assert result["status"] == "unresolved"
    assert not any(row["slot"] == "confirmed" for row in case.inventory.records())
    assert case.client.posts == before
    with pytest.raises(LifecycleError, match="confirmation"):
        case.issue()
    assert not any(provider.creates for provider in case.providers["provision"].values())


def test_496_actual_confirmation_lost_reply_keeps_pending_and_never_reposts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch, journal_permission=496)
    before = case.client.posts
    case.client.lose_reply = True
    with pytest.raises(LifecycleError, match="lost response"):
        case.execute()
    assert case.client.posts == before + 1
    pending = tmp_path / "independent/pending"
    retained = {path: path.read_bytes() for path in pending.iterdir()}
    assert len(retained) == 1
    # Hide only the uncertain confirmation; keep the real manifest/import visible.
    posted = case.client.items.pop(f"{case.client.posts:026d}")
    with pytest.raises(LifecycleError, match=r"pending|unobserved"):
        case.execute()
    assert case.client.posts == before + 1
    assert all(path.read_bytes() == raw for path, raw in retained.items())
    with pytest.raises(LifecycleError, match="confirmation"):
        case.issue()
    case.client.items[str(posted["id"])] = posted
    assert case.execute()["status"] == "ready"
    assert case.client.posts == before + 1
    assert all(path.read_bytes() == raw for path, raw in retained.items())


@pytest.mark.parametrize(
    "closing", ["unpublished-local", "newly-visible-remote", "second-read-unavailable"]
)
def test_sweep_reports_unresolved_when_reconciliation_discovers_close_after_initial_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, closing: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    if closing == "unpublished-local":
        publish = case.inventory.publish

        def unavailable(record: dict[str, object]) -> None:
            if str(record["slot"]).startswith("close-"):
                raise LifecycleError("synthetic close publication failure")
            publish(record)

        monkeypatch.setattr(case.inventory, "publish", unavailable)
        with pytest.raises(LifecycleError):
            case.lifecycle.request_close("cancel")
        root = case.state.directory.parent
    elif closing == "newly-visible-remote":
        records = case.inventory.records
        before_close = records()
        case.lifecycle.request_close("cancel")
        snapshots = iter([before_close])
        monkeypatch.setattr(case.inventory, "records", lambda: next(snapshots, None) or records())
        root = tmp_path / "independent-cold"
    else:
        case.lifecycle.request_close("cancel")
        records = case.inventory.records
        calls = 0

        def unavailable_read() -> list[dict[str, object]]:
            nonlocal calls
            calls += 1
            if calls == 2:  # noqa: PLR2004 - fail reconciliation's read after the first snapshot
                raise LifecycleError("synthetic second inventory read failure")
            return records()

        monkeypatch.setattr(case.inventory, "records", unavailable_read)
        root = tmp_path / "independent-cold"
    result = cleanup.sweep_leases(
        case.config,
        case.inventory,
        root=root,
        actor="github",
        connect_client=case.client,
    )
    assert result["status"] == "unresolved"
    leases = cast(list[dict[str, object]], result["leases"])
    assert len(leases) == 1 and leases[0]["status"] == "unresolved"
    assert all(
        row["status"] == "unresolved" for row in cast(list[dict[str, object]], leases[0]["results"])
    )
    assert sum(len(provider.deletes) for provider in case.providers["cleanup"].values()) == (
        0 if closing == "second-read-unavailable" else len(ROLES)
    )
    assert not any(row["slot"] == "closed" for row in case.inventory.records())


@pytest.mark.parametrize(
    "fault", ["orphan", "unavailable", "legacy-missing", "unavailable-provider"]
)
def test_failed_inventory_or_legacy_read_never_confirms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = Case(tmp_path, monkeypatch)
    if fault == "orphan":
        case.client.items = {
            key: item
            for key, item in case.client.items.items()
            if str(item["title"]).startswith("m3-11-import-")
        }
        case.inventory.publish(fact(case.manifest, "close-cancel", {}))
    elif fault == "unavailable":
        case.client.fail_list = True
    elif fault == "legacy-missing":
        del case.client.items[next(iter(case.client.items))]
    else:
        case.providers["cleanup"]["spaces"].fail_read = True
    with suppress(LifecycleError):
        assert case.execute()["status"] == "unresolved"
    case.client.fail_list = False
    assert not any(row["slot"] == "confirmed" for row in case.inventory.records())
    assert all(provider.creates == 0 for provider in case.providers["provision"].values())


def test_native_authentication_retry_is_bounded_and_teardown_preserves_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path, monkeypatch)
    case.auth_failures = 1
    ticks = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: ticks[0])
    monkeypatch.setattr(time, "sleep", lambda duration: ticks.__setitem__(0, ticks[0] + duration))
    assert case.execute()["status"] == "ready"
    assert case.auth_attempts == case.auth_failures + 1
    case.auth_failures = 1000
    with pytest.raises(LifecycleError):
        case.execute()
    assert ticks[0] <= action.SYNC_SECONDS + action.POLL_SECONDS
    case.auth_failures = 0
    case.teardown_failure = True
    with pytest.raises(LifecycleError):
        case.execute()
    assert read_private(tmp_path / "independent/cleanup.json")["status"] == "ready"


@pytest.mark.parametrize("fail", [False, True])
def test_main_replaces_progress_and_sanitizes_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], fail: bool
) -> None:
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", action.REPOSITORY)
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    monkeypatch.setenv(
        "GITHUB_WORKFLOW_REF",
        f"{action.REPOSITORY}/.github/workflows/{action.WORKFLOW}@refs/heads/main",
    )
    monkeypatch.setenv("M3_11_HELPER_REVISION", "a" * 40)
    monkeypatch.setattr(action, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"{}")))

    def execute(
        _raw: object, *, directory: Path, helper: str, progress: Callable[[str], None]
    ) -> dict[str, object]:
        progress("credential-cleanup")
        assert read_private(directory / "receipt.json")["status"] == "unresolved"
        if fail:
            raise ValueError(CANARY)
        return {"format": action.RECEIPT_FORMAT, "status": "ready", "helper_revision": helper}

    monkeypatch.setattr(action, "execute", execute)
    assert action.main() == int(fail)
    receipt = read_private(tmp_path / "m3-11-connect/receipt.json")
    assert receipt["status"] == ("unresolved" if fail else "ready")
    captured = capsys.readouterr()
    assert CANARY not in json.dumps(receipt) + captured.out + captured.err


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
from typing import cast
value = json.load(sys.stdin)
Path("delivery.json").write_text(json.dumps({{
    "received": value["bootstrap"] == {{"token": "{CANARY}"}},
    "environment_clean": all(key not in os.environ for key in (
        "M3_11_CONNECT_BOOTSTRAP", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")),
    "argv_clean": "{CANARY}" not in str(sys.argv),
}}))
print("{CANARY}")
print("{CANARY}", file=sys.stderr)
''')
    receiver.chmod(0o700)
    environment = {
        **os.environ,
        "M3_11_CONNECT_BOOTSTRAP": json.dumps({"token": CANARY}),
        "M3_11_CONNECT_OPERATION": "confirm",
        "ACTIONS_RUNTIME_TOKEN": "runtime-canary",
        "GH_TOKEN": CANARY,
        "GITHUB_TOKEN": CANARY,
    }
    source = Path(__file__).resolve().parents[2] / ".github/actions/m3-11-connect/index.js"
    result = subprocess.run(  # noqa: S603 - private local receiver
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


def attempt(case: Case) -> tuple[Path, dict[str, object]]:

    run_id = str(uuid.uuid7())
    directory = case.root / "host/runs" / run_id
    directory.mkdir(mode=0o700, parents=True)
    directory.parent.chmod(0o700)
    directory.parent.parent.chmod(0o700)
    binding: dict[str, object] = {
        "managed_run_id": run_id,
        "source_revision": "f" * 40,
        "helper_revision": case.config.helper_revision,
        "artifact_sha256": "a" * 64,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": case.config.targets.storage_digest,
    }
    write_private(
        directory / "request.json",
        {
            "format": "lowerduckpond-m3-11-unattended-request-v2",
            "binding": binding,
            "mode": "qualification",
            "approval_sha256": "c" * 64,
            "controller_image": "sha256:" + "d" * 64,
            "daemon": {},
            "lease_id": case.manifest.lease_id,
        },
    )
    return directory, binding


@pytest.mark.parametrize("contended", [False, True])
def test_worker_owns_reuse_before_first_child_probe_and_rejected_consumer_cannot_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contended: bool
) -> None:

    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    directory, binding = attempt(case)
    selected = worker.Worker(directory, case.config, tmp_path / "source")
    selected.state.begin(binding)
    monkeypatch.setattr(selected, "_inventory", lambda: case.inventory)
    monkeypatch.setattr(worker, "Docker", object)
    if contended:
        with case.state.use_lock():
            case.state.acquire_use(
                attempt_id=case.manifest.lease_id, binding_sha256="d" * 64, kind="attempt"
            )
    probes = []
    for provider in case.providers["cleanup"].values():
        original = provider.inspect

        def inspect(
            identifier: str, original: Callable[[str], dict[str, object] | None] = original
        ) -> dict[str, object] | None:
            assert read_private(case.state.directory / ("use-" + selected.run_id + ".json"))[
                "binding_sha256"
            ] == digest(binding)
            probes.append(identifier)
            return original(identifier)

        monkeypatch.setattr(provider, "inspect", inspect)
    if contended:
        with pytest.raises(LifecycleError, match="quiescence"):
            selected._provision()
        selected.state.finish_journey("failed", 1)
        assert not selected.revoke()
        assert prepare_lease_cleanup(directory.parent, cast(Docker, None), case.inventory)
        assert probes == []
        assert not any(str(row["slot"]).startswith("close-") for row in case.inventory.records())
    else:
        credentials, receipt = selected._provision()
        assert set(credentials) == ROLES and len(probes) == len(ROLES)
        assert receipt["managed_run_id"] == selected.run_id
        assert selected.owns_lease
    assert sum(provider.creates for provider in case.providers["provision"].values()) == len(ROLES)


@pytest.mark.parametrize("started", [False, True])
def test_watchdog_retains_only_approved_failure_after_actual_attempt_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, started: bool
) -> None:

    case = Case(tmp_path, monkeypatch)
    case.execute()
    case.issue()
    directory, binding = attempt(case)
    state = RunState(directory)
    state.begin(binding)
    state.finish_journey("failed", 1)
    with case.state.use_lock():
        case.state.acquire_use(
            attempt_id=directory.name, binding_sha256=digest(binding), kind="attempt"
        )
    if started:
        write_private(
            directory / "attempt-started.json",
            {"binding_sha256": digest(binding), "manifest_sha256": case.manifest.sha256},
        )

    class DeadDocker:
        def owned(self, _name: str) -> dict[str, object]:
            return {"State": {"Running": False}}

    assert prepare_lease_cleanup(directory.parent, cast(Docker, DeadDocker()), case.inventory)
    assert ("close-cancel" in case.lifecycle.records()) is not started
