"""Keep independent cleanup usable within the real account-wide request budget."""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, current_thread
from types import SimpleNamespace
from typing import cast

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import cleanup, docker, journal_cache, quota, watchdog, worker
from scripts.m3_11_unattended.config import Bootstrap, Configuration, Connections
from scripts.m3_11_unattended.journal import OnePassword, OpJournal, event
from scripts.m3_11_unattended.journal_cache import JournalCache
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import ROLES, Credential, LifecycleError, stamp
from scripts.m3_11_unattended.state import RunState, cleanup_lock, replace_private

from .test_m3_11_unattended_controller import bound, subject
from .test_m3_11_unattended_lifecycle import CANARY, TARGETS, Case
from .test_m3_11_unattended_providers import JournalCli

DAY_SECONDS = 24 * 60 * 60
DAILY_SWEEPS = 2 * 24
IDLE_REQUEST_BUDGET = 600
DAILY_REQUEST_BUDGET = 1000


class CountedCli(JournalCli):
    def __init__(self) -> None:
        super().__init__()
        self.requests = 0
        self.gets = 0
        self.fail_list = False

    def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
        # Official CLI accounting with explicit immutable vault/item IDs:
        # list is two requests; get, create and read each consume one.
        self.requests += 2 if arguments[:2] == ("item", "list") else 1
        if arguments[:2] == ("item", "get"):
            self.gets += 1
        if arguments[:2] == ("item", "list") and self.fail_list:
            raise LifecycleError("provider unavailable")
        return super().command(*arguments, stdin=stdin)

    def journal_cache(self, path: Path, vault: str, *, output: Path | None = None) -> JournalCache:
        return JournalCache(path, token=CANARY + "cleanup", vault=vault, output=output)


def cached(cli: CountedCli, path: Path, *, output: Path | None = None) -> OpJournal:
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    journal.use_cache(path, output=output)
    return journal


def test_encrypted_cache_requires_live_inventory_and_fetches_new_records(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    path = tmp_path / "journal.json"
    original = event("result", Case(tmp_path / "case").run_id, {"test": CANARY})
    first = cached(cli, path)
    first.append(original)
    assert first.records() == [original]
    assert CANARY.encode() not in path.read_bytes()
    before = cli.gets
    assert cached(cli, path).records() == [original]
    assert cli.gets == before
    later = event("result", str(original["run_id"]), {"later": True})
    OpJournal(cast(OnePassword, cli), "a" * 26).append(later)
    before = cli.gets
    assert cached(cli, path).records() == [original, later]
    assert cli.gets == before + 1
    cli.fail_list = True
    with pytest.raises(LifecycleError, match="unavailable"):
        cached(cli, path).records()


@pytest.mark.parametrize("fault", ["edit", "delete", "title", "other-token", "other-vault"])
def test_cached_obligations_cannot_be_changed_erased_or_forged(tmp_path: Path, fault: str) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    path = tmp_path / "journal.json"
    journal = cached(cli, path)
    journal.append(event("result", Case(tmp_path / "case").run_id, {"test": CANARY}))
    journal.records()
    item = next(iter(cli.items.values()))
    if fault == "edit":
        item["version"] = 2
    elif fault == "delete":
        cli.items.clear()
    elif fault == "title":
        item["title"] = "untrusted"
    if fault.startswith("other-"):
        selected = JournalCache(
            path,
            token="other" if fault == "other-token" else CANARY + "cleanup",
            vault="b" * 26 if fault == "other-vault" else "a" * 26,
        )
        with pytest.raises(LifecycleError):
            selected.read()
    else:
        with pytest.raises(LifecycleError):
            cached(cli, path).records()


def native_limits() -> list[dict[str, object]]:
    return [
        {
            "type": kind,
            "action": action,
            "limit": maximum,
            "used": 0,
            "remaining": maximum,
            "reset": 0,
        }
        for kind, action, maximum in (
            ("token", "read", 1000),
            ("token", "write", 100),
            ("account", "read_write", 1000),
        )
    ]


class QuotaCli:
    def __init__(self, value: object) -> None:
        self.value = value

    def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
        assert arguments == ("service-account", "ratelimit", "--format", "json")
        return json.dumps(self.value).encode()


@pytest.mark.parametrize("index", [0, 1, 2])
def test_each_native_quota_must_leave_headroom_for_both_authorities(index: int) -> None:
    healthy = QuotaCli(native_limits())
    quota.require_capacity(cast(OnePassword, healthy), cast(OnePassword, healthy), records=100)
    value = native_limits()
    value[index]["used"], value[index]["remaining"] = value[index]["limit"], 0
    failed = QuotaCli(value)
    for provision, independent in ((failed, healthy), (healthy, failed)):
        with pytest.raises(LifecycleError, match="insufficient"):
            quota.require_capacity(
                cast(OnePassword, provision), cast(OnePassword, independent), records=100
            )


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "negative", "bool", "mismatch", "unknown"]
)
def test_quota_metadata_fails_closed(fault: str) -> None:
    value = native_limits()
    if fault == "missing":
        value.pop()
    elif fault == "duplicate":
        value[2] = copy.deepcopy(value[0])
    elif fault == "unknown":
        value[0]["action"] = CANARY
    else:
        value[0]["remaining"] = {"negative": -1, "bool": True, "mismatch": 3}[fault]
    with pytest.raises(LifecycleError):
        quota.limits(cast(OnePassword, QuotaCli(value)))


def prepare_cleanup_day(
    tmp_path: Path,
    cli: CountedCli,
    selected: worker.Worker,
    case: Case,
    failed_cleanup: str | None,
) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir(mode=0o700)
    directory = runs / case.run_id
    selected.directory.rename(directory)
    selected.directory = directory
    selected.state = RunState(directory)
    initial = OpJournal(cast(OnePassword, cli), "a" * 26)
    for number in range(100 if failed_cleanup else 20):
        initial.append(event("result", case.run_id, {"historical_record": number}))
    if failed_cleanup:
        selected.state.begin(selected.binding)
        for name in ("credential-intents", "credential-cleanup"):
            (selected.directory / name).mkdir(mode=0o700)
        case.lifecycle = Lifecycle(
            initial,
            {"spaces": case.provider},
            clock=lambda: case.now,
            remember=selected.remember,
            remember_intent=selected.remember_intent,
        )
        for role in ROLES:
            case.create(role=role)
        selected.state.finish_journey("failed", 1)
        case.provider.fail_delete = failed_cleanup == "deletion"
        case.provider.still_authenticates = failed_cleanup == "authentication"
    cli.requests = 0
    return runs


@pytest.mark.parametrize(
    "failed_cleanup",
    [pytest.param(None, id="idle"), "deletion", "authentication"],
)
def test_full_day_of_cleanup_stays_within_quota_and_preserves_unresolved_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failed_cleanup: str | None,
) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    selected, case = subject(tmp_path, monkeypatch)
    runs = prepare_cleanup_day(tmp_path, cli, selected, case, failed_cleanup)
    directory = selected.directory
    clock = [0.0]
    connections = []

    class Clock:
        @staticmethod
        def now(_zone: object) -> datetime:
            return datetime(2026, 10, 5, tzinfo=UTC) + timedelta(seconds=clock[0])

    def connect(*_args: object, **_kwargs: object) -> Lifecycle:
        connections.append(clock[0])
        cli.requests += 4  # the four immutable bootstrap references
        return Lifecycle(OpJournal(cast(OnePassword, cli), "a" * 26), {"spaces": case.provider})

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        # The actual worker entry point's matching cadence is checked separately.
        if failed_cleanup and clock[0] in {
            300,
            900,
            2100,
            4500,
            *range(8100, DAY_SECONDS, 3600),
        }:
            assert not selected.revoke()
        if clock[0] % 3600 == 0:
            output = tmp_path / "journal.json"
            restored = tmp_path / "restored.json"
            if output.exists():
                output.replace(restored)
            with monkeypatch.context() as context:
                context.setattr(
                    sys,
                    "argv",
                    [
                        "cleanup",
                        "--actor",
                        "github",
                        "--config",
                        "/unused",
                        "--journal-cache",
                        str(restored),
                        "--journal-cache-output",
                        str(tmp_path / "journal.json"),
                    ],
                )
                assert cleanup.main() == (1 if failed_cleanup else 0)
                # Save only newly validated output, including when the provider
                # is unavailable; never republish the restored input file.
                assert output.exists()
        if clock[0] >= DAY_SECONDS:
            raise KeyboardInterrupt

    for key, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": "lowerduckpond-net/lowerduckpond.net",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(cleanup, "datetime", Clock)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(
        cleanup, "cleanup_configuration", lambda _path: (TARGETS, "a" * 26, Bootstrap({}))
    )
    monkeypatch.setattr(cleanup, "connect_cleanup", connect)
    monkeypatch.setattr(
        docker,
        "Docker",
        lambda: SimpleNamespace(owned=lambda _name: {"State": {"Running": True}}),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cleanup",
            "--actor",
            "watchdog",
            "--watch",
            "--config",
            "/unused",
            "--runs",
            str(runs),
            "--journal-cache",
            str(selected.cleanup_cache),
        ],
    )
    if failed_cleanup:
        assert not selected.revoke()
    with pytest.raises(KeyboardInterrupt):
        cleanup.main()
    if failed_cleanup:
        assert selected.state.status()["credential_cleanup"] == "unresolved"
        assert selected.state.status()["qualification"] == "failed"
        assert worker.retained_credentials(directory)
        assert bool(case.provider.items) == (failed_cleanup == "deletion")
        assert cli.requests < DAILY_REQUEST_BUDGET
    else:
        assert len(connections) == DAILY_SWEEPS
        assert cli.requests < IDLE_REQUEST_BUDGET
    assert CANARY not in capsys.readouterr().out


@pytest.mark.parametrize("death_at", [60, 17 * 60])
def test_local_death_detection_does_not_wait_for_hourly_remote_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, death_at: int
) -> None:
    clock = [0.0]
    calls = []
    case = Case(tmp_path)
    (tmp_path / "runs").mkdir(mode=0o700)
    cli = CountedCli()

    def connect(*_args: object, **_kwargs: object) -> Lifecycle:
        calls.append(clock[0])
        return Lifecycle(OpJournal(cast(OnePassword, cli), "a" * 26), {"spaces": case.provider})

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        if clock[0] >= 25 * 60:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(
        cleanup, "cleanup_configuration", lambda _path: (TARGETS, "a" * 26, Bootstrap({}))
    )
    monkeypatch.setattr(cleanup, "connect_cleanup", connect)
    monkeypatch.setattr(docker, "Docker", SimpleNamespace)
    monkeypatch.setattr(
        watchdog, "due_processes", lambda *_args: [tmp_path] if clock[0] >= death_at else []
    )
    monkeypatch.setattr(watchdog, "reconcile_processes", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cleanup",
            "--actor",
            "watchdog",
            "--watch",
            "--config",
            "/unused",
            "--runs",
            str(tmp_path / "runs"),
        ],
    )
    with pytest.raises(KeyboardInterrupt):
        cleanup.main()
    assert calls == [0, *range(death_at, 25 * 60, 300)]


@pytest.mark.parametrize("recovers", [False, True])
def test_surviving_controller_bounds_failed_cleanup_retries_and_stops_after_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recovers: bool
) -> None:
    clock = [0.0]
    recovery_at, stop_at = 600, 12000
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    selected, case = subject(tmp_path, monkeypatch)
    calls = []
    outcomes = []
    revoke = selected.revoke

    def provision() -> tuple[dict[str, Credential], dict[str, object]]:
        case.lifecycle.remember = selected.remember
        case.lifecycle.remember_intent = selected.remember_intent
        _, credential = case.create()
        return {"archive": credential}, {}

    def fail_after_provisioning(_credentials: dict[str, Credential]) -> dict[str, object]:
        case.provider.fail_delete = True
        raise LifecycleError(CANARY)

    def observe_revocation() -> bool:
        calls.append(clock[0])
        result = revoke()
        outcomes.append((selected.directory / "journey-result.json").read_bytes())
        assert selected.state.status()["credential_cleanup"] == (
            "verified" if result else "unresolved"
        )
        assert bool(worker.retained_credentials(selected.directory)) is not result
        return result

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        if recovers and clock[0] >= recovery_at:
            case.provider.fail_delete = False
        if clock[0] >= stop_at:
            raise KeyboardInterrupt

    monkeypatch.setattr(selected, "_provision", provision)
    monkeypatch.setattr(selected, "_production", fail_after_provisioning)
    monkeypatch.setattr(selected, "revoke", observe_revocation)
    monkeypatch.setattr(worker, "Worker", lambda *_args: selected)
    monkeypatch.setattr(Configuration, "load", lambda _path: selected.config)
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker",
            "--directory",
            str(selected.directory),
            "--config",
            "/unused",
            "--source",
            str(selected.source),
        ],
    )
    previous_umask = os.umask(0o077)
    try:
        with pytest.raises(KeyboardInterrupt):
            worker.main()
    finally:
        os.umask(previous_umask)
    assert calls == ([0, 300, 900] if recovers else [0, 300, 900, 2100, 4500, 8100, 11700])
    assert len(set(outcomes)) == 1
    assert selected.state.status()["qualification"] == "failed"
    assert selected.state.status()["closure"] == "unresolved"
    assert case.provider.creates == 1
    assert bool(case.provider.items) is not recovers


def test_real_provisioning_refuses_low_quota_before_any_run_or_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    selected.request["mode"] = "rehearsal"

    class ExhaustedCli(CountedCli):
        def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
            if arguments[:2] == ("service-account", "ratelimit"):
                value = native_limits()
                value[2]["used"], value[2]["remaining"] = 1000, 0
                return json.dumps(value).encode()
            return super().command(*arguments, stdin=stdin)

    cli = ExhaustedCli()
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    journal.append(
        event(
            "heartbeat",
            case.run_id,
            {
                "actor": "github",
                "helper_revision": selected.helper,
                "observed_at": stamp(datetime.now(UTC)),
                "status": "ready",
                "overdue": 0,
                "results": [],
            },
        )
    )
    case.provider.items["existing00000001"] = {"id": "existing00000001"}
    connection = Connections(
        journal,
        {"spaces": case.provider},
        dataclasses.replace(case.authority, valid_until=datetime.now(UTC) + timedelta(days=7)),
    )
    monkeypatch.setattr(worker, "connect", lambda *_args, **_kwargs: connection)
    with pytest.raises(LifecycleError, match="capacity is insufficient"):
        selected._provision()
    assert case.provider.creates == 0
    assert not any(record["kind"] in {"run", "intent"} for record in journal.records())


def test_cache_does_not_resolve_revocation_during_outage_and_cleanup_ignores_admission_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    path = tmp_path / "cache.json"
    case = Case(tmp_path / "case")
    case.lifecycle = Lifecycle(cached(cli, path), {"spaces": case.provider}, clock=lambda: case.now)
    intent, _credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    case.lifecycle.journal.records()
    cli.fail_list = True
    independent = Lifecycle(cached(cli, path), {"spaces": case.provider}, clock=lambda: case.now)
    with pytest.raises(LifecycleError, match="unavailable"):
        cleanup.sweep(independent, actor="github", helper="f" * 40)
    assert case.provider.deletes == []
    cli.fail_list = False
    monkeypatch.setattr(
        quota,
        "require_capacity",
        lambda *_args, **_kwargs: pytest.fail("cleanup must run even with low quota"),
    )
    independent = Lifecycle(cached(cli, path), {"spaces": case.provider}, clock=lambda: case.now)
    receipt = cleanup.sweep(independent, actor="github", helper="f" * 40)
    assert receipt["status"] == "ready"
    assert receipt["results"] == [
        {
            "intent_sha256": intent.sha256,
            "status": "verified",
            "negative_authentication": "unavailable",
        }
    ]
    assert case.provider.deletes == ["credential00000001"]


@pytest.mark.parametrize("fault", ["tamper", "changed-token"])
def test_invalid_restore_is_cold_read_and_only_fresh_validated_output_is_saved(
    tmp_path: Path, fault: str
) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    directory = tmp_path / "m3-11-journal-cache"
    directory.mkdir(mode=0o700)
    restored, output = directory / "restored.json", directory / "journal.json"
    record = event("result", Case(tmp_path / "case").run_id, {"test": CANARY})
    initial = cached(cli, output)
    initial.append(record)
    initial.records()
    if fault == "tamper":
        replace_private(output, {"ciphertext": "invalid"})
    else:
        # This models a separately authorized service-account replacement, not
        # automatic rotation. The live obligation vault remains authoritative.
        JournalCache(output, token=CANARY + "previous-account", vault="a" * 26).write({})
    workflow = yaml.safe_load(Path(".github/workflows/m3-11-credential-cleanup.yml").read_text())
    stage = next(
        step for step in workflow["jobs"]["reconcile"]["steps"] if step.get("id") == "cache_input"
    )
    # Execute the workflow's real boundary: a subsequent cleanup failure must
    # never leave unvalidated restored bytes at the path its save action uploads.
    subprocess.run(  # noqa: S603 - fixed workflow step with isolated non-secret paths
        ["/usr/bin/bash", "-e", "-o", "pipefail", "-c", stage["run"]],
        env={"PATH": os.environ["PATH"], "RUNNER_TEMP": str(tmp_path)},
        check=True,
        capture_output=True,
    )
    assert not output.exists()
    rejected = restored.read_bytes()
    cli.fail_list = True
    with pytest.raises(LifecycleError, match="unavailable"):
        cached(cli, restored, output=output).records()
    assert not output.exists()
    cli.fail_list = False
    before = cli.gets
    assert cached(cli, restored, output=output).records() == [record]
    assert cli.gets == before + 1
    assert restored.read_bytes() == rejected
    assert CANARY.encode() not in output.read_bytes()
    before = cli.gets
    assert cached(cli, output).records() == [record]
    assert cli.gets == before  # the next run can use the repaired cache


@pytest.mark.parametrize("fault", ["oversize", "unwritable", "unsafe-directory"])
def test_optional_cache_storage_cannot_prevent_live_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    case = Case(tmp_path / "case")
    case.lifecycle = Lifecycle(
        OpJournal(cast(OnePassword, cli), "a" * 26),
        {"spaces": case.provider},
        clock=lambda: case.now,
    )
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    if fault == "oversize":
        monkeypatch.setattr(journal_cache, "MAX_CACHE_BYTES", 1)
    elif fault == "unwritable":

        def unavailable(*_args: object) -> None:
            raise PermissionError

        monkeypatch.setattr(journal_cache, "replace_private", unavailable)
    output = tmp_path / "journal.json"
    if fault == "unsafe-directory":
        public = tmp_path / "unsafe-cache"
        public.mkdir(mode=0o755)
        public.chmod(0o755)  # Exercise public storage even under the CLI's private umask.
        output = public / "journal.json"
    independent = Lifecycle(
        cached(cli, tmp_path / "restored.json", output=output),
        {"spaces": case.provider},
        clock=lambda: case.now,
    )
    receipt = cleanup.sweep(
        independent, actor="github", helper="f" * 40, secrets={intent.sha256: credential}
    )
    assert receipt["status"] == "ready"
    assert case.provider.deletes == [credential.identifier]
    assert not output.exists()
    assert CANARY not in json.dumps(receipt)


def test_initialization_quiet_mode_never_publishes_admission_or_hides_new_intents(
    tmp_path: Path,
) -> None:
    cli = CountedCli()
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    case = Case(tmp_path / "case")
    independent = Lifecycle(journal, {"spaces": case.provider}, clock=lambda: case.now)
    receipt = cleanup.sweep(independent, actor="github", helper="f" * 40, quiet_empty=True)
    assert receipt["status"] == "initializing-empty"
    assert not journal.records()
    case.lifecycle = Lifecycle(
        OpJournal(cast(OnePassword, cli), "a" * 26),
        {"spaces": case.provider},
        clock=lambda: case.now,
    )
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    receipt = cleanup.sweep(
        independent,
        actor="github",
        helper="f" * 40,
        quiet_empty=True,
        secrets={intent.sha256: credential},
    )
    assert receipt["status"] == "ready" and case.provider.deletes == [credential.identifier]
    assert any(record["kind"] == "heartbeat" for record in journal.records())


def test_initialization_quiet_mode_refuses_failed_fresh_inventory(tmp_path: Path) -> None:
    cli = CountedCli()
    journal = OpJournal(cast(OnePassword, cli), "a" * 26)
    assert journal.records() == []
    cli.fail_list = True
    case = Case(tmp_path / "case")
    with pytest.raises(LifecycleError):
        cleanup.sweep(
            Lifecycle(journal, {"spaces": case.provider}),
            actor="github",
            helper="f" * 40,
            quiet_empty=True,
        )


@pytest.mark.parametrize("failed_revocation", [False, True])
def test_dead_controller_leaves_retry_set_only_after_verified_revocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failed_revocation: bool,
) -> None:
    cli = CountedCli()
    case = Case(tmp_path / "case")
    case.now = datetime.now(UTC)
    case.authority = dataclasses.replace(case.authority, valid_until=case.now + timedelta(days=7))
    case.lifecycle = Lifecycle(
        OpJournal(cast(OnePassword, cli), "a" * 26),
        {"spaces": case.provider},
        clock=lambda: case.now,
    )
    root = tmp_path / "runs"
    root.mkdir(mode=0o700)
    directory = root / case.run_id
    directory.mkdir(mode=0o700)
    for name in ("credential-intents", "credential-cleanup"):
        (directory / name).mkdir(mode=0o700)
    state = RunState(directory)
    state.begin(bound(case))
    write_private(
        directory / "request.json",
        {"binding": bound(case), "approval_sha256": "c" * 64},
    )
    intent, credential = case.create()
    case.provider.fail_delete = failed_revocation
    write_private(directory / "credential-intents" / (intent.sha256 + ".json"), intent.document())
    write_private(
        directory / "credential-cleanup" / (intent.sha256 + ".json"),
        {
            "intent_sha256": intent.sha256,
            "identifier": credential.identifier,
            "secret": credential.secret,
        },
    )
    write_private(directory / "runtime-inputs.json", {"private": CANARY})
    (directory / "failed.log").write_text(CANARY)
    state.update("running", cleanup="pending")
    clock = [0.0]
    calls = []
    death_at = 60

    class Daemon:
        def owned(self, name: str) -> dict[str, object]:
            assert name == docker.controller_name(case.run_id)
            return {"State": {"Running": clock[0] < death_at}}

    def connect(*_args: object, **_kwargs: object) -> Lifecycle:
        calls.append(clock[0])
        return Lifecycle(
            OpJournal(cast(OnePassword, cli), "a" * 26),
            {"spaces": case.provider},
            clock=lambda: case.now,
        )

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        if clock[0] >= 2 * 3600:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(
        cleanup, "cleanup_configuration", lambda _path: (TARGETS, "a" * 26, Bootstrap({}))
    )
    monkeypatch.setattr(cleanup, "connect_cleanup", connect)
    monkeypatch.setattr(docker, "Docker", Daemon)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cleanup",
            "--actor",
            "watchdog",
            "--watch",
            "--config",
            "/unused",
            "--runs",
            str(root),
        ],
    )
    with pytest.raises(KeyboardInterrupt):
        cleanup.main()
    assert calls == ([0, 60, 360, 960, 2160, 4560] if failed_revocation else [0, 60, 3660])
    assert state.status()["qualification"] == "interrupted"
    assert state.status()["credential_cleanup"] == (
        "unresolved" if failed_revocation else "verified"
    )
    assert state.status()["phase"] == "finished"
    assert state.status()["closure"] == "unresolved"
    assert len(list(directory.glob("watchdog-revocation-*.json"))) == (
        0 if failed_revocation else 1
    )
    assert bool(list((directory / "credential-cleanup").iterdir())) == failed_revocation
    assert (directory / "runtime-inputs.json").exists() == failed_revocation
    assert (directory / "failed.log").read_text() == CANARY
    assert CANARY not in capsys.readouterr().out


@pytest.mark.parametrize("completion", ["before-finish", "during-validation"])
def test_stale_watchdog_failure_preserves_concurrent_verified_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, completion: str
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    directory = selected.directory.with_name(case.run_id)
    selected.directory.rename(directory)
    selected.directory = directory
    selected.state = RunState(directory)
    selected.state.begin(selected.binding)
    for name in ("credential-intents", "credential-cleanup"):
        (directory / name).mkdir(mode=0o700)
    case.lifecycle.remember = selected.remember
    case.lifecycle.remember_intent = selected.remember_intent
    intent, credential = case.create()
    selected.state.finish_journey("failed", 1)
    original = (directory / "journey-result.json").read_bytes()
    case.lifecycle.request_revocation(case.run_id)
    case.provider.fail_delete = True
    stale = cleanup.sweep(
        case.lifecycle,
        actor="watchdog",
        helper=selected.helper,
        secrets={intent.sha256: credential},
    )
    assert stale["status"] == "unresolved"
    selected.state.update("finished", cleanup="unresolved")

    def finish_controller() -> None:
        case.provider.fail_delete = False
        assert selected.revoke()
        assert selected.state.status()["credential_cleanup"] == "verified"

    if completion == "before-finish":
        finish_controller()
    else:
        retained = worker.retained_credentials

        def finish_during_validation(path: Path) -> dict[str, Credential]:
            finish_controller()
            return retained(path)

        monkeypatch.setattr(watchdog, "retained_credentials", finish_during_validation)
    watchdog.finish_reconciled(case.lifecycle, {directory}, stale)
    assert selected.state.status()["credential_cleanup"] == "verified"
    assert selected.state.status()["qualification"] == "failed"
    assert (directory / "journey-result.json").read_bytes() == original
    assert not list(directory.glob("watchdog-revocation-*.json"))
    assert case.provider.creates == 1
    assert not case.provider.items


@pytest.mark.parametrize("first", ["controller", "watchdog"])
def test_local_cleanup_serializes_refresh_probe_and_secret_disposal(  # noqa: PLR0915 - real actor interleave
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, first: str
) -> None:
    selected, case = subject(tmp_path, monkeypatch)
    root = tmp_path / "runs"
    root.mkdir(mode=0o700)
    directory = root / case.run_id
    selected.directory.rename(directory)
    selected.directory, selected.state = directory, RunState(directory)
    selected.state.begin(selected.binding)
    for name in ("credential-intents", "credential-cleanup"):
        (directory / name).mkdir(mode=0o700)
    cli = CountedCli()
    case.lifecycle = Lifecycle(
        OpJournal(cast(OnePassword, cli), "a" * 26),
        {"spaces": case.provider},
        clock=lambda: case.now,
        remember=selected.remember,
        remember_intent=selected.remember_intent,
    )
    case.create()
    selected.state.finish_journey("failed", 1)
    original_result = (directory / "journey-result.json").read_bytes()
    entered, waiting, release, follower_connected = Event(), Event(), Event(), Event()
    inventory = case.provider.inventory
    denied = case.provider.denied

    def pause_inventory() -> list[dict[str, object]]:
        if not entered.is_set():
            entered.set()
            assert release.wait(10)
        return inventory()

    def connect(*_args: object, **_kwargs: object) -> Lifecycle:
        if current_thread().name == "follower":
            follower_connected.set()
        return Lifecycle(
            OpJournal(cast(OnePassword, cli), "a" * 26),
            {"spaces": case.provider},
            clock=lambda: case.now,
        )

    @contextmanager
    def locking(path: Path, *, blocking: bool = True) -> Iterator[None]:
        if current_thread().name == "follower":
            waiting.set()
        with cleanup_lock(path, blocking=blocking):
            yield

    monkeypatch.setattr(case.provider, "inventory", pause_inventory)
    monkeypatch.setattr(
        case.provider,
        "denied",
        lambda intent, credential: current_thread().name != "leader" and denied(intent, credential),
    )
    monkeypatch.setattr(cleanup, "connect_cleanup", connect)
    monkeypatch.setattr(worker, "cleanup_lock", locking)
    monkeypatch.setattr(cleanup, "cleanup_lock", locking)
    monkeypatch.setattr(
        cleanup, "cleanup_configuration", lambda _path: (TARGETS, "a" * 26, Bootstrap({}))
    )
    monkeypatch.setattr(
        cleanup,
        "parse_arguments",
        lambda: SimpleNamespace(
            runs=root,
            actor="watchdog",
            watch=False,
            config=Path("/unused"),
            journal_cache=None,
            journal_cache_output=None,
            quiet_empty=False,
        ),
    )
    monkeypatch.setattr(
        docker, "Docker", lambda: SimpleNamespace(owned=lambda _name: {"State": {"Running": False}})
    )

    def execute(actor: str, name: str) -> bool:
        current_thread().name = name
        return selected.revoke() if actor == "controller" else cleanup.main() == 0

    with ThreadPoolExecutor(max_workers=2) as pool:
        leader = pool.submit(execute, first, "leader")
        try:
            assert entered.wait(10)
            other = "watchdog" if first == "controller" else "controller"
            follower = pool.submit(execute, other, "follower")
            assert waiting.wait(10)
            assert follower.result(timeout=10) is False
            assert not follower_connected.is_set()
            assert worker.retained_credentials(directory)
        finally:
            release.set()
        assert leader.result(timeout=10) is False
        assert pool.submit(execute, other, "follower").result(timeout=10) is True
    assert follower_connected.is_set()
    assert not worker.retained_credentials(directory)
    assert selected.revoke()
    assert selected.state.status()["credential_cleanup"] == "verified"
    assert selected.state.status()["qualification"] == "failed"
    assert (directory / "journey-result.json").read_bytes() == original_result
    assert case.provider.creates == 1
    assert not case.provider.items
