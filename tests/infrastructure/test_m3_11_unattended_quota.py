"""Keep independent cleanup usable within the real account-wide request budget."""

from __future__ import annotations

import copy
import dataclasses
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import cleanup, docker, journal_cache, quota, watchdog, worker
from scripts.m3_11_unattended.config import Bootstrap, Connections
from scripts.m3_11_unattended.journal import OnePassword, OpJournal, event
from scripts.m3_11_unattended.journal_cache import JournalCache
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import LifecycleError, stamp
from scripts.m3_11_unattended.state import RunState, replace_private

from .test_m3_11_unattended_controller import subject
from .test_m3_11_unattended_lifecycle import CANARY, TARGETS, Case
from .test_m3_11_unattended_providers import JournalCli

DAY_SECONDS = 24 * 60 * 60
DAILY_SWEEPS = 2 * 24
IDLE_REQUEST_BUDGET = 600


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


def test_full_day_of_real_cleanup_loops_stays_below_idle_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    cli = CountedCli()
    case = Case(tmp_path / "case")
    initial = OpJournal(cast(OnePassword, cli), "a" * 26)
    for number in range(20):
        initial.append(event("result", case.run_id, {"historical_record": number}))
    cli.requests = 0
    clock = [0.0]
    connections = []

    class Clock:
        @staticmethod
        def now(_zone: object) -> datetime:
            return datetime(2026, 10, 5, tzinfo=UTC) + timedelta(seconds=clock[0])

    def connect(*_args: object) -> Lifecycle:
        connections.append(clock[0])
        cli.requests += 4  # the four immutable bootstrap references
        return Lifecycle(OpJournal(cast(OnePassword, cli), "a" * 26), {"spaces": case.provider})

    def sleep(seconds: float) -> None:
        clock[0] += seconds
        if clock[0] % 3600 == 0:
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
                        str(tmp_path / "journal.json"),
                    ],
                )
                assert cleanup.main() == 0
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
    monkeypatch.setattr(docker, "Docker", SimpleNamespace)
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
    cli = CountedCli()

    def connect(*_args: object) -> Lifecycle:
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
    restored, output = tmp_path / "restored.json", tmp_path / "journal.json"
    record = event("result", Case(tmp_path / "case").run_id, {"test": CANARY})
    initial = cached(cli, restored)
    initial.append(record)
    initial.records()
    if fault == "tamper":
        replace_private(restored, {"ciphertext": "invalid"})
    else:
        # This models a separately authorized service-account replacement, not
        # automatic rotation. The live obligation vault remains authoritative.
        JournalCache(restored, token=CANARY + "previous-account", vault="a" * 26).write({})
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
    state.begin({"managed_run_id": case.run_id})
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

    def connect(*_args: object) -> Lifecycle:
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
    assert calls == ([0, *range(60, 2 * 3600, 300)] if failed_revocation else [0, 60, 3660])
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
