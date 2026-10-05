"""Real launcher, activation and journal paths with asynchronous local replicas."""

# ruff: noqa: PLR2004 - exact operation counts and time bounds are the safety assertions

from __future__ import annotations

import copy
import json
import subprocess
import time
import uuid
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_connect_activate import HELPER, Case
from infrastructure.test_m3_11_connect_ledger import ANCHOR, CANARY, REMOTE_AUTHOR, VAULT, note
from infrastructure.test_m3_11_unattended_lifecycle import TARGETS
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import __main__ as cli
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended import connect_diagnostics as diagnostics
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.connect_api import Response
from scripts.m3_11_unattended.connect_ledger import SnapshotChangedError
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import LifecycleError


def launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Case, Configuration, dict[str, object], Path]:
    case = Case(tmp_path, monkeypatch)
    case.activation().activate(case.output)
    configuration = Configuration.load(case.output)
    run_id = str(uuid.uuid7())
    request: dict[str, object] = {
        "binding": {
            "managed_run_id": run_id,
            "source_revision": HELPER,
            "helper_revision": HELPER,
            "qualification_inputs_sha256": "d" * 64,
            "artifact_sha256": "e" * 64,
            "storage_target_sha256": TARGETS.storage_digest,
        },
        "mode": "rehearsal",
        "approval_sha256": "c" * 64,
        "ignored_private_input": CANARY,
    }
    monkeypatch.setattr(action, "WITNESS_SECONDS", 0)
    monkeypatch.setattr(control, "GitHub", lambda: case.github)
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 5)
    monkeypatch.setattr(control, "POLL_SECONDS", 1)
    return case, configuration, request, tmp_path / "connect-dispatch" / run_id


@pytest.mark.parametrize("scan", [1, 2, 3])
def test_valid_growth_during_each_snapshot_retries_same_native_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scan: int
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    native_request = case.shared.request
    reads = 0
    sleeps: list[float] = []

    def arrive(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        if method == "GET" and path == f"/v1/vaults/{VAULT}/items":
            reads += 1
            if reads == scan * 2:
                record = event("heartbeat", str(uuid.uuid7()), {"format": "local-double"})
                case.shared.items["9" * 26] = note(record, "9" * 26, author=REMOTE_AUTHOR)
                case.shared.version += 1
        return native_request(method, path, body)

    monkeypatch.setattr(case.shared, "request", arrive)
    monkeypatch.setattr(time, "sleep", sleeps.append)
    control.await_witness(configuration, request, directory=directory)
    proof = read_private(directory / "witness-ready.json")
    assert proof["github_run_id"] == len(case.github.executions)
    assert len(case.github.executions) == 4  # three activation operations, one witness
    assert sleeps == [1]
    assert reads == 8  # three stable scans, plus the complete restarted scan
    assert case.provider.creates == 0
    assert CANARY not in (directory / "launch-request.json").read_text()
    assert not (directory / "launcher-failure.json").exists()


@pytest.mark.parametrize("fault", ["malformed", "anchor", "adverse"])
def test_snapshot_retries_cannot_hide_invalid_or_adverse_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    native_request = case.shared.request
    reads = 0

    def arrive(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        if method == "GET" and path == f"/v1/vaults/{VAULT}/items":
            reads += 1
            if reads == 1:
                if fault == "anchor":
                    altered = copy.deepcopy(case.anchor)
                    cast(dict[str, object], altered["payload"])["changed"] = CANARY
                    case.shared.items[ANCHOR] = note(altered, ANCHOR)
                elif fault == "malformed":
                    record = event("heartbeat", str(uuid.uuid7()), {"format": "local-double"})
                    item = note(record, "9" * 26, author=REMOTE_AUTHOR)
                    item["version"] = 0
                    case.shared.items["9" * 26] = item
                else:
                    record = next(
                        json.loads(cast(list[dict[str, str]], item["fields"])[0]["value"])
                        for item in case.shared.items.values()
                        if json.loads(cast(list[dict[str, str]], item["fields"])[0]["value"])[
                            "payload"
                        ].get("actor")
                        == "github"
                    )
                    payload: dict[str, object] = {
                        **cast(dict[str, object], record["payload"]),
                        "status": "unresolved",
                    }
                    case.shared.items["9" * 26] = note(
                        event("heartbeat", str(uuid.uuid7()), payload),
                        "9" * 26,
                        author=REMOTE_AUTHOR,
                    )
                case.shared.version += 1
        return native_request(method, path, body)

    monkeypatch.setattr(case.shared, "request", arrive)
    # The first update can invalidate the initial snapshot; the next must reject
    # the actual contents instead of waiting for a more convenient later receipt.
    waits: list[float] = []
    monkeypatch.setattr(time, "sleep", waits.append)
    with pytest.raises(LifecycleError) as failure:
        control.await_witness(configuration, request, directory=directory)
    assert not isinstance(failure.value, SnapshotChangedError)
    assert len(waits) <= 1
    assert not (directory / "witness-ready.json").exists()
    assert len(case.github.executions) == 4
    assert case.provider.creates == 0


def test_continuously_changing_snapshot_expires_without_dispatch_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    native_request = case.shared.request
    clock = [0.0]
    reads = 0

    def arrive(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        nonlocal reads
        if method == "GET" and path == f"/v1/vaults/{VAULT}/items":
            reads += 1
            case.shared.version += 1
        return native_request(method, path, body)

    monkeypatch.setattr(case.shared, "request", arrive)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(LifecycleError, match="snapshot observation deadline elapsed"):
        control.await_witness(configuration, request, directory=directory)
    assert reads == 10 and clock[0] == 5
    assert len(case.github.executions) == 4 and case.provider.creates == 0
    assert not (directory / "witness-ready.json").exists()
    diagnostic = control.launch_evidence(directory, run_id=directory.name, helper=HELPER)
    assert CANARY not in json.dumps(diagnostic)
    detail = fields(diagnostic["diagnostic"], {"binding", "stage", "failure"})
    failure = fields(detail["failure"], {"category", "origin"})
    assert fields(failure["origin"], {"path", "line", "function"})["function"] == "stable_records"
    original = (directory / "launcher-failure.json").read_bytes()
    with pytest.raises(LifecycleError, match="attempt already consumed"):
        control.await_witness(configuration, request, directory=directory)
    assert (directory / "launcher-failure.json").read_bytes() == original
    assert len(case.github.executions) == 4


@pytest.mark.parametrize("fault", ["completed", "attempt", "late", "stopped-after-retry"])
def test_launcher_rechecks_native_execution_and_deadline_after_snapshot_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    native = case.github.run
    observations = 0
    clock = [0.0]

    def changed(run_id: int, *, attempt: int | None = None) -> dict[str, object]:
        nonlocal observations
        observations += 1
        result = native(run_id, attempt=attempt)
        if observations > 2:  # find_run validates identity before the first observation
            if fault in {"completed", "stopped-after-retry"}:
                result["status"] = "completed"
            elif fault == "attempt":
                result["run_attempt"] = 2
            else:
                clock[0] = 6
        return result

    monkeypatch.setattr(case.github, "run", changed)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    if fault == "stopped-after-retry":

        def pending(*args: object, **kwargs: object) -> None:
            raise SnapshotChangedError("valid async update")

        monkeypatch.setattr(control, "require_independent_ready", pending)
    with pytest.raises(LifecycleError):
        control.await_witness(configuration, request, directory=directory)
    assert observations == (4 if fault == "stopped-after-retry" else 3)
    assert not (directory / "witness-ready.json").exists()
    assert case.provider.creates == 0


def test_launcher_snapshot_requests_share_original_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    native = case.shared.request
    clock = [0.0]
    budgets = []

    def slow(method: str, path: str, body: dict[str, object] | None = None) -> Response:
        budgets.append(case.shared._request_timeout)
        clock[0] += min(3, case.shared._request_timeout)
        return native(method, path, body)

    monkeypatch.setattr(case.shared, "request", slow)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    with pytest.raises(LifecycleError, match="deadline elapsed"):
        control.await_witness(configuration, request, directory=directory)
    assert budgets == [5, 2] and clock[0] == 5
    assert case.shared._request_timeout == 30
    assert getattr(case.github, "_read_deadline", None) is None
    assert not (directory / "witness-ready.json").exists()


@pytest.mark.parametrize("late", [True, False])
def test_github_reads_use_remaining_budget_and_reject_late_success(
    monkeypatch: pytest.MonkeyPatch, late: bool
) -> None:
    client = control.GitHub()
    clock = [0.0]
    budgets = []

    def exchange(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        budgets.append(kwargs["timeout"])
        clock[0] += 3
        return subprocess.CompletedProcess([], 0, b"{}")

    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(subprocess, "run", exchange)
    with client.read_budget(2 if late else 4):
        if late:
            with pytest.raises(LifecycleError):
                client.api(control.PREFIX + "/actions/runs/1")
        else:
            assert client.api(control.PREFIX + "/actions/runs/1") == {}
        with pytest.raises(LifecycleError):
            client.api(control.PREFIX + "/actions/runs/1", method="POST")
    assert budgets == [2 if late else 4]
    assert client._read_deadline is None


@pytest.mark.parametrize(
    "fault", ["binding", "stage", "category", "path", "function", "line", "extra"]
)
def test_launcher_failure_export_rejects_secret_canaries_in_all_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    _case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 0)
    with pytest.raises(LifecycleError):
        control.await_witness(configuration, request, directory=directory)
    path = directory / "launcher-failure.json"
    value = read_private(path)
    if fault in {"binding", "stage"}:
        value[fault] = CANARY
    elif fault == "category":
        cast(dict[str, object], value["failure"])[fault] = CANARY
    elif fault == "extra":
        value["extra"] = CANARY
    else:
        detail = cast(dict[str, object], value["failure"])
        cast(dict[str, object], detail["origin"])[fault] = CANARY
    monkeypatch.setattr(control, "read_private", lambda p: value if p == path else read_private(p))
    with pytest.raises((LifecycleError, ValueError)):
        control.launch_evidence(directory, run_id=directory.name, helper=HELPER)


def test_launcher_cli_exports_only_closed_failure_and_requires_exact_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 0)
    with pytest.raises(LifecycleError):
        control.await_witness(configuration, request, directory=directory)
    monkeypatch.setattr(
        "sys.argv", ["unattended", "launch-evidence", directory.name, "--config", str(case.output)]
    )
    monkeypatch.setattr(cli, "git", lambda *_args: HELPER.encode())
    assert cli.main() == 0
    result = capsys.readouterr().out
    assert CANARY not in result
    assert json.loads(result)["request"]["binding"] == request["binding"]
    for run_id, helper in ((str(uuid.uuid7()), HELPER), (directory.name, "f" * 40)):
        with pytest.raises(LifecycleError, match="exact attempt"):
            control.launch_evidence(directory, run_id=run_id, helper=helper)


def test_broken_launcher_diagnostic_does_not_replace_original_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 0)

    def broken(*args: object, **kwargs: object) -> None:
        raise OSError(CANARY)

    monkeypatch.setattr(diagnostics, "write_private", broken)
    with pytest.raises(LifecycleError, match="readiness remains unproven"):
        control.await_witness(configuration, request, directory=directory)
    assert not (directory / "launcher-failure.json").exists()
    assert (directory / "submitted.json").exists()
    assert case.provider.creates == 0
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 5)
    with pytest.raises(LifecycleError, match="attempt already consumed"):
        control.await_witness(configuration, request, directory=directory)
    assert not (directory / "witness-ready.json").exists()
    assert len(case.github.executions) == 4


def test_interrupted_launcher_cannot_reenter_its_consumed_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    native = case.github.find_run

    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(case.github, "find_run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        control.await_witness(configuration, request, directory=directory)
    assert not (directory / "launcher-failure.json").exists()
    monkeypatch.setattr(case.github, "find_run", native)
    with pytest.raises(LifecycleError, match="attempt already consumed"):
        control.await_witness(configuration, request, directory=directory)
    assert len(case.github.executions) == 4 and case.provider.creates == 0
    assert not (directory / "witness-ready.json").exists()


def test_witness_rerun_cannot_replace_first_attempt_after_snapshot_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, configuration, request, directory = launcher(tmp_path, monkeypatch)
    checked = []

    def pending(*args: object, **kwargs: object) -> None:
        checked.append(True)
        raise SnapshotChangedError("valid async update")

    def rerun(_seconds: float) -> None:
        case.github.executions[-1]["run_attempt"] = 2

    monkeypatch.setattr(control, "require_independent_ready", pending)
    monkeypatch.setattr(time, "sleep", rerun)
    with pytest.raises(LifecycleError, match="execution changed during observation"):
        control.await_witness(configuration, request, directory=directory)
    assert checked == [True]
    assert read_private(directory / "witness-execution.json")["github_run_attempt"] == 1
    assert len(case.github.executions) == 4 and case.provider.creates == 0
    assert not (directory / "witness-ready.json").exists()
