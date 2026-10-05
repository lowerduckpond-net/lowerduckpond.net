"""Exact dispatch reconciliation and authenticated receipts for the private launcher."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast, override
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended.github_checkpoint import REPOSITORY, WORKFLOW, WORKFLOW_ID
from scripts.m3_11_unattended.model import LifecycleError, digest, instant, stamp


class GitHubDouble(control.GitHub):
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, object]] = []
        self.executions: list[dict[str, object]] = []
        self.fail_after_dispatch = False
        self.receipts: dict[int, dict[str, object]] = {}
        self.archive: bytes = b""
        self.archive_digest = ""
        now = datetime.now(UTC)
        self.started = stamp(now - timedelta(minutes=2))
        self.completed = stamp(now + timedelta(minutes=2))
        self.created = stamp(now)
        self.artifacts: list[dict[str, object]] | None = None
        self.jobs: list[dict[str, object]] | None = None

    @override
    def api(
        self, path: str, *, method: str = "GET", body: object = None, binary: bool = False
    ) -> object:
        self.requests.append((method, path, body))
        if method == "POST" and path.endswith("/dispatches"):
            assert isinstance(body, dict)
            inputs = cast(dict[str, str], body["inputs"])
            self.executions.append(
                {
                    "id": len(self.executions) + 1,
                    "display_title": f"M3.11 cleanup {inputs['operation']} {inputs['dispatch_id']}",
                    "workflow_id": WORKFLOW_ID,
                    "path": ".github/workflows/" + WORKFLOW,
                    "head_branch": "main",
                    "event": "workflow_dispatch",
                    "repository": {"full_name": REPOSITORY, "id": 42},
                    "head_repository": {"full_name": REPOSITORY, "id": 42},
                    "status": "completed",
                    "conclusion": "success",
                    "run_attempt": 1,
                    "head_sha": "a" * 40,
                    "run_started_at": self.started,
                    "updated_at": self.completed,
                }
            )
            if self.fail_after_dispatch:
                raise LifecycleError("simulated lost reply")
            return None
        if "/runs?" in path:
            query = parse_qs(urlsplit(path).query)
            rows = [
                row
                for row in self.executions
                if "status" not in query or row["status"] == query["status"][0]
            ]
            return {"workflow_runs": rows, "total_count": len(rows)}
        if "/artifacts?" in path:
            rows = self.artifacts if self.artifacts is not None else [self.artifact(15)]
            return {
                "total_count": len(rows),
                "artifacts": copy.deepcopy(rows),
            }
        if path.endswith("/zip"):
            assert binary
            return self.archive
        if "/actions/runs/" in path:
            run_id = int(path.split("/actions/runs/")[1].split("/", maxsplit=1)[0])
            run = self.executions[run_id - 1]
            if "/jobs?" in path:
                jobs = (
                    self.jobs
                    if self.jobs is not None
                    else [
                        {
                            "id": 50,
                            "run_id": run_id,
                            "run_attempt": run["run_attempt"],
                            "head_sha": run["head_sha"],
                            "name": "connect",
                            "status": "completed",
                            "conclusion": "success",
                            "started_at": self.started,
                            "completed_at": self.completed,
                        }
                    ]
                )
                return {"total_count": len(jobs), "jobs": copy.deepcopy(jobs)}
            return copy.deepcopy(run)
        raise AssertionError(path)

    def artifact(self, identifier: int, *, legacy: bool = False) -> dict[str, object]:
        attempt = self.executions[0]["run_attempt"]
        return {
            "id": identifier,
            "name": "m3-11-credential-cleanup-1" + ("" if legacy else f"-attempt-{attempt}"),
            "expired": False,
            "digest": self.archive_digest,
            "created_at": self.created,
            "workflow_run": {
                "id": 1,
                "repository_id": 42,
                "head_repository_id": 42,
                "head_branch": "main",
                "head_sha": "a" * 40,
            },
        }

    def package(self, receipt: dict[str, object], *, extra: bool = False) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("receipt.json", json.dumps(receipt))
            if extra:
                archive.writestr("private.log", "PRIVATE-CANARY")
        self.archive = output.getvalue()
        self.archive_digest = "sha256:" + hashlib.sha256(self.archive).hexdigest()


def test_lost_dispatch_reply_reconciles_unique_run_without_another_post(tmp_path: Path) -> None:
    github = GitHubDouble()
    github.fail_after_dispatch = True
    selected: dict[str, object] = {"active_helper": "a" * 40}
    dispatch = github.dispatch(
        tmp_path, operation="witness", selection=selected, run_sha256="b" * 64
    )
    assert read_private(tmp_path / "submitted.json") == {"dispatch_sha256": digest(dispatch)}
    assert github.find_run(dispatch) == 1
    assert (
        github.dispatch(tmp_path, operation="witness", selection=selected, run_sha256="b" * 64)
        == dispatch
    )
    assert len(github.executions) == 1
    with pytest.raises(LifecycleError, match="rebound"):
        github.dispatch(tmp_path, operation="witness", selection=selected, run_sha256="c" * 64)


@pytest.mark.parametrize("fault", ["duplicates", "workflow", "repository", "branch", "event"])
def test_dispatch_cannot_accept_another_execution(tmp_path: Path, fault: str) -> None:
    github = GitHubDouble()
    dispatch = github.dispatch(tmp_path, operation="discovery", selection={})
    run = github.executions[0]
    if fault == "duplicates":
        github.executions.append(copy.deepcopy(run))
    elif fault == "workflow":
        run["workflow_id"] = 20
    elif fault == "repository":
        run["head_repository"] = {"full_name": "someone/else"}
    elif fault == "branch":
        run["head_branch"] = "unreviewed"
    else:
        run["event"] = "pull_request"
    with pytest.raises(LifecycleError):
        github.find_run(dispatch)


@pytest.mark.parametrize("fault", ["none", "extra", "digest", "identity", "helper", "failed"])
def test_only_exact_sanitized_success_receipt_can_complete_dispatch(
    tmp_path: Path, fault: str
) -> None:
    github = GitHubDouble()
    dispatch = github.dispatch(tmp_path, operation="genesis", selection={})
    value: dict[str, object] = {
        "format": action.RECEIPT_FORMAT,
        "status": "ready",
        "operation": "genesis",
        "dispatch_id": dispatch["dispatch_id"],
        "helper_revision": "a" * 40,
        "selection_sha256": dispatch["selection_sha256"],
        "observed_at": dispatch["requested_at"],
        "proof": {"provider_children_created": False},
    }
    if fault == "identity":
        value["dispatch_id"] = str(uuid.uuid7())
    if fault == "helper":
        value["helper_revision"] = "b" * 40
    if fault == "failed":
        github.executions[0]["conclusion"] = "failure"
    github.package(value, extra=fault == "extra")
    if fault == "digest":
        github.archive_digest = "sha256:" + "0" * 64
    if fault == "none":
        assert github.wait(dispatch, helper="a" * 40, directory=tmp_path) == value
        assert read_private(tmp_path / "receipt.json") == value
    else:
        with pytest.raises(LifecycleError):
            github.wait(dispatch, helper="a" * 40, directory=tmp_path)
        assert not (tmp_path / "receipt.json").exists()


def test_missing_execution_keeps_submission_identity_without_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = GitHubDouble()
    dispatch = github.dispatch(tmp_path, operation="discovery", selection={})
    github.executions.clear()
    monkeypatch.setattr(control, "TIMEOUT_SECONDS", 0)
    with pytest.raises(LifecycleError, match="pending"):
        github.wait(dispatch, helper="a" * 40, directory=tmp_path)
    github.dispatch(tmp_path, operation="discovery", selection={})
    assert not github.executions and (tmp_path / "submitted.json").exists()


def receipt_case(tmp_path: Path) -> tuple[GitHubDouble, dict[str, object], dict[str, object]]:
    github = GitHubDouble()
    dispatch = github.dispatch(tmp_path, operation="discovery", selection={})
    receipt: dict[str, object] = {
        "format": action.RECEIPT_FORMAT,
        "status": "ready",
        "operation": "discovery",
        "dispatch_id": dispatch["dispatch_id"],
        "helper_revision": "a" * 40,
        "selection_sha256": dispatch["selection_sha256"],
        "observed_at": dispatch["requested_at"],
        "proof": {"provider_children_created": False},
    }
    github.package(receipt)
    return github, dispatch, receipt


@pytest.mark.parametrize("legacy", [False, True])
def test_successful_rerun_retains_failed_artifact_and_binds_current_attempt(
    tmp_path: Path, legacy: bool
) -> None:
    github, dispatch, receipt = receipt_case(tmp_path)
    github.executions[0]["run_attempt"] = 2
    old = github.artifact(100, legacy=True)
    old["created_at"] = stamp(instant(github.started) - timedelta(minutes=1))
    current = github.artifact(16, legacy=legacy)
    github.artifacts = [old, current]
    assert github.wait(dispatch, helper="a" * 40, directory=tmp_path) == receipt
    source = read_private(tmp_path / "receipt-source.json")
    assert source["run_attempt"] == github.executions[0]["run_attempt"]
    assert source["artifact_id"] == current["id"]
    assert source["receipt_sha256"] == digest(receipt)
    assert github.artifacts == [old, current]
    assert any(path.endswith("/artifacts/16/zip") for _method, path, _body in github.requests)
    assert not any(method in {"DELETE", "PATCH"} for method, _path, _body in github.requests)


@pytest.mark.parametrize(
    "fault",
    [
        "old-only",
        "boundary",
        "duplicates",
        "canonical-duplicates",
        "expired",
        "misbound",
        "old-name",
    ],
)
def test_rerun_does_not_select_stale_ambiguous_or_invalid_artifacts(
    tmp_path: Path, fault: str
) -> None:
    github, dispatch, _receipt = receipt_case(tmp_path)
    github.executions[0]["run_attempt"] = 2
    current = github.artifact(16, legacy=fault in {"old-only", "boundary", "duplicates"})
    github.artifacts = [current]
    if fault == "old-only":
        current["created_at"] = stamp(instant(github.started) - timedelta(seconds=1))
    elif fault == "boundary":
        current["created_at"] = github.started
    elif fault in {"duplicates", "canonical-duplicates"}:
        github.artifacts.append({**current, "id": 17})
    elif fault == "old-name":
        current["name"] = "m3-11-credential-cleanup-1-attempt-1"
    else:
        # An invalid canonical receipt must not fall back to a valid legacy one.
        github.artifacts.append(github.artifact(17, legacy=True))
        if fault == "expired":
            current["expired"] = True
        else:
            cast(dict[str, object], current["workflow_run"])["head_sha"] = "b" * 40
    with pytest.raises(LifecycleError):
        github.wait(dispatch, helper="a" * 40, directory=tmp_path)
    assert not (tmp_path / "receipt.json").exists()
    assert not (tmp_path / "receipt-source.json").exists()


@pytest.mark.parametrize(
    "field", ["id", "repository_id", "head_repository_id", "head_branch", "head_sha"]
)
def test_receipt_native_metadata_cannot_cross_execution_boundaries(
    tmp_path: Path, field: str
) -> None:
    github, _dispatch, _receipt = receipt_case(tmp_path)
    artifact = github.artifact(15)
    cast(dict[str, object], artifact["workflow_run"])[field] = "unrelated"
    github.artifacts = [artifact]
    with pytest.raises(LifecycleError, match="misbound"):
        github.receipt(1)


@pytest.mark.parametrize(
    "fault",
    [
        "attempt-head",
        "attempt-status",
        "attempt-count",
        "rerun",
        "truncated-jobs",
        "truncated-artifacts",
        "old-job",
    ],
)
def test_receipt_requires_stable_successful_attempt_and_complete_job_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    github, _dispatch, _receipt = receipt_case(tmp_path)
    api = github.api

    def changing(path: str, **kwargs: object) -> object:
        value = api(path, **kwargs)  # type: ignore[arg-type]
        if "/attempts/" in path and "/jobs?" not in path:
            assert isinstance(value, dict)
            if fault == "attempt-head":
                value["head_sha"] = "b" * 40
            elif fault == "attempt-status":
                value["conclusion"] = "failure"
            elif fault == "attempt-count":
                value["run_attempt"] = 2
        if path.endswith("/zip") and fault == "rerun":
            github.executions[0]["run_attempt"] = 2
        if "/jobs?" in path or "/artifacts?" in path:
            assert isinstance(value, dict)
            if ("/jobs?" in path and fault == "truncated-jobs") or (
                "/artifacts?" in path and fault == "truncated-artifacts"
            ):
                value["total_count"] = cast(int, value["total_count"]) + 1
            if "/jobs?" in path and fault == "old-job":
                cast(list[dict[str, object]], value["jobs"])[0]["run_attempt"] = 0
        return value

    monkeypatch.setattr(github, "api", changing)
    with pytest.raises(LifecycleError):
        github.receipt(1)


def test_current_artifact_cannot_repackage_an_old_receipt(tmp_path: Path) -> None:
    github, _dispatch, receipt = receipt_case(tmp_path)
    receipt["observed_at"] = stamp(instant(github.started) - timedelta(seconds=1))
    github.package(receipt)
    with pytest.raises(LifecycleError, match="observed during"):
        github.receipt(1)


def test_receipt_origin_survives_interruption_and_cannot_be_replaced_by_another_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github, dispatch, receipt = receipt_case(tmp_path)
    write = control.write_private

    def stop(path: Path, value: dict[str, object]) -> None:
        if path.name == "receipt.json":
            raise OSError("interrupted after source retention")
        write(path, value)

    with monkeypatch.context() as interrupted:
        interrupted.setattr(control, "write_private", stop)
        with pytest.raises(OSError, match="interrupted after"):
            github.wait(dispatch, helper="a" * 40, directory=tmp_path)
    source = (tmp_path / "receipt-source.json").read_bytes()
    assert not (tmp_path / "receipt.json").exists()
    assert github.wait(dispatch, helper="a" * 40, directory=tmp_path) == receipt
    assert (tmp_path / "receipt-source.json").read_bytes() == source
    github.executions[0]["run_attempt"] = 2
    with pytest.raises(LifecycleError, match="origin changed"):
        github.wait(dispatch, helper="a" * 40, directory=tmp_path)
    assert (tmp_path / "receipt-source.json").read_bytes() == source
    assert read_private(tmp_path / "receipt.json") == receipt


@pytest.mark.parametrize("truncate", [False, True])
def test_initialization_drains_complete_paginated_pending_execution_inventory(
    monkeypatch: pytest.MonkeyPatch, truncate: bool
) -> None:
    github = GitHubDouble()
    total = 101

    def inventory(path: str, **_kwargs: object) -> object:
        query = parse_qs(urlsplit(path).query)
        if query["status"] != ["pending"]:
            return {"total_count": 0, "workflow_runs": []}
        page = int(query["page"][0])
        ids = range(1, total) if page == 1 else ([] if truncate else [total])
        return {
            "total_count": total,
            "workflow_runs": [
                {
                    "id": value,
                    "workflow_id": WORKFLOW_ID,
                    "head_branch": "main",
                    "status": "pending",
                }
                for value in ids
            ],
        }

    monkeypatch.setattr(github, "api", inventory)
    if truncate:
        with pytest.raises(LifecycleError, match="pagination"):
            github.active_executions()
    else:
        assert github.active_executions() == set(range(1, total + 1))
    pending = [{1}, set(), set()]
    monkeypatch.setattr(github, "active_executions", lambda: pending.pop(0))
    monkeypatch.setattr(control, "POLL_SECONDS", 0)
    github.drain()
    assert not pending
