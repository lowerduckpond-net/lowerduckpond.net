"""Exact dispatch reconciliation and authenticated receipts for the private launcher."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import uuid
import zipfile
from pathlib import Path
from typing import cast, override

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_control as control
from scripts.m3_11_unattended.github_checkpoint import REPOSITORY, WORKFLOW, WORKFLOW_ID
from scripts.m3_11_unattended.model import LifecycleError, digest


class GitHubDouble(control.GitHub):
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, object]] = []
        self.executions: list[dict[str, object]] = []
        self.fail_after_dispatch = False
        self.receipts: dict[int, dict[str, object]] = {}
        self.archive: bytes = b""
        self.archive_digest = ""

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
                    "repository": {"full_name": REPOSITORY},
                    "head_repository": {"full_name": REPOSITORY},
                    "status": "completed",
                    "conclusion": "success",
                    "run_attempt": 1,
                }
            )
            if self.fail_after_dispatch:
                raise LifecycleError("simulated lost reply")
            return None
        if "/runs?" in path:
            return {"workflow_runs": self.executions}
        if "/artifacts?" in path:
            return {
                "total_count": 1,
                "artifacts": [
                    {
                        "id": 15,
                        "name": "m3-11-credential-cleanup-1",
                        "expired": False,
                        "digest": self.archive_digest,
                    }
                ],
            }
        if path.endswith("/zip"):
            assert binary
            return self.archive
        if "/actions/runs/" in path:
            return self.executions[int(path.rsplit("/", 1)[-1]) - 1]
        raise AssertionError(path)

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
