"""Authenticated GET capture and strict offline independent diagnostic proof.

The offline parser does not authenticate arbitrary JSON. The supported live
entry uses the existing authenticated gh CLI and captures only these fixed GETs;
it never dispatches, changes a variable or exports bootstrap/child credentials.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from subprocess import SubprocessError
from typing import cast

from scripts.m3_11_frozen_collect import read_command
from scripts.m3_11_frozen_github import MAX_BODY, MAX_ZIP, RUN_KEYS, _list
from scripts.m3_11_isolation_action import FORMAT, REPOSITORY, WORKFLOW
from scripts.m3_11_isolation_journal import github
from scripts.m3_11_isolation_manifest import Manifest
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import digest, instant


class GitHub:
    def __init__(self) -> None:
        executable = shutil.which("gh")
        if executable is None:
            raise ValueError("authenticated GitHub GET transport is unavailable")
        self.executable = executable

    def get(self, path: str) -> bytes:
        pattern = (
            r"repos/"
            + re.escape(REPOSITORY)
            + r"(?:/actions/(?:workflows/m3-11-public-ca-cleanup\.yml|runs/[1-9][0-9]*"
            r"(?:/attempts/1(?:/jobs\?per_page=100)?|/artifacts\?per_page=100)?"
            r"|artifacts/[1-9][0-9]*/zip))?"
        )
        if re.fullmatch(pattern, path) is None:
            raise ValueError("isolated proof GET escaped its fixed repository")
        try:
            raw = read_command(
                [self.executable, "api", "--hostname", "github.com", "--method", "GET", path],
                environment=dict(os.environ),
                deadline=time.monotonic() + 60,
                maximum=MAX_ZIP,
            )
        except OSError, RuntimeError, ValueError, SubprocessError:
            raise ValueError("isolated GitHub GET failed") from None
        if not 0 < len(raw) <= MAX_ZIP:
            raise ValueError("isolated GitHub GET was unsuccessful or exceeds its bound")
        return raw


@dataclass(frozen=True)
class Proof:
    manifest_sha256: str
    operation: str
    receipt: dict[str, object]
    authentication: dict[str, object]
    provenance: dict[str, object]


def _json(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_BODY:
        raise ValueError("isolated proof document exceeds its bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("isolated proof document is not an object")
    return value


def _run(  # noqa: PLR0913 - exact native identity selectors
    value: dict[str, object],
    *,
    manifest: Manifest,
    repository_id: int,
    workflow_id: int,
    run_id: int,
    operation: str,
) -> None:
    expected_title = "M3.11 isolated public CA " + operation
    if (
        value.get("id") != run_id
        or value.get("run_attempt") != 1
        or value.get("head_sha") != manifest.plan.source_revision
        or value.get("workflow_id") != workflow_id
        or value.get("path") != ".github/workflows/" + WORKFLOW
        or value.get("head_branch") != "main"
        or value.get("status") != "completed"
        or value.get("conclusion") != "success"
        or value.get("event")
        not in (
            {"workflow_dispatch"} if operation != "reconcile" else {"schedule", "workflow_dispatch"}
        )
        or value.get("display_title") != expected_title
    ):
        raise ValueError("isolated independent run identity or result differs")
    for key in ("repository", "head_repository"):
        row = value.get(key)
        if (
            not isinstance(row, dict)
            or row.get("id") != repository_id
            or row.get("full_name") != REPOSITORY
        ):
            raise ValueError("isolated independent repository identity differs")
    if (
        not instant(value["created_at"])
        <= instant(value["run_started_at"])
        <= instant(value["updated_at"])
    ):
        raise ValueError("isolated independent run chronology differs")


def capture(  # noqa: PLR0912, PLR0915 - complete native GET/ZIP proof
    manifest: Manifest, run_id: int, *, operation: str, api: Callable[[str], bytes] | None = None
) -> Proof:
    """Capture complete native responses; transport substitution is for tests."""
    if (
        type(run_id) is not int
        or run_id < 1
        or operation not in {"validate", "confirm", "reconcile", "cleanup"}
    ):
        raise ValueError("isolated independent proof selector is invalid")
    get = GitHub().get if api is None else api
    base = "repos/" + REPOSITORY
    repository = _json(get(base))
    workflow = _json(get(base + "/actions/workflows/" + WORKFLOW))
    repository_id, workflow_id = repository.get("id"), workflow.get("id")
    if (
        type(repository_id) is not int
        or repository_id < 1
        or repository.get("full_name") != REPOSITORY
        or type(workflow_id) is not int
        or workflow_id < 1
        or workflow.get("path") != ".github/workflows/" + WORKFLOW
        or workflow.get("state") != "active"
    ):
        raise ValueError("isolated independent workflow authority differs")
    prefix = base + f"/actions/runs/{run_id}"
    run = _json(get(prefix))
    attempt = _json(get(prefix + "/attempts/1"))
    for value in (run, attempt):
        _run(
            value,
            manifest=manifest,
            repository_id=repository_id,
            workflow_id=workflow_id,
            run_id=run_id,
            operation=operation,
        )
    if any(run.get(key) != attempt.get(key) for key in RUN_KEYS):
        raise ValueError("isolated independent attempt changed")
    jobs = _list(_json(get(prefix + "/attempts/1/jobs?per_page=100")), "jobs")
    selected = [job for job in jobs if job.get("name") == "isolation"]
    if len(selected) != 1:
        raise ValueError("isolated independent job is ambiguous")
    job = selected[0]
    if (
        type(job.get("id")) is not int
        or cast(int, job["id"]) < 1
        or job.get("run_id") != run_id
        or job.get("run_attempt") != 1
        or job.get("head_sha") != manifest.plan.source_revision
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or not instant(run["run_started_at"])
        <= instant(job["started_at"])
        <= instant(job["completed_at"])
        <= min(instant(run["updated_at"]), instant(attempt["updated_at"]))
    ):
        raise ValueError("isolated independent job binding differs")
    steps = job.get("steps")
    if not isinstance(steps, list):
        raise ValueError("isolated independent steps are missing")
    for name in (
        "Select the exact public diagnostic manifest",
        "Require trusted main history",
        "Run the bounded independent diagnostic operation",
    ):
        matches = [item for item in steps if isinstance(item, dict) and item.get("name") == name]
        if len(matches) != 1 or matches[0].get("conclusion") != "success":
            raise ValueError("isolated independent executed another path")
    artifacts = _list(_json(get(prefix + "/artifacts?per_page=100")), "artifacts")
    documents: dict[str, dict[str, object]] = {}
    hashes: dict[str, object] = {}
    for kind, name, filename in (
        ("receipt", f"m3-11-public-ca-{run_id}-attempt-1", "receipt.json"),
        (
            "authentication",
            f"m3-11-public-ca-authentication-{run_id}-attempt-1",
            "authentication.json",
        ),
    ):
        matches = [row for row in artifacts if row.get("name") == name]
        if len(matches) != 1:
            raise ValueError("isolated independent artifact is missing or ambiguous")
        artifact = matches[0]
        native = artifact.get("workflow_run")
        if (
            type(artifact.get("id")) is not int
            or artifact["id"] < 1
            or artifact.get("expired") is not False
            or not isinstance(native, dict)
            or native.get("id") != run_id
            or native.get("head_sha") != manifest.plan.source_revision
            or native.get("head_branch") != "main"
            or native.get("repository_id") != repository_id
            or native.get("head_repository_id") != repository_id
            or not instant(job["started_at"])
            <= instant(artifact["created_at"])
            <= instant(job["completed_at"])
        ):
            raise ValueError("isolated independent artifact provenance differs")
        raw = get(base + f"/actions/artifacts/{artifact['id']}/zip")
        if (
            not 0 < len(raw) <= MAX_ZIP
            or artifact.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest()
        ):
            raise ValueError("isolated independent ZIP digest differs")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if (
                len(entries) != 1
                or entries[0].filename != filename
                or entries[0].file_size > MAX_BODY
            ):
                raise ValueError("isolated independent artifact members differ")
            body = archive.read(entries[0])
        value = _json(body)
        if (
            not instant(job["started_at"])
            <= instant(value["observed_at"])
            < instant(job["completed_at"]) + timedelta(seconds=1)
        ):
            raise ValueError("isolated independent observation is outside its job")
        documents[kind] = value
        hashes[kind] = {
            "artifact_id": artifact["id"],
            "zip_sha256": hashlib.sha256(raw).hexdigest(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    auth = documents["authentication"]
    expected = {**manifest.independent_access, "authenticated": True, "forbidden_vaults_denied": 2}
    if fields(auth, {*expected, "status", "observed_at"}) != {
        **expected,
        "status": "verified",
        "observed_at": auth["observed_at"],
    } or not instant(auth["observed_at"]) < instant(auth["expires_at"]):
        raise ValueError("isolated independent authentication differs from its signed baseline")
    receipt = documents["receipt"]
    actor = github(receipt.get("github"), manifest)
    if (
        receipt.get("format") != FORMAT
        or receipt.get("status") != "ready"
        or receipt.get("manifest_sha256") != manifest.sha256
        or receipt.get("plan_sha256") != manifest.plan.sha256
        or receipt.get("operation") != operation
        or receipt.get("credential_creation") is not False
        or receipt.get("temporary_runtime_closed") is not True
        or actor["run_id"] != run_id
        or actor["run_attempt"] != 1
        or actor["event"] != run["event"]
        or actor["authentication_sha256"] != digest(expected)
    ):
        raise ValueError("isolated independent constructed receipt differs")
    if operation == "confirm" and (
        receipt.get("confirmation") != "exact-three-role-manifest"
        or receipt.get("create_verified") is not False
    ):
        raise ValueError("isolated confirmation does not cover the exact pre-CREATE manifest")
    if operation in {"cleanup", "reconcile"} and receipt.get("lease_state") != "closed":
        raise ValueError("isolated final proof is not closed")
    if not instant(receipt["observed_at"]) <= datetime.now(UTC):
        raise ValueError("isolated independent proof is from the future")
    return Proof(
        manifest.sha256,
        operation,
        receipt,
        auth,
        {
            "run_id": run_id,
            "run_attempt": 1,
            "job_id": job["id"],
            "source_revision": manifest.plan.source_revision,
            "event": run["event"],
            "artifacts": hashes,
            "receipt_sha256": digest(receipt),
            "authentication_sha256": digest(auth),
        },
    )
