"""Workspace-side control of the fixed protected cleanup workflow, without bootstrap delivery."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
import shutil
import subprocess
import time
import uuid
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_qualification_evidence import digest as sha256
from scripts.m3_11_unattended import connect_action
from scripts.m3_11_unattended.cleanup import ReadinessPendingError, require_independent_ready
from scripts.m3_11_unattended.config import Configuration
from scripts.m3_11_unattended.connect_admission import run_digest
from scripts.m3_11_unattended.connect_diagnostics import retain_failure, verified_failure
from scripts.m3_11_unattended.connect_journal import ConnectJournal
from scripts.m3_11_unattended.connect_ledger import SnapshotChangedError
from scripts.m3_11_unattended.github_checkpoint import REPOSITORY, WORKFLOW, WORKFLOW_ID
from scripts.m3_11_unattended.inputs import BINDING
from scripts.m3_11_unattended.model import LifecycleError, digest, identity, instant, stamp
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import revision

ENVIRONMENT = "m3-11-credential-cleanup"
PREFIX = f"repos/{REPOSITORY}"
VARIABLES = f"{PREFIX}/environments/{ENVIRONMENT}/variables"
SETTING = "M3_11_CONNECT_CONFIGURATION"
BACKEND = "M3_11_CLEANUP_BACKEND"
HELPER = "M3_11_CLEANUP_REVISION"
TIMEOUT_SECONDS = 20 * 60
POLL_SECONDS = 10
MAX_BYTES = 1024 * 1024
MAX_EXECUTIONS = 1000
EXECUTION_PAGE_SIZE = 25
EXECUTION_SCAN_SECONDS = 90


class GitHub:
    def __init__(self) -> None:
        executable = shutil.which("gh")
        if executable is None:
            raise LifecycleError("GitHub control CLI is unavailable")
        self.executable = executable
        self._receipt_source: dict[str, object] | None = None

    @contextmanager
    def read_budget(self, deadline: float) -> Iterator[None]:
        previous = getattr(self, "_read_deadline", None)
        self._read_deadline = min(previous, deadline) if previous is not None else deadline
        try:
            yield
        finally:
            self._read_deadline = previous

    def api(
        self, path: str, *, method: str = "GET", body: object = None, binary: bool = False
    ) -> object:
        if not path.startswith(PREFIX + "/") or method not in {"GET", "POST", "PATCH"}:
            raise LifecycleError("GitHub control escaped the dedicated repository")
        deadline = getattr(self, "_read_deadline", None)
        timeout = 30 if deadline is None else min(30, deadline - time.monotonic())
        if timeout <= 0 or (deadline is not None and method != "GET"):
            raise LifecycleError("GitHub observation exceeded its read-only time budget")
        arguments = [self.executable, "api", "--hostname", "github.com", "--method", method, path]
        if body is not None:
            arguments.extend(["--input", "-"])
        try:
            result = subprocess.run(  # noqa: S603 - fixed repository, JSON stdin, captured output
                arguments,
                input=canonical_bytes(body) if body is not None else None,
                capture_output=True,
                check=False,
                timeout=timeout,
            )
            if (
                result.returncode
                or len(result.stdout) > MAX_BYTES
                or (deadline is not None and time.monotonic() >= deadline)
            ):
                raise LifecycleError("GitHub control operation remains unresolved")
            return result.stdout if binary else json.loads(result.stdout) if result.stdout else None
        except OSError, subprocess.SubprocessError, ValueError:
            raise LifecycleError("GitHub control operation remains unresolved") from None

    def protection(self) -> None:
        path = f"{PREFIX}/environments/{ENVIRONMENT}"
        value, policies = self.api(path), self.api(path + "/deployment-branch-policies")
        if not isinstance(value, dict) or not isinstance(policies, dict):
            raise LifecycleError("protected cleanup environment is unavailable")
        rules, branches = value.get("protection_rules"), policies.get("branch_policies")
        if (
            not isinstance(rules, list)
            or any(not isinstance(row, dict) or row.get("type") != "branch_policy" for row in rules)
            or value.get("deployment_branch_policy")
            != {"protected_branches": False, "custom_branch_policies": True}
            or not isinstance(branches, list)
            or len(branches) != 1
            or not isinstance(branches[0], dict)
            or branches[0].get("name") != "main"
            or branches[0].get("type") != "branch"
        ):
            raise LifecycleError(
                "cleanup requires its main-only environment without approval waits"
            )

    def merged(self, helper: str) -> None:
        value = self.api(f"{PREFIX}/compare/{revision(helper)}...main")
        if (
            not isinstance(value, dict)
            or value.get("status") not in {"ahead", "identical"}
            or not isinstance(value.get("merge_base_commit"), dict)
            or value["merge_base_commit"].get("sha") != helper
        ):
            raise LifecycleError("the exact lifecycle helper has not reached main")

    def _execution_inventory(self, query: str) -> list[dict[str, object]]:
        """Read complete small pages without relaxing the per-response byte bound."""
        rows: list[dict[str, object]] = []
        identities: set[int] = set()
        page, total = 1, None
        with self.read_budget(time.monotonic() + EXECUTION_SCAN_SECONDS):
            while total is None or len(rows) < total:
                value = self.api(
                    f"{PREFIX}/actions/workflows/{WORKFLOW}/runs?branch=main"
                    f"&{query}&per_page={EXECUTION_PAGE_SIZE}&page={page}"
                )
                if (
                    not isinstance(value, dict)
                    or not isinstance(value.get("workflow_runs"), list)
                    or type(value.get("total_count")) is not int
                    # Filtered GitHub inventories cap their results at 1,000.
                    # At that boundary, completeness cannot be established.
                    or not 0 <= value["total_count"] < MAX_EXECUTIONS
                    or (total is not None and total != value["total_count"])
                ):
                    raise LifecycleError("cleanup execution inventory changed or is incomplete")
                total = value["total_count"]
                batch = value["workflow_runs"]
                if not batch and len(rows) < total:
                    raise LifecycleError("cleanup execution pagination is incomplete")
                for row in batch:
                    if (
                        not isinstance(row, dict)
                        or type(row.get("id")) is not int
                        or row["id"] < 1
                        or row["id"] in identities
                        or row.get("workflow_id") != WORKFLOW_ID
                        or row.get("head_branch") != "main"
                    ):
                        raise LifecycleError("cleanup execution inventory has unexpected entries")
                    identities.add(row["id"])
                    rows.append(row)
                if len(rows) > total:
                    raise LifecycleError("cleanup execution inventory grew during pagination")
                page += 1
        return rows

    def active_executions(self) -> set[int]:
        """Complete bounded inventories, including executions waiting in concurrency queues."""
        found: set[int] = set()
        for status in ("requested", "waiting", "pending", "queued", "in_progress"):
            for row in self._execution_inventory(f"status={status}"):
                if row.get("status") != status:
                    raise LifecycleError("cleanup execution inventory has unexpected entries")
                found.add(cast(int, row["id"]))
        return found

    def drain(self) -> None:
        until = time.monotonic() + TIMEOUT_SECONDS
        empty = False
        while time.monotonic() < until:
            current = self.active_executions()
            if not current and empty:
                return
            empty = not current
            time.sleep(POLL_SECONDS)
        raise LifecycleError("older cleanup executions remain pending; no inventory frozen")

    def variables(self) -> dict[str, str]:
        value = self.api(VARIABLES + "?per_page=100")
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("variables"), list)
            or type(value.get("total_count")) is not int
            or len(value["variables"]) != value["total_count"]
        ):
            raise LifecycleError("cleanup configuration inventory is incomplete")
        result: dict[str, str] = {}
        for row in value["variables"]:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("name"), str)
                or not isinstance(row.get("value"), str)
                or row["name"] in result
            ):
                raise LifecycleError("cleanup configuration inventory is ambiguous")
            result[row["name"]] = row["value"]
        return result

    def set_variable(self, name: str, value: str) -> None:
        if name not in {SETTING, BACKEND} or len(value.encode()) > 48 * 1024:
            raise LifecycleError("cleanup configuration exceeds its explicit boundary")
        exists = name in self.variables()
        self.api(
            VARIABLES + ("/" + name if exists else ""),
            method="PATCH" if exists else "POST",
            body={"name": name, "value": value},
        )
        if self.variables().get(name) != value:
            raise LifecycleError("cleanup configuration update lacks exact readback")

    def run(self, run_id: int, *, attempt: int | None = None) -> dict[str, object]:
        path = f"{PREFIX}/actions/runs/{run_id}"
        value = self.api(path if attempt is None else path + f"/attempts/{attempt}")
        if (
            not isinstance(value, dict)
            or value.get("id") != run_id
            or value.get("workflow_id") != WORKFLOW_ID
            or value.get("path") != ".github/workflows/" + WORKFLOW
            or value.get("head_branch") != "main"
            or value.get("event") != "workflow_dispatch"
            or (attempt is not None and value.get("run_attempt") != attempt)
            or any(
                not isinstance(value.get(key), dict) or value[key].get("full_name") != REPOSITORY
                for key in ("repository", "head_repository")
            )
        ):
            raise LifecycleError("cleanup execution differs from the protected main workflow")
        return value

    def _receipt_job(self, execution: dict[str, object]) -> dict[str, object]:
        """Bind the successful Connect job to one immutable native run attempt."""
        run_id, attempt = execution["id"], execution.get("run_attempt")
        if type(run_id) is not int or run_id < 1 or type(attempt) is not int or attempt < 1:
            raise LifecycleError("cleanup attempt identity is unavailable")
        revision(execution.get("head_sha"))
        selected = self.run(run_id, attempt=attempt)
        if any(
            selected.get(key) != execution.get(key)
            for key in ("run_attempt", "head_sha", "status", "conclusion", "run_started_at")
        ):
            raise LifecycleError("cleanup attempt differs from the completed execution")
        started, completed = (
            instant(selected.get("run_started_at")),
            instant(selected.get("updated_at")),
        )
        if started > completed:
            raise LifecycleError("cleanup attempt has an invalid execution interval")
        value = self.api(f"{PREFIX}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100")
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("jobs"), list)
            or type(value.get("total_count")) is not int
            or len(value["jobs"]) != value["total_count"]
        ):
            raise LifecycleError("cleanup attempt job inventory is incomplete")
        matches = [
            row for row in value["jobs"] if isinstance(row, dict) and row.get("name") == "connect"
        ]
        if len(matches) != 1:
            raise LifecycleError("cleanup attempt has no unique Connect job")
        job = matches[0]
        if (
            type(job.get("id")) is not int
            or job["id"] < 1
            or job.get("run_id") != run_id
            or job.get("run_attempt") != attempt
            or job.get("head_sha") != execution["head_sha"]
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or not started
            <= instant(job.get("started_at"))
            <= instant(job.get("completed_at"))
            <= completed
        ):
            raise LifecycleError("cleanup receipt job differs from its successful attempt")
        return job

    def _receipt_artifact(
        self, execution: dict[str, object], job: dict[str, object]
    ) -> dict[str, object]:
        run_id, attempt = execution["id"], execution["run_attempt"]
        value = self.api(f"{PREFIX}/actions/runs/{run_id}/artifacts?per_page=100")
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("artifacts"), list)
            or type(value.get("total_count")) is not int
            or len(value["artifacts"]) != value["total_count"]
        ):
            raise LifecycleError("cleanup receipt inventory is incomplete")
        legacy = f"m3-11-credential-cleanup-{run_id}"
        canonical = legacy + f"-attempt-{attempt}"
        rows = value["artifacts"]
        matches = [row for row in rows if isinstance(row, dict) and row.get("name") == canonical]
        started, completed = instant(job["started_at"]), instant(job["completed_at"])
        if not matches:
            # Old helpers named every attempt's artifact alike. Native upload
            # times must unambiguously place one in this successful job. Strict
            # lower bounds reject same-second artifacts from a prior attempt.
            matches = [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("name") == legacy
                and started < instant(row.get("created_at")) <= completed
            ]
        if len(matches) != 1:
            raise LifecycleError("cleanup has no unique receipt for its successful attempt")
        artifact = matches[0]
        native = artifact.get("workflow_run")
        repository, head_repository = execution["repository"], execution["head_repository"]
        if (
            not isinstance(repository, dict)
            or not isinstance(head_repository, dict)
            or type(repository.get("id")) is not int
            or type(head_repository.get("id")) is not int
            or repository["id"] < 1
            or head_repository["id"] < 1
            or not isinstance(native, dict)
            or native.get("id") != run_id
            or native.get("repository_id") != repository["id"]
            or native.get("head_repository_id") != head_repository["id"]
            or native.get("head_branch") != "main"
            or native.get("head_sha") != execution["head_sha"]
            or artifact.get("expired") is not False
            or type(artifact.get("id")) is not int
            or artifact["id"] < 1
            or not started <= instant(artifact.get("created_at")) <= completed
        ):
            raise LifecycleError("cleanup receipt artifact is expired or misbound")
        return artifact

    def find_run(self, dispatch: dict[str, object]) -> int | None:
        rows = self._execution_inventory("event=workflow_dispatch")
        if any(row.get("event") != "workflow_dispatch" for row in rows):
            raise LifecycleError("cleanup execution inventory has unexpected entries")
        title = "M3.11 cleanup " + str(dispatch["operation"]) + " " + str(dispatch["dispatch_id"])
        matches = [row for row in rows if row.get("display_title") == title]
        if len(matches) > 1:
            raise LifecycleError("cleanup dispatch has ambiguous execution identities")
        if not matches:
            return None
        selected = matches[0].get("id")
        if type(selected) is not int or selected < 1:
            raise LifecycleError("cleanup execution identity is invalid")
        self.run(selected)
        return selected

    def dispatch(
        self, directory: Path, *, operation: str, selection: dict[str, object], run_sha256: str = ""
    ) -> dict[str, object]:
        if operation not in {"discovery", "genesis", "reconcile", "witness"} or (
            re.fullmatch(r"[0-9a-f]{64}", run_sha256) is None
            if operation == "witness"
            else run_sha256 != ""
        ):
            raise LifecycleError("cleanup dispatch request is invalid")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(directory)
        expected = {
            "operation": operation,
            "selection_sha256": digest(selection),
            "run_sha256": run_sha256,
        }
        path = directory / "dispatch.json"
        if path.exists():
            saved = fields(read_private(path), {*expected, "dispatch_id", "requested_at"})
            identity(saved["dispatch_id"])
            instant(saved["requested_at"])
            if any(saved[key] != value for key, value in expected.items()):
                raise LifecycleError("a previous dispatch cannot be rebound to another request")
        else:
            saved = {
                **expected,
                "dispatch_id": str(uuid.uuid7()),
                "requested_at": stamp(datetime.now(UTC)),
            }
            write_private(path, saved)
        marker = directory / "submitted.json"
        if not marker.exists():
            write_private(marker, {"dispatch_sha256": digest(saved)})
            # Exactly one submission. A lost reply is reconciled by its unique
            # workflow name, never by submitting an untracked duplicate.
            with suppress(LifecycleError):
                self.api(
                    f"{PREFIX}/actions/workflows/{WORKFLOW}/dispatches",
                    method="POST",
                    body={
                        "ref": "main",
                        "inputs": {
                            "operation": operation,
                            "run_sha256": run_sha256,
                            "dispatch_id": saved["dispatch_id"],
                        },
                    },
                )
        elif read_private(marker) != {"dispatch_sha256": digest(saved)}:
            raise LifecycleError("cleanup dispatch intent changed")
        return saved

    def receipt(self, run_id: int) -> dict[str, object]:
        self._receipt_source = None
        execution = self.run(run_id)
        if execution.get("status") != "completed" or execution.get("conclusion") != "success":
            raise LifecycleError("independent cleanup has not completed successfully")
        job = self._receipt_job(execution)
        artifact = self._receipt_artifact(execution, job)
        raw = self.api(f"{PREFIX}/actions/artifacts/{artifact['id']}/zip", binary=True)
        if (
            not isinstance(raw, bytes)
            or artifact.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest()
        ):
            raise LifecycleError("cleanup receipt archive integrity is unverified")
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                if (
                    len(entries) != 1
                    or entries[0].filename != "receipt.json"
                    or entries[0].file_size > MAX_BYTES
                ):
                    raise LifecycleError("cleanup receipt has unexpected archive contents")
                receipt = fields(
                    json.loads(archive.read(entries[0])),
                    {
                        "format",
                        "operation",
                        "dispatch_id",
                        "helper_revision",
                        "selection_sha256",
                        "observed_at",
                        "status",
                        "proof",
                    },
                )
        except ValueError, zipfile.BadZipFile:
            raise LifecycleError("cleanup receipt cannot be verified") from None
        if (
            not instant(job["started_at"])
            <= instant(receipt["observed_at"])
            < instant(job["completed_at"]) + timedelta(seconds=1)
        ):
            raise LifecycleError("cleanup receipt was not observed during its selected job")
        current = self.run(run_id)
        if any(
            current.get(key) != execution.get(key)
            for key in (
                "run_attempt",
                "head_sha",
                "status",
                "conclusion",
                "run_started_at",
                "updated_at",
            )
        ):
            raise LifecycleError("cleanup execution changed while its receipt was read")
        self._receipt_source = {
            "format": "lowerduckpond-m3-11-cleanup-receipt-source-v1",
            "run_id": run_id,
            "run_attempt": execution["run_attempt"],
            "head_sha": execution["head_sha"],
            "job_id": job["id"],
            "artifact_id": artifact["id"],
            "artifact_digest": artifact["digest"],
            "receipt_sha256": digest(receipt),
        }
        return receipt

    def wait(
        self, dispatch: dict[str, object], *, helper: str, directory: Path
    ) -> dict[str, object]:
        until = time.monotonic() + TIMEOUT_SECONDS
        while time.monotonic() < until:
            run_id = self.find_run(dispatch)
            if run_id is not None and self.run(run_id).get("status") == "completed":
                value = self.receipt(run_id)
                if (
                    value["format"] != connect_action.RECEIPT_FORMAT
                    or value["status"] != "ready"
                    or value["helper_revision"] != helper
                    or any(
                        value[key] != dispatch[key]
                        for key in ("operation", "dispatch_id", "selection_sha256")
                    )
                    or instant(value["observed_at"])
                    < instant(dispatch["requested_at"]) - timedelta(minutes=5)
                ):
                    raise LifecycleError(
                        "cleanup receipt differs from its exact requested operation"
                    )
                source = getattr(self, "_receipt_source", None)
                if source is not None:
                    source_path = directory / "receipt-source.json"
                    if source_path.exists():
                        if read_private(source_path) != source:
                            raise LifecycleError("retained cleanup receipt origin changed")
                    else:
                        write_private(source_path, source)
                path = directory / "receipt.json"
                if path.exists():
                    if read_private(path) != value:
                        raise LifecycleError("retained cleanup receipt changed")
                else:
                    write_private(path, value)
                return value
            time.sleep(POLL_SECONDS)
        raise LifecycleError("cleanup dispatch remains pending; retain its identity and evidence")


def launch_request(request: dict[str, object]) -> dict[str, object]:
    """Only closed, non-secret request bindings may enter launcher diagnostics."""
    binding = fields(request["binding"], BINDING)
    identity(binding["managed_run_id"])
    if revision(binding["source_revision"]) != revision(binding["helper_revision"]):
        raise LifecycleError("launcher source and helper differ")
    for name in BINDING - {"managed_run_id", "source_revision", "helper_revision"}:
        sha256(binding[name])
    sha256(request["approval_sha256"])
    if request["mode"] not in {"rehearsal", "qualification"}:
        raise LifecycleError("launcher mode is invalid")
    return {
        "binding": binding,
        "mode": request["mode"],
        "approval_sha256": request["approval_sha256"],
    }


def launch_evidence(directory: Path, *, run_id: str, helper: str) -> dict[str, object]:
    private_directory(directory)
    raw = read_private(directory / "launch-request.json")
    request = launch_request(fields(raw, {"binding", "mode", "approval_sha256"}))
    binding = fields(request["binding"], BINDING)
    if binding["managed_run_id"] != identity(run_id) or binding["helper_revision"] != revision(
        helper
    ):
        raise LifecycleError("launcher evidence requires its exact attempt and pinned helper")
    return {
        "request": request,
        "diagnostic": verified_failure(
            read_private(directory / "launcher-failure.json"),
            binding=binding,
            stages=frozenset({"await-witness"}),
        ),
    }


def await_witness(
    configuration: Configuration, request: dict[str, object], *, directory: Path
) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(directory)
    retained = launch_request(request)
    path = directory / "launch-request.json"
    if path.exists():
        if read_private(path) != retained:
            raise LifecycleError("launcher request changed")
        raise LifecycleError("launcher attempt already consumed; retain its original evidence")
    # Consumption is durable before dispatch and independent of optional diagnostics.
    # A killed launcher cannot silently resume the old attempt with a fresh deadline.
    write_private(path, retained)
    try:
        _await_witness(configuration, request, directory=directory)
    except Exception as error:
        retain_failure(
            directory / "launcher-failure.json",
            binding=fields(retained["binding"], BINDING),
            stage="await-witness",
            error=error,
        )
        raise


def _await_witness(
    configuration: Configuration, request: dict[str, object], *, directory: Path
) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_directory(directory)
    settings = configuration.cleanup.connect_settings
    if settings is None:
        raise LifecycleError("Connect witness cannot use service-account configuration")
    binding = fields(
        request["binding"],
        {
            "managed_run_id",
            "source_revision",
            "helper_revision",
            "qualification_inputs_sha256",
            "storage_target_sha256",
            "artifact_sha256",
        },
    )
    helper = revision(binding["helper_revision"])
    client = GitHub()
    client.protection()
    client.merged(helper)
    variables = client.variables()
    if variables.get(BACKEND) != "connect":
        raise LifecycleError("independent Connect is not active at the approved helper")
    selected = connect_action.selection(json.loads(variables.get(SETTING, "{}")), helper=helper)
    if selected["stage"] != "active":
        raise LifecycleError("independent Connect has not completed activation")
    approved = selected["request"]
    if not isinstance(approved, dict) or approved["targets_sha256"] != digest(
        dataclasses.asdict(configuration.targets)
    ):
        raise LifecycleError("controller targets differ from protected independent cleanup")
    journal = configuration.cleanup.journal(
        configuration.journal_vault, directory=directory / "journal"
    )
    if not isinstance(journal, ConnectJournal):
        raise LifecycleError("independent witness journal is unavailable")
    proof = fields(selected["receipt"], connect_action.GENESIS_RECEIPT_FIELDS)
    if (
        connect_action.witness(proof, active_helper=helper) != journal.witness
        or proof["initial"] != settings["initial"]
    ):
        raise LifecycleError("controller witness differs from protected independent cleanup")
    expected = run_digest(
        identity(binding["managed_run_id"]),
        {
            "binding": request["binding"],
            "mode": request["mode"],
            "approval_sha256": request["approval_sha256"],
        },
    )
    dispatch = client.dispatch(
        directory, operation="witness", selection=selected, run_sha256=expected
    )
    until = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < until:
        try:
            with (
                client.read_budget(until),
                journal.ledger.read_budget(deadline=until, check_cancelled=lambda: None),
            ):
                if _witness_ready(
                    client,
                    journal,
                    dispatch,
                    expected=expected,
                    helper=helper,
                    directory=directory,
                    deadline=until,
                ):
                    return
        except SnapshotChangedError, ReadinessPendingError:
            # A valid asynchronous update may invalidate any complete scan.
            # Start the next observation at the native execution; never redispatch.
            pass
        remaining = until - time.monotonic()
        if remaining > 0:
            time.sleep(min(POLL_SECONDS, remaining))
    raise LifecycleError(
        "independent witness readiness remains unproven; controller was not launched"
    )


def _witness_ready(  # noqa: PLR0913 - preserve the original dispatch and shared observation budget
    client: GitHub,
    journal: ConnectJournal,
    dispatch: dict[str, object],
    *,
    expected: str,
    helper: str,
    directory: Path,
    deadline: float,
) -> bool:
    run_id = client.find_run(dispatch)
    if run_id is not None:
        execution = client.run(run_id)
        if execution.get("status") == "completed":
            raise LifecycleError("independent witness stopped before controller launch")
        attempt = execution.get("run_attempt")
        if type(attempt) is not int or attempt < 1:
            raise LifecycleError("independent witness attempt is unavailable")
        binding: dict[str, object] = {"github_run_id": run_id, "github_run_attempt": attempt}
        path = directory / "witness-execution.json"
        if path.exists():
            if read_private(path) != binding:
                raise LifecycleError("independent witness execution changed during observation")
        else:
            write_private(path, binding)
        for record in journal.records():
            value = record["payload"]
            if not isinstance(value, dict) or value.get("format") != connect_action.READY_FORMAT:
                continue
            if (
                record["kind"] == "heartbeat"
                and value.get("request_sha256") == expected
                and value.get("dispatch_id") == dispatch["dispatch_id"]
                and value.get("active_helper") == helper
                and value.get("witness") == journal.witness.binding()
                and value.get("github_run_id") == run_id
                and value.get("github_run_attempt") == execution.get("run_attempt")
                and execution.get("status") == "in_progress"
                and datetime.now(UTC) - timedelta(minutes=2)
                <= instant(value.get("observed_at"))
                <= datetime.now(UTC) + timedelta(minutes=1)
                and journal.ledger.authored(record, journal.witness.author)
                and journal.confirmed(record)
            ):
                require_independent_ready(journal, helper=helper, now=datetime.now(UTC))
                # Snapshot I/O can outlive the witness. Recheck the same native
                # attempt immediately before accepting readiness, even without a retry.
                current = client.run(run_id)
                if (
                    current.get("status") != "in_progress"
                    or current.get("run_attempt") != execution.get("run_attempt")
                    or time.monotonic() >= deadline
                    or not datetime.now(UTC) - timedelta(minutes=2)
                    <= instant(value.get("observed_at"))
                    <= datetime.now(UTC) + timedelta(minutes=1)
                ):
                    raise LifecycleError("independent witness changed or readiness arrived late")
                write_private(
                    directory / "witness-ready.json",
                    {
                        "dispatch_id": dispatch["dispatch_id"],
                        "github_run_id": run_id,
                        "event_sha256": digest(record),
                        "run_sha256": expected,
                    },
                )
                return True
    return False
