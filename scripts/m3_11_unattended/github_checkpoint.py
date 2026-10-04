"""Encrypted immutable checkpoints in the protected cleanup workflow's artifacts.

Only the serialized main-branch workflow writes. Append-only commit statuses
retain the latest artifact identity independently of the deletable payloads.
Missing payloads therefore cannot silently roll cleanup back to an older head.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.journal_cache import MAX_CACHE_BYTES, JournalCache
from scripts.m3_11_unattended.model import LifecycleError, digest, identity
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import revision

REPOSITORY = "lowerduckpond-net/lowerduckpond.net"
WORKFLOW = "m3-11-credential-cleanup.yml"
UPLOAD_REVISION = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
PAGE_SIZE = 100
MAX_RUN_PAGES = 10
MAX_ARTIFACTS = 500
IO_SECONDS = 30
SCAN_SECONDS = 90
STATUS_AUTHOR = 41898282  # github-actions[bot], immutable GitHub user identity


def _number(value: object) -> int:
    if type(value) is not int or value < 1:
        raise LifecycleError("GitHub checkpoint identity is invalid")
    return value


class GitHubArtifacts:
    def __init__(self, *, epoch: str, registry_revision: str, token: str, directory: Path) -> None:
        self.epoch = identity(epoch)
        self.registry_revision = revision(registry_revision)
        self.context = "m3-11/connect-checkpoint/" + self.epoch
        self.prefix = "m311-connect-" + uuid.UUID(epoch).hex + "-"
        self._token, self.directory = token, directory
        self._environment = {
            key: os.environ[key] for key in ("PATH", "HOME", "GH_TOKEN") if key in os.environ
        }
        self._environment["GH_HOST"] = "github.com"
        executable = shutil.which("gh", path=self._environment.get("PATH"))
        if executable is None:
            raise LifecycleError("GitHub CLI is unavailable")
        self._executable = executable
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_directory(directory)
        self._until = 0.0
        self._published_runs: dict[int, int] = {}

    def _api(
        self, path: str, *, binary: bool = False, body: dict[str, object] | None = None
    ) -> object:
        remaining = min(IO_SECONDS, self._until - time.monotonic())
        if remaining <= 0:
            raise LifecycleError("GitHub checkpoint operation exceeded its deadline")
        try:
            command = [self._executable, "api", "--hostname", "github.com", "--method"]
            command.extend(["GET", path] if body is None else ["POST", path, "--input", "-"])
            result = subprocess.run(  # noqa: S603 - fixed API origin/paths; token only in env
                command,
                input=None if body is None else canonical_bytes(body),
                env=self._environment,
                capture_output=True,
                check=False,
                timeout=remaining,
            )
            if result.returncode or len(result.stdout) > MAX_CACHE_BYTES:
                raise LifecycleError("GitHub checkpoint operation remains unresolved")
            return result.stdout if binary else json.loads(result.stdout)
        except OSError, subprocess.SubprocessError, ValueError:
            raise LifecycleError("GitHub checkpoint operation remains unresolved") from None

    def _runs(self) -> list[dict[str, object]]:
        observed: dict[int, dict[str, object]] = {}
        seen: set[int] = set()
        total = None
        created = datetime.fromtimestamp(uuid.UUID(self.epoch).time // 1000, UTC).isoformat()
        for page in range(1, MAX_RUN_PAGES + 1):
            value = self._api(
                f"repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/runs"
                + "?"
                + urlencode(
                    {
                        "branch": "main",
                        "created": ">=" + created,
                        "per_page": PAGE_SIZE,
                        "page": page,
                    }
                )
            )
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("workflow_runs"), list)
                or type(value.get("total_count")) is not int
                or not 0 <= value["total_count"] < MAX_RUN_PAGES * PAGE_SIZE
                or (total is not None and value["total_count"] != total)
            ):
                raise LifecycleError("GitHub workflow inventory is unavailable")
            total = value["total_count"]
            rows = value["workflow_runs"]
            for row in rows:
                if not isinstance(row, dict) or row.get("head_branch") != "main":
                    raise LifecycleError("GitHub workflow inventory is invalid")
                selected = _number(row.get("id"))
                if selected in seen:
                    raise LifecycleError("GitHub workflow inventory changed during pagination")
                seen.add(selected)
                if row.get("status") in {"in_progress", "completed"}:
                    observed[selected] = row
            # The epoch bounds this inventory independently of older repository
            # history. Complete pagination avoids assuming an API sort order.
            if len(seen) == total:
                return sorted(observed.values(), key=lambda row: _number(row["id"]), reverse=True)
        raise LifecycleError("GitHub workflow history exceeds its checkpoint scan bound")

    def _artifacts(self, run_id: int) -> list[dict[str, object]]:
        observed: dict[int, dict[str, object]] = {}
        total = None
        for page in range(1, MAX_ARTIFACTS // PAGE_SIZE + 1):
            value = self._api(
                f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts"
                f"?per_page={PAGE_SIZE}&page={page}"
            )
            if (
                not isinstance(value, dict)
                or type(value.get("total_count")) is not int
                or not isinstance(value.get("artifacts"), list)
                or not 0 <= value["total_count"] <= MAX_ARTIFACTS
                or (total is not None and value["total_count"] != total)
            ):
                raise LifecycleError("GitHub checkpoint inventory is partial or unavailable")
            total = value["total_count"]
            for row in value["artifacts"]:
                if not isinstance(row, dict):
                    raise LifecycleError("GitHub checkpoint inventory is invalid")
                selected = _number(row.get("id"))
                if selected in observed:
                    raise LifecycleError("GitHub checkpoint inventory has duplicate identities")
                observed[selected] = row
            if len(observed) == total:
                return list(observed.values())
        raise LifecycleError("GitHub checkpoint inventory is incomplete")

    def _reference(self, value: dict[str, object], *, run_id: int | None = None) -> Stored:
        name, workflow = value.get("name"), value.get("workflow_run")
        match = re.fullmatch(re.escape(self.prefix) + r"([0-9a-f]{64})-[0-9a-f]{32}", str(name))
        if (
            match is None
            or value.get("expired") is not False
            or not isinstance(workflow, dict)
            or workflow.get("head_branch") != "main"
            or (run_id is not None and workflow.get("id") != run_id)
        ):
            raise LifecycleError("latest GitHub checkpoint is missing, expired or misbound")
        _number(workflow.get("id"))
        return Stored(_number(value.get("id")), match[1])

    def latest(self) -> Stored | None:
        self._until = time.monotonic() + SCAN_SECONDS
        # GitHub returns individual statuses newest first. Unlike artifacts,
        # these records have no expiry, replacement or deletion API. Never
        # infer the head from the surviving artifact inventory.
        for page in range(1, MAX_RUN_PAGES + 1):
            rows = self._api(
                f"repos/{REPOSITORY}/commits/{self.registry_revision}/statuses"
                f"?per_page={PAGE_SIZE}&page={page}"
            )
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                raise LifecycleError("independent checkpoint registry is unavailable")
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("context"), str):
                    raise LifecycleError("independent checkpoint registry is malformed")
                if cast(str, row["context"]).lower() == self.context:
                    return self._status_reference(row)
            if len(rows) < PAGE_SIZE:
                return None
        raise LifecycleError("independent checkpoint registry exceeds its scan bound")

    def _status_reference(self, row: dict[str, object]) -> Stored:
        author, description = row.get("creator"), row.get("description")
        match = re.fullmatch(
            re.escape(f"https://github.com/{REPOSITORY}/actions/runs/")
            + r"([1-9][0-9]*)/artifacts/([1-9][0-9]*)",
            str(row.get("target_url")),
        )
        if (
            match is None
            or not isinstance(author, dict)
            or author.get("id") != STATUS_AUTHOR
            or author.get("type") != "Bot"
            or row.get("state") != "success"
            or not isinstance(description, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", description) is None
        ):
            raise LifecycleError("latest checkpoint registry entry is untrusted or malformed")
        _number(row.get("id"))
        stored = Stored(int(match[2]), description.removeprefix("sha256:"))
        self._published_runs[stored.identity] = int(match[1])
        return stored

    def read(self, stored: Stored) -> dict[str, object]:
        self._until = time.monotonic() + SCAN_SECONDS
        metadata = self._api(f"repos/{REPOSITORY}/actions/artifacts/{stored.identity}")
        if (
            not isinstance(metadata, dict)
            or self._reference(metadata, run_id=self._published_runs.get(stored.identity)) != stored
            or type(metadata.get("size_in_bytes")) is not int
            or not 0 < metadata["size_in_bytes"] <= MAX_CACHE_BYTES
        ):
            raise LifecycleError("GitHub checkpoint metadata differs from its registry identity")
        raw = self._api(f"repos/{REPOSITORY}/actions/artifacts/{stored.identity}/zip", binary=True)
        if (
            not isinstance(raw, bytes)
            or metadata.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest()
        ):
            raise LifecycleError("GitHub checkpoint archive integrity is unverified")
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                entries = archive.infolist()
                if (
                    len(entries) != 1
                    or entries[0].filename != "checkpoint.json"
                    or entries[0].file_size > MAX_CACHE_BYTES
                ):
                    raise LifecycleError("GitHub checkpoint archive has unexpected contents")
                encrypted = json.loads(archive.read(entries[0]))
            with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                path = Path(temporary) / "checkpoint.json"
                write_private(path, encrypted, maximum=MAX_CACHE_BYTES)
                value = JournalCache(path, token=self._token, vault="connect:" + self.epoch).read()
            if digest(value) != stored.sha256:
                raise LifecycleError("GitHub checkpoint plaintext binding changed")
            return value
        except OSError, ValueError, zipfile.BadZipFile:
            raise LifecycleError("GitHub checkpoint cannot be recovered") from None

    def create(self, document: dict[str, object]) -> Stored:
        self._until = time.monotonic() + SCAN_SECONDS
        if (
            os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_WORKFLOW_REF")
            != f"{REPOSITORY}/.github/workflows/{WORKFLOW}@refs/heads/main"
            or not os.environ.get("ACTIONS_RUNTIME_TOKEN")
        ):
            raise LifecycleError("checkpoint writes require the protected cleanup action")
        run_id = _number(int(os.environ.get("GITHUB_RUN_ID", "0")))
        runs = self._runs()
        if not runs or runs[0].get("id") != run_id:
            raise LifecycleError("an older cleanup run cannot publish over a newer checkpoint")
        previous = self.latest()
        action = (
            Path(os.environ["RUNNER_WORKSPACE"]).parent
            / "_actions/actions/upload-artifact"
            / UPLOAD_REVISION
            / "dist/upload/index.js"
        )
        node = os.environ.get("M3_11_ACTION_NODE")
        if not action.is_file() or node is None or not Path(node).is_file():
            raise LifecycleError("the pinned artifact uploader is unavailable")
        name = self.prefix + digest(document) + "-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
            path = Path(temporary) / "checkpoint.json"
            codec = JournalCache(path, token=self._token, vault="connect:" + self.epoch)
            if not codec.write(document):
                raise LifecycleError("independent checkpoint exceeds its encrypted bound")
            environment = {
                key: value
                for key, value in os.environ.items()
                if key.startswith(("GITHUB_", "ACTIONS_", "RUNNER_")) or key in {"PATH", "HOME"}
            }
            environment.update(
                {
                    "INPUT_NAME": name,
                    "INPUT_PATH": str(path),
                    "INPUT_RETENTION-DAYS": "30",
                    "INPUT_IF-NO-FILES-FOUND": "error",
                    "INPUT_OVERWRITE": "false",
                    "INPUT_COMPRESSION-LEVEL": "0",
                    "INPUT_INCLUDE-HIDDEN-FILES": "false",
                    "INPUT_ARCHIVE": "true",
                    "GITHUB_OUTPUT": str(Path(temporary) / "output"),
                }
            )
            try:
                result = subprocess.run(  # noqa: S603 - pinned GitHub action, encrypted file only
                    [node, str(action)],
                    env=environment,
                    capture_output=True,
                    check=False,
                    timeout=SCAN_SECONDS,
                )
            except OSError, subprocess.SubprocessError:
                raise LifecycleError("checkpoint upload is uncertain; do not acknowledge") from None
            if result.returncode:
                raise LifecycleError("checkpoint upload is uncertain; do not acknowledge")
        self._until = time.monotonic() + SCAN_SECONDS
        matches = [row for row in self._artifacts(run_id) if row.get("name") == name]
        if len(matches) != 1:
            raise LifecycleError("checkpoint upload has no unique registry readback")
        created = self._reference(matches[0], run_id=run_id)
        if self.read(created) != document:
            raise LifecycleError("checkpoint upload has no exact plaintext readback")
        if self.latest() != previous:
            raise LifecycleError("checkpoint registry advanced during this upload")
        self._api(
            f"repos/{REPOSITORY}/statuses/{self.registry_revision}",
            body={
                "context": self.context,
                "state": "success",
                "description": "sha256:" + created.sha256,
                "target_url": (
                    f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
                    f"/artifacts/{created.identity}"
                ),
            },
        )
        if self.latest() != created:
            raise LifecycleError("checkpoint registry publication remains unconfirmed")
        return created
