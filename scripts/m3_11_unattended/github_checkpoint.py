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
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

from scripts.m3_11_private_inputs import read_private_bytes, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.connect_checkpoint import FORMAT, Stored
from scripts.m3_11_unattended.journal_cache import MAX_CACHE_BYTES, JournalCache
from scripts.m3_11_unattended.model import LifecycleError, digest, identity
from scripts.m3_11_unattended.state import private_directory
from scripts.production_qualification_inputs import revision

REPOSITORY = "lowerduckpond-net/lowerduckpond.net"
WORKFLOW = "m3-11-credential-cleanup.yml"
WORKFLOW_ID = 374497951
UPLOAD_REVISION = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
PAGE_SIZE = 100
MAX_RUN_PAGES = 10
MAX_ARTIFACTS = 500
IO_SECONDS = 30
SCAN_SECONDS = 90
STATUS_AUTHOR = 41898282  # github-actions[bot], immutable GitHub user identity
STATUS_LIMIT = 1000  # GitHub's hard per-SHA/context limit.
MINIMUM_START_CAPACITY = 384  # 128 witness writes plus 256 reserved cleanup writes.
MAX_STATUS_PAGES = 30
READ_POLL_SECONDS = 2
UPLOAD_OUTPUT_LINES = 9


class _UnavailableError(LifecycleError):
    """A bounded exchange failed before any metadata or integrity decision."""


def upload_output(path: Path, *, run_id: int) -> tuple[int, str]:
    """Read only the three outputs emitted by the pinned Actions toolkit."""
    try:
        lines = read_private_bytes(path, maximum=4096).decode("ascii").splitlines()
        values = {}
        if len(lines) != UPLOAD_OUTPUT_LINES:
            raise ValueError
        for offset in range(0, len(lines), 3):
            match = re.fullmatch(
                r"(artifact-id|artifact-digest|artifact-url)<<(ghadelimiter_[0-9a-f-]{36})",
                lines[offset],
            )
            if match is None or lines[offset + 2] != match[2] or match[1] in values:
                raise ValueError
            values[match[1]] = lines[offset + 1]
        if (
            set(values) != {"artifact-id", "artifact-digest", "artifact-url"}
            or re.fullmatch(r"[1-9][0-9]{0,19}", values["artifact-id"]) is None
            or re.fullmatch(r"[0-9a-f]{64}", values["artifact-digest"]) is None
            or values["artifact-url"]
            != f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/artifacts/"
            + values["artifact-id"]
        ):
            raise ValueError
        return int(values["artifact-id"]), values["artifact-digest"]
    except OSError, ValueError, KeyError:
        raise LifecycleError("checkpoint upload outputs are unavailable or ambiguous") from None


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
        self._parents: dict[int, Stored | None] = {}
        self._verified_runs: set[int] = set()
        self._history: tuple[Stored, ...] = ()

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
            if result.returncode:
                raise _UnavailableError("GitHub checkpoint operation remains unresolved")
            if len(result.stdout) > MAX_CACHE_BYTES:
                raise LifecycleError("GitHub checkpoint response exceeds its bound")
            return result.stdout if binary else json.loads(result.stdout)
        except OSError, subprocess.SubprocessError, ValueError:
            raise _UnavailableError("GitHub checkpoint operation remains unresolved") from None

    def _runs(self) -> list[dict[str, object]]:
        observed: dict[int, dict[str, object]] = {}
        seen: set[int] = set()
        ordinals: set[int] = set()
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
                if (
                    not isinstance(row, dict)
                    or row.get("head_branch") != "main"
                    or row.get("workflow_id") != WORKFLOW_ID
                ):
                    raise LifecycleError("GitHub workflow inventory is invalid")
                selected = _number(row.get("id"))
                ordinal = _number(row.get("run_number"))
                if selected in seen or ordinal in ordinals:
                    raise LifecycleError("GitHub workflow inventory changed during pagination")
                seen.add(selected)
                ordinals.add(ordinal)
                if row.get("status") in {"in_progress", "completed"}:
                    observed[selected] = row
            # The epoch bounds this inventory independently of older repository
            # history. Complete pagination avoids assuming an API sort order.
            if len(seen) == total:
                # Only run_number is documented to increment within a workflow.
                return sorted(
                    observed.values(), key=lambda row: _number(row["run_number"]), reverse=True
                )
        raise LifecycleError("GitHub workflow history exceeds its checkpoint scan bound")

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
        history = self.lineage()
        return history[-1] if history else None

    def lineage(self) -> tuple[Stored, ...]:
        self._until = time.monotonic() + SCAN_SECONDS
        # GitHub returns individual statuses newest first. Unlike artifacts,
        # these records have no expiry, replacement or deletion API. Never
        # infer the head from the surviving artifact inventory.
        history: list[Stored] = []
        seen: set[int] = set()
        parents: dict[int, Stored | None] = {}
        published_runs: dict[int, int] = {}
        for row in self._statuses():
            if cast(str, row["context"]).lower() != self.context:
                continue
            selected, run_id = self._status_reference(row)
            if (
                published_runs.get(selected.identity, run_id) != run_id
                or self._published_runs.get(selected.identity, run_id) != run_id
            ):
                raise LifecycleError("checkpoint registry changed an immutable artifact's workflow")
            published_runs[selected.identity] = run_id
            if history and selected == history[-1]:
                continue  # An adjacent exact publication retry is idempotent.
            if selected.identity in seen:
                raise LifecycleError("checkpoint registry repeats or changes an immutable identity")
            if history:
                parents[history[-1].identity] = selected
            seen.add(selected.identity)
            history.append(selected)
        if history:
            parents[history[-1].identity] = None
        ordered = tuple(reversed(history))
        if ordered[: len(self._history)] != self._history:
            raise LifecycleError("checkpoint registry moved backwards or changed retained history")
        self._parents = parents
        self._published_runs = published_runs
        self._history = ordered
        return ordered

    def remaining_capacity(self) -> int:
        """Readiness must reserve cleanup writes before it admits any new children."""
        self._until = time.monotonic() + SCAN_SECONDS
        used = sum(cast(str, row["context"]).lower() == self.context for row in self._statuses())
        return max(0, STATUS_LIMIT - used)

    def _statuses(self) -> Iterator[dict[str, object]]:
        seen = set()
        for page in range(1, MAX_STATUS_PAGES + 1):
            rows = self._api(
                f"repos/{REPOSITORY}/commits/{self.registry_revision}/statuses"
                f"?per_page={PAGE_SIZE}&page={page}"
            )
            if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
                raise LifecycleError("independent checkpoint registry is unavailable")
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("context"), str):
                    raise LifecycleError("independent checkpoint registry is malformed")
                selected = _number(row.get("id"))
                if selected in seen:
                    raise LifecycleError("checkpoint registry changed during pagination")
                seen.add(selected)
                yield row
            if len(rows) < PAGE_SIZE:
                return
        raise LifecycleError("independent checkpoint registry exceeds its scan bound")

    def _status_reference(self, row: dict[str, object]) -> tuple[Stored, int]:
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
        return stored, int(match[1])

    def read(self, stored: Stored) -> dict[str, object]:
        self._until = time.monotonic() + SCAN_SECONDS
        metadata = self._api(f"repos/{REPOSITORY}/actions/artifacts/{stored.identity}")
        return self._read(stored, metadata)

    def _read(self, stored: Stored, metadata: object) -> dict[str, object]:
        # The caller owns the deadline, including upload visibility retries.
        if (
            not isinstance(metadata, dict)
            or self._reference(metadata, run_id=self._published_runs.get(stored.identity)) != stored
            or type(metadata.get("size_in_bytes")) is not int
            or not 0 < metadata["size_in_bytes"] <= MAX_CACHE_BYTES
        ):
            raise LifecycleError("GitHub checkpoint metadata differs from its registry identity")
        workflow = metadata["workflow_run"]
        if not isinstance(workflow, dict):
            raise LifecycleError("GitHub checkpoint workflow identity is unavailable")
        self._verify_run(_number(workflow["id"]))
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
            if (
                value.get("format") == FORMAT
                and stored.identity in self._parents
                and value.get("previous") != self._parent(self._parents[stored.identity])
            ):
                raise LifecycleError("checkpoint predecessor differs from its registry history")
            return value
        except OSError, ValueError, zipfile.BadZipFile:
            raise LifecycleError("GitHub checkpoint cannot be recovered") from None

    def _uploaded(
        self, stored: Stored, *, name: str, run_id: int, archive_sha256: str
    ) -> dict[str, object]:
        self._until = time.monotonic() + SCAN_SECONDS
        while True:
            try:
                metadata = self._api(f"repos/{REPOSITORY}/actions/artifacts/{stored.identity}")
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("name") != name
                    or self._reference(metadata, run_id=run_id) != stored
                    or metadata.get("digest") != "sha256:" + archive_sha256
                ):
                    raise LifecycleError("uploaded checkpoint differs from its exact output")
                return self._read(stored, metadata)
            except _UnavailableError:
                remaining = self._until - time.monotonic()
                if remaining <= 0:
                    raise LifecycleError(
                        "uploaded checkpoint readback remains unavailable"
                    ) from None
                time.sleep(min(READ_POLL_SECONDS, remaining))

    @staticmethod
    def _parent(previous: Stored | None) -> dict[str, object] | None:
        return (
            None if previous is None else {"identity": previous.identity, "sha256": previous.sha256}
        )

    def _verify_run(self, run_id: int) -> None:
        if run_id in self._verified_runs:
            return
        value = self._api(f"repos/{REPOSITORY}/actions/runs/{run_id}")
        if (
            not isinstance(value, dict)
            or value.get("id") != run_id
            or value.get("workflow_id") != WORKFLOW_ID
            or value.get("path") != ".github/workflows/" + WORKFLOW
            or value.get("head_branch") != "main"
            or value.get("event") not in {"schedule", "workflow_dispatch"}
            or any(
                not isinstance(value.get(key), dict)
                or cast(dict[str, object], value[key]).get("full_name") != REPOSITORY
                for key in ("repository", "head_repository")
            )
        ):
            raise LifecycleError("checkpoint was not produced by the protected cleanup workflow")
        self._verified_runs.add(run_id)

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
        history = self.lineage()
        previous = history[-1] if history else None
        if document.get("format") == FORMAT and (
            document.get("previous") != self._parent(previous)
            or type(document.get("sequence")) is not int
            or document.get("sequence") != len(history) + 1
        ):
            raise LifecycleError("checkpoint upload is not an extension of the registered head")
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
            output = Path(temporary) / "output"
            # The pinned action sets outputs after uploading; the Actions SDK
            # requires this runner-owned file to exist before setOutput runs.
            output.touch(mode=0o600, exist_ok=False)
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
                    "GITHUB_OUTPUT": str(output),
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
            artifact_id, archive_sha256 = upload_output(output, run_id=run_id)
        created = Stored(artifact_id, digest(document))
        if (
            self._uploaded(created, name=name, run_id=run_id, archive_sha256=archive_sha256)
            != document
        ):
            raise LifecycleError("checkpoint upload has no exact plaintext readback")
        if self.lineage() != history:
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
        if self.lineage() != (*history, created):
            raise LifecycleError("checkpoint registry publication remains unconfirmed")
        return created
