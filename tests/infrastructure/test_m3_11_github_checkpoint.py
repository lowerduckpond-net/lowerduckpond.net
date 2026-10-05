"""GitHub registry and encrypted artifact fault boundaries without live writes."""

from __future__ import annotations

import copy
import hashlib
import io
import subprocess
import sys
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import override
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts.m3_11_unattended import github_checkpoint as github
from scripts.m3_11_unattended.connect_checkpoint import Checkpoint, Stored
from scripts.m3_11_unattended.journal import event
from scripts.m3_11_unattended.model import LifecycleError, digest

CANARY = "github-checkpoint-private-canary"


class Registry(github.GitHubArtifacts):
    def __init__(self, directory: Path) -> None:
        super().__init__(
            epoch=str(uuid.uuid7()), registry_revision="a" * 40, token=CANARY, directory=directory
        )
        self.runs: list[dict[str, object]] = [
            {"id": 3, "status": "in_progress", "head_branch": "main"}
        ]
        self.artifacts: dict[int, list[dict[str, object]]] = {3: []}
        self.archives: dict[int, bytes] = {}
        self.fail_download = False
        self.statuses: list[dict[str, object]] = []
        self.lose_status_reply = False
        self.workflow_id = github.WORKFLOW_ID

    @override
    def _api(  # noqa: PLR0911 - distinct GitHub API routes in the provider double
        self, path: str, *, binary: bool = False, body: dict[str, object] | None = None
    ) -> object:
        page = int(parse_qs(urlsplit(path).query).get("page", ["1"])[0])
        start = (page - 1) * github.PAGE_SIZE
        if "/statuses/" in path:
            assert body is not None
            row = {
                **body,
                "id": len(self.statuses) + 1,
                "creator": {"id": github.STATUS_AUTHOR, "type": "Bot"},
            }
            self.statuses.insert(0, row)
            if self.lose_status_reply:
                raise LifecycleError("registry response lost")
            return copy.deepcopy(row)
        if "/commits/" in path:
            return copy.deepcopy(self.statuses[start : start + github.PAGE_SIZE])
        if "/workflows/" in path:
            return {
                "workflow_runs": copy.deepcopy(self.runs[start : start + github.PAGE_SIZE]),
                "total_count": len(self.runs),
            }
        if "/runs/" in path:
            run_id = int(path.split("/runs/")[1].split("/", maxsplit=1)[0])
            if "/artifacts" not in path:
                return {
                    "id": run_id,
                    "workflow_id": self.workflow_id,
                    "path": ".github/workflows/" + github.WORKFLOW,
                    "event": "workflow_dispatch",
                    "head_branch": "main",
                    "repository": {"full_name": github.REPOSITORY},
                    "head_repository": {"full_name": github.REPOSITORY},
                }
            values = copy.deepcopy(self.artifacts.get(run_id, []))
            return {
                "artifacts": values[start : start + github.PAGE_SIZE],
                "total_count": len(values),
            }
        selected = int(path.split("/artifacts/")[1].split("/", maxsplit=1)[0])
        if binary:
            if self.fail_download:
                raise LifecycleError("download unavailable")
            return self.archives[selected]
        for rows in self.artifacts.values():
            for row in rows:
                if row["id"] == selected:
                    return copy.deepcopy(row)
        raise LifecycleError("artifact is missing")

    def add(
        self, *, name: str, raw: bytes, run_id: int = 3, expired: bool = False
    ) -> dict[str, object]:
        selected = len(self.archives) + 10
        self.archives[selected] = raw
        value: dict[str, object] = {
            "id": selected,
            "name": name,
            "workflow_run": {"id": run_id, "head_branch": "main"},
            "expired": expired,
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "size_in_bytes": len(raw),
        }
        self.artifacts.setdefault(run_id, []).append(value)
        return value


def archive(path: Path) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as output:
        output.writestr("checkpoint.json", path.read_bytes())
    return stream.getvalue()


def action_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "work/repository"
    action = (
        workspace.parent
        / "_actions/actions/upload-artifact"
        / github.UPLOAD_REVISION
        / "dist/upload/index.js"
    )
    action.parent.mkdir(parents=True)
    action.write_text("pinned-test-placeholder")
    node = tmp_path / "node"
    node.touch()
    for key, value in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": github.REPOSITORY,
        "GITHUB_WORKFLOW_REF": (
            f"{github.REPOSITORY}/.github/workflows/{github.WORKFLOW}@refs/heads/main"
        ),
        "GITHUB_RUN_ID": "3",
        "ACTIONS_RUNTIME_TOKEN": CANARY,
        "RUNNER_WORKSPACE": str(workspace),
        "M3_11_ACTION_NODE": str(node),
        "OP_SERVICE_ACCOUNT_TOKEN": CANARY + "unrelated",
        "CLEANUP_CONFIGURATION": CANARY + "bootstrap",
    }.items():
        monkeypatch.setenv(key, value)


def uploader(
    registry: Registry, *, uncertain: bool = False
) -> Callable[..., subprocess.CompletedProcess[bytes]]:
    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert "OP_SERVICE_ACCOUNT_TOKEN" not in environment
        assert "CLEANUP_CONFIGURATION" not in environment
        assert environment["INPUT_OVERWRITE"] == "false"
        assert CANARY not in repr(command)
        path = Path(environment["INPUT_PATH"])
        assert CANARY.encode() not in path.read_bytes()
        registry.add(name=environment["INPUT_NAME"], raw=archive(path))
        if uncertain:
            raise subprocess.TimeoutExpired(command, 1, output=CANARY.encode())
        return subprocess.CompletedProcess(command, 0, CANARY.encode(), CANARY.encode())

    return run


def test_encrypted_checkpoint_roundtrip_and_clean_uploader_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    value: dict[str, object] = {"records": [{"name": "owned-id", "canary": CANARY}]}
    stored = registry.create(value)
    assert registry.latest() == stored
    assert stored.sha256 == digest(value)
    assert registry.read(stored) == value
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err


def test_uploader_can_publish_outputs_after_upload_without_losing_registry_acknowledgement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    upload = uploader(registry)
    native_run = subprocess.run

    def require_runner_output(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        uploaded = upload(command, **kwargs)
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        # The pinned Actions toolkit checks existence before appending outputs.
        # Run that contract in a child process after the upload has succeeded.
        result = native_run(
            [
                sys.executable,
                "-c",
                "import os, pathlib, stat\n"
                "p = pathlib.Path(os.environ['GITHUB_OUTPUT'])\n"
                "assert p.is_file() and not p.is_symlink()\n"
                "assert stat.S_IMODE(p.stat().st_mode) == 0o600\n"
                "assert p.read_bytes() == b''\n"
                "fd = os.open(p, os.O_WRONLY | os.O_APPEND)\n"
                "os.write(fd, b'artifact-id=10\\n')\n"
                "os.close(fd)\n",
            ],
            env=environment,
            capture_output=True,
            check=False,
            timeout=10,
        )
        return uploaded if result.returncode == 0 else result

    monkeypatch.setattr(subprocess, "run", require_runner_output)
    document: dict[str, object] = {"records": ["owned-intent"]}
    created = registry.create(document)
    assert registry.latest() == created
    assert registry.read(created) == document
    assert len(registry.archives) == 1
    assert len(registry.statuses) == 1
    assert list(registry.directory.iterdir()) == []


def test_uncertain_upload_cannot_advance_registry_but_preserves_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry, uncertain=True))
    value: dict[str, object] = {"records": ["owned-intent-and-returned-id"]}
    with pytest.raises(LifecycleError, match="uncertain") as error:
        registry.create(value)
    assert CANARY not in str(error.value)
    assert registry.latest() is None  # No ACK can have been issued for this orphan upload.
    assert len(registry.archives) == 1


def test_lost_registry_reply_recovers_exact_head_without_another_upload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    registry.lose_status_reply = True
    value: dict[str, object] = {"records": ["owned-intent-and-returned-id"]}
    with pytest.raises(LifecycleError, match="response lost"):
        registry.create(value)
    stored = registry.latest()
    assert stored is not None and registry.read(stored) == value
    assert len(registry.archives) == 1


def test_deleted_newest_payload_remains_the_head_after_process_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    older = registry.create({"records": ["old"]})
    newer = registry.create({"records": ["old", "acknowledged-intent"]})
    registry.artifacts[3].pop()
    restarted = Registry(tmp_path / "restarted")
    restarted.context, restarted.prefix = registry.context, registry.prefix
    restarted.epoch = registry.epoch
    restarted.statuses = copy.deepcopy(registry.statuses)
    restarted.artifacts, restarted.archives = registry.artifacts, registry.archives
    assert restarted.latest() == newer
    with pytest.raises(LifecycleError, match="missing"):
        restarted.read(newer)
    assert restarted.read(older) == {"records": ["old"]}  # Available, never silently adopted.


def test_roundtrip_above_private_file_default_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    value: dict[str, object] = {"records": ["x" * 300_000]}
    stored = registry.create(value)
    assert registry.read(stored) == value


def test_missing_payload_cannot_forget_an_acknowledged_intent_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    anchor = event("run", str(uuid.uuid7()), {"initial": True})
    initial = {str(anchor["event_id"]): digest(anchor)}
    checkpoint = Checkpoint(
        registry, epoch=registry.epoch, genesis=None, initial=initial, initialize=True
    )
    genesis = checkpoint.persist([anchor])
    intent = event("intent", str(anchor["run_id"]), {"name": "acknowledged-owned-double"})
    checkpoint.persist([anchor, intent])
    registry.artifacts[3].pop()
    restarted = Checkpoint(registry, epoch=registry.epoch, genesis=genesis, initial=initial)
    with pytest.raises(LifecycleError, match="missing"):
        restarted.restore()
    assert not restarted.records  # No older snapshot is accepted as complete.


@pytest.mark.parametrize("fault", ["creator", "state", "url", "digest", "context-case"])
def test_newest_registry_entry_cannot_be_skipped_when_untrusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    registry.create({"records": ["old"]})
    registry.create({"records": ["old", "latest"]})
    row = registry.statuses[0]
    if fault == "creator":
        row["creator"] = {"id": 1, "type": "User"}
    elif fault == "state":
        row["state"] = "failure"
    elif fault == "url":
        row["target_url"] = "https://untrusted.example/credential-canary"
    elif fault == "digest":
        row["description"] = "not-a-digest"
    else:
        row["context"] = registry.context.upper()
        row["description"] = "not-a-digest"
    with pytest.raises(LifecycleError, match="untrusted"):
        registry.latest()


def test_append_only_head_rejects_replayed_old_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    registry.create({"records": ["old"]})
    registry.create({"records": ["old", "new"]})
    replay = {**registry.statuses[-1], "id": 3}
    registry.statuses.insert(0, replay)
    with pytest.raises(LifecycleError, match="backwards"):
        registry.latest()


def test_replayed_valid_prefix_cannot_hide_a_later_acknowledged_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    for values in (["A"], ["A", "B"], ["A", "B", "C"]):
        registry.create({"records": values})
    # The newest pair B -> A is valid in isolation, but omits acknowledged C.
    registry.statuses.insert(0, {**registry.statuses[-1], "id": 4})
    registry.statuses.insert(0, {**registry.statuses[-2], "id": 5})
    with pytest.raises(LifecycleError, match="backwards"):
        registry.latest()


def test_other_workflow_cannot_supply_a_checkpoint_despite_same_bot_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    stored = registry.create({"records": ["owned"]})
    registry._verified_runs.clear()
    registry.workflow_id += 1
    with pytest.raises(LifecycleError, match="protected"):
        registry.read(stored)


def test_capacity_counts_all_matching_history_and_duplicate_registration_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    stored = registry.create({"records": ["owned"]})
    original = registry.statuses[0]
    used = github.STATUS_LIMIT - github.MINIMUM_START_CAPACITY + 1
    registry.statuses = [{**original, "id": index + 1} for index in reversed(range(used))]
    assert registry.latest() == stored
    assert registry.remaining_capacity() == github.MINIMUM_START_CAPACITY - 1
    registry.statuses.extend(
        {"id": index + used + 1, "context": "unrelated-ci"} for index in range(105)
    )
    assert registry.remaining_capacity() == github.MINIMUM_START_CAPACITY - 1


def test_stale_writer_and_republished_genesis_cannot_erase_an_intervening_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    anchor = event("run", str(uuid.uuid7()), {"initial": True})
    initial = {str(anchor["event_id"]): digest(anchor)}
    checkpoint = Checkpoint(
        registry, epoch=registry.epoch, genesis=None, initial=initial, initialize=True
    )
    genesis = checkpoint.persist([anchor])
    old = registry.read(genesis)
    checkpoint.persist([anchor, event("intent", str(anchor["run_id"]), {"owned": True})])
    uploads = len(registry.archives)
    with pytest.raises(LifecycleError, match="extension"):
        registry.create(old)
    assert len(registry.archives) == uploads
    # Even an authenticated status pointing at a new copy of old content fails
    # the full predecessor check when the independent process starts afresh.
    copied = registry.add(
        name=str(registry.artifacts[3][0]["name"]), raw=registry.archives[genesis.identity]
    )
    registry.statuses.insert(
        0,
        {
            **registry.statuses[-1],
            "id": 3,
            "target_url": (
                f"https://github.com/{github.REPOSITORY}/actions/runs/3/artifacts/{copied['id']}"
            ),
        },
    )
    restarted = Checkpoint(registry, epoch=registry.epoch, genesis=genesis, initial=initial)
    with pytest.raises(LifecycleError, match="predecessor"):
        restarted.restore()


def test_older_workflow_rerun_cannot_write_over_newer_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    registry.runs.append({"id": 4, "status": "completed", "head_branch": "main"})
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: pytest.fail("must not upload"))
    with pytest.raises(LifecycleError, match="older"):
        registry.create({"records": []})


def test_queued_newer_run_does_not_preempt_the_serialized_current_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    registry.runs.append({"id": 4, "status": "queued", "head_branch": "main"})
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    stored = registry.create({"records": ["owned"]})
    assert registry.latest() == stored


def test_complete_pagination_and_newest_run_without_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    stored = registry.create({"records": ["owned"]})
    registry.runs.extend(
        {"id": value, "status": "completed", "head_branch": "main"} for value in range(4, 107)
    )
    for value in range(101):
        registry.add(name=f"unrelated-{value}", raw=b"not-a-checkpoint")
    # All pages are examined even when the API order is not chronological.
    assert len(registry._runs()) == len(registry.runs)
    assert len(registry._artifacts(3)) == len(registry.artifacts[3])
    assert registry.latest() == stored


@pytest.mark.parametrize("inventory", ["runs", "artifacts"])
@pytest.mark.parametrize("fault", ["duplicate", "count-change", "partial"])
def test_incomplete_inventory_never_selects_an_older_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inventory: str, fault: str
) -> None:
    registry = Registry(tmp_path / "private")
    original = registry._api

    def changed(
        path: str, *, binary: bool = False, body: dict[str, object] | None = None
    ) -> object:
        target = "/workflows/" if inventory == "runs" else "/runs/"
        if target not in path:
            return original(path, binary=binary, body=body)
        page = int(parse_qs(urlsplit(path).query)["page"][0])
        field = "workflow_runs" if inventory == "runs" else "artifacts"
        row = {"id": 3, "status": "completed", "head_branch": "main"}
        if fault == "partial":
            return {field: [], "total_count": 1}
        total = 2 if fault == "duplicate" or page == 1 else 3
        return {field: [row], "total_count": total}

    monkeypatch.setattr(registry, "_api", changed)
    with pytest.raises(LifecycleError):
        registry._runs() if inventory == "runs" else registry._artifacts(3)


@pytest.mark.parametrize("field,value", [("head_branch", "untrusted"), ("id", True)])
def test_workflow_identity_mismatch_stops_registry_discovery(
    tmp_path: Path, field: str, value: object
) -> None:
    registry = Registry(tmp_path / "private")
    registry.runs[0][field] = value
    with pytest.raises(LifecycleError):
        registry._runs()


@pytest.mark.parametrize(
    "fault", ["expired", "download", "wrong-hash", "wrong-epoch", "corrupt-zip", "empty-zip"]
)
def test_latest_checkpoint_failure_never_falls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    older = registry.create({"records": ["old"]})
    newer = registry.create({"records": ["old", "new-owned-intent"]})
    value = registry.artifacts[3][-1]
    if fault == "expired":
        value["expired"] = True
        assert registry.latest() == newer
        with pytest.raises(LifecycleError, match="expired"):
            registry.read(newer)
        return
    if fault == "download":
        registry.fail_download = True
    elif fault == "wrong-hash":
        value["digest"] = "sha256:" + "0" * 64
    elif fault == "wrong-epoch":
        value["name"] = "m311-connect-unexpected-epoch"
    elif fault == "corrupt-zip":
        registry.archives[newer.identity] = b"broken"
        value["digest"] = "sha256:" + hashlib.sha256(b"broken").hexdigest()
    else:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w"):
            pass
        raw = stream.getvalue()
        registry.archives[newer.identity] = raw
        value["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    with pytest.raises(LifecycleError):
        registry.read(newer)
    assert older.identity in registry.archives  # Failure never deletes retained evidence.


def test_plaintext_binding_and_epoch_cipher_prevent_cross_checkpoint_adoption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action_environment(tmp_path, monkeypatch)
    registry = Registry(tmp_path / "private")
    monkeypatch.setattr(subprocess, "run", uploader(registry))
    stored = registry.create({"records": ["owned"]})
    altered = Stored(stored.identity, "0" * 64)
    with pytest.raises(LifecycleError):
        registry.read(altered)
    registry._token = CANARY + "wrong-cleanup-client"
    with pytest.raises(LifecycleError):
        registry.read(stored)


def test_gh_cli_error_suppresses_stdout_stderr_and_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GH_TOKEN", CANARY)
    client = github.GitHubArtifacts(
        epoch=str(uuid.uuid7()),
        registry_revision="a" * 40,
        token=CANARY,
        directory=tmp_path / "private",
    )

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert CANARY not in repr(command)
        assert kwargs["env"]["GH_TOKEN"] == CANARY  # type: ignore[index] # subprocess boundary
        return subprocess.CompletedProcess(command, 1, CANARY.encode(), CANARY.encode())

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(LifecycleError) as error:
        client.latest()
    assert CANARY not in str(error.value)
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
