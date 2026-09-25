"""Exact completion and durable ownership precede every live fixture deletion."""

from __future__ import annotations

import copy
import hashlib
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_owned_teardown as teardown
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as restore
from scripts.m3_11_combined_inputs import allocate
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_case import private_document
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, HOST_ENV, RUN_ENV, run_lease
from scripts.qualification_group_runner import Completion

SOURCE = "a" * 64
ARCHIVE = "b" * 64
DESTINATION = "c" * 64
ACME = "d" * 64
IMAGE = "sha256:" + "e" * 64


class Fixture:
    def __init__(self, directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.directory = directory
        directory.chmod(0o700)
        self.environment = allocate(directory, {"DOCKER_HOST": "unix:///var/run/docker.sock"})
        artifact = Path(self.environment[ARTIFACT_ENV])
        artifact.write_bytes(b"original selected artifact")
        self.bound = {HOST_ENV: SOURCE, ARCHIVE_ENV: ARCHIVE}
        self.current = dict(self.bound)
        self.pair = {"destination": DESTINATION, "acme": ACME}
        self.pair_current = dict(self.pair)
        self.image = IMAGE
        self.actions: list[str] = []
        self.failure: str | None = None
        self.after_response = False
        self.states = {
            identity: {
                "started_at": "2026-09-25T00:00:00Z",
                "restarts": 0,
                "running": True,
                "status": "running",
            }
            for identity in self.bound.values()
        }
        self.receipts = {
            kind: {
                "id": identity,
                "name": f"/ldp-m3-{self.environment[RUN_ENV]}-{kind}",
                "owner": self.environment[RUN_ENV],
                "image": IMAGE,
                "running": True,
            }
            for kind, identity in {"source": SOURCE, **self.pair}.items()
        }
        self.receipts["source"]["name"] = "/" + self.environment[HOST_ENV]
        restore.directory(self.environment).mkdir(mode=0o700)
        for kind, receipt in self.receipts.items():
            private_document(restore.directory(self.environment), f"{kind}.json", receipt)
        binding: dict[str, object] = dict.fromkeys(evidence.BINDING_FIELDS, "f" * 64)
        binding["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        self.context: dict[str, object] = {
            **binding,
            "run_id": str(uuid.UUID(self.environment[RUN_ENV])),
            **{
                kind + "_fixture_sha256": teardown._digest(
                    {key: self.receipts[kind][key] for key in ("id", "name", "owner", "image")}
                )
                for kind in ("source", "destination")
            },
        }
        write_private(directory / "combined-context.json", self.context)
        write_private(
            directory / "paired-accounting.json",
            {
                "context_sha256": teardown._digest(self.context),
                "original": "paired accounting",
            },
        )
        self.storage = Mock()
        self.storage.environment = self.environment
        self.storage.binding = binding
        self.storage.target.run_id = self.context["run_id"]
        self.storage.target.archive_bucket = "owned-archive-bucket"
        self.storage.owner_version = "original-full-owner-version"
        self.storage.target.manifest.return_value = {"original": "storage ownership"}
        self.writer, self.observer = Mock(), Mock()
        self.storage.target.clients.return_value = (self.writer, self.observer)
        self.archive_absent = Mock()
        self.local_absent = Mock()
        self.fenced = Mock()
        self.dns = Mock(return_value="1" * 64)
        self.removal = Mock()
        self.removal.directory = directory / "owned-teardown/backup"
        self.removal.run.side_effect = self.backup
        self.removal._observed.return_value = copy.deepcopy(teardown.EMPTY)
        self._patch(monkeypatch)
        self.controller = teardown.Teardown(directory, self.storage, self.dns)
        self.completion = Completion(teardown.nodes(self.environment))
        self.completion.collected = list(self.completion.expected)
        self.completion.reports = {
            node: [(phase, "passed", False) for phase in ("setup", "call", "teardown")]
            for node in self.completion.expected
        }

    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(teardown, "Removal", Mock(return_value=self.removal))
        monkeypatch.setattr(
            teardown, "owned_containers", lambda *args, **kwargs: dict(self.current)
        )
        monkeypatch.setattr(
            teardown, "snapshot", lambda environment, identity: dict(self.states[identity])
        )
        monkeypatch.setattr(teardown, "present", lambda *args: dict(self.pair_current))
        monkeypatch.setattr(teardown, "remove_owned_image", self.remove_image)
        monkeypatch.setattr(teardown, "assert_storage_empty", self.archive_absent)
        monkeypatch.setattr(teardown, "uninstalled_storage_absence", self.local_absent)
        monkeypatch.setattr(restore, "command", self.command)
        monkeypatch.setattr(restore, "paired_proof", lambda *args: dict(self.pair_current))
        monkeypatch.setattr(restore, "inspect", lambda *args: dict(self.receipts["source"]))
        monkeypatch.setattr(restore, "source_fenced", self.fenced)
        monkeypatch.setattr(restore, "remove_pair", self.remove_pair)

    def interrupt(self, step: str, *, after: bool) -> None:
        if self.failure == step and after == self.after_response:
            self.failure = None
            raise OSError("lost cleanup response")

    def authorized(self, step: str) -> None:
        assert read_private(self.controller.root / f"{step}.started.json") == {
            "intent_sha256": teardown._digest(self.controller.intent),
        }

    def command(self, environment: dict[str, str], *arguments: str, **kwargs: object) -> bytes:
        assert environment == self.environment
        if arguments[1:3] == ("image", "ls"):
            return (self.image + "\n").encode()
        identity = arguments[-1]
        kind = "source" if identity == SOURCE else "archive"
        key = teardown.KEYS[kind]
        action = "stop" if arguments[1] == "stop" else "remove"
        step = f"{action}-{kind}"
        self.authorized(step)
        self.interrupt(step, after=False)
        self.actions.append(step)
        if action == "stop":
            assert arguments == ("docker", "stop", "--time", "20", identity)
            self.states[identity].update(running=False, status="exited")
        else:
            assert arguments == ("docker", "rm", "--volumes", identity)
            assert self.states[identity]["running"] is False
            del self.current[key]
        self.interrupt(step, after=True)
        return b""

    def remove_pair(self, environment: dict[str, str], expected: dict[str, str]) -> None:
        assert expected == self.pair
        self.authorized("pair")
        self.interrupt("pair", after=False)
        if self.pair_current:
            self.actions.append("pair")
            self.pair_current.clear()
        private_document(restore.directory(environment), "removed.json", {"identities": expected})
        self.interrupt("pair", after=True)

    def backup(self) -> dict[str, object]:
        self.authorized("backup")
        assert not self.pair_current
        self.controller._quiet()
        self.interrupt("backup", after=False)
        if not self.removal.directory.exists():
            self.actions.append("backup")
            self.removal.directory.mkdir(mode=0o700)
            intent = {
                "ownership": self.controller.intent["storage"],
                "owner_version": self.storage.owner_version,
                "quiescent_sha256": teardown._digest(self.controller.intent),
            }
            write_private(self.removal.directory / "intent.json", intent)
            write_private(
                self.removal.directory / "removed.json",
                {
                    "intent_sha256": teardown._digest(intent),
                    "remaining_backup_objects": 0,
                },
            )
        self.interrupt("backup", after=True)
        return read_private(self.removal.directory / "removed.json")

    def remove_image(self, environment: dict[str, str]) -> None:
        assert not self.current
        self.authorized("image")
        self.interrupt("image", after=False)
        if self.image:
            self.actions.append("image")
            self.image = ""
        self.interrupt("image", after=True)

    def authorize(self) -> None:
        self.controller.authorize(self.completion, 0)


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    return Fixture(tmp_path, monkeypatch)


def test_complete_teardown_proves_absence_before_emitting_its_receipt(fixture: Fixture) -> None:
    fixture.authorize()
    result = fixture.controller.run()
    assert fixture.actions == list(teardown.STEPS)
    assert result["teardown"] == dict.fromkeys(evidence.ZERO_TEARDOWN, 0)
    assert not fixture.current and not fixture.pair_current and not fixture.image
    assert fixture.archive_absent.call_args.args == (fixture.observer,)
    assert fixture.dns.call_count == 2  # noqa: PLR2004 - authorization and final absence
    original = (fixture.controller.root / "removed.json").read_bytes()
    fixture.dns.return_value = "2" * 64
    assert fixture.controller.run() == result
    assert (fixture.controller.root / "removed.json").read_bytes() == original
    assert not (fixture.directory / "combined.json").exists()


@pytest.mark.parametrize("step", teardown.STEPS)
@pytest.mark.parametrize("after", [False, True])
def test_lost_responses_resume_only_previously_authorized_cleanup(
    fixture: Fixture, step: str, after: bool
) -> None:
    fixture.authorize()
    fixture.failure, fixture.after_response = step, after
    with pytest.raises(OSError, match="lost cleanup response"):
        fixture.controller.run()
    assert not (fixture.controller.root / "removed.json").exists()
    fixture.controller = teardown.Teardown(fixture.directory, fixture.storage, fixture.dns)
    fixture.controller.run()
    assert fixture.actions == list(teardown.STEPS)
    assert not (fixture.directory / "combined.json").exists()


@pytest.mark.parametrize(
    "fault", ["failed", "skipped", "xfail", "missing", "other-node", "duplicate"]
)
def test_incomplete_or_different_tests_cannot_authorize_any_deletion(
    fixture: Fixture, fault: str
) -> None:
    status = 1 if fault == "failed" else 0
    key = fixture.completion.expected[0]
    if fault == "skipped":
        fixture.completion.reports[key][1] = ("call", "skipped", False)
    elif fault == "xfail":
        fixture.completion.reports[key][1] = ("call", "passed", True)
    elif fault == "missing":
        fixture.completion.reports[key].pop()
    elif fault == "other-node":
        fixture.completion.expected = ("another-test",)
    elif fault == "duplicate":
        fixture.completion.collected.append(key)
    with pytest.raises(ValueError, match="exact installed-test completion"):
        fixture.controller.authorize(fixture.completion, status)
    assert not fixture.actions
    assert not fixture.controller.root.exists()


@pytest.mark.parametrize(
    "fault", ["local-storage", "archive", "dns", "image", "accounting", "context", "stopped"]
)
def test_changed_or_unresolved_initial_proofs_retain_all_resources(
    fixture: Fixture, fault: str
) -> None:
    if fault == "local-storage":
        fixture.local_absent.side_effect = ValueError("local storage is not empty")
    elif fault == "archive":
        fixture.archive_absent.side_effect = ValueError("provider storage is not empty")
    elif fault == "dns":
        fixture.dns.side_effect = ValueError("DNS records remain")
    elif fault == "image":
        fixture.image = "sha256:" + "f" * 64
    elif fault == "stopped":
        fixture.states[SOURCE].update(running=False, status="exited")
    elif fault == "accounting":
        replace(fixture.directory / "paired-accounting.json", {"context_sha256": "0" * 64})
    else:
        fixture.controller.context["source_fixture_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        fixture.authorize()
    assert not fixture.actions
    assert fixture.current == fixture.bound
    assert fixture.pair_current == fixture.pair


def replace(path: Path, value: dict[str, object]) -> None:
    path.unlink()
    write_private(path, value)


@pytest.mark.parametrize("key", [HOST_ENV, ARCHIVE_ENV])
@pytest.mark.parametrize("fault", ["missing", "replaced", "restarted", "stopped"])
def test_unexpected_resource_transitions_before_teardown_are_not_adopted(
    fixture: Fixture, key: str, fault: str
) -> None:
    fixture.authorize()
    if fault == "missing":
        del fixture.current[key]
    elif fault == "replaced":
        fixture.current[key] = "f" * 64
    else:
        fixture.states[fixture.bound[key]].update(
            {"restarts": 1} if fault == "restarted" else {"running": False, "status": "exited"}
        )
    with pytest.raises(ValueError):
        fixture.controller.run()
    assert not fixture.actions


@pytest.mark.parametrize("kind", ["source", "archive"])
def test_restart_after_a_lost_stop_response_cannot_reuse_the_original_proof(
    fixture: Fixture, kind: str
) -> None:
    fixture.authorize()
    fixture.failure, fixture.after_response = f"stop-{kind}", True
    with pytest.raises(OSError):
        fixture.controller.run()
    identity = fixture.bound[teardown.KEYS[kind]]
    fixture.states[identity]["restarts"] = 1
    actions = list(fixture.actions)
    with pytest.raises(ValueError, match="restarted"):
        fixture.controller.run()
    assert fixture.actions == actions


@pytest.mark.parametrize("fault", ["pair", "backup", "archive", "dns", "image", "source"])
def test_new_resources_or_failed_final_proofs_cannot_publish_zero_accounting(
    fixture: Fixture, fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture.authorize()
    fixture.failure, fixture.after_response = "image", True
    with pytest.raises(OSError):
        fixture.controller.run()
    if fault == "pair":
        fixture.pair_current.update(fixture.pair)
    elif fault == "backup":
        fixture.removal._observed.return_value = {**teardown.EMPTY, "current": ["new-object"]}
    elif fault == "archive":
        fixture.archive_absent.side_effect = ValueError("new archive object")
    elif fault == "dns":
        fixture.dns.side_effect = ValueError("DNS records remain")
    elif fault == "image":
        fixture.image = "sha256:" + "f" * 64
    else:
        fixture.current[HOST_ENV] = SOURCE
    with pytest.raises(ValueError):
        fixture.controller.run()
    assert not (fixture.controller.root / "removed.json").exists()


@pytest.mark.parametrize(
    "filename", ["combined-tests.json", "paired-accounting.json", "combined-context.json"]
)
def test_changed_original_evidence_cannot_resume_cleanup(fixture: Fixture, filename: str) -> None:
    fixture.authorize()
    value = read_private(fixture.directory / filename)
    value["unexpected"] = True
    replace(fixture.directory / filename, value)
    with pytest.raises(ValueError, match="changed"):
        fixture.controller.run()
    assert not fixture.actions


def test_failed_durable_authorization_never_reaches_a_destructive_action(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture.authorize()
    monkeypatch.setattr(teardown, "_once", Mock(side_effect=OSError("journal unavailable")))
    with pytest.raises(OSError, match="journal unavailable"):
        fixture.controller.run()
    assert not fixture.actions


def test_explicit_resume_finishes_cleanup_after_backup_owner_is_already_gone(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    with run_lease(fixture.directory, create=True):
        fixture.authorize()
        fixture.failure, fixture.after_response = "stop-source", True
        with pytest.raises(OSError):
            fixture.controller.run()
    monkeypatch.setattr(LiveStorage, "_retained", Mock(return_value=fixture.storage))
    monkeypatch.setattr(teardown, "removal_absence", Mock(return_value=Mock(sha256="2" * 64)))
    result = teardown.resume(fixture.directory, fixture.environment)
    assert read_private(result)["teardown"] == dict.fromkeys(evidence.ZERO_TEARDOWN, 0)
    assert fixture.actions == list(teardown.STEPS)
    assert not (fixture.directory / "combined.json").exists()


def test_cleanup_cannot_race_the_live_controller_or_create_missing_authorization(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    retained = Mock(return_value=fixture.storage)
    monkeypatch.setattr(LiveStorage, "_retained", retained)
    with run_lease(fixture.directory, create=True), pytest.raises(BlockingIOError):
        teardown.resume(fixture.directory, fixture.environment)
    retained.assert_not_called()
    with pytest.raises(FileNotFoundError):
        teardown.resume(fixture.directory, fixture.environment)
    assert not fixture.actions


def test_teardown_cannot_reauthorize_or_run_without_original_authorization(
    fixture: Fixture,
) -> None:
    with pytest.raises(FileNotFoundError):
        fixture.controller.run()
    fixture.authorize()
    original = (fixture.controller.root / "intent.json").read_bytes()
    with pytest.raises(ValueError, match="original authorization"):
        fixture.authorize()
    assert (fixture.controller.root / "intent.json").read_bytes() == original
    assert not fixture.actions
