"""Terminal ownership and local effects against real lease files, no live backend."""

from __future__ import annotations

import json
import re
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from scripts import m3_11_frozen_disposal as local
from scripts import m3_11_frozen_retirement as retirement
from scripts.m3_11_frozen_context import actor
from scripts.m3_11_frozen_stage import AUTHORIZATION
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended import storage_admission
from scripts.m3_11_unattended.state import LeaseState
from scripts.qualification_context import IMAGE_ENV, resource_names
from scripts.qualification_fence import commit, require_unfenced
from scripts.qualification_mutation import ownership

from .test_m3_11_frozen_actor_export import Reader
from .test_m3_11_lease_runtime import DAEMON
from .test_m3_11_storage_admission import prepared


def approval(plan: dict[str, object], stage: str) -> dict[str, object]:
    return {
        "format": AUTHORIZATION,
        "stage": stage,
        "plan_sha256": digest(plan),
        "approval_reference_sha256": "a" * 64,
        "approved_at": "2020-01-01T00:00:00Z",
        "acknowledge_irreversible_scoped_removal": True,
        "acknowledge_execution_remains_excluded": True,
        "acknowledge_no_automatic_replay": True,
    }


class Daemon(local.LocalDocker):
    def __init__(self, rows: dict[str, Any], endpoint: str) -> None:
        self.rows, self.endpoint = rows, endpoint
        self.image = "sha256:" + "9" * 64
        self.mutations: list[tuple[str, str]] = []
        self.reads = 0
        self.fail_after: str | None = None

    def info(self) -> dict[str, str]:
        self.reads += 1
        return DAEMON

    def command(self, *args: str, stdin: bytes | None = None, timeout: int = 1200) -> bytes:
        assert stdin is None
        self.reads += 1
        if args[:2] == ("image", "ls"):
            return self.image.encode()
        if args[0] == "inspect":
            return json.dumps([self.rows[args[-1]]]).encode()
        assert args[0] == "ps"
        selector = args[args.index("--filter") + 1]
        selected = [
            key
            for key, row in self.rows.items()
            if (selector.startswith("id=") and key == selector.removeprefix("id="))
            or (
                selector.startswith("name=")
                and re.search(selector.removeprefix("name="), row["Name"])
            )
            or (
                selector.startswith("label=")
                and row["Config"]["Labels"].get("lowerduckpond.qualification.run")
                == selector.removeprefix("label=lowerduckpond.qualification.run=")
            )
        ]
        return "".join(key + "\n" for key in selected).encode()

    def actor_bytes(
        self, operation: str, selected: str, guard: Callable[[], None]
    ) -> Iterator[bytes]:
        assert selected in self.rows
        guard()
        yield Reader().archive if operation == "export" else b"synthetic private logs\n"

    def remove_container(self, selected: str) -> None:
        self.mutations.append(("container", selected))
        del self.rows[selected]
        if self.fail_after == selected:
            raise KeyboardInterrupt

    def remove_image(self, reference: str, owner: str) -> None:
        assert reference == "molecule_local/" + resource_names(owner)[IMAGE_ENV]
        self.mutations.append(("image", self.image))
        self.image = ""


@pytest.fixture
def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    producer, lease, existing, _configuration, _inventory = prepared(tmp_path, monkeypatch)
    root = producer.parent.parent
    for path in (root, root / "runs", root / "leases", producer / "qualification"):
        path.chmod(0o700)
    run = producer / "qualification/spaces-aaaaaaa.synthetic"
    (producer / "qualification/synthetic-fixture").rename(run)
    run.chmod(0o700)
    owner = str(
        cast(dict[str, Any], existing.rows["1" * 64])["Config"]["Labels"][
            "lowerduckpond.qualification.run"
        ]
    )
    fixture_id = str(uuid.UUID(hex=owner))
    (run / "fixture.json").unlink()
    write_private(run / "fixture.json", {"run_id": fixture_id})
    for path in (run / "run.lock", producer / "controller.lock"):
        path.touch(mode=0o600)
    for row in existing.rows.values():
        row.update(Mounts=[], RestartCount=0)
        row["State"] = {
            "Running": False,
            "Pid": 0,
            "StartedAt": "original",
            "FinishedAt": "stopped",
        }
    daemon = Daemon(cast(dict[str, Any], existing.rows), existing.endpoint)
    fixture = {
        "actors": [actor(row) for row in daemon.rows.values()],
        "original_files": {},
        "consumer_binding": "a" * 64,
        "producer_binding": "b" * 64,
        "source_incarnation": {
            "id": "1" * 64,
            "started": "original",
            "finished": "stopped",
            "restarts": 0,
        },
    }
    plan: dict[str, Any] = {
        "format": retirement.FORMAT,
        "original_run": str(run),
        "producing_attempt": producer.name,
        "consumer_attempt": producer.name,
        "lease_id": lease.manifest().lease_id,
        "manifest_sha256": lease.manifest().sha256,
        "implementation_revision": "a" * 40,
        "fixture_sha256": digest(fixture),
        "evidence_sha256": "f" * 64,
        "archive": {
            "bucket": lease.manifest().targets.archive_bucket,
            "key": "archives/synthetic.zip",
            "version": "v1",
            "size": 10,
            "sha256": "b" * 64,
        },
        "retained": retirement.RETAINED,
    }
    with ownership(run, exclusive=True):
        exclusion = commit(run, plan_sha256=digest(plan), authorization_sha256="e" * 64)
    selected = {
        "format": local.FORMAT,
        "implementation_revision": "a" * 40,
        "retirement_plan": plan,
        "fixture": fixture,
        "exclusion": exclusion,
        "terminal_selection": {"synthetic": "test-boundary"},
        "terminal_capture": {"synthetic": "test-boundary"},
        "remote_directory": str(root),
        "remote_receipt_file": "completed.json",
        "remote_receipt_sha256": "c" * 64,
        "image": {
            "id": daemon.image,
            "reference": "molecule_local/" + resource_names(owner)[IMAGE_ENV],
        },
        "export_directory": str(root / "fixture-dispositions/full-export"),
        "maximum_export_bytes": 1000000,
        "maximum_export_entries": 1000,
    }
    for path in lease.directory.glob("credential-*.json"):
        path.unlink()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("local disposal opened child credentials")

    monkeypatch.setattr(LeaseState, "credential", forbidden)
    monkeypatch.setattr(local, "LEASE_DIRECTORY", vars(storage_admission)["LEASE_DIRECTORY"])
    monkeypatch.setattr(storage_admission, "_deadline", time.monotonic() + 21600)
    # These tests isolate real local ownership/effects from independently tested
    # terminal-fact/native ZIP and full remote-proof validators.
    monkeypatch.setattr(local, "terminal_proof", lambda *_args: {"synthetic": "closed"})
    monkeypatch.setattr(local, "install_terminal", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(local, "require_supported_closeout", lambda: None)

    class IsolatedLocal(local.NativeLocal):
        def prerequisites(self) -> None:
            self.owner()
            self.inventory(set())
            assert self.image_present()
            self.remote = {"synthetic": "independently-tested-boundary"}

        def remote_evidence(self, preserved: dict[str, object] | None = None) -> None:
            self.remote = {"synthetic": "independently-tested-boundary"}

    native = IsolatedLocal(evidence_root=root, docker=daemon, revalidate_copies=lambda: "f" * 64)
    return SimpleNamespace(
        native=native,
        plan=selected,
        approval=approval(selected, "local-disposal"),
        daemon=daemon,
        root=root,
        run=run,
        producer=producer,
        lease=lease,
        original=plan,
        fixture=fixture,
        owner=owner,
    )


def test_local_disposal_keeps_lease_failed_result_and_complete_private_exports(
    case: SimpleNamespace,
) -> None:
    before = {
        path.name: path.read_bytes() for path in case.lease.directory.iterdir() if path.is_file()
    }
    journey = (case.producer / "journey-result.json").read_bytes()
    receipt = case.native.execute(case.plan, case.approval)
    assert receipt["provider_calls"] == 0 and receipt["lease_changed"] is False
    assert case.daemon.rows == {} and case.daemon.image == "" and not case.run.exists()
    assert before == {
        path.name: path.read_bytes() for path in case.lease.directory.iterdir() if path.is_file()
    }
    assert (case.producer / "journey-result.json").read_bytes() == journey
    with pytest.raises(ValueError, match="permanently excludes"):
        require_unfenced(case.run)
    assert (case.native.stage_root.parent / "disposed.json").is_file()
    assert len(list((case.native.stage_root / "actors").glob("*/rootfs.tar"))) == len(
        case.fixture["actors"]
    )


def test_lost_local_response_retains_identity_without_automatic_replay(
    case: SimpleNamespace,
) -> None:
    case.daemon.fail_after = "1" * 64
    with pytest.raises(KeyboardInterrupt):
        case.native.execute(case.plan, case.approval)
    assert case.daemon.mutations == [("container", "1" * 64)]
    before = list(case.daemon.mutations)
    with pytest.raises((ValueError, OSError)):
        case.native.execute(case.plan, case.approval)
    assert case.daemon.mutations == before and case.run.exists()


@pytest.mark.parametrize("kind", ["live-use", "mounted", "restarted", "wrong-daemon"])
def test_missing_ownership_prerequisite_has_zero_disposal_effects(
    case: SimpleNamespace, kind: str
) -> None:
    if kind == "live-use":
        (case.lease.directory / ("released-" + case.producer.name + ".json")).unlink()
    elif kind == "mounted":
        case.daemon.rows["1" * 64]["Mounts"] = [{"Type": "volume", "Destination": "/state"}]
    elif kind == "restarted":
        case.daemon.rows["1" * 64]["State"]["StartedAt"] = "restarted"
    else:
        case.daemon.info = lambda: {**DAEMON, "ID": "wrong"}
    with pytest.raises((ValueError, OSError)):
        case.native.execute(case.plan, case.approval)
    assert case.daemon.mutations == [] and case.run.exists()


def test_local_copy_guard_has_no_per_chunk_daemon_work(case: SimpleNamespace) -> None:
    case.native.selected(case.plan)
    with case.native.locked():
        case.native.owner()
        reads = case.daemon.reads
        for _ in range(100):
            case.native.copy_guard()
        assert case.daemon.reads == reads


def test_explicit_local_continuation_does_not_replay_lost_actor_response(
    case: SimpleNamespace,
) -> None:
    case.daemon.fail_after = "1" * 64
    with pytest.raises(KeyboardInterrupt):
        case.native.execute(case.plan, case.approval)
    before = list(case.daemon.mutations)
    observed = case.native.reconcile(case.plan, case.approval)
    assert observed["removed_actor_ids"] == ["1" * 64]
    assert observed["mutation_submissions"] == 0 and case.daemon.mutations == before
    case.native.reconcile(case.plan, case.approval, continue_unsubmitted=True)
    assert case.daemon.mutations.count(("container", "1" * 64)) == 1
    assert not case.run.exists() and (case.native.stage_root.parent / "disposed.json").exists()
    assert not (
        case.native.stage_root / ("remove-container-" + "1" * 64 + ".acknowledged.json")
    ).exists()


def test_root_absent_lost_certificate_is_reconciled_without_resource_replay(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import m3_11_frozen_certificate as certificate  # noqa: PLC0415 - test boundary

    original = certificate.publish

    def lost(*_args: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(certificate, "publish", lost)
    with pytest.raises(KeyboardInterrupt):
        case.native.execute(case.plan, case.approval)
    assert not case.run.exists()
    before = list(case.daemon.mutations)
    observation = case.native.reconcile(case.plan, case.approval)
    assert observation["completion_recorded"] is True
    assert observation["tree"]["unsubmitted"] == []
    assert case.daemon.mutations == before
    monkeypatch.setattr(certificate, "publish", original)
    case.native.reconcile(case.plan, case.approval, continue_unsubmitted=True)
    assert case.daemon.mutations == before
    assert (case.native.stage_root.parent / "disposed.json").is_file()


def test_interrupted_export_keeps_partial_bytes_and_can_continue_before_any_removal(
    case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = case.daemon.actor_bytes

    def interrupted(operation: str, selected: str, guard: Callable[[], None]) -> Iterator[bytes]:
        if operation == "export":
            yield b"original partial evidence"
            raise KeyboardInterrupt
        yield from original(operation, selected, guard)

    monkeypatch.setattr(case.daemon, "actor_bytes", interrupted)
    with pytest.raises(KeyboardInterrupt):
        case.native.execute(case.plan, case.approval)
    assert case.daemon.mutations == [] and case.run.exists()
    assert not list(case.native.stage_root.glob("*.submitted.json"))
    partials = list(case.native.stage_root.glob("actors/*/rootfs.tar.partial"))
    assert len(partials) == 1
    retained = partials[0].read_bytes()
    with pytest.raises((ValueError, OSError)):
        case.native.reconcile(case.plan, case.approval)
    assert case.daemon.mutations == []
    monkeypatch.setattr(case.daemon, "actor_bytes", original)
    result = case.native.reconcile(case.plan, case.approval, continue_unsubmitted=True)
    assert result["original_directory"] == "absent" and not case.run.exists()
    saved = list(case.native.stage_root.glob("actors/*.interrupted-*/rootfs.tar.partial"))
    assert len(saved) == 1 and saved[0].read_bytes() == retained
