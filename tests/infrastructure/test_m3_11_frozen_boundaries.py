"""Operational freshness, original controller and interrupted exclusion boundaries."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import m3_11_frozen_entry as entry
from scripts import m3_11_frozen_retirement as retirement
from scripts import m3_11_frozen_stage_entry as staged
from scripts import qualification_fence as fence
from scripts.m3_11_frozen_context import NativeFixture
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_retirement_files import digest, sync
from scripts.m3_11_unattended.docker import OWNER, controller_name
from scripts.m3_11_unattended.state import replace_private
from scripts.m3_11_unattended.storage_admission import ReadOnlyDocker, existing_lock

from .test_m3_11_frozen_fence import fixture
from .test_m3_11_frozen_owner import owner as owner  # noqa: PLC0414 - pytest fixture
from .test_m3_11_frozen_retirement import Fixture
from .test_m3_11_frozen_retirement import case as case  # noqa: PLC0414 - pytest fixture


def test_long_read_can_refresh_new_native_proof_without_reanchoring_old_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    proof = entry.LocalProof("a" * 64)
    proof.valid_until = now + timedelta(seconds=entry.REFRESH_RESERVE)
    responses = [proof.valid_until, now + timedelta(seconds=5300)]
    calls = []

    def refresh(self: entry.LocalProof) -> str:
        calls.append(self.valid_until)
        self.valid_until = responses.pop(0)
        return self.evidence_sha256

    monkeypatch.setattr(entry.LocalProof, "__call__", refresh)
    with pytest.raises(ValueError, match="whole next"):
        proof.refresh_if_needed()
    assert proof.valid_until == calls[0]  # The old native proof was not renewed.
    proof.refresh_if_needed()
    proof.refresh_if_needed()
    assert len(calls) == 2  # noqa: PLR2004 - one stale result, then one new native result
    proof.current()


def test_no_freshness_refresh_is_possible_inside_revocation_exclusion(owner: NativeFixture) -> None:
    calls = []
    owner.root.chmod(0o700)
    lock = owner.root / ".credential-cleanup.lock"

    def refresh() -> None:
        with existing_lock(lock):
            calls.append("refresh")

    owner.refresh_cleanup = refresh
    owner.owner()
    with owner.submission():
        before = list(calls)
        owner.owner()  # Includes the immediate before-send owner predicate.
        assert calls == before
        with pytest.raises(BlockingIOError), existing_lock(lock):
            pytest.fail("revocation passed an in-flight mutation")
    assert calls


@pytest.mark.parametrize(
    "change", ["none", "request", "use", "controller", "image", "daemon", "helper", "stopped"]
)
def test_terminal_reader_requires_actual_original_controller_request_and_use(
    owner: NativeFixture,
    change: str,
) -> None:
    request = read_private(owner.consumer / "request.json")
    request["controller_image"] = "sha256:" + "9" * 64
    replace_private(owner.consumer / "request.json", request)
    binding = cast(dict[str, object], request["binding"])
    identity = {
        "id": "a" * 64,
        "image": request["controller_image"],
        "name": "/" + controller_name(owner.consumer.name),
        "daemon_sha256": digest(request["daemon"]),
    }
    write_private(owner.consumer / "controller-identity.json", identity)
    plan = {
        **owner.plan,
        "runtime_revision": binding["source_revision"],
        "helper_revision": binding["helper_revision"],
        "controller_identity": identity,
        "request_sha256": digest(request),
        "consumer_binding": digest(binding),
    }
    native = {
        "Id": identity["id"],
        "Image": identity["image"],
        "Name": identity["name"],
        "Config": {"Labels": {OWNER: "true", OWNER + ".source": binding["helper_revision"]}},
        "State": {"Running": True},
    }
    daemon = request["daemon"]
    if change == "request":
        plan["request_sha256"] = "f" * 64
    elif change == "use":
        (owner.lease.directory / ("use-" + owner.consumer.name + ".json")).unlink()
    elif change == "controller":
        native["Id"] = "b" * 64
    elif change == "image":
        native["Image"] = "sha256:" + "8" * 64
    elif change == "daemon":
        daemon = {"different": True}
    elif change == "helper":
        plan["helper_revision"] = "b" * 40
    elif change == "stopped":
        native["State"] = {"Running": False}
    docker = cast(ReadOnlyDocker, SimpleNamespace(info=lambda: daemon, owned=lambda _name: native))
    if change == "none":
        assert staged.terminal_provenance(plan, owner.root, docker)["consumer_binding"] == digest(
            binding
        )
    else:
        with pytest.raises((ValueError, OSError)):
            staged.terminal_provenance(plan, owner.root, docker)


@pytest.mark.parametrize("boundary", ["intent", "identity", "path", "inner-directory"])
def test_partial_external_exclusion_never_allows_reentering_archive_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[retirement.FrozenRetirement, Fixture, dict[str, object]],
    boundary: str,
) -> None:
    original, backend, approval = case
    run = fixture(tmp_path / "managed")
    selected = {**original.plan, "original_run": str(run), "producing_attempt": run.parents[1].name}
    approved = {**approval, "plan_sha256": digest(selected)}
    transaction = retirement.FrozenRetirement(selected, backend)
    registry = fence.registry(run)
    assert registry is not None
    original_record = fence.record
    stop_at = {"intent": 1, "identity": 2, "path": 3, "inner-directory": 0}[boundary]
    writes = []

    def interrupted(path: Path, value: dict[str, object]) -> None:
        original_record(path, value)
        writes.append(path)
        if len(writes) == stop_at:
            raise KeyboardInterrupt

    monkeypatch.setattr(fence, "record", interrupted)
    if boundary == "inner-directory":
        original_sync = sync

        def interrupt_after_directory(path: Path) -> None:
            original_sync(path)
            if path == run:
                assert transaction.root.is_dir()
                raise KeyboardInterrupt

        monkeypatch.setattr(retirement, "sync", interrupt_after_directory)
    # The synthetic provider transaction uses real external operation locks.
    with fence.ownership(run, exclusive=True), pytest.raises(KeyboardInterrupt):
        transaction.execute(approved)
    assert backend.store.deletes == []
    alias = fixture(tmp_path / "managed", str(read_private(run / "fixture.json")["run_id"]))
    for path in (run, alias):
        with pytest.raises(ValueError, match="permanently"):
            fence.require_unfenced(path)
    monkeypatch.setattr(fence, "record", original_record)
    stopped = "no replay" if boundary == "inner-directory" else "permanently"
    with fence.ownership(run, exclusive=True), pytest.raises(ValueError, match=stopped):
        transaction.execute(approved)
    # Explicit separately approved remote normalization has no archive client.
    with fence.ownership(run, exclusive=True):
        completed = fence.commit(
            run,
            plan_sha256=digest(selected),
            authorization_sha256=digest(approved),
            continuing=True,
        )
        fence.require_committed(run, completed)
    assert backend.store.deletes == [] and not (transaction.root / "delete-submitted.json").exists()
    # The original path remains excluded even with another fixture identity.
    replace_private(run / "fixture.json", {"run_id": str(uuid.uuid7())})
    with pytest.raises(ValueError, match="permanently"):
        fence.require_unfenced(run)


def test_torn_final_intent_cannot_be_normalized_from_a_projection(tmp_path: Path) -> None:
    run = fixture(tmp_path)
    with fence.ownership(run, exclusive=True):
        value = fence.commit(run, plan_sha256="a" * 64, authorization_sha256="b" * 64)
    registry = fence.registry(run)
    assert registry is not None
    intent = registry / ("identity-" + str(value["fixture_id"]).replace("-", "") + ".intent.json")
    intent.write_bytes(b"{")
    with fence.ownership(run, exclusive=True), pytest.raises(ValueError):
        fence.commit(run, plan_sha256="a" * 64, authorization_sha256="b" * 64, continuing=True)
