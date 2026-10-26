"""Real retained files reject changed roles, use ownership, expiry and terminal state."""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import m3_11_frozen_context as native
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended.model import LifecycleError, instant, stamp
from scripts.m3_11_unattended.state import RunState, replace_private

from .test_m3_11_storage_admission import prepared


@pytest.fixture
def owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> native.NativeFixture:
    producer, lease, docker, config, _inventory = prepared(tmp_path, monkeypatch)
    manifest = lease.manifest()
    now = instant(manifest.created_at) + timedelta(minutes=1)
    monkeypatch.setattr(native, "datetime", SimpleNamespace(now=lambda _zone: now))
    consumer = producer.parent / str(uuid.uuid7())
    consumer.mkdir(mode=0o700)
    request = read_private(producer / "request.json")
    old_binding = request["binding"]
    assert isinstance(old_binding, dict)
    current_binding = {**old_binding, "managed_run_id": consumer.name}
    replace_private(producer / "request.json", {**request, "mode": "qualification"})
    write_private(
        consumer / "request.json", {**request, "binding": current_binding, "mode": "qualification"}
    )
    state = RunState(consumer)
    state.begin(current_binding)
    state.finish_journey("failed", 2)
    state.update("finished", cleanup="pending")
    for path, binding in ((producer, old_binding), (consumer, current_binding)):
        replace_private(
            path / "journey-result.json",
            {**read_private(path / "journey-result.json"), "observed_at": stamp(now)},
        )
        write_private(
            path / "attempt-started.json",
            {"binding_sha256": digest(binding), "manifest_sha256": manifest.sha256},
        )
    write_private(
        consumer / "host-drained.json", {"binding_sha256": digest(current_binding), "drained": True}
    )
    with lease.use_lock():
        lease.acquire_use(
            attempt_id=consumer.name, binding_sha256=digest(current_binding), kind="attempt"
        )
    instance = native.NativeFixture(
        configuration=config,
        fixture={
            "consumer_binding": digest(current_binding),
            "producer_binding": digest(old_binding),
        },
        evidence_root=producer.parent.parent,
        revalidate_copies_and_cleanup=lambda: "e" * 64,
        docker=docker,  # type: ignore[arg-type]  # synthetic read-only daemon
        require_cleanup_current=lambda: None,
    )
    instance.held = True
    instance.manifest, instance.lease = manifest, lease
    instance.producer, instance.consumer = producer, consumer
    instance.plan = {
        "manifest_sha256": manifest.sha256,
        "lease_id": manifest.lease_id,
        "consumer_attempt": consumer.name,
    }
    instance.deliveries = {intent.role: lease.credential(intent) for intent in manifest.intents}
    instance.uses = sorted(lease.directory.glob("use-*.json"))
    instance.uses_digest = digest([read_private(path) for path in instance.uses])
    instance.owner()
    return instance


@pytest.mark.parametrize("role", sorted(native.RETAINED_ROLES))
def test_every_private_delivery_is_required(owner: native.NativeFixture, role: str) -> None:
    (owner.lease.directory / ("credential-" + role + ".json")).unlink()
    with pytest.raises((ValueError, OSError)):
        owner.owner()


@pytest.mark.parametrize(
    "kind",
    [
        "cancel",
        "stop",
        "unfinished",
        "changed-binding",
        "drain",
        "started",
        "closing",
        "released",
        "extra-use",
        "uses-changed",
        "expiry",
        "proof",
        "unlocked",
    ],
)
def test_native_owner_rejects_drift_before_any_request(
    owner: native.NativeFixture, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    if kind == "cancel":
        RunState(owner.consumer).cancel()
    elif kind == "stop":
        RunState(owner.consumer).stop_attempt()
    elif kind == "unfinished":
        RunState(owner.consumer).update("running", cleanup="pending")
    elif kind == "changed-binding":
        replace_private(
            owner.consumer / "request.json",
            {**read_private(owner.consumer / "request.json"), "binding": {"different": True}},
        )
    elif kind in {"drain", "started"}:
        (
            owner.consumer / ("host-drained.json" if kind == "drain" else "attempt-started.json")
        ).unlink()
    elif kind == "closing":
        write_private(owner.lease.directory / "close-cancelled.json", {})
    elif kind == "released":
        write_private(owner.lease.directory / ("released-" + owner.consumer.name + ".json"), {})
    elif kind == "extra-use":
        write_private(owner.lease.directory / ("use-" + str(uuid.uuid7()) + ".json"), {})
    elif kind == "uses-changed":
        replace_private(owner.uses[-1], {"changed": True})
    elif kind == "expiry":
        deadline = owner.manifest.policy.deadline(instant(owner.manifest.created_at))
        monkeypatch.setattr(native, "datetime", SimpleNamespace(now=lambda _zone: deadline))
    elif kind == "proof":

        def stale() -> None:
            raise ValueError("proof is stale")

        owner.cleanup_current = stale
    elif kind == "unlocked":
        owner.held = False
    with pytest.raises((LifecycleError, ValueError, OSError)):
        owner.owner()


def test_native_owner_preserves_all_original_bytes(owner: native.NativeFixture) -> None:
    before = {path: path.read_bytes() for path in owner.root.rglob("*") if path.is_file()}
    owner.owner()
    assert before == {path: path.read_bytes() for path in owner.root.rglob("*") if path.is_file()}
