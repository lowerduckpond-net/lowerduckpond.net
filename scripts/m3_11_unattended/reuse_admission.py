"""Durable, nonreplayable retained-lease reservation under admission ownership."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import approval, inputs
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import (
    LifecycleError,
    Targets,
    digest,
    fingerprint,
    identity,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState, RunState, private_directory, replace_private

FORMAT = "lowerduckpond-m3-11-reuse-admission-v1"


class AdmissionUncertainError(RuntimeError):
    def __init__(self, attempt_id: str) -> None:
        self.attempt_id = identity(attempt_id)
        super().__init__("retained admission requires reconciliation")


def request_binding(request: object, approved: object, *, now: datetime) -> dict[str, object]:
    value = fields(
        request,
        {"format", "lease_id", "binding", "mode", "approval_sha256", "controller_image", "daemon"},
    )
    allowed = approval.validate(approved, mode=str(value["mode"]), now=now)
    prepared = fields(allowed["prepared"], approval.PREPARED)
    binding = fields(value["binding"], inputs.BINDING)
    identity(binding["managed_run_id"])
    if (
        value["format"] != "lowerduckpond-m3-11-unattended-request-v2"
        or value["lease_id"] != allowed["lease_id"]
        or allowed["lease_id"] is None
        or value["approval_sha256"] != digest(allowed)
        or value["controller_image"] != prepared["controller_image"]
        or value["daemon"] != prepared["daemon"]
        or binding["source_revision"] != prepared["source_revision"]
        or binding["helper_revision"] != prepared["helper_revision"]
        or binding["artifact_sha256"] != prepared["artifact_sha256"]
        or binding["qualification_inputs_sha256"] != allowed["qualification_inputs_sha256"]
    ):
        raise LifecycleError("reuse admission request differs from its approval")
    return value


def record_for(lease: LeaseState, attempt_id: str) -> dict[str, object]:
    attempt_id = identity(attempt_id)
    record = fields(
        read_private(lease.directory / ("admission-" + attempt_id + ".json")),
        {"format", "request", "approved", "manifest_sha256", "configuration_sha256", "admitted_at"},
    )
    fingerprint(record["configuration_sha256"])
    admitted = instant(record["admitted_at"])
    request = request_binding(record["request"], record["approved"], now=admitted)
    manifest = lease.manifest()
    binding = cast(dict[str, object], request["binding"])
    if (
        record["format"] != FORMAT
        or admitted > datetime.now(UTC)
        or record["manifest_sha256"] != manifest.sha256
        or request["lease_id"] != manifest.lease_id
        or binding["managed_run_id"] != attempt_id
        or binding["storage_target_sha256"] != manifest.targets.storage_digest
        or cast(dict[str, object], record["approved"])["policy_sha256"] != manifest.policy.sha256
    ):
        raise LifecycleError("reuse reservation differs from its retained lease")
    return record


def exact_use(lease: LeaseState, request: dict[str, object]) -> dict[str, object]:
    binding = cast(dict[str, object], request["binding"])
    attempt = identity(binding["managed_run_id"])
    record = record_for(lease, attempt)
    directory = lease.directory.parent.parent / "runs" / attempt
    if (
        record["request"] != request
        or read_private(directory / "request.json") != request
        or read_private(lease.directory / ("use-" + attempt + ".json"))
        != {"attempt_id": attempt, "binding_sha256": digest(binding), "kind": "attempt"}
        or (lease.directory / ("released-" + attempt + ".json")).exists()
    ):
        raise LifecycleError("reuse reservation lacks its exact unreleased use")
    return record


def require_prior_reservations_released(lease: LeaseState) -> None:
    for path in lease.directory.glob("admission-*.json"):
        attempt = identity(path.stem.removeprefix("admission-"))
        record = record_for(lease, attempt)
        request = cast(dict[str, object], record["request"])
        directory = lease.directory.parent.parent / "runs" / attempt
        if read_private(directory / "request.json") != request or not lease.released_use(
            attempt_id=attempt, binding_sha256=digest(request["binding"])
        ):
            raise LifecycleError("pending reuse reservation requires reconciliation")


def pending(lease: LeaseState, directory: Path) -> bool:
    """Missing launch is not cancellation; explicit cancellation/expiry still wins."""
    if not (lease.directory / ("admission-" + directory.name + ".json")).exists():
        return False
    exact_use(lease, read_private(directory / "request.json"))
    return (
        not any(
            (directory / name).exists()
            for name in (
                "attempt.json",
                "attempt-started.json",
                "journey-result.json",
                "cancel.json",
                "stop-attempt.json",
            )
        )
        and RunState(directory).status()["phase"] == "starting"
    )


def commit(  # noqa: PLR0913 - exact approved request and storage roots, no ambient inputs
    lease: LeaseState,
    config: LeaseConfiguration,
    request: dict[str, object],
    approved: object,
    *,
    configuration_root: Path,
    cleanup_root: Path,
    clock: Callable[[], datetime],
    guard: Callable[[], None],
) -> dict[str, object]:
    """Caller holds runtime/storage/cleanup locks. A partial commit is never replayed."""
    now = clock()
    request_binding(request, approved, now=now)
    allowed = approval.validate(approved, mode=str(request["mode"]), now=now)
    binding = cast(dict[str, object], request["binding"])
    attempt = identity(binding["managed_run_id"])
    manifest = lease.manifest()
    if (
        request["lease_id"] != manifest.lease_id
        or allowed["policy_sha256"] != manifest.policy.sha256
        or Targets.parse(allowed["targets"]) != manifest.targets
        or config.mode != "controller"
        or config.targets != manifest.targets
        or config.approved_policy_sha256 != manifest.policy.sha256
        or config.helper_revision != binding["helper_revision"]
        or binding["storage_target_sha256"] != manifest.targets.storage_digest
    ):
        raise LifecycleError("reuse configuration differs from retained authority")
    for root in (configuration_root, cleanup_root, lease.directory.parent.parent / "runs"):
        private_directory(root)
    guard()
    # Root validation and the final lease survey cannot borrow an earlier time.
    now = clock()
    approval.validate(approved, mode=str(request["mode"]), now=now)
    record = {
        "format": FORMAT,
        "request": request,
        "approved": approved,
        "manifest_sha256": manifest.sha256,
        "configuration_sha256": digest(config.document()),
        "admitted_at": stamp(now),
    }
    # First durable effect binds the known candidate even if any later write fails.
    write_private(lease.directory / ("admission-" + attempt + ".json"), record)
    directory = lease.directory.parent.parent / "runs" / attempt
    directory.mkdir(mode=0o700)
    descriptor = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    write_private(directory / "request.json", request)
    state = RunState(directory)
    state.update("starting", cleanup="pending")
    replace_private(configuration_root / "controller.json", config.document())
    replace_private(cleanup_root / "cleanup.json", config.document(cleanup_only=True))
    guard()
    if state.cancelled or state.stopped:
        raise LifecycleError("reuse admission was cancelled before reservation")
    lease.acquire_use(attempt_id=attempt, binding_sha256=digest(binding), kind="attempt")
    if state.cancelled or state.stopped or any(lease.directory.glob("close-*.json")):
        raise LifecycleError("reuse admission was cancelled at reservation")
    return {
        "attempt_id": attempt,
        "request_sha256": digest(request),
        "admission_sha256": digest(record),
        "binding_sha256": digest(binding),
    }
