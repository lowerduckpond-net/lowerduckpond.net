"""Offline admission races, crash boundaries and original retained-role semantics."""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import os
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast, override

import pytest

from scripts import production_qualification_inputs
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import (
    approval,
    readiness_credentials,
    reuse_admission,
    storage_admission,
    watchdog,
)
from scripts.m3_11_unattended import connect_activate as activation
from scripts.m3_11_unattended import state as state_module
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_api import Response as ConnectResponse
from scripts.m3_11_unattended.http import Api, Response
from scripts.m3_11_unattended.inventory import LocalInventory, fact
from scripts.m3_11_unattended.lifecycle import validate_reused_credentials
from scripts.m3_11_unattended.model import (
    ROLES,
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    digest,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState, RunState, replace_private

from .standing_authority_support import execution
from .test_m3_11_lease_inventory import NOW, manifest
from .test_m3_11_lease_runtime import RuntimeDocker
from .test_m3_11_storage_admission import prepared
from .test_m3_11_unattended_lifecycle import ProviderDouble


class RetainedProvider(ProviderDouble):
    def __init__(self) -> None:
        super().__init__()
        self.verified: list[str] = []
        self.reject: str | None = None

    @override
    def verify(self, intent: Intent, credential: Credential, *, now: datetime) -> None:
        self.verified.append(intent.role)
        if intent.role == self.reject or credential.secret != "synthetic-secret-" + intent.role:
            raise LifecycleError("synthetic live authentication rejected")


def retained(tmp_path: Path) -> tuple[LeaseState, RetainedProvider, dict[str, dict[str, object]]]:
    selected = manifest()
    lease = LeaseState(tmp_path / "lease")
    lease.initialize(selected)
    lease.claim_issuer(writer_sha256="a" * 64)
    provider = RetainedProvider()
    rows = {"manifest": fact(selected, "manifest", selected.document())}
    for intent in selected.intents:
        identifier = "synthetic-" + intent.role
        lease.remember(intent, identifier, "synthetic-secret-" + intent.role)
        provider.items[identifier] = {
            "id": identifier,
            "name": intent.name,
            "scope": intent.scope,
            "status": "active",
            "created_at": intent.requested_at,
        }
        rows["created:" + intent.role] = fact(
            selected,
            "created:" + intent.role,
            {
                "intent_sha256": intent.sha256,
                "credential_id": identifier,
            },
        )
    stopped = lease.finish_issuer(writer_sha256="a" * 64, stopped_at=selected.created_at)
    rows["issuer-stopped"] = fact(selected, "issuer-stopped", stopped)
    return lease, provider, rows


@pytest.mark.parametrize("role", sorted(ROLES))
@pytest.mark.parametrize(
    "fault", ["missing", "fact", "absent", "scope", "owner", "revoked", "secret"]
)
def test_every_retained_role_fails_before_admission(
    tmp_path: Path,
    role: str,
    fault: str,
) -> None:
    lease, provider, rows = retained(tmp_path)
    identifier = "synthetic-" + role
    if fault == "missing":
        (lease.directory / ("credential-" + role + ".json")).unlink()
    elif fault == "fact":
        rows["created:" + role]["payload"] = {}
    elif fault == "absent":
        del provider.items[identifier]
    elif fault in {"scope", "owner"}:
        provider.items[identifier]["scope" if fault == "scope" else "name"] = "changed"
    elif fault == "revoked":
        provider.reject = role
    else:
        path = lease.directory / ("credential-" + role + ".json")
        value = read_private(path)
        value["secret"] = "changed"  # noqa: S105 - synthetic invalid credential
        replace_private(path, value)
    with pytest.raises(LifecycleError):
        validate_reused_credentials(
            lease.manifest(),
            lease,
            dict.fromkeys(
                cast(tuple[ProviderKind, ...], ("spaces", "cloudflare-account", "cloudflare-user")),
                provider,
            ),
            rows,
            clock=lambda: NOW + timedelta(minutes=1),
        )
    assert provider.creates == 0 and provider.deletes == []
    assert not list(lease.directory.glob("admission-*.json"))


def test_full_role_validation_reads_final_close_and_never_writes_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease, provider, rows = retained(tmp_path)
    selected = lease.manifest()
    bootstrap = SimpleNamespace(
        generation=selected.cleanup,
        reader=object,
        providers=lambda **_kwargs: {intent.provider: provider for intent in selected.intents},
    )
    config = cast(
        LeaseConfiguration,
        SimpleNamespace(
            active_generation="synthetic",
            generations={"synthetic": {"cleanup": bootstrap}},
            journal_vault="synthetic",
            targets=selected.targets,
        ),
    )
    monkeypatch.setattr(
        readiness_credentials,
        "ConnectInventoryReader",
        lambda *_args: SimpleNamespace(records=lambda: list(rows.values())),
    )
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    final = readiness_credentials.validate_all_roles(
        config,
        selected,
        lease,
        clock=lambda: NOW + timedelta(minutes=1),
        guard=lambda: None,
    )
    assert set(provider.verified) == ROLES
    assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    rows["close-cancelled"] = {**rows["manifest"], "slot": "close-cancelled"}
    with pytest.raises(LifecycleError, match="closing"):
        final()


def request_for(
    lease: LeaseState, config: LeaseConfiguration
) -> tuple[dict[str, object], dict[str, object]]:
    now = instant(lease.manifest().created_at) + timedelta(minutes=1)
    prepared_inputs = {
        "source_revision": config.helper_revision,
        "helper_revision": config.helper_revision,
        "artifact_sha256": "c" * 64,
        "controller_image": "sha256:" + "b" * 64,
        "daemon": dict.fromkeys(
            ("ID", "Name", "DockerRootDir", "ServerVersion"), "synthetic-daemon"
        ),
    }
    allowed: dict[str, object] = {
        "format": approval.FORMAT,
        "prepared": prepared_inputs,
        "targets": dataclasses.asdict(config.targets),
        "qualification_inputs_sha256": "d" * 64,
        "modes": ["qualification"],
        "approved_at": stamp(now - timedelta(seconds=1)),
        "expires_at": stamp(now + timedelta(hours=1)),
        "policy_sha256": config.approved_policy_sha256,
        "lease_id": lease.manifest().lease_id,
        "approval_reference": "SYNTHETIC no live authority",
    }
    request: dict[str, object] = {
        "format": "lowerduckpond-m3-11-unattended-request-v2",
        "lease_id": allowed["lease_id"],
        "binding": {
            "managed_run_id": str(uuid.uuid7()),
            "source_revision": config.helper_revision,
            "helper_revision": config.helper_revision,
            "artifact_sha256": "c" * 64,
            "qualification_inputs_sha256": "d" * 64,
            "storage_target_sha256": config.targets.storage_digest,
        },
        "mode": "qualification",
        "approval_sha256": digest(allowed),
        "controller_image": prepared_inputs["controller_image"],
        "daemon": prepared_inputs["daemon"],
    }
    return request, allowed


type Allocator = Callable[[LeaseState, Callable[[], None]], dict[str, object]]
type Observer = Callable[..., dict[str, object]]
type Writer = Callable[[Path, dict[str, object]], object]


def admission_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    clock: Callable[[], datetime] | None = None,
    *,
    standing: bool = False,
) -> tuple[LeaseState, dict[str, object], Observer, Allocator, RuntimeDocker]:
    old, lease, daemon, config, _inventory = prepared(tmp_path, monkeypatch)
    root = old.parent.parent
    for path in (root, root / "runs"):
        path.chmod(0o700)
    for name in ("configuration", "cleanup"):
        (tmp_path / name).mkdir(mode=0o700)
    request, allowed = request_for(lease, config)
    now = instant(lease.manifest().created_at) + timedelta(minutes=1)
    selected_clock = clock or (lambda: now)
    if standing:
        allowed = execution(allowed, selected_clock())
        request["approval_sha256"] = digest(allowed)

    def allocate(selected: LeaseState, guard: Callable[[], None]) -> dict[str, object]:
        return reuse_admission.commit(
            selected,
            config,
            request,
            allowed,
            configuration_root=tmp_path / "configuration",
            cleanup_root=tmp_path / "cleanup",
            clock=selected_clock,
            guard=guard,
        )

    def observe(callback: Allocator = allocate) -> dict[str, object]:
        return storage_admission.observe(
            config,
            lease_id=lease.manifest().lease_id,
            manifest_sha256=lease.manifest().sha256,
            evidence_root=root,
            docker=daemon,
            clock=selected_clock,
            allocate=callback,
        )

    return lease, request, observe, allocate, daemon


def test_ownership_is_held_through_allocation_and_pending_blocks_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease, request, observe, allocate, daemon = admission_case(tmp_path, monkeypatch)
    root = lease.directory.parent.parent
    checks = []

    def locked(selected: LeaseState, guard: Callable[[], None]) -> dict[str, object]:
        for path in (
            selected.directory / "runtime-use.lock",
            root / ".credential-cleanup.lock",
            next((tmp_path / "storage-leases").glob("*.lock")),
        ):
            fd = os.open(path, os.O_RDONLY)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                checks.append(path)
            finally:
                os.close(fd)
        return allocate(selected, guard)

    result = observe(locked)
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]
    directory = root / "runs" / attempt
    assert len(checks) == 3  # noqa: PLR2004 - the three ownership locks
    assert cast(dict[str, object], result["admitted"])["attempt_id"] == attempt
    assert reuse_admission.exact_use(lease, request)["request"] == request
    assert reuse_admission.pending(lease, directory)
    watchdog.require_released_consumers(lease, daemon, admitted_request=request)
    with pytest.raises(LifecycleError, match="pending reuse"):
        observe()
    assert not (directory / "attempt.json").exists()
    RunState(directory).begin(cast(dict[str, object], request["binding"]))
    assert not reuse_admission.pending(lease, directory)


@pytest.mark.parametrize(
    "boundary", ["admission", "request", "status", "controller", "cleanup", "use"]
)
@pytest.mark.parametrize("standing", [False, True])
def test_interrupted_commit_preserves_exact_identity_and_cannot_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    standing: bool,
) -> None:
    lease, request, observe, _allocate, _daemon = admission_case(
        tmp_path, monkeypatch, standing=standing
    )
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]

    def injected(original: Writer) -> Writer:
        def write(path: Path, value: dict[str, object]) -> None:
            original(path, value)
            if path.name == boundary + ".json" or path.name == boundary + "-" + attempt + ".json":
                raise OSError("synthetic interrupted local write")

        return write

    monkeypatch.setattr(reuse_admission, "write_private", injected(write_private))
    monkeypatch.setattr(reuse_admission, "replace_private", injected(replace_private))
    monkeypatch.setattr(state_module, "write_private", injected(write_private))
    monkeypatch.setattr(state_module, "replace_private", injected(state_module.replace_private))
    with pytest.raises(OSError, match="interrupted"):
        observe()
    assert read_private(lease.directory / ("admission-" + attempt + ".json"))["request"] == request
    with pytest.raises((LifecycleError, OSError)):
        reuse_admission.require_prior_reservations_released(lease)
    assert len(list(lease.directory.glob("admission-*.json"))) == 1


@pytest.mark.parametrize("cause", ["cancel", "close", "expired"])
def test_cancel_and_expiry_still_win_during_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cause: str,
) -> None:
    moment = [NOW + timedelta(minutes=1)]
    lease, request, observe, allocate, _daemon = admission_case(
        tmp_path, monkeypatch, clock=lambda: moment[0]
    )
    original = replace_private
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]

    def during(path: Path, value: dict[str, object]) -> None:
        original(path, value)
        if path.name == "cleanup.json":
            if cause == "cancel":
                write_private(lease.directory.parent.parent / "runs" / attempt / "cancel.json", {})
            elif cause == "close":
                write_private(lease.directory / "close-cancelled.json", {})
            else:
                moment[0] = NOW + timedelta(days=8)

    monkeypatch.setattr(reuse_admission, "replace_private", during)
    with pytest.raises(LifecycleError):
        observe(allocate)
    assert not (lease.directory / ("use-" + attempt + ".json")).exists()


def test_parent_directory_sync_failure_remains_a_nonreplayable_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease, request, observe, _allocate, _daemon = admission_case(tmp_path, monkeypatch)
    runs = lease.directory.parent.parent / "runs"
    parent_inode = runs.stat().st_ino
    original = os.fsync

    def sync(fd: int) -> None:
        if os.fstat(fd).st_ino == parent_inode:
            raise OSError("synthetic parent directory sync failure")
        original(fd)

    monkeypatch.setattr(os, "fsync", sync)
    with pytest.raises(OSError, match="parent directory"):
        observe()
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]
    assert read_private(lease.directory / ("admission-" + attempt + ".json"))["request"] == request
    assert not (runs / attempt / "request.json").exists()
    with pytest.raises((LifecycleError, OSError)):
        reuse_admission.require_prior_reservations_released(lease)


@pytest.mark.parametrize("trigger", ["pending", "cancel", "expiry"])
@pytest.mark.parametrize("standing", [False, True])
def test_watchdog_preserves_pending_reservation_but_honors_cancel_and_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trigger: str,
    standing: bool,
) -> None:
    lease, request, observe, _allocate, daemon = admission_case(
        tmp_path, monkeypatch, standing=standing
    )
    observe()
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]
    directory = lease.directory.parent.parent / "runs" / attempt
    now = instant(lease.manifest().created_at) + timedelta(minutes=1)
    if trigger == "cancel":
        RunState(directory).cancel()
    elif trigger == "expiry":
        now = lease.manifest().policy.deadline(instant(lease.manifest().created_at))
    monkeypatch.setattr(watchdog, "datetime", SimpleNamespace(now=lambda _zone: now))
    inspected = []

    def owned(name: str) -> dict[str, object]:
        inspected.append(name)
        return {"State": {"Running": False}}

    monkeypatch.setattr(daemon, "owned", owned)
    inventory = LocalInventory(tmp_path / "inventory")
    assert watchdog.prepare_lease_cleanup(directory.parent, daemon, inventory)
    if trigger == "pending":
        assert inspected == [] and not RunState(directory).cancelled
        assert not list(lease.directory.glob("close-*.json"))
    else:
        assert inspected and RunState(directory).cancelled
        assert (lease.directory / "close-cancel.json").exists()
        assert any(row["slot"] == "close-cancel" for row in inventory.records())


def test_only_exact_own_reservation_is_excluded_from_prior_consumer_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease, request, observe, _allocate, daemon = admission_case(tmp_path, monkeypatch)
    observe()
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]
    path = lease.directory / ("use-" + attempt + ".json")
    write_private(lease.directory / ("use-" + str(uuid.uuid7()) + ".json"), read_private(path))
    with pytest.raises(LifecycleError, match="filename"):
        watchdog.require_released_consumers(lease, daemon, admitted_request=request)


def test_admission_control_transport_only_reads_and_never_renews_its_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def provider(*_args: object) -> Response:
        calls.append("provider")
        return Response(200, {})

    def journal(*_args: object) -> ConnectResponse:
        calls.append("journal")
        return ConnectResponse(200, {})

    monkeypatch.setattr(Api, "_request", provider)
    monkeypatch.setattr(Connect, "request", journal)
    monkeypatch.setattr(storage_admission, "_deadline", time.monotonic() + 3600)
    api, connect = object.__new__(Api), object.__new__(Connect)
    with readiness_credentials.read_only_requests(lambda: None) as counts:
        with pytest.raises(LifecycleError, match="mutation"):
            api._request("DELETE", "/synthetic", None)
        with pytest.raises(LifecycleError, match="mutation"):
            connect.request("POST", "/synthetic", {})
        api._request("GET", "/synthetic", None)
        connect.request("GET", "/synthetic")
        # Native journals can legitimately exceed the proposed arbitrary 512 cap.
        for _index in range(513):
            connect.request("GET", "/synthetic")
        assert counts == {"control_read_count": 515, "credential_probe_read_count": 0}
    before_expiry = list(calls)
    monkeypatch.setattr(storage_admission, "_deadline", time.monotonic() + 80)
    with (
        readiness_credentials.read_only_requests(lambda: None),
        pytest.raises(LifecycleError, match="complete read"),
    ):
        api._request("GET", "/synthetic", None)
    assert calls == before_expiry


@pytest.mark.parametrize("fault", ["policy", "targets", "storage-binding"])
def test_native_envelope_rejects_mismatched_authority_before_credential_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    old, lease, daemon, config, inventory = prepared(tmp_path, monkeypatch)
    request, allowed = request_for(lease, config)
    root = old.parent.parent
    artifact = root / "prepared" / config.helper_revision / "static-host-agent.tar"
    artifact.parent.mkdir(parents=True, mode=0o700)
    artifact.write_bytes(b"synthetic-artifact")
    prepared_inputs = cast(dict[str, object], allowed["prepared"])
    prepared_inputs["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    binding = cast(dict[str, object], request["binding"])
    binding["artifact_sha256"] = prepared_inputs["artifact_sha256"]
    if fault == "policy":
        allowed["policy_sha256"] = "f" * 64
    elif fault == "targets":
        cast(dict[str, object], allowed["targets"])["archive_bucket"] = "other-test-archive"
    else:
        binding["storage_target_sha256"] = "f" * 64
    request["approval_sha256"] = digest(allowed)
    monkeypatch.setattr(production_qualification_inputs, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(storage_admission, "ReadOnlyDocker", lambda: daemon)
    monkeypatch.setattr(storage_admission, "_deadline", None)
    monkeypatch.setattr(
        activation, "datetime", SimpleNamespace(now=lambda _zone: NOW + timedelta(minutes=1))
    )
    monkeypatch.setattr(
        readiness_credentials,
        "validate_all_roles",
        lambda *_args, **_kwargs: pytest.fail(
            "authority must be checked before credentials or provider calls"
        ),
    )
    envelope = {
        "format": activation.UTILITY_FORMAT,
        "operation": "reuse-admission",
        "prepared": prepared_inputs,
        "payload": {
            "configuration": config.document(),
            "lease_id": lease.manifest().lease_id,
            "manifest_sha256": lease.manifest().sha256,
            "request": request,
            "approved": allowed,
        },
    }
    with pytest.raises(LifecycleError, match="prepared envelope"):
        activation.daemon_utility(envelope, evidence_root=root)
    assert inventory.calls == [] and daemon.mutations == []
    assert not list(lease.directory.glob("admission-*.json"))


def test_final_guard_cannot_cross_approval_expiry_before_allocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    moment = [NOW + timedelta(minutes=1)]
    lease, _request, observe, allocate, _daemon = admission_case(
        tmp_path,
        monkeypatch,
        clock=lambda: moment[0],
    )
    before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    def delayed(selected: LeaseState, guard: Callable[[], None]) -> dict[str, object]:
        def cross_expiry() -> None:
            guard()
            moment[0] += timedelta(hours=2)

        return allocate(selected, cross_expiry)

    with pytest.raises(LifecycleError, match="expired"):
        observe(delayed)
    assert not list(lease.directory.glob("admission-*.json"))
    assert before == {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}


@pytest.mark.parametrize(
    "boundary", ["before", "admission", "request", "status", "controller", "cleanup", "use"]
)
@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
def test_launcher_interrupt_reports_same_candidate_at_real_durable_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    interruption: type[BaseException],
) -> None:
    lease, request, observe, _allocate, _daemon = admission_case(tmp_path, monkeypatch)
    attempt = cast(dict[str, str], request["binding"])["managed_run_id"]
    candidate = reuse_admission.AdmissionCandidate(attempt)

    def injected(original: Writer) -> Writer:
        def write(path: Path, value: dict[str, object]) -> None:
            if boundary == "before":
                raise interruption("synthetic interruption before first commit")
            original(path, value)
            if path.name in {boundary + ".json", boundary + "-" + attempt + ".json"}:
                raise interruption("synthetic interruption after durable commit")

        return write

    monkeypatch.setattr(reuse_admission, "write_private", injected(write_private))
    monkeypatch.setattr(reuse_admission, "replace_private", injected(replace_private))
    monkeypatch.setattr(state_module, "write_private", injected(write_private))
    monkeypatch.setattr(state_module, "replace_private", injected(state_module.replace_private))
    with pytest.raises(reuse_admission.AdmissionUncertainError) as rejected, candidate.reporting():
        observe()
    assert rejected.value.attempt_id == attempt
    assert isinstance(rejected.value.__cause__, interruption)
    reservations = list(lease.directory.glob("admission-*.json"))
    if boundary == "before":
        assert not reservations
    else:
        assert len(reservations) == 1
        assert read_private(reservations[0])["request"] == request
        with pytest.raises((LifecycleError, OSError)):
            reuse_admission.require_prior_reservations_released(lease)
