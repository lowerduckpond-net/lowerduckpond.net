"""Old consent survives waiting; execution clocks, withdrawal and one-use do not."""

from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import approval
from scripts.m3_11_unattended import standing_authority as standing
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import LifecycleError, digest, stamp
from scripts.m3_11_unattended.state import LeaseState, replace_private

from .standing_authority_support import execution
from .test_m3_11_lease_inventory import NOW, manifest
from .test_m3_11_reuse_admission import request_for
from .test_m3_11_storage_admission import prepared


def case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    _old, lease, _daemon, config, _inventory = prepared(tmp_path, monkeypatch)
    _request, original = request_for(lease, config)
    return execution(original, NOW + timedelta(minutes=1))


def nested(value: dict[str, object], name: str) -> dict[str, object]:
    return cast(dict[str, object], value[name])


def test_old_original_consent_and_unknown_timestamp_are_not_freshened(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = case(tmp_path, monkeypatch)
    before = deepcopy(value)
    now = NOW + timedelta(minutes=2)
    assert approval.validate(value, mode="qualification", now=now) == before
    consent = nested(nested(value, "authority"), "consent")
    consent["approved_at"] = None
    nested(value, "assessment")["authority_sha256"] = digest(value["authority"])
    assert approval.validate(value, mode="qualification", now=now) == value
    assert consent["approved_at"] is None
    assert consent["approval_reference"] == "SYNTHETIC original standing consent"


@pytest.mark.parametrize(
    "fault",
    [
        "expired",
        "too-long",
        "future-ready",
        "withdrawn",
        "stale-assessment",
        "scope-hash",
        "authority-hash",
        "scope-lease",
        "scope-policy",
        "scope-target",
        "scope-mode",
        "issuance",
        "future-consent",
        "owner-deadline",
        "empty-reference",
        "missing-provenance",
        "unlearned",
    ],
)
def test_readiness_rejects_expiry_withdrawal_and_scope_expansion(  # noqa: PLR0912 - independent rejection cases
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    value = case(tmp_path, monkeypatch)
    now = NOW + timedelta(minutes=2)
    ready, assessed = nested(value, "readiness"), nested(value, "assessment")
    consent = nested(nested(value, "authority"), "consent")
    if fault == "expired":
        ready["expires_at"] = stamp(now)
    elif fault == "too-long":
        ready["expires_at"] = stamp(now + timedelta(days=2))
    elif fault == "future-ready":
        ready["checked_at"] = stamp(now + timedelta(seconds=1))
    elif fault == "withdrawn":
        assessed["status"] = "withdrawn"
    elif fault == "stale-assessment":
        assessed["checked_at"] = stamp(now - timedelta(days=1))
    elif fault in {"scope-hash", "authority-hash"}:
        assessed[fault.replace("-hash", "_sha256")] = "0" * 64
    elif fault == "scope-lease":
        value["lease_id"] = manifest().lease_id
    elif fault == "scope-policy":
        value["policy_sha256"] = "0" * 64
    elif fault == "scope-target":
        value["targets"] = {**nested(value, "targets"), "archive_bucket": "changed"}
    elif fault == "scope-mode":
        value["modes"] = ["rehearsal"]
    elif fault == "issuance":
        value["lease_id"] = None
    elif fault == "owner-deadline":
        nested(nested(value, "authority"), "scope")["not_after"] = stamp(now)
    elif fault == "future-consent":
        consent["approved_at"] = stamp(now + timedelta(seconds=1))
    elif fault == "empty-reference":
        consent["approval_reference"] = ""
    elif fault == "missing-provenance":
        consent["evidence_sha256"] = ""
    else:
        ready["learning_reference"] = ""
    with pytest.raises((LifecycleError, ValueError)):
        approval.validate(value, mode="qualification", now=now)


def test_current_assessment_is_read_again_and_never_replaced_by_embedded_active_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = case(tmp_path, monkeypatch)
    path = tmp_path / "current-authority.json"
    value["assessment_path"] = str(path)
    checked = nested(value, "assessment")
    write_private(path, checked)
    now = NOW + timedelta(minutes=2)
    standing.require_current(value, path, now=now)
    archived = tmp_path / "historical-active.json"
    write_private(archived, checked)
    with pytest.raises(LifecycleError, match="canonical private"):
        standing.require_current(value, archived, now=now)
    replace_private(path, {**checked, "status": "withdrawn"})
    with pytest.raises(LifecycleError, match="withdrawn"):
        standing.require_current(value, path, now=now)
    replace_private(path, {**checked, "check_reference": "SYNTHETIC scope reconsidered"})
    with pytest.raises(LifecycleError, match="changed"):
        standing.require_current(value, path, now=now)
    with pytest.raises(LifecycleError, match="canonical private"):
        standing.require_current(value, None, now=now)


@pytest.mark.parametrize("changed_provenance", [False, True])
def test_released_admission_permanently_consumes_action_even_after_provenance_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed_provenance: bool,
) -> None:
    from scripts.m3_11_unattended import reuse_admission  # noqa: PLC0415

    from . import test_m3_11_reuse_admission as support  # noqa: PLC0415

    moment = NOW + timedelta(minutes=1)
    captured: list[tuple[LeaseConfiguration, dict[str, object]]] = []

    def standing_request(
        lease: LeaseState,
        config: LeaseConfiguration,
    ) -> tuple[dict[str, object], dict[str, object]]:
        request, old = request_for(lease, config)
        allowed = execution(old, moment)
        request["approval_sha256"] = digest(allowed)
        captured.append((config, allowed))
        return request, allowed

    monkeypatch.setattr(support, "request_for", standing_request)
    lease, request, observe, _allocate, _daemon = support.admission_case(tmp_path, monkeypatch)
    observe()
    config, allowed = captured[0]
    attempt = str(nested(request, "binding")["managed_run_id"])
    lease.release_use(
        attempt_id=attempt,
        quiescence={
            "host_commands_drained": True,
            "complete": True,
            "containers": [
                {
                    "id": "f" * 64,
                    "name": "synthetic",
                    "image": "e" * 64,
                    "owner": attempt,
                    "running": False,
                    "restart_policy": "no",
                }
            ],
        },
    )
    assert lease.released_use(attempt_id=attempt, binding_sha256=digest(request["binding"]))
    original = reuse_admission.record_for(lease, attempt)
    refreshed = deepcopy(allowed)
    if changed_provenance:
        nested(nested(refreshed, "authority"), "consent")["approval_reference"] = (
            "SYNTHETIC amended reference"
        )
        nested(refreshed, "assessment")["authority_sha256"] = digest(refreshed["authority"])
    nested(refreshed, "readiness")["checked_at"] = stamp(moment + timedelta(minutes=1))
    second, _unused = request_for(lease, config)
    second["approval_sha256"] = digest(refreshed)
    with lease.use_lock(), pytest.raises(LifecycleError, match="already consumed"):
        reuse_admission.commit(
            lease,
            config,
            second,
            refreshed,
            configuration_root=tmp_path / "configuration",
            cleanup_root=tmp_path / "cleanup",
            clock=lambda: moment + timedelta(minutes=1),
            guard=lambda: None,
        )
    # Expired current readiness does not invalidate historical admission reads.
    assert reuse_admission.record_for(lease, attempt) == original
    assert len(list(lease.directory.glob("admission-*.json"))) == 1
    assert not (
        lease.directory.parent.parent / "runs" / str(nested(second, "binding")["managed_run_id"])
    ).exists()


def test_historical_action_scan_cannot_borrow_earlier_clock_before_durable_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uuid  # noqa: PLC0415

    from scripts.m3_11_unattended import reuse_admission  # noqa: PLC0415

    old, lease, _daemon, config, _inventory = prepared(tmp_path, monkeypatch)
    root = old.parent.parent
    root.chmod(0o700)
    (root / "runs").chmod(0o700)
    for name in ("configuration", "cleanup"):
        (tmp_path / name).mkdir(mode=0o700)
    request, legacy = request_for(lease, config)
    moment = [NOW + timedelta(minutes=1)]
    allowed = execution(legacy, moment[0])
    request["approval_sha256"] = digest(allowed)
    previous = str(uuid.uuid7())
    retained = lease.directory / ("admission-" + previous + ".json")
    write_private(retained, {"synthetic_prior_record": True})

    def slow_prior(_lease: LeaseState, attempt: str) -> dict[str, object]:
        assert attempt == previous
        moment[0] += timedelta(hours=2)
        return {"approved": {"format": approval.FORMAT}}

    monkeypatch.setattr(reuse_admission, "record_for", slow_prior)
    attempt = str(nested(request, "binding")["managed_run_id"])
    with lease.use_lock(), pytest.raises(LifecycleError, match="expired"):
        reuse_admission.commit(
            lease,
            config,
            request,
            allowed,
            configuration_root=tmp_path / "configuration",
            cleanup_root=tmp_path / "cleanup",
            clock=lambda: moment[0],
            guard=lambda: None,
        )
    assert list(lease.directory.glob("admission-*.json")) == [retained]
    assert not (root / "runs" / attempt).exists()
