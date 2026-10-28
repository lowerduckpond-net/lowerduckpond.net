"""Manual active custody proof never impersonates scheduled terminal evidence."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from scripts import m3_11_custody_github as custody
from scripts import m3_11_frozen_github as terminal
from scripts.m3_11_unattended.model import LeaseManifest

from .test_m3_11_frozen_github import api_responses, fixture

NOW = datetime(2026, 10, 10, 0, 6, tzinfo=UTC)


def current() -> tuple[LeaseManifest, dict[str, Any], dict[str, Any]]:
    manifest, contract, original = fixture()
    value = json.loads(json.dumps(original).replace("2026-10-18", "2026-10-10"))
    for row in (value["run"], value["job"]):
        row["head_sha"] = manifest.helper_revision
    contract["native_workflow_revision"] = manifest.helper_revision
    value["run"].update(event="workflow_dispatch", display_title="M3.11 confirm")
    active = {
        "lease_id": manifest.lease_id,
        "manifest_sha256": manifest.sha256,
        "status": "active",
        "overdue": False,
        "results": [
            {
                "intent_sha256": i.sha256,
                "status": "not-due",
                "negative_authentication": "not-tested",
            }
            for i in manifest.intents
        ],
    }
    old = {
        **contract["closed_leases"][0],
        "lease_id": "01a14e4f-7025-7618-88eb-d665bbc8d0ae",
        "manifest_sha256": "9" * 64,
    }
    contract["closed_leases"] = [old]
    value["documents"]["cleanup"]["leases"] = [old, active]
    return manifest, contract, value


def native_responses(value: dict[str, Any]) -> dict[str, bytes]:
    return {
        key: raw if key.endswith("/zip") else raw.replace(b"2026-10-18", b"2026-10-10")
        for key, raw in api_responses(value).items()
    }


def test_manual_capture_authenticates_six_gets_and_exact_active_manifest(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    manifest, contract, value = current()
    responses = native_responses(value)
    calls = []

    def get(path: str) -> bytes:
        calls.append(path)
        return responses[path]

    result = custody.capture(get, 456, tmp_path / "native", contract, manifest, clock=lambda: NOW)
    assert result["format"] == custody.FORMAT
    assert result["status"] == custody.STATUS
    assert result["event"] == "workflow_dispatch"
    assert len(calls) == len(responses) == 6  # noqa: PLR2004 - four metadata and two ZIP GETs
    assert custody.verify(tmp_path / "native", contract, manifest, now=NOW) == result
    with pytest.raises(ValueError, match="scheduled run"):
        terminal.verify(tmp_path / "native", contract, manifest)


@pytest.mark.parametrize(
    "change",
    [
        "schedule",
        "cleanup-operation",
        "attempt",
        "source",
        "job",
        "path",
        "repository",
        "helper",
        "auth",
        "expiry",
        "legacy",
        "closed",
        "overdue",
        "missing-role",
        "wrong-intent",
        "duplicate-intent",
        "due-role",
        "extra-lease",
        "missing-old",
        "old-unresolved",
        "stale",
        "future",
        "future-completion",
        "reversed-authentication",
        "artifact-before-observation",
    ],
)
def test_manual_proof_rejects_cross_protocol_or_incomplete_native_evidence(  # noqa: PLR0912, PLR0915 - trust-boundary mutations
    tmp_path: Path, change: str
) -> None:
    tmp_path.chmod(0o700)
    manifest, contract, value = current()
    receipt = value["documents"]["cleanup"]
    auth = value["documents"]["authentication"]
    active = receipt["leases"][1]
    now = NOW
    if change == "schedule":
        value["run"].update(event="schedule", display_title="M3.11 reconcile")
    elif change == "cleanup-operation":
        value["run"]["display_title"] = "M3.11 cleanup"
    elif change == "attempt":
        value["run"]["run_attempt"] = 2
    elif change == "source":
        value["run"]["head_sha"] = "f" * 40
    elif change == "job":
        value["job"]["conclusion"] = "failure"
    elif change == "path":
        value["run"]["path"] = ".github/workflows/other.yml"
    elif change == "repository":
        value["run"]["repository"]["id"] = 999
    elif change == "helper":
        receipt["helper_revision"] = "f" * 40
    elif change == "auth":
        auth["exact_native_and_signed_policy"] = False
    elif change == "expiry":
        auth["expires_at"] = contract["authentication"]["expires_at"] = "2026-10-11T00:00:00Z"
    elif change == "legacy":
        receipt["legacy"]["results"].pop()
    elif change == "closed":
        active["status"] = "closed"
    elif change == "overdue":
        active["overdue"] = True
    elif change == "missing-role":
        active["results"].pop()
    elif change == "wrong-intent":
        active["results"][0]["intent_sha256"] = "f" * 64
    elif change == "duplicate-intent":
        active["results"][0] = deepcopy(active["results"][1])
    elif change == "due-role":
        active["results"][0]["status"] = "verified"
    elif change == "extra-lease":
        receipt["leases"].append({**active, "lease_id": "01a148f3-3c82-703c-ac2e-e208b89d39b9"})
    elif change == "missing-old":
        receipt["leases"].pop(0)
    elif change == "old-unresolved":
        receipt["leases"][0]["status"] = "unresolved"
    elif change == "stale":
        now += timedelta(seconds=5400)
    elif change == "future":
        now = datetime(2026, 10, 9, tzinfo=UTC)
    elif change == "future-completion":
        value["run"]["updated_at"] = "2026-10-10T00:11:00Z"
        value["job"]["completed_at"] = "2026-10-10T00:10:00Z"
    elif change == "reversed-authentication":
        auth["observed_at"] = "2026-10-10T00:02:00Z"
    elif change == "artifact-before-observation":
        receipt["observed_at"] = "2026-10-10T00:04:30Z"

    responses = native_responses(value)
    with pytest.raises(ValueError):
        custody.capture(
            responses.__getitem__, 456, tmp_path / "native", contract, manifest, clock=lambda: now
        )


def test_capture_uses_final_clock_and_never_renews_native_origin(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    manifest, contract, value = current()
    responses = native_responses(value)
    elapsed = [NOW]

    def get(path: str) -> bytes:
        elapsed[0] += timedelta(minutes=20)
        return responses[path]

    with pytest.raises(ValueError, match="stale"):
        custody.capture(get, 456, tmp_path / "native", contract, manifest, clock=lambda: elapsed[0])
