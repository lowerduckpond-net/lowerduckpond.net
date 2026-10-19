"""Native GET/ZIP selection cannot turn stale labels into terminal cleanup proof."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts import m3_11_frozen_github as github
from scripts.m3_11_unattended.model import LeaseManifest

from .test_m3_11_frozen_terminal import closed


def fixture(
    selected: LeaseManifest | None = None,
) -> tuple[LeaseManifest, dict[str, Any], dict[str, Any]]:
    manifest, _, _, _ = closed(selected)
    source = "a" * 40
    repository = {"id": 123, "full_name": "lowerduckpond-net/lowerduckpond.net"}
    run = {
        "id": 456,
        "run_attempt": 1,
        "workflow_id": 789,
        "path": ".github/workflows/m3-11-credential-cleanup.yml",
        "head_sha": source,
        "head_branch": "main",
        "event": "schedule",
        "display_title": "M3.11 reconcile",
        "status": "completed",
        "conclusion": "success",
        "created_at": "2026-10-18T00:00:00Z",
        "run_started_at": "2026-10-18T00:00:01Z",
        "updated_at": "2026-10-18T00:05:00Z",
        "repository": repository,
        "head_repository": repository,
    }
    job = {
        "id": 1234,
        "run_id": 456,
        "run_attempt": 1,
        "head_sha": source,
        "name": "connect",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-10-18T00:00:02Z",
        "completed_at": "2026-10-18T00:04:59Z",
        "steps": [
            {"name": name, "conclusion": conclusion}
            for name, conclusion in (
                (
                    "Select the installed cleanup contract without activating a replacement",
                    "success",
                ),
                ("Reconcile through the selected pinned cleanup contract", "success"),
                ("Reconcile legacy cleanup with the approved import reader", "skipped"),
            )
        ],
    }
    authentication = {
        "authenticated": True,
        "create_verified": False,
        "exact_native_and_signed_policy": True,
        "expires_at": "2027-01-01T00:00:00Z",
        "server_sha256": "b" * 64,
        "token_id_sha256": "c" * 64,
        "signed_grants_by_vault_sha256": "d" * 64,
        "forbidden_vaults_denied": 2,
        "status": "verified",
    }
    legacy = {
        "status": "ready",
        "expiry_updates": "verified",
        "migration_sha256": "e" * 64,
        "accepted_historical_uncertainty": 1,
        "audit_restoration": "verified",
        "results": [
            {
                "intent_sha256": f"{index:064x}",
                "status": "verified" if index else "operator-accepted-uncertainty",
                "negative_authentication": "denied" if index else "unavailable",
            }
            for index in range(51)
        ],
    }
    lease = {
        "lease_id": manifest.lease_id,
        "manifest_sha256": manifest.sha256,
        "status": "closed",
        "overdue": False,
    }
    contract = {
        "repository": repository["full_name"],
        "repository_id": 123,
        "workflow_id": 789,
        "native_workflow_revision": source,
        "installed_helper_revision": manifest.helper_revision,
        "authentication": authentication,
        "legacy": deepcopy(legacy),
        "closed_leases": [lease],
    }
    documents = {
        "cleanup": {
            "format": "lowerduckpond-m3-11-independent-lease-receipt-v1",
            "actor": "github",
            "status": "ready",
            "helper_revision": manifest.helper_revision,
            "observed_at": "2026-10-18T00:01:00Z",
            "legacy": legacy,
            "leases": [
                {
                    **lease,
                    "results": [
                        {
                            "intent_sha256": intent.sha256,
                            "status": "verified",
                            "negative_authentication": "denied",
                        }
                        for intent in manifest.intents
                    ],
                }
            ],
        },
        "authentication": {**authentication, "observed_at": "2026-10-18T00:01:00Z"},
    }
    return manifest, contract, {"run": run, "job": job, "documents": documents}


def api_responses(value: dict[str, Any]) -> dict[str, bytes]:
    prefix = "repos/lowerduckpond-net/lowerduckpond.net/actions/"
    result = {
        prefix + "runs/456": json.dumps(value["run"]).encode(),
        prefix + "runs/456/attempts/1": json.dumps(value["run"]).encode(),
        prefix + "runs/456/attempts/1/jobs?per_page=100": json.dumps(
            {"total_count": 1, "jobs": [value["job"]]}
        ).encode(),
    }
    artifacts = []
    for index, (kind, name, member) in enumerate(
        (
            ("cleanup", "m3-11-credential-cleanup", "receipt.json"),
            ("authentication", "m3-11-independent-authentication", "authentication.json"),
        )
    ):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(member, json.dumps(value["documents"][kind]))
        raw = stream.getvalue()
        result[prefix + f"artifacts/{100 + index}/zip"] = raw
        artifacts.append(
            {
                "id": 100 + index,
                "name": name + "-456-attempt-1",
                "expired": False,
                "created_at": "2026-10-18T00:04:00Z",
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "workflow_run": {
                    "id": 456,
                    "head_sha": value["run"]["head_sha"],
                    "head_branch": "main",
                    "repository_id": 123,
                    "head_repository_id": 123,
                },
            }
        )
    result[prefix + "runs/456/artifacts?per_page=100"] = json.dumps(
        {"total_count": 2, "artifacts": artifacts}
    ).encode()
    return result


def test_capture_verifies_native_job_both_digests_and_all_original_obligations(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    manifest, contract, value = fixture()
    responses = api_responses(value)
    calls = []

    def get(path: str) -> bytes:
        calls.append(path)
        return responses[path]

    result = github.capture(get, 456, tmp_path / "proof", contract, manifest)
    assert result["status"] == "verified-terminal-independent"
    assert result["manifest_sha256"] == manifest.sha256
    assert len(calls) == 6 and set(calls) == set(responses)  # noqa: PLR2004 - four native GETs, two ZIPs
    assert github.verify(tmp_path / "proof", contract, manifest) == result


@pytest.mark.parametrize(
    "change",
    [
        "source",
        "helper",
        "job",
        "step",
        "auth",
        "expiry",
        "active",
        "missing-denial",
        "wrong-intent",
        "lost-legacy",
        "regressed-legacy",
        "native-digest",
        "incomplete-list",
        "another-repository",
        "duplicate-job",
        "artifact-source",
        "bad-member",
    ],
)
def test_rejects_labels_without_exact_native_terminal_proof(tmp_path: Path, change: str) -> None:  # noqa: PLR0912, PLR0915 - independent trust boundaries
    tmp_path.chmod(0o700)
    manifest, contract, value = fixture()
    cleanup = value["documents"]["cleanup"]
    if change == "source":
        value["run"]["head_sha"] = "f" * 40
    elif change == "helper":
        cleanup["helper_revision"] = "f" * 40
    elif change == "job":
        value["job"]["run_attempt"] = 2
    elif change == "step":
        value["job"]["steps"][-1]["conclusion"] = "success"
    elif change == "auth":
        value["documents"]["authentication"]["exact_native_and_signed_policy"] = False
    elif change == "expiry":
        contract["authentication"]["expires_at"] = "2025-01-01T00:00:00Z"
        value["documents"]["authentication"]["expires_at"] = "2025-01-01T00:00:00Z"
    elif change == "active":
        cleanup["leases"][0]["status"] = "active"
    elif change == "missing-denial":
        cleanup["leases"][0]["results"][0]["negative_authentication"] = "not-tested"
    elif change == "wrong-intent":
        cleanup["leases"][0]["results"][0]["intent_sha256"] = "f" * 64
    elif change == "lost-legacy":
        cleanup["legacy"]["results"].pop()
    elif change == "regressed-legacy":
        cleanup["legacy"]["results"][1]["negative_authentication"] = "not-tested"
    elif change == "another-repository":
        value["run"]["repository"]["id"] = 999
    responses = api_responses(value)
    inventory = "repos/lowerduckpond-net/lowerduckpond.net/actions/runs/456/artifacts?per_page=100"
    jobs = "repos/lowerduckpond-net/lowerduckpond.net/actions/runs/456/attempts/1/jobs?per_page=100"
    if change in {"native-digest", "incomplete-list", "artifact-source", "bad-member"}:
        row = json.loads(responses[inventory])
        if change == "native-digest":
            row["artifacts"][0]["digest"] = "sha256:" + "0" * 64
        elif change == "incomplete-list":
            row["total_count"] = 3
        elif change == "artifact-source":
            row["artifacts"][0]["workflow_run"]["id"] = 999
        else:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("../receipt.json", b"{}")
            raw = stream.getvalue()
            responses["repos/lowerduckpond-net/lowerduckpond.net/actions/artifacts/100/zip"] = raw
            row["artifacts"][0]["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        responses[inventory] = json.dumps(row).encode()
    if change == "duplicate-job":
        responses[jobs] = json.dumps(
            {"total_count": 2, "jobs": [value["job"], value["job"]]}
        ).encode()
    with pytest.raises(ValueError):
        github.capture(responses.__getitem__, 456, tmp_path / "proof", contract, manifest)
    assert not (tmp_path / "proof/verified.json").exists()
