"""Full independent scheduled terminal proof, native identities plus ZIP digests.

The capture adapter only performs authenticated GitHub GETs. Offline disposal
rechecks the exact retained native responses/artifacts bound by its approval;
it never substitutes this parser for authentication of arbitrary supplied JSON.
Workflow source and installed cleanup helper are separate exact contract values.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import RetirementError, digest, directory, preserve, record
from scripts.m3_11_unattended.model import LeaseManifest, instant

FORMAT = "lowerduckpond-m3-11-native-terminal-github-v1"
MAX_ZIP = 8 * 1024 * 1024
MAX_BODY = 4 * 1024 * 1024
RUN_KEYS = (
    "id",
    "run_attempt",
    "head_sha",
    "status",
    "conclusion",
    "created_at",
    "run_started_at",
    "workflow_id",
    "path",
    "head_branch",
    "event",
    "display_title",
)


def require(value: object, explanation: str) -> None:
    if not value:
        raise RetirementError(explanation)


def _list(value: object, key: str) -> list[dict[str, object]]:
    require(isinstance(value, dict), "native terminal inventory is missing")
    data = cast(dict[str, object], value)
    rows = data.get(key)
    require(
        isinstance(rows, list)
        and all(isinstance(row, dict) for row in rows)
        and type(data.get("total_count")) is int
        and len(rows) == data["total_count"],
        "native terminal inventory is incomplete",
    )
    return cast(list[dict[str, object]], rows)


def _run(raw: object, contract: dict[str, object]) -> dict[str, object]:
    require(isinstance(raw, dict), "native terminal run is missing")
    run = cast(dict[str, object], raw)
    require(
        type(run.get("id")) is int
        and cast(int, run["id"]) > 0
        and type(run.get("run_attempt")) is int
        and run["run_attempt"] == 1
        and run.get("workflow_id") == contract["workflow_id"]
        and run.get("path") == ".github/workflows/m3-11-credential-cleanup.yml"
        and run.get("head_sha") == contract["native_workflow_revision"]
        and run.get("head_branch") == "main"
        and run.get("event") == "schedule"
        and run.get("display_title") == "M3.11 reconcile"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success",
        "native terminal scheduled run identity or result differs",
    )
    for key in ("repository", "head_repository"):
        require(isinstance(run.get(key), dict), "native terminal repository is missing")
        row = cast(dict[str, object], run[key])
        require(
            row.get("id") == contract["repository_id"]
            and row.get("full_name") == contract["repository"],
            "native terminal repository identity differs",
        )
    require(
        instant(run["created_at"]) <= instant(run["run_started_at"]) <= instant(run["updated_at"]),
        "native terminal run chronology differs",
    )
    return run


def verify(output: Path, contract: object, manifest: LeaseManifest) -> dict[str, object]:
    selected = fields(
        contract,
        {
            "repository",
            "repository_id",
            "workflow_id",
            "native_workflow_revision",
            "installed_helper_revision",
            "authentication",
            "legacy",
            "closed_leases",
        },
    )
    require(
        selected["repository"] == "lowerduckpond-net/lowerduckpond.net"
        and type(selected["repository_id"]) is int
        and selected["repository_id"] > 0
        and type(selected["workflow_id"]) is int
        and selected["workflow_id"] > 0
        and all(
            isinstance(selected[key], str) and re.fullmatch(r"[a-f0-9]{40}", str(selected[key]))
            for key in ("native_workflow_revision", "installed_helper_revision")
        )
        and selected["installed_helper_revision"] == manifest.helper_revision,
        "native terminal collector contract differs",
    )
    directory(output)
    run = _run(read_private(output / "run.json", maximum=MAX_BODY), selected)
    attempt = _run(read_private(output / "attempt.json", maximum=MAX_BODY), selected)
    require(all(run[key] == attempt[key] for key in RUN_KEYS), "native terminal attempt changed")
    rows = _list(read_private(output / "jobs.json", maximum=MAX_BODY), "jobs")
    jobs = [row for row in rows if row.get("name") == "connect"]
    require(len(jobs) == 1, "native terminal Connect job is ambiguous")
    job = jobs[0]
    require(
        type(job.get("id")) is int
        and cast(int, job["id"]) > 0
        and job.get("run_id") == run["id"]
        and job.get("run_attempt") == run["run_attempt"]
        and job.get("head_sha") == run["head_sha"]
        and job.get("status") == "completed"
        and job.get("conclusion") == "success"
        and instant(run["run_started_at"])
        <= instant(job["started_at"])
        <= instant(job["completed_at"])
        <= min(instant(run["updated_at"]), instant(attempt["updated_at"])),
        "native terminal Connect job binding or result differs",
    )
    steps = job.get("steps")
    require(
        isinstance(steps, list) and all(isinstance(row, dict) for row in steps),
        "native terminal steps unavailable",
    )
    for name, conclusion in (
        ("Select the installed cleanup contract without activating a replacement", "success"),
        ("Reconcile through the selected pinned cleanup contract", "success"),
        ("Reconcile legacy cleanup with the approved import reader", "skipped"),
    ):
        matches = [row for row in cast(list[dict[str, object]], steps) if row.get("name") == name]
        require(
            len(matches) == 1 and matches[0].get("conclusion") == conclusion,
            "native terminal executed another cleanup path",
        )
    artifacts = _list(read_private(output / "artifacts.json", maximum=MAX_BODY), "artifacts")
    documents: dict[str, dict[str, object]] = {}
    hashes: dict[str, object] = {}
    for kind, prefix, filename in (
        ("cleanup", "m3-11-credential-cleanup", "receipt.json"),
        ("authentication", "m3-11-independent-authentication", "authentication.json"),
    ):
        name = f"{prefix}-{run['id']}-attempt-{run['run_attempt']}"
        matches = [row for row in artifacts if row.get("name") == name]
        require(len(matches) == 1, "native terminal artifact is missing or ambiguous")
        row = matches[0]
        native = row.get("workflow_run")
        require(isinstance(native, dict), "native terminal artifact source is missing")
        native = cast(dict[str, object], native)
        require(
            type(row.get("id")) is int
            and cast(int, row["id"]) > 0
            and row.get("expired") is False
            and native.get("id") == run["id"]
            and native.get("head_sha") == run["head_sha"]
            and native.get("head_branch") == "main"
            and native.get("repository_id") == selected["repository_id"]
            and native.get("head_repository_id") == selected["repository_id"]
            and instant(job["started_at"])
            <= instant(row["created_at"])
            <= instant(job["completed_at"]),
            "native terminal artifact source/chronology differs",
        )
        raw = read_private_bytes(output / (kind + ".zip"), maximum=MAX_ZIP)
        require(
            row.get("digest") == "sha256:" + hashlib.sha256(raw).hexdigest(),
            "native terminal ZIP digest differs",
        )
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(
                len(entries) == 1
                and entries[0].filename == filename
                and entries[0].file_size <= MAX_BODY,
                "native terminal artifact members differ",
            )
            body = archive.read(entries[0])
        value = json.loads(body)
        require(isinstance(value, dict), "native terminal artifact document is invalid")
        require(
            instant(job["started_at"])
            <= instant(value.get("observed_at"))
            < instant(job["completed_at"]) + timedelta(seconds=1),
            "native terminal artifact observation is outside its job",
        )
        documents[kind] = value
        hashes[kind] = {
            "artifact_id": row["id"],
            "zip_sha256": hashlib.sha256(raw).hexdigest(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    _receipts(documents, selected, manifest)
    return {
        "format": FORMAT,
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "job_id": job["id"],
        "contract_sha256": digest(selected),
        "artifacts": hashes,
        "lease_id": manifest.lease_id,
        "manifest_sha256": manifest.sha256,
        "status": "verified-terminal-independent",
        "observed_at": documents["cleanup"]["observed_at"],
    }


def _receipts(
    documents: dict[str, dict[str, object]], contract: dict[str, object], manifest: LeaseManifest
) -> None:
    receipt, auth = documents["cleanup"], documents["authentication"]
    expected = fields(
        contract["authentication"],
        {
            "authenticated",
            "create_verified",
            "exact_native_and_signed_policy",
            "expires_at",
            "server_sha256",
            "token_id_sha256",
            "signed_grants_by_vault_sha256",
            "forbidden_vaults_denied",
            "status",
        },
    )
    require(
        expected["authenticated"] is True
        and expected["exact_native_and_signed_policy"] is True
        and expected["create_verified"] is False
        and expected["status"] == "verified"
        and expected["forbidden_vaults_denied"] == 2  # noqa: PLR2004 - both forbidden vaults
        and all(auth.get(key) == value for key, value in expected.items()),
        "native terminal independent authentication differs",
    )
    require(
        instant(auth["observed_at"]) < instant(auth["expires_at"]),
        "native terminal authentication was expired during its proof",
    )
    require(
        receipt.get("format") == "lowerduckpond-m3-11-independent-lease-receipt-v1"
        and receipt.get("helper_revision") == contract["installed_helper_revision"]
        and receipt.get("actor") == "github"
        and receipt.get("status") == "ready",
        "native terminal cleanup receipt differs",
    )
    legacy = receipt.get("legacy")
    baseline = cast(dict[str, object], contract["legacy"])
    require(isinstance(legacy, dict), "native terminal historical obligations are missing")
    legacy = cast(dict[str, object], legacy)
    require(
        legacy.get("status") == "ready"
        and legacy.get("expiry_updates") == "verified"
        and all(
            legacy.get(key) == baseline[key]
            for key in ("migration_sha256", "accepted_historical_uncertainty", "audit_restoration")
        ),
        "native terminal historical policy or recovery changed",
    )

    def by_id(raw: object) -> dict[str, dict[str, object]]:
        require(
            isinstance(raw, list) and all(isinstance(row, dict) for row in raw),
            "native terminal result inventory is invalid",
        )
        rows = cast(list[dict[str, object]], raw)
        result = {str(row.get("intent_sha256")): row for row in rows}
        require(len(result) == len(rows), "native terminal results repeat an obligation")
        return result

    actual, original = by_id(legacy.get("results")), by_id(baseline.get("results"))
    require(
        set(actual) == set(original)
        and len(actual) == 51  # noqa: PLR2004 - immutable historical obligations
        and Counter(row.get("status") for row in actual.values())
        == Counter({"verified": 50, "operator-accepted-uncertainty": 1}),
        "native terminal historical outcome inventory differs",
    )
    for key, old in original.items():
        allowed = {old.get("negative_authentication")}
        if old.get("negative_authentication") in {"unavailable", "not-tested"}:
            allowed.add("denied")
        require(
            actual[key].get("status") == old.get("status")
            and actual[key].get("negative_authentication") in allowed,
            "native terminal historical uncertainty or denial regressed",
        )
    leases = receipt.get("leases")
    require(isinstance(leases, list), "native terminal lease inventory is missing")
    projected = []
    for raw in cast(list[object], leases):
        keys = {"lease_id", "manifest_sha256", "status", "overdue"}
        require(
            isinstance(raw, dict) and set(raw) in (keys, keys | {"results"}),
            "native terminal lease fields differ",
        )
        row = cast(dict[str, object], raw)
        require(
            row["status"] == "closed" and row["overdue"] is False,
            "native terminal lease is unresolved",
        )
        if "results" in row:
            results = by_id(row["results"])
            require(
                len(results) == 7  # noqa: PLR2004 - original seven roles
                and all(
                    item.get("status") == "verified"
                    and item.get("negative_authentication") == "denied"
                    for item in results.values()
                ),
                "native terminal lease denials are incomplete",
            )
            if row["lease_id"] == manifest.lease_id:
                require(
                    set(results) == {intent.sha256 for intent in manifest.intents},
                    "native terminal lease intents differ",
                )
        projected.append({key: row[key] for key in keys})
    require(
        len({row["lease_id"] for row in projected}) == len(projected)
        and sorted(projected, key=digest)
        == sorted(cast(list[dict[str, object]], contract["closed_leases"]), key=digest)
        and {
            "lease_id": manifest.lease_id,
            "manifest_sha256": manifest.sha256,
            "status": "closed",
            "overdue": False,
        }
        in projected,
        "native terminal closed lease set differs from the exact original obligations",
    )


def capture(
    api: Callable[[str], bytes],
    run_id: int,
    output: Path,
    contract: dict[str, object],
    manifest: LeaseManifest,
) -> dict[str, object]:
    """GET adapter is supplied by the sealed collector, not an arbitrary live CLI option."""
    require(type(run_id) is int and run_id > 0, "native terminal run ID is invalid")
    directory(output.parent)
    output.mkdir(mode=0o700)
    prefix = "repos/lowerduckpond-net/lowerduckpond.net/actions/"
    responses = {}
    for filename, suffix in (
        ("run", f"runs/{run_id}"),
        ("attempt", f"runs/{run_id}/attempts/1"),
        ("jobs", f"runs/{run_id}/attempts/1/jobs?per_page=100"),
        ("artifacts", f"runs/{run_id}/artifacts?per_page=100"),
    ):
        raw = api(prefix + suffix)
        require(len(raw) <= MAX_BODY, "native terminal response exceeds its byte bound")
        value = json.loads(raw)
        require(isinstance(value, dict), "native terminal response is not an object")
        write_private(output / (filename + ".json"), value, maximum=MAX_BODY)
        responses[filename] = value
    _run(responses["run"], contract)
    for kind, prefix_name in (
        ("cleanup", "m3-11-credential-cleanup"),
        ("authentication", "m3-11-independent-authentication"),
    ):
        rows = [
            row
            for row in _list(responses["artifacts"], "artifacts")
            if row.get("name") == f"{prefix_name}-{run_id}-attempt-1"
        ]
        require(
            len(rows) == 1 and type(rows[0].get("id")) is int and cast(int, rows[0]["id"]) > 0,
            "native terminal artifact selection differs",
        )
        raw = api(prefix + f"artifacts/{rows[0]['id']}/zip")
        require(0 < len(raw) <= MAX_ZIP, "native terminal ZIP exceeds its byte bound")
        preserve(
            output / (kind + ".zip"),
            (raw[index : index + 1024 * 1024] for index in range(0, len(raw), 1024 * 1024)),
            len(raw),
            hashlib.sha256(raw).hexdigest(),
        )
    result = verify(output, contract, manifest)
    record(output / "verified.json", result)
    return result
