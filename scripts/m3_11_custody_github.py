"""Typed issuance confirmation and genuine scheduled active-lease evidence.

Manual confirmation is issuance evidence only; it does not enable retirement.
The scheduled entry is a distinct contract, preserving the scheduled gate.
Capture is six GETs only; offline verification never dispatches, reconciles or
reads a secret. The sealed caller authenticates and binds every captured byte.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts import m3_11_frozen_github as native
from scripts.m3_11_custody_plan import require
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest, record
from scripts.m3_11_unattended.model import LeaseManifest, fingerprint, identity, instant

FORMAT = "lowerduckpond-m3-11-issuance-manual-confirmation-v1"
STATUS = "verified-manual-independent-issuance"
SCHEDULED_FORMAT = "lowerduckpond-m3-11-custody-scheduled-active-v1"
SCHEDULED_STATUS = "verified-scheduled-independent-active-lease"
PROOF_SECONDS = 5400


def active(raw: object, manifest: LeaseManifest) -> dict[str, object]:
    value = fields(raw, {"lease_id", "manifest_sha256", "status", "overdue", "results"})
    require(
        value["lease_id"] == manifest.lease_id
        and value["manifest_sha256"] == manifest.sha256
        and value["status"] == "active"
        and value["overdue"] is False,
        "custody confirmation does not cover the exact active lease",
    )
    results = native._by_id(value["results"])
    require(
        set(results) == {intent.sha256 for intent in manifest.intents}
        and all(
            set(row) == {"intent_sha256", "status", "negative_authentication"}
            and row["status"] == "not-due"
            and row["negative_authentication"] == "not-tested"
            for row in results.values()
        ),
        "custody confirmation omits or changes an active obligation",
    )
    return value


def _leases(raw: object, contract: dict[str, object], manifest: LeaseManifest) -> dict[str, object]:
    require(isinstance(raw, list), "custody confirmation lease inventory is unavailable")
    current: dict[str, object] | None = None
    closed = []
    seen: set[str] = set()
    for item in cast(list[object], raw):
        require(isinstance(item, dict), "custody confirmation lease is invalid")
        row = cast(dict[str, object], item)
        lease_id = identity(row.get("lease_id"))
        fingerprint(row.get("manifest_sha256"))
        require(lease_id not in seen, "custody confirmation repeats a lease")
        seen.add(lease_id)
        if lease_id == manifest.lease_id:
            current = active(row, manifest)
            continue
        keys = {"lease_id", "manifest_sha256", "status", "overdue"}
        require(
            set(row) in (keys, keys | {"results"})
            and row.get("status") == "closed"
            and row.get("overdue") is False,
            "another active or unresolved lease blocks custody retirement",
        )
        if "results" in row:
            outcomes = native._by_id(row["results"])
            for key in outcomes:
                fingerprint(key)
            require(
                len(outcomes) == len(manifest.intents)
                and all(
                    set(result) == {"intent_sha256", "status", "negative_authentication"}
                    and result.get("status") == "verified"
                    and result.get("negative_authentication")
                    in {"denied", "not-tested", "unavailable"}
                    for result in outcomes.values()
                ),
                "historical closed lease has unresolved outcomes",
            )
        closed.append({key: row[key] for key in keys})
    expected = contract["closed_leases"]
    require(
        isinstance(expected, list)
        and all(isinstance(row, dict) for row in expected)
        and len({str(row.get("lease_id")) for row in expected}) == len(expected)
        and sorted(closed, key=digest) == sorted(expected, key=digest)
        and current is not None,
        "custody confirmation historical closed set differs",
    )
    return cast(dict[str, object], current)


def _verify(
    output: Path, contract: object, manifest: LeaseManifest, *, now: datetime, manual: bool
) -> dict[str, object]:
    verified = native.verified_documents(output, contract, manifest, manual_confirmation=manual)
    selected, run, job = verified.contract, verified.run, verified.job
    documents, hashes = verified.documents, verified.hashes
    require(
        selected["native_workflow_revision"]
        == selected["installed_helper_revision"]
        == manifest.helper_revision
        == manifest.source_revision,
        "custody confirmation workflow and current helper differ",
    )
    native.baseline(documents, selected)
    receipt, authentication = documents["cleanup"], documents["authentication"]
    created, observed = instant(run["created_at"]), instant(receipt["observed_at"])
    deadline = manifest.policy.deadline(instant(manifest.created_at))
    require(
        instant(manifest.created_at) <= created <= observed <= now
        and instant(authentication["observed_at"]) <= observed
        and instant(run["updated_at"]) <= now
        and instant(verified.attempt["updated_at"]) <= now
        and observed < deadline
        and instant(authentication["expires_at"])
        >= deadline + timedelta(seconds=manifest.policy.cleanup_reserve_seconds),
        "custody confirmation chronology or independent cleanup coverage differs",
    )
    for kind, value in documents.items():
        binding = cast(dict[str, object], hashes[kind])
        artifact = next(row for row in verified.artifacts if row["id"] == binding["artifact_id"])
        require(
            instant(value["observed_at"]) <= instant(artifact["created_at"]),
            "custody artifact predates its native observation",
        )
    valid_until = created + timedelta(seconds=PROOF_SECONDS)
    require(now < valid_until, "custody confirmation original proof is stale")
    lease = _leases(receipt.get("leases"), selected, manifest)
    return {
        "format": FORMAT if manual else SCHEDULED_FORMAT,
        "status": STATUS if manual else SCHEDULED_STATUS,
        "event": "workflow_dispatch" if manual else "schedule",
        "operation": "confirm" if manual else "reconcile",
        "run_id": run["id"],
        "run_attempt": run["run_attempt"],
        "job_id": job["id"],
        "contract_sha256": digest(selected),
        "artifacts": hashes,
        "native_created_at": run["created_at"],
        "native_observed_at": receipt["observed_at"],
        "active_lease": lease,
        "legacy_verified": 50,
        "accepted_uncertainty": 1,
        "provider_calls": 0,
        "new_dispatches": 0,
        "live_mutations": 0,
    }


def verify(
    output: Path, contract: object, manifest: LeaseManifest, *, now: datetime
) -> dict[str, object]:
    """Manual issuance-proof type; this is not enabled as retirement eligibility."""
    return _verify(output, contract, manifest, now=now, manual=True)


def verify_scheduled(
    output: Path, contract: object, manifest: LeaseManifest, *, now: datetime
) -> dict[str, object]:
    """The live custody integration retains actual scheduled coverage."""
    return _verify(output, contract, manifest, now=now, manual=False)


def capture(  # noqa: PLR0913 - fixed native capture plus the final fresh clock
    api: Callable[[str], bytes],
    run_id: int,
    output: Path,
    contract: dict[str, object],
    manifest: LeaseManifest,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    native.capture_files(api, run_id, output, contract, manual_confirmation=True)
    result = verify(output, contract, manifest, now=clock())
    record(output / "verified.json", result)
    return result


def capture_scheduled(  # noqa: PLR0913 - fixed native capture plus final fresh clock
    api: Callable[[str], bytes],
    run_id: int,
    output: Path,
    contract: dict[str, object],
    manifest: LeaseManifest,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    native.capture_files(api, run_id, output, contract)
    result = verify_scheduled(output, contract, manifest, now=clock())
    record(output / "verified.json", result)
    return result
