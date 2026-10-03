"""Use the actual managed input and report paths, including secret-export canaries."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from scripts import m3_10_qualification_report as reports
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_unattended import inputs
from scripts.m3_11_unattended.model import ROLES, LifecycleError, Targets, digest, stamp
from scripts.production_qualification_inputs import fingerprint

from .test_m3_11_qualification_report import ARTIFACT, TARGET, Run
from .test_m3_11_qualification_report import run as run  # noqa: PLC0414 - shared pytest fixture

TARGETS = Targets(
    "nyc3", "example-archive", "example-backup", "a" * 32, "b" * 32, "c" * 32, "d" * 32
)
CANARY = "unexported-fixture-secret-canary-4637"


def mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def pair(binding: dict[str, object]) -> dict[str, object]:
    start = datetime.now(UTC) - timedelta(minutes=8)
    common = {
        **binding,
        "started_at": stamp(start),
        "completed_at": stamp(start + timedelta(minutes=1)),
    }
    return {
        "production": {
            **common,
            "format": inputs.PRODUCTION_FORMAT,
            "checks": inputs.PRODUCTION_RESULT,
            "identities_sha256": {
                key: hashlib.sha256(("production-" + key).encode()).hexdigest()
                for key in ("archive", "backup", "caddy")
            },
        },
        "fixture": {
            **common,
            "format": inputs.FIXTURE_FORMAT,
            "checks": inputs.FIXTURE_RESULT,
            "deadline": stamp(start + timedelta(hours=14)),
            "identities_sha256": {
                key: hashlib.sha256(("fixture-" + key).encode()).hexdigest() for key in ROLES
            },
        },
    }


def binding(run: Run, *, target: str = TARGET) -> dict[str, object]:
    return {
        "managed_run_id": str(uuid.uuid7()),
        "source_revision": run.source,
        "helper_revision": run.source,
        "artifact_sha256": ARTIFACT,
        "qualification_inputs_sha256": fingerprint(run.repository, run.source),
        "storage_target_sha256": target,
    }


def managed_report(run: Run) -> dict[str, object]:
    bound = binding(run)
    receipts = pair(bound)
    write_private(
        run.directory / "managed-credentials.json",
        {
            "format": "lowerduckpond-m3-11-managed-credentials-v1",
            **bound,
            "receipts": receipts,
            "receipts_sha256": digest(receipts),
        },
    )
    return run.create()


def test_real_managed_packaging_and_verifier_keep_production_distinct(run: Run) -> None:
    report = managed_report(run)
    assert report["format"] == reports.MANAGED_FORMAT
    raw = run.verify(report)
    assert b"production-and-fixture-distinct" in raw
    assert CANARY.encode() not in raw
    assert (
        report["oldest_evidence_at"]
        == mapping(mapping(mapping(report["managed_credentials"])["receipts"])["production"])[
            "started_at"
        ]
    )


@pytest.mark.parametrize(
    "key",
    [
        "source_revision",
        "helper_revision",
        "qualification_inputs_sha256",
        "storage_target_sha256",
        "artifact_sha256",
    ],
)
def test_receipt_transplant_is_rejected_by_real_verifier(run: Run, key: str) -> None:
    report = managed_report(run)
    wrapper = mapping(report["managed_credentials"])
    receipts = mapping(wrapper["receipts"])
    mapping(receipts["production"])[key] = "f" * (40 if key.endswith("revision") else 64)
    wrapper["receipts_sha256"] = digest(receipts)
    with pytest.raises((ValueError, RuntimeError)):
        run.verify(report)


@pytest.mark.parametrize(
    "change", ["stale", "future", "missing", "failed", "extra-secret", "same-credential"]
)
def test_invalid_production_receipt_cannot_be_replaced_by_fixture_pass(
    run: Run, change: str
) -> None:
    report = managed_report(run)
    wrapper = mapping(report["managed_credentials"])
    receipts = mapping(wrapper["receipts"])
    production = mapping(receipts["production"])
    if change == "stale":
        production["started_at"] = stamp(datetime.now(UTC) - timedelta(days=8))
    elif change == "future":
        production["completed_at"] = stamp(datetime.now(UTC) + timedelta(hours=1))
    elif change == "missing":
        receipts.pop("production")
    elif change == "failed":
        production["checks"] = {**inputs.PRODUCTION_RESULT, "storage": "failed"}
    elif change == "extra-secret":
        production["private_log"] = CANARY
    else:
        mapping(production["identities_sha256"])["caddy"] = mapping(
            mapping(receipts["fixture"])["identities_sha256"]
        )["caddy"]
    wrapper["receipts_sha256"] = digest(receipts)
    with pytest.raises((ValueError, RuntimeError)):
        run.verify(report)


def test_managed_missing_receipts_refuses_instead_of_producing_legacy_pass(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(inputs.MANAGED_ENV, "/private/example.json")
    with pytest.raises(ValueError, match="omitted"):
        run.create()


def document(run: Run) -> dict[str, object]:
    bound = binding(run, target=TARGETS.storage_digest)
    credentials = {name: CANARY + "-" + name for name in inputs.SECRET_ENV}
    credentials.update(
        SPACES_ARCHIVE_ACCESS_KEY_ID="fixture-archive",
        SPACES_BACKUP_ACCESS_KEY_ID="fixture-backup",
        SPACES_ACCESS_KEY_ID="fixture-operator",
    )
    return {
        "format": inputs.FORMAT,
        "binding": bound,
        "targets": {
            "region": TARGETS.region,
            "archive_bucket": TARGETS.archive_bucket,
            "backup_bucket": TARGETS.backup_bucket,
            "account_id": TARGETS.account_id,
            "zone_id": TARGETS.zone_id,
            "tenant_zone_id": TARGETS.tenant_zone_id,
            "user_id": TARGETS.user_id,
        },
        "credentials": credentials,
        "receipts": pair(bound),
    }


def test_managed_input_cannot_be_overwritten_or_gain_state_secrets(run: Run) -> None:
    path = run.directory / "delivery.json"
    write_private(path, document(run))
    environment, _ = inputs.load(path, repository=run.repository, now=datetime.now(UTC))
    inputs.require_environment(environment, environment)
    for name, value in (
        ("SPACES_ARCHIVE_ACCESS_KEY_ID", "production-archive"),
        ("OPENTOFU_ENCRYPTION_PASSPHRASE", CANARY),
        ("OP_SERVICE_ACCOUNT_TOKEN", CANARY),
        ("AWS_SECRET_ACCESS_KEY", CANARY),
        ("SPACES_ENDPOINT_URL", "https://example.test"),
        ("CLOUDFLARE_BOOTSTRAP", CANARY),
    ):
        with pytest.raises(LifecycleError):
            inputs.require_environment({**environment, name: value}, environment)


@pytest.mark.parametrize(
    "change", ["missing", "duplicate", "expired", "wrong-target", "unissued-key"]
)
def test_managed_input_rejects_incomplete_or_ambiguous_delivery(run: Run, change: str) -> None:
    original = document(run)
    credentials = mapping(original["credentials"])
    if change == "missing":
        credentials.pop("M3_10_PAGE_RULES_TOKEN")
    elif change == "duplicate":
        credentials["CADDY_CLOUDFLARE_API_TOKEN"] = credentials["M3_10_TOKEN_AUDIT_TOKEN"]
    elif change == "expired":
        mapping(mapping(original["receipts"])["fixture"])["deadline"] = stamp(
            datetime.now(UTC) - timedelta(hours=1)
        )
    elif change == "wrong-target":
        mapping(original["targets"])["archive_bucket"] = "different-archive"
    else:
        credentials["SPACES_ARCHIVE_ACCESS_KEY_ID"] = "unissued-key"
    path = run.directory / "delivery.json"
    write_private(path, original)
    with pytest.raises((LifecycleError, ValueError)):
        inputs.load(path, repository=run.repository, now=datetime.now(UTC))


def test_managed_capture_exports_only_sanitized_receipts(
    run: Run, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = run.directory / "delivery.json"
    original = document(run)
    write_private(path, original)
    environment, _ = inputs.load(path, repository=run.repository, now=datetime.now(UTC))
    monkeypatch.setattr(os, "environ", environment)
    inputs.capture(path, run.directory, repository=run.repository, now=datetime.now(UTC))
    raw = (run.directory / "managed-credentials.json").read_text()
    assert CANARY not in raw
    assert "SPACES_" not in raw
    assert "OPENTOFU_" not in raw
    assert "example-archive" not in raw
    assert mapping(json.loads(raw))["receipts"] == original["receipts"]


def test_current_private_credential_metadata_is_required(run: Run) -> None:
    path = run.directory / "delivery.json"
    write_private(path, copy.deepcopy(document(run)))
    path.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe"):
        inputs.load(path, repository=run.repository, now=datetime.now(UTC))
