"""Durable publication of the single, authority-bound platform launch."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC
from pathlib import Path

from lowerduckpond_static_host_agent.audit import has_tenant_audit_history
from lowerduckpond_static_host_agent.durable import DurableDirectory, FailureHook
from lowerduckpond_static_host_agent.locks import LockMode
from lowerduckpond_static_host_agent.repository import StateRecordPath, StateRepository
from scripts.m3_12_contracts import (
    MAX_RECORD_BYTES,
    AdmissionContext,
    Document,
    Evidence,
    decode,
    digest,
    encode,
    instant,
    require,
    validate_admission,
    validate_launch,
)

ADMISSION = ("admission.json",)
INTENT = ("launch-intent.json",)
RECEIPT = ("launch-receipt.json",)
LAUNCH = StateRecordPath.platform_launch().components
NAMESPACE = StateRecordPath.platform_namespace()


def _read(root: DurableDirectory, path: tuple[str, ...], owner: int) -> bytes:
    return root.read_regular(
        path, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
    )


def _optional(root: DurableDirectory, path: tuple[str, ...], owner: int) -> bytes | None:
    try:
        return _read(root, path, owner)
    except FileNotFoundError:
        return None


def _sync(root: DurableDirectory) -> None:
    descriptor = root.duplicate_descriptor()
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _seal(
    root: DurableDirectory,
    key: tuple[str, ...],
    data: bytes,
    owner: int,
    *,
    failure_hook: FailureHook | None = None,
) -> None:
    previous = _optional(root, key, owner)
    if previous is None:
        root.create_immutable(key, data, failure_hook=failure_hook)
    else:
        require(previous == data, "conflicting-launch-state")
        # A prior process may have died between rename and directory sync.
        _sync(root)


def _launch_bytes(admission: Document, intent: Document) -> tuple[bytes, bytes]:
    platform = admission["platform"]
    launch = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "LaunchRecord",
        "configurationVersion": admission["candidate"]["revision"],
        "trustedPlatformDomain": platform["trustedPlatformDomain"],
        "aliasSuffix": platform["aliasSuffix"],
        "tenantOriginSuffix": platform["tenantOriginSuffix"],
        "cookiePolicyVersion": platform["cookiePolicyVersion"],
        "edgePolicyVersion": platform["edgePolicyVersion"],
        "cloudflareNetworkSetDigest": {
            "format": "lowerduckpond-cloudflare-network-set-v1",
            "algorithm": "sha256",
            "value": platform["cloudflareNetworkSetSha256"],
        },
        "acceptanceEvidenceDigest": {
            "format": "lowerduckpond-m3-acceptance-v1",
            "algorithm": "sha256",
            "value": digest(admission),
        },
        "launchedAt": intent["intendedAt"],
    }
    receipt = {
        "format": "lowerduckpond-m3-12-launch-receipt-v1",
        "binding": admission["binding"],
        "admissionSha256": digest(admission),
        "intentSha256": digest(intent),
        "launchRecordSha256": digest(launch),
        "launchedAt": intent["intendedAt"],
    }
    return encode(launch), encode(receipt)


def initialize_launch(  # noqa: PLR0913 - explicit authority, host and durability boundaries
    state_path: Path,
    authority_path: Path,
    admission_raw: bytes,
    evidence: Evidence,
    observe: Callable[[], AdmissionContext],
    *,
    owner: int = 0,
    failure_hook: FailureHook | None = None,
) -> Document:
    """Read fresh leased observations while holding publication then tenant-state."""
    with (
        DurableDirectory.open(
            authority_path, expected_owner=owner, expected_directory_mode=0o700
        ) as authority,
        DurableDirectory.open(
            state_path, expected_owner=owner, expected_directory_mode=0o700
        ) as state,
        StateRepository(state_path, expected_owner=owner) as repository,
        repository.publication_transaction() as transaction,
        state.open_descendant(("platform",)) as platform,
    ):
        context = observe()
        fresh = validate_admission(admission_raw, context, evidence)
        original_raw = _optional(authority, ADMISSION, owner)
        admission = fresh if original_raw is None else decode(original_raw, "admission")
        require(
            all(
                admission[name] == fresh[name]
                for name in ("binding", "target", "candidate", "platform", "authoritySha256")
            ),
            "launch-original-admission-changed",
        )
        admission_raw = admission_raw if original_raw is None else original_raw
        namespace = transaction.read(NAMESPACE).document
        require(
            digest(namespace) == admission["platform"]["namespaceSha256"]
            and namespace["tenantOriginSuffix"] == admission["platform"]["tenantOriginSuffix"],
            "launch-namespace-changed",
        )
        existing_intent = _optional(authority, INTENT, owner)
        existing_launch = _optional(state, LAUNCH, owner)
        existing_receipt = _optional(authority, RECEIPT, owner)
        require(
            not ((existing_launch or existing_receipt) and existing_intent is None)
            and not (existing_receipt and existing_launch is None),
            "launch-chain-incomplete",
        )
        inventory = transaction.measure_inventory()
        require(
            not inventory.tenant_count
            and not inventory.authorization_record_count
            and not transaction.measure_intent_records().records
            and not has_tenant_audit_history(
                state,
                expected_owner=owner,
                expected_directory_mode=0o700,
                expected_record_mode=0o600,
            ),
            "launch-history-or-work",
        )
        intended = context.now.astimezone(UTC).replace(microsecond=0)
        require(intended >= instant(fresh["preparedAt"]), "launch-time-before-preparation")
        intent = (
            {
                "format": "lowerduckpond-m3-12-launch-intent-v1",
                "binding": admission["binding"],
                "admissionSha256": digest(admission),
                "invocationId": admission["invocationId"],
                "leaseSha256": admission["leaseSha256"],
                "intendedAt": intended.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            if existing_intent is None
            else decode(existing_intent, "launch-intent")
        )
        intent_raw = encode(intent)
        launch, receipt = _launch_bytes(admission, intent)
        validated = validate_launch(admission_raw, intent_raw, launch, receipt)
        require(
            existing_launch in {None, launch} and existing_receipt in {None, receipt},
            "conflicting-launch-state",
        )
        _seal(authority, ADMISSION, admission_raw, owner)
        _seal(authority, INTENT, intent_raw, owner)
        _seal(platform, (LAUNCH[-1],), launch, owner, failure_hook=failure_hook)
        _seal(authority, RECEIPT, receipt, owner)
        return validated


def verify_launch(state_path: Path, authority_path: Path, *, owner: int = 0) -> Document:
    """Reopen the native launch, retained admission, and backed-up namespace."""
    with (
        DurableDirectory.open(
            authority_path, expected_owner=owner, expected_directory_mode=0o700
        ) as authority,
        StateRepository(state_path, expected_owner=owner) as repository,
        repository.transaction(mode=LockMode.SHARED) as transaction,
    ):
        admission_raw = _read(authority, ADMISSION, owner)
        admission = decode(admission_raw, "admission")
        launch = transaction.read(StateRecordPath.platform_launch()).document
        receipt = validate_launch(
            admission_raw,
            _read(authority, INTENT, owner),
            encode(launch),
            _read(authority, RECEIPT, owner),
        )
        namespace = transaction.read(NAMESPACE).document
        require(
            digest(namespace) == admission["platform"]["namespaceSha256"],
            "launch-namespace-changed",
        )
        return receipt


def require_local_launch_binding(
    authority_path: Path, receipt: Document, *, disposable: bool, owner: int = 0
) -> None:
    """Reject receipts copied from a different target or native transaction."""
    with DurableDirectory.open(
        authority_path, expected_owner=owner, expected_directory_mode=0o700
    ) as authority:
        binding = receipt["binding"]
        transaction_raw = _optional(authority, ("transaction.json",), owner)
        if transaction_raw is not None:
            transaction = decode(transaction_raw, "transaction")
            require(
                not disposable
                and binding["targetKind"] == "production-host"
                and binding["purpose"] == "production"
                and binding == transaction["binding"],
                "native-publication-binding-changed",
            )
            return
        require(disposable, "installed-publication-requires-disposable")
        target = decode(_read(authority, ("installed-target.json",), owner), "target")
        require(
            binding["targetKind"] == target["targetKind"] == "installed-fixture"
            and binding["purpose"] == target["purpose"] == "installed-test"
            and binding["targetSha256"] == digest(target),
            "installed-publication-binding-changed",
        )
