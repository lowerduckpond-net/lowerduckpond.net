"""Reacquire only the original managed attempt's retained runtime credentials."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields, parse_timestamp
from scripts.m3_11_unattended import inputs
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.model import digest, identity, instant
from scripts.m3_11_unattended.state import LeaseState, RunState
from scripts.m3_11_unattended.worker import SECRETS, safe_environment
from scripts.qualification_disposition import require_available


def require_live(directory: Path) -> None:
    require_available(directory)
    attempt = directory.parent.parent
    request = read_private(attempt / "request.json")
    lease = LeaseState(attempt.parent.parent / "leases" / identity(request["lease_id"]))
    receipt = read_private(directory / "managed-credentials.json")
    pair = fields(receipt["receipts"], {"production", "fixture"})
    fixture = pair["fixture"]
    if not isinstance(fixture, dict):
        raise ValueError("finalization fixture receipt is invalid")
    now = datetime.now(UTC)
    if (
        RunState(attempt).cancelled
        or any(lease.directory.glob("close-*.json"))
        or (lease.directory / f"released-{attempt.name}.json").exists()
        or now >= instant(fixture["deadline"])
        or any(now >= instant(intent.deadline) for intent in lease.manifest().intents)
    ):
        raise ValueError("finalization access expired, was cancelled, or was released")


@contextmanager
def access(directory: Path) -> Iterator[dict[str, str]]:
    """No new lease, credential issuance, delivery bundle, or ownership release."""
    attempt = directory.parent.parent
    request = read_private(attempt / "request.json")
    if (
        directory.parent.name != "qualification"
        or attempt.parent.name != "runs"
        or request.get("format") != "lowerduckpond-m3-11-unattended-request-v2"
        or request.get("mode") != "qualification"
    ):
        raise ValueError("finalization requires the original managed qualification attempt")
    lease = LeaseState(attempt.parent.parent / "leases" / identity(request["lease_id"]))
    state = RunState(attempt)
    with state.lock(), lease.use_lock():
        require_available(directory)
        binding = fields(request["binding"], inputs.BINDING)
        run_id = identity(binding["managed_run_id"])
        manifest = lease.manifest()
        receipt = read_private(directory / "managed-credentials.json")
        completed = parse_timestamp(
            read_private(directory / "functional-completion.json")["completed_at"]
        )
        if completed > datetime.now(UTC):
            raise ValueError("functional completion is future-dated")
        pairs = inputs.receipt_pair(receipt["receipts"], binding=binding, now=completed)
        fixture = pairs["fixture"]
        context = read_private(directory / "combined-context.json")
        own = lease.directory / f"use-{run_id}.json"
        if (
            attempt.name != run_id
            or any(context[key] != binding[key] for key in inputs.BINDING & context.keys())
            or any(receipt[key] != binding[key] for key in binding)
            or receipt["receipts_sha256"] != digest(receipt["receipts"])
            or fixture.get("lease_manifest_sha256") != manifest.sha256
            or fixture.get("lease_id") != manifest.lease_id
            or not manifest.policy.retain_after_failure
            or datetime.now(UTC) >= instant(fixture["deadline"])
            or state.cancelled
            or state.status()["qualification"] not in {"failed", "interrupted"}
            or any(lease.directory.glob("close-*.json"))
            or not (lease.directory / "issuer-stopped.json").exists()
            or (lease.directory / f"released-{run_id}.json").exists()
            or read_private(own)
            != {"attempt_id": run_id, "binding_sha256": digest(binding), "kind": "attempt"}
            or any(
                p != own
                and not (
                    lease.directory / ("released-" + p.stem.removeprefix("use-") + ".json")
                ).exists()
                for p in lease.directory.glob("use-*.json")
            )
            or read_private(attempt / "host-drained.json")
            != {"binding_sha256": digest(binding), "drained": True}
            or read_private(attempt / "attempt-started.json")
            != {"binding_sha256": digest(binding), "manifest_sha256": manifest.sha256}
            or Docker().info() != request["daemon"]
        ):
            raise ValueError("finalization lost original exclusive ownership or valid credentials")
        environment = {**safe_environment(), **manifest.targets.environment()}
        ids = fields(fixture["identities_sha256"], set(SECRETS))
        for intent in manifest.intents:
            credential = lease.credential(intent)
            if (
                credential is None
                or datetime.now(UTC) >= instant(intent.deadline)
                or hashlib.sha256(credential.identifier.encode()).hexdigest() != ids[intent.role]
                or lease.created(intent)
                != {"intent_sha256": intent.sha256, "credential_id": credential.identifier}
            ):
                raise ValueError(
                    "finalization credential differs from its original issued identity"
                )
            identifier_name, secret_name = SECRETS[intent.role]
            if identifier_name is not None:
                environment[identifier_name] = credential.identifier
            environment[secret_name] = credential.secret
        require_live(directory)
        yield environment
