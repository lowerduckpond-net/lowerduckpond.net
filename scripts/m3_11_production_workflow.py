"""Execute the original rollout phases through one live controller session."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts import m3_11_production_converge as converge
from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_probe as probe
from scripts.m3_11_production_proposals import Proposals
from scripts.m3_11_production_replica import Replica

ROOT = Path(__file__).resolve().parents[1]


def _document(raw: bytes) -> dict[str, object]:
    result = json.loads(raw, object_pairs_hook=probe.unique_object)
    if type(result) is not dict or journal.canonical(result) != raw:
        raise ValueError("production action returned an invalid observation")
    return cast(dict[str, object], result)


def action(pair: Replica, operation: str, *arguments: str) -> dict[str, object]:
    chain = pair.synchronize()
    result = pair.session.run(
        operation,
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            pair.session.helper,
            operation,
            pair.session.token,
            *arguments,
        ],
        backup=operation in {"backup", "inspect", "observe"},
    )
    if result.status or pair.synchronize() != chain:
        raise ValueError("production action failed or changed its original phase")
    return _document(result.read())


def _drain(pair: Replica, original: dict[str, object]) -> dict[str, object]:
    drained = action(pair, "drain")
    raw_original = pair.synchronize()[0][1]
    if drained != {
        "format": "lowerduckpond-m3-11-predecessor-drain-v1",
        "original_sha256": journal.digest(raw_original),
        "predecessor_sha256": journal.digest(cast(str, original["predecessor"]).encode()),
        "fences": {
            unit: journal.digest(fence.content(raw_original, phase))
            for unit, phase in fence.FENCES.items()
        },
        "active_units": [],
        "external_commands": [],
        "populated_groups": [],
    }:
        raise ValueError("production predecessor did not prove its complete service drain")
    artifact, source, *_ = cast(str, original["predecessor"]).split()
    # Recheck actual empty history, release/routes, artifact and Caddy authority
    # after services have been fenced, using the verified predecessor's reader.
    chain = pair.synchronize()
    result = pair.session.run(
        "drained-host-authority",
        ["/bin/bash", "-s", "--", artifact, "upgrade-host", source],
        data=(ROOT / "scripts/m3-10-completed-host-preflight").read_bytes(),
    )
    if result.status or pair.synchronize() != chain:
        raise ValueError("production drained predecessor authority changed")
    authority = _document(result.read())
    if authority != {
        "format": "lowerduckpond-m3-10-archive-authority-v1",
        "artifactSha256": artifact,
        "sourceRevision": source,
        "archives": [],
    }:
        raise ValueError("production drained predecessor retains unexpected history")
    return {
        "services_sha256": journal.digest(journal.canonical(drained)),
        "static_state_sha256": journal.digest(journal.canonical(authority)),
        "predecessor_sha256": drained["predecessor_sha256"],
    }


def _perform(pair: Replica, phase: str, artifact: Path) -> dict[str, object]:
    chain = pair.synchronize()
    original = cast(dict[str, object], journal.validate(chain)["original"])
    candidate = cast(dict[str, str], original["candidate"])
    if phase == "drained":
        return _drain(pair, original)
    if phase == "namespace":
        converge.playbook(pair, "bootstrap", artifact)
        return action(pair, "initialize", "namespace")
    if phase == "lineage":
        return action(pair, "initialize", "lineage")
    if phase in {"converged", "rotation-enabled"}:
        return converge.converge(pair, artifact, rotation=phase == "rotation-enabled")
    if phase == "backup-verified":
        return action(pair, "backup")
    if phase != "accepted":
        raise ValueError("unsupported production phase")
    accepted = converge.playbook(pair, "accepted", artifact)
    inspect(pair)
    lineage = cast(dict[str, object], _document(dict(chain)["lineage"])["observations"])
    backup = cast(dict[str, object], _document(dict(chain)["backup-verified"])["observations"])
    return {
        "acceptance_sha256": accepted,
        "artifact_sha256": candidate["artifact_sha256"],
        "namespace_sha256": journal.digest(
            journal.canonical(cast(dict[str, object], original["namespace"]))
        ),
        "lineage_sha256": lineage["lineage_sha256"],
        "snapshot_id": backup["snapshot_id"],
        "publication_enabled": False,
    }


def inspect(pair: Replica) -> None:
    chain = pair.synchronize()
    state = journal.validate(chain)
    if state["phase"] not in {"accepted.started", "complete"}:
        raise ValueError("production rollout is not ready for final inspection")
    if action(pair, "inspect") != {
        "format": "lowerduckpond-m3-11-production-inspection-v1",
        "original_sha256": state["original_sha256"],
        "last_sha256": state["last_sha256"],
        "publication_enabled": False,
        "recovery_enabled": True,
        "rotation_enabled": True,
    }:
        raise ValueError("production final inspection did not prove its original authority")


def run(pair: Replica, artifact: Path, proposals: Proposals, guard: Callable[[], None]) -> None:
    """Caller has validated original report/inputs and fresh provider controls."""
    while True:
        guard()
        chain = proposals.recover(pair)
        state = journal.validate(chain)
        if state["phase"] == "complete":
            inspect(pair)
            guard()
            return
        if state["phase"] == "absent":
            raise ValueError("production rollout lacks its original qualified proposal")
        started = str(state["phase"]).endswith(".started")
        phase = (
            str(state["phase"]).removesuffix(".started")
            if started
            else journal.RECORDS[len(chain)].removesuffix(".started")
        )
        observation = _perform(pair, phase, artifact) if started else None
        guard()
        receipt: dict[str, object] = {
            "format": journal.RECEIPT_FORMAT,
            "original_sha256": state["original_sha256"],
            "previous_sha256": state["last_sha256"],
            "phase": phase,
            "observed_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if observation is not None:
            receipt["observations"] = observation
        proposals.publish(
            pair, phase if started else phase + ".started", journal.canonical(receipt)
        )
