"""Read-only historical membership diagnostics; never authorize cleanup closure."""

from __future__ import annotations

import re
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.connect_checkpoint import FORMAT, Checkpoint
from scripts.m3_11_unattended.github_checkpoint import GitHubArtifacts
from scripts.m3_11_unattended.journal import validate
from scripts.m3_11_unattended.model import Intent, LifecycleError, digest, instant, stamp

AUDIT_SECONDS = 180


def collect(  # noqa: PLR0912 - verify publication, cumulative content and exact membership separately
    checkpoint: Checkpoint, store: GitHubArtifacts, wanted: set[str]
) -> dict[str, object]:
    """Verify cumulative checkpoints and native publications, without inference."""
    if not wanted or any(re.fullmatch(r"[0-9a-f]{64}", key) is None for key in wanted):
        raise LifecycleError("creation audit requires exact intent digests")
    until = time.monotonic() + AUDIT_SECONDS
    history = store.lineage(deadline=until)
    if not history or history[0] != checkpoint.genesis:
        raise LifecycleError("creation audit differs from its original genesis")
    published: dict[int, datetime] = {}
    for row in store._statuses():
        if str(row["context"]).lower() != store.context:
            continue
        selected, _ = store._status_reference(row)
        if selected not in history:
            raise LifecycleError("creation audit registry changed during observation")
        when = instant(row.get("created_at"))
        published[selected.identity] = min(published.get(selected.identity, when), when)
    if published.keys() != {item.identity for item in history}:
        raise LifecycleError("creation audit publication inventory is incomplete")
    previous_records: dict[str, str] = dict(checkpoint.initial)
    rows: list[dict[str, object]] = []
    found: dict[str, str] = {}
    for sequence, selected in enumerate(history, start=1):
        raw = store.read(selected, deadline=until)
        value = fields(raw, {"format", "epoch", "sequence", "previous", "records"})
        parent = history[sequence - 2] if sequence > 1 else None
        if (
            digest(raw) != selected.sha256
            or value["format"] != FORMAT
            or value["epoch"] != checkpoint.epoch
            or type(value["sequence"]) is not int
            or value["sequence"] != sequence
            or value["previous"]
            != ({"identity": parent.identity, "sha256": parent.sha256} if parent else None)
            or not isinstance(value["records"], list)
        ):
            raise LifecycleError("creation audit checkpoint lineage is invalid")
        records = [validate(record) for record in value["records"]]
        current = {str(record["event_id"]): digest(record) for record in records}
        if (
            len(current) != len(records)
            or not previous_records.keys() <= current.keys()
            or any(current[key] != expected for key, expected in previous_records.items())
        ):
            raise LifecycleError("creation audit history removed or changed an event")
        membership = dict.fromkeys(sorted(wanted), False)
        for record in records:
            if record["kind"] != "intent":
                continue
            intent = Intent.parse(record["payload"])
            if intent.sha256 in wanted:
                key = str(record["event_id"])
                if found.get(intent.sha256, key) != key:
                    raise LifecycleError("creation audit has conflicting original intent events")
                found[intent.sha256] = key
                membership[intent.sha256] = True
        rows.append(
            {
                "sequence": sequence,
                "artifact_id": selected.identity,
                "document_sha256": selected.sha256,
                "first_registry_publication": stamp(published[selected.identity]),
                "membership": membership,
            }
        )
        previous_records = current
    if set(found) != wanted or store.lineage(deadline=until) != history:
        raise LifecycleError("creation audit has incomplete or changing history")
    return {
        "status": "observed",
        "epoch": checkpoint.epoch,
        "intent_events": found,
        "checkpoints": rows,
        "limitation": (
            "Historical membership only. No controller clock comparison, "
            "non-submission attestation or cleanup closure is established."
        ),
    }


def retain(
    path: Path, checkpoint: Checkpoint, store: GitHubArtifacts, proof: dict[str, object]
) -> None:
    """Diagnostics follow provider cleanup and cannot erase its result."""
    results = proof.get("results")
    if not isinstance(results, list):
        return
    wanted = {
        str(result["intent_sha256"])
        for result in results
        if isinstance(result, dict) and result.get("status") == "creation-uncertain"
    }
    if not wanted:
        return
    result: dict[str, object] = {"status": "inconclusive"}
    with suppress(Exception):  # No raw exception/provider payload enters diagnostics.
        result = collect(checkpoint, store, wanted)
    with suppress(Exception):  # Missing evidence is inconclusive, never success.
        write_private(
            path,
            {
                "format": "lowerduckpond-m3-11-checkpoint-membership-audit-v1",
                "observed_at": stamp(datetime.now(UTC)),
                **result,
            },
        )
