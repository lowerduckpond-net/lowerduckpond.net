"""Fresh paired/provider accounting after the combined public recovery phase."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import audit_protection_support as audits
from lowerduckpond_m3_archive.storage import assert_storage_empty
from public_ca_recovery import PublicRecovery
from restore_fixture import RECOVERY, checked
from test_export_import import _selected_python

from scripts import m3_11_pending_probe as pending
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_phase_receipts import Recorder
from scripts.m3_11_private_inputs import read_private, write_private


def _source_inputs(public: PublicRecovery) -> dict[str, object]:
    fixture = public.fixture
    owned.source_fenced(fixture.environment)
    body = (
        f"exec(compile({Path(pending.__file__).read_bytes()!r}, 'm3_11_pending_probe.py', 'exec'))"
    )
    value = json.loads(checked(fixture.source, _selected_python(fixture.source, body)))
    result = evidence.fields(value, {"sha256", "files", "bytes"})
    evidence.digest(result["sha256"])
    counts = evidence.fields(result["files"], set(pending.ROOTS))
    for count in counts.values():
        evidence.count(count, minimum=0, maximum=pending.MAX_ENTRIES)
    # The reconstruction explicitly leaves the excluded intake and unacknowledged
    # export on the fenced source. An empty replacement source cannot qualify.
    if counts["intake"] == 0 or counts["exports"] == 0:
        raise ValueError("fenced source lost the original excluded pending inputs")
    evidence.count(result["bytes"], minimum=1, maximum=pending.MAX_BYTES)
    return result


def _protection(public: PublicRecovery, reconstruction: dict[str, object]) -> dict[str, object]:
    actual = evidence.fields(
        json.loads(
            audits.root_agent(
                public.fixture.destination,
                """
import hashlib
from lowerduckpond_static_host_agent.audit_archive_coordinator import (
    ProtectionPaths, verify_archive,
)
with inherit_restic_leases((9, selection)):
    verified = verify_archive(ProtectionPaths(), os.environ, expected_owner=0, expected_group=0)
    index = Path('/var/lib/lowerduckpond/static/audit/archive/index-00000000000000000001.json')
    print(json.dumps({
        'protected_segments': len(verified.local.prefix.segments),
        'index_sha256': hashlib.sha256(index.read_bytes()).hexdigest(),
        'inventory': verified.proof.inventory_digest,
        'snapshot_ids': list(verified.proof.snapshot_ids),
    }))
""",
            )
        ),
        {"protected_segments", "index_sha256", "inventory", "snapshot_ids"},
    )
    if any(actual[key] != reconstruction[key] for key in ("protected_segments", "index_sha256")):
        raise ValueError("final protected history differs from the reconstructed original")
    return actual


def run(
    public: PublicRecovery,
    storage: LiveStorage,
    recorder: Recorder,
    reconstruction: dict[str, object],
) -> dict[str, object]:
    """Caller still must prove pytest completion before any destructive teardown."""
    fixture, directory = public.fixture, public.directory
    with recorder.phase("paired-accounting") as observations:
        public._identity()
        if (
            fixture.live_storage is not storage
            or read_private(directory / "public-ca.json")["context_sha256"] != public.context_sha256
        ):
            raise ValueError("final accounting requires the original completed public proof")
        before = _source_inputs(public)
        pair = owned.paired_proof(fixture.environment)
        protection = _protection(public, reconstruction)
        _, observer = storage.target.clients(storage.environment)
        assert_storage_empty(observer, bucket=storage.target.archive_bucket)
        if _source_inputs(public) != before or owned.paired_proof(fixture.environment) != pair:
            raise ValueError("paired accounting changed during independent provider observation")
        fence = fixture.source.file(f"{RECOVERY}/source-fence-{fixture.restore_id}.json").content
        if fence != fixture.fence:
            raise ValueError("original source fencing receipt changed")
        public._identity()
        accounting = {
            **dict.fromkeys(evidence.ZERO_ACCOUNTING, 0),
            "source_state": "fenced",
            "source_fence_sha256": hashlib.sha256(fence).hexdigest(),
            "source_pending_inputs_sha256": before["sha256"],
            "destination_quarantine": False,
        }
        details: dict[str, object] = {
            "context_sha256": public.context_sha256,
            "identities": pair,
            "source_pending_inputs": before,
            "protected_history": protection,
            "accounting": accounting,
        }
        write_private(directory / "paired-accounting.json", details)
        observations.update(details)
    return accounting
