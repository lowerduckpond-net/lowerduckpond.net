"""One real backup/rotation/restore history, reused by local and live qualification."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from contextlib import nullcontext
from pathlib import Path

import audit_protection_support as audits
import audit_rotation_support as rotation
import backup_capture_support as captures
import restore_scenarios as restore
import test_audit_rotation as rotation_checks
import test_backup_coherence as backups
import test_backup_identity as identity
import test_lifecycle as support
from restore_fixture import RECOVERY, UNIT, Fixture
from testinfra.host import Host

from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_phase_receipts import Recorder
from scripts.m3_11_qualification_evidence import canonical_bytes


def run(
    host: Host,
    tmp_path: Path,
    *,
    live_storage: LiveStorage | None = None,
    recorder: Recorder | None = None,
    existing_namespace: bool = False,
) -> tuple[Fixture, dict[str, object]]:
    """The same actual assertions serve independent, complete and live callers."""
    with recorder.phase("backup-mutation-overlap") if recorder else nullcontext({}) as observations:
        history, overlap = backup_mutation(
            host, tmp_path, live_storage=live_storage, existing_namespace=existing_namespace
        )
        observations.update(overlap)
    with recorder.phase("protected-rotation") if recorder else nullcontext({}) as observations:
        rotated = protected_rotation(host, tmp_path, history)
        observations.update(rotated)
    with recorder.phase("reconstruction") if recorder else nullcontext({}) as observations:
        fixture, restored = reconstruction(host, tmp_path, history, live_storage=live_storage)
        observations.update(restored)
    with recorder.phase("reboot") if recorder else nullcontext({}) as observations:
        observations.update(reboot_and_replay(fixture, history))
    return fixture, {
        **restored,
        "protected_segments": rotated["protected_segments"],
        "index_sha256": rotated["index_sha256"],
    }


def backup_mutation(
    host: Host,
    tmp_path: Path,
    *,
    live_storage: LiveStorage | None = None,
    existing_namespace: bool = False,
) -> tuple[restore.SourceHistory, dict[str, object]]:
    if live_storage is not None:
        live_storage.require_source(os.environ)
    elif os.environ.get("M3_10_ARCHIVE_BACKEND", "minio") != "minio":
        raise ValueError("combined Spaces mutation requires its explicit owned storage inputs")
    restore.activate_source(host, archived_prefix=True, existing_namespace=existing_namespace)
    history = restore.prepare_history(host, tmp_path, retain_existing=existing_namespace)
    backups._source_exclusion_canaries(host)
    request = support._request(
        "rename",
        str(uuid.uuid7()),
        tenantId=history.tenants[0],
        slug=f"combined-{uuid.uuid7().hex[-12:]}",
    )
    job = support._issue_without_handoff(host, request)
    result, descriptor = captures.race_job(host, job)
    assert result["status"] == "succeeded"
    assert {item["tenantId"] for item in descriptor["tenants"]} == set(history.tenants)
    return history, {
        "descriptor_sha256": hashlib.sha256(canonical_bytes(descriptor)).hexdigest(),
        "mutation_result_sha256": hashlib.sha256(canonical_bytes(result)).hexdigest(),
        "tenant_count": len(history.tenants),
    }


def protected_rotation(
    host: Host, tmp_path: Path, history: restore.SourceHistory
) -> dict[str, object]:
    # Keep periodic work from racing the deliberate process exits. The installed
    # service policies, production segment size, and timeout bounds are unchanged.
    assert (
        host.run(
            "systemctl stop lowerduckpond-backup.timer lowerduckpond-backup-maintenance.timer "
            "lowerduckpond-audit-verify.timer lowerduckpond-audit-rotate.timer"
        ).rc
        == 0
    )
    rotation_checks._assert_bounded_service(host)
    before = set(audits.snapshots(host))
    digests = []
    for number, point in enumerate(("lost-response", "index")):
        closed = rotation.close_full_segment(host)
        assert closed["number"] == number
        rotation.interrupt_rotation(host, point=point, number=number)
        assert host.file(f"{audits.PREFIX}/rotation-intent.json").exists
        rotation.run_bounded_rotation(host)
        digests.append(str(closed["sha256"]))
        rotation_checks._assert_completed_rotation(host, digests, before)
    protected = {
        snapshot
        for snapshot, metadata in audits.snapshots(host).items()
        if "lowerduckpond-audit-archive" in metadata["tags"]
    }
    assert len(protected) == 2  # noqa: PLR2004 - two full protected transitions
    index = host.file(f"{audits.PREFIX}/index-00000000000000000001.json").content
    lineage = json.loads(host.file(f"{support.STATE_ROOT}/platform/audit-lineage.json").content)
    assert (
        host.run(
            "install -m 0600 /dev/null /var/cache/lowerduckpond-backup/audit/ordinary-fixture"
        ).rc
        == 0
    )
    ordinary = {
        audits.ordinary_snapshot(
            host, lineage["repository"]["nodeName"], f"2020-01-01 0{hour}:00:00"
        )
        for hour in (1, 2, 3)
    }
    ordinary_before = set(audits.snapshots(host)) - protected
    audits.interrupt_maintenance(host, phase="forgotten")
    intent = json.loads(host.file(f"{audits.PREFIX}/maintenance-intent.json").content)
    removed = set(intent["removeIds"])
    assert removed & ordinary and removed <= ordinary_before and not removed & protected
    audits.interrupt_maintenance(host, phase="pruning")
    assert (
        set(json.loads(host.file(f"{audits.PREFIX}/maintenance-intent.json").content)["removeIds"])
        == removed
    )
    audits.run_unit(host, audits.MAINTENANCE_UNIT)
    remaining = set(audits.snapshots(host))
    assert protected <= remaining and not removed & remaining
    assert host.file(f"{audits.PREFIX}/index-00000000000000000001.json").content == index
    assert not host.file(f"{audits.PREFIX}/maintenance-intent.json").exists
    assert rotation.archived_digests(host) == digests
    assert (
        support._submit(tmp_path, *history.connection, history.replay["request"])
        == history.replay["result"]
    )
    return {
        "protected_segments": len(digests),
        "index_sha256": hashlib.sha256(index).hexdigest(),
        "segment_sha256": digests,
        "ordinary_snapshots_removed": len(removed),
    }


def reconstruction(
    host: Host,
    tmp_path: Path,
    history: restore.SourceHistory,
    *,
    live_storage: LiveStorage | None = None,
) -> tuple[Fixture, dict[str, object]]:
    fixture, tenants, replay = restore.capture_source(
        host, tmp_path, history, live_storage=live_storage
    )
    fixture.fault("dns")
    fixture.start()
    fixture.wait({"installed"})
    fixture.fault_observed("deniedDns")
    restore.gate_closed(fixture)
    assert fixture.destination.run("systemctl stop %s", UNIT).rc == 0
    interrupted = fixture.destination.file(f"{RECOVERY}/host-restore.json").content
    assert fixture.status()["phase"] == "installed"
    fixture.fault("none")
    fixture.start()
    fixture.wait({"complete"}, seconds=300)
    journal = fixture.destination.file(f"{RECOVERY}/host-restore.json").content
    assert journal != interrupted
    assert not fixture.destination.file("/var/lib/lowerduckpond/recovery/restore-gate.json").exists
    assert fixture.destination.service("caddy").is_running
    restore.verify_reconstruction(fixture, replay)
    descriptor_raw = identity._restic(
        host, f"dump {fixture.snapshot} {captures.DESCRIPTOR}"
    ).encode()
    descriptor = json.loads(descriptor_raw)
    assert descriptor == replay["descriptor"]
    states = dict.fromkeys(("active", "suspended", "archived", "undeployed"), 0)
    for tenant in tenants:
        original = host.file(f"{support.STATE_ROOT}/tenants/{tenant}/desired.json").content
        assert (
            fixture.destination.file(f"{support.STATE_ROOT}/tenants/{tenant}/desired.json").content
            == original
        )
        spec = json.loads(original)["spec"]
        state = "undeployed" if spec.get("desiredDeployment") is None else spec["desiredState"]
        states[state] += 1
    assert all(count > 0 for count in states.values())
    releases = sum(len(tenant["releases"]) for tenant in descriptor["tenants"])
    assert releases >= 2  # noqa: PLR2004 - actual retained release inventory
    return fixture, {
        "snapshot_sha256": hashlib.sha256(fixture.snapshot.encode("ascii")).hexdigest(),
        "descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
        "journal_sha256": hashlib.sha256(journal).hexdigest(),
        "tenant_states": states,
        "retained_releases": releases,
    }


def reboot_and_replay(fixture: Fixture, history: restore.SourceHistory) -> dict[str, object]:
    original = fixture.destination.file(f"{RECOVERY}/host-restore.json").content
    fixture.reboot()
    assert fixture.destination.service("caddy").is_running
    assert fixture.destination.file(f"{RECOVERY}/host-restore.json").content == original
    fixture.start()
    fixture.wait({"complete"})
    assert fixture.destination.file(f"{RECOVERY}/host-restore.json").content == original
    return restore.replay_and_retire(fixture, history.tenants, history.replay)
