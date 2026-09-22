"""Real installed protected proof and retention, before rotation is enabled."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import audit_protection_support as audits
import test_backup_identity as identity
import test_lifecycle as support
from independent_fixture import require_owned_fixture
from testinfra.host import Host

TIMERS = (
    "lowerduckpond-audit-verify.timer lowerduckpond-backup.timer "
    "lowerduckpond-backup-maintenance.timer"
)


def _boundaries(host: Host) -> None:
    for unit, timeout, memory, descriptors in (
        (audits.VERIFY_UNIT, "5min", "256M", "256"),
        (audits.MAINTENANCE_UNIT, "30min", "512M", "1024"),
    ):
        contents = host.run("systemctl cat %s", unit).stdout
        for line in (
            f"TimeoutStartSec={timeout}",
            f"MemoryMax={memory}",
            f"LimitNOFILE={descriptors}",
            "MemorySwapMax=0",
            "TasksMax=32",
            "CPUQuota=100%",
            "NoNewPrivileges=true",
            "InaccessiblePaths=-/etc/lowerduckpond/archive",
            "InaccessiblePaths=-/run/lowerduckpond-archive",
        ):
            assert line in contents
    for command in ("backup-audit-agent", "backup-audit-protection", "check-audit-protection"):
        path = f"/usr/local/libexec/lowerduckpond/{command}"
        assert host.file(path).user == "root" and host.file(path).mode == 0o700  # noqa: PLR2004
        assert host.run("runuser -u ldp-provisioner -- %s --verify", path).rc != 0
    assert host.run("/usr/local/libexec/lowerduckpond/backup-audit-agent --maintain").rc != 0
    assert host.run("/usr/local/libexec/lowerduckpond/backup-audit-protection --prune").rc != 0
    assert not host.file("/etc/systemd/system/lowerduckpond-audit-rotate.timer").exists


def _snapshot_file_fault(host: Host, snapshot: str, *, missing: bool | None) -> None:
    audits.root_agent(
        host,
        f"""
from lowerduckpond_static_host_agent.audit_archive_formats import full_snapshot_id
repository = Path(os.environ['RESTIC_REPOSITORY'])
assert repository == Path('/mnt/lowerduckpond-restic-test')
path = repository / 'snapshots' / full_snapshot_id({snapshot!r})
saved = Path('/var/cache/lowerduckpond-backup/audit/fault-snapshot-original')
raw = path.read_bytes()
assert len(raw) < 1024 * 1024 and not saved.exists()
with saved.open('xb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
saved.chmod(0o600)
if {missing!r}:
    path.unlink()
elif {missing!r} is False:
    changed = bytearray(raw)
    changed[-1] ^= 1
    path.write_bytes(changed)
parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
os.fsync(parent)
os.close(parent)
""",
    )


def _restore_snapshot_file(host: Host, snapshot: str, extra_ids: tuple[str, ...] = ()) -> None:
    audits.root_agent(
        host,
        f"""
from lowerduckpond_static_host_agent.audit_archive_formats import full_snapshot_id
repository = Path(os.environ['RESTIC_REPOSITORY'])
assert repository == Path('/mnt/lowerduckpond-restic-test')
path = repository / 'snapshots' / full_snapshot_id({snapshot!r})
saved = Path('/var/cache/lowerduckpond-backup/audit/fault-snapshot-original')
raw = saved.read_bytes()
assert len(raw) < 1024 * 1024
with path.open('wb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
path.chmod(0o600)
for value in {extra_ids!r}:
    (repository / 'snapshots' / full_snapshot_id(value)).unlink()
parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
os.fsync(parent)
os.close(parent)
saved.unlink()
""",
    )


def _snapshot_file_ids(host: Host) -> list[str]:
    return json.loads(
        audits.root_agent(
            host,
            """
repository = Path(os.environ['RESTIC_REPOSITORY'])
assert repository == Path('/mnt/lowerduckpond-restic-test')
print(json.dumps(sorted(path.name for path in (repository / 'snapshots').iterdir())))
""",
        )
    )


def _failed_proof_preserves_ordinary_ids_and_index(
    host: Host, selected: str, ordinary: str
) -> None:
    original = host.file(f"{audits.PREFIX}/index-00000000000000000000.json").content
    for missing in (True, False):
        _snapshot_file_fault(host, selected, missing=missing)
        try:
            before = _snapshot_file_ids(host)
            assert ordinary in before
            audits.run_unit(host, audits.MAINTENANCE_UNIT, succeeds=False)
            assert _snapshot_file_ids(host) == before
            assert host.file(f"{audits.PREFIX}/index-00000000000000000000.json").content == original
            assert not host.file(f"{audits.PREFIX}/maintenance-intent.json").exists
            assert "lowerduckpond_audit_protection_verified 0" in audits.health(
                host, succeeds=False
            )
        finally:
            _restore_snapshot_file(host, selected)
    audits.run_unit(host, audits.VERIFY_UNIT)


def _scheduled_retag_cannot_make_indexed_evidence_ordinary(
    host: Host, selected: str, ordinary: str
) -> None:
    # Preserve the exact encrypted fixture object privately. Restic retagging
    # creates a different snapshot ID, so retagging back is not exact-ID repair.
    _snapshot_file_fault(host, selected, missing=None)
    before = set(audits.snapshots(host))
    identity._restic(host, f"tag --add scheduled {selected}")
    changed = audits.snapshots(host)
    replacement = tuple(sorted(set(changed) - before))
    assert len(replacement) == 1 and selected not in changed
    try:
        assert "scheduled" in changed[replacement[0]]["tags"]
        audits.run_unit(host, audits.MAINTENANCE_UNIT, succeeds=False)
        assert set(audits.snapshots(host)) == set(changed)
        assert ordinary in changed
    finally:
        _restore_snapshot_file(host, selected, replacement)
    audits.run_unit(host, audits.VERIFY_UNIT)


def test_installed_audit_protection_reconciles_orphans_and_preserves_retention(  # noqa: PLR0915
    host: Host, tmp_path: Path
) -> None:
    require_owned_fixture()
    assert support._initialize_namespace(host)
    # Bootstrap the supported empty lineage, then activate publication and
    # coherent backup together. Nonempty-lineage migration is independently
    # qualified by backup-coherence; the real tenant history below still spans
    # the archived prefix and its local successor.
    audits.run_unit(host, identity.UNIT)
    support._assert_ansible_reapply_result(
        support._run_ansible_reapply(backup_recovery_enabled=True), expected_changes=8
    )
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    created = support._submit(
        tmp_path,
        *connection,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=f"m3-audit-{uuid.uuid7().hex[-12:]}",
            quotas={"storageMiB": 1, "entries": 10},
        ),
    )
    assert created["status"] == "succeeded"
    _boundaries(host)
    assert host.service("lowerduckpond-audit-verify.timer").is_enabled
    assert host.run(f"systemctl stop {TIMERS} {audits.VERIFY_UNIT}").rc == 0
    try:
        metadata = audits.stage_closed_segment(host)
        assert type(metadata["bytes"]) is int
        assert 8 * 1024 * 1024 - 16384 < metadata["bytes"] <= 8 * 1024 * 1024
        first = audits.snapshot(host, metadata, "2000-01-01 00:00:00")
        second = audits.snapshot(host, metadata, "2000-01-02 00:00:00")
        assert first != second
        assert json.loads(host.file(f"{audits.PREFIX}/head.json").content)["indexCount"] == 0
        # No durable attempt response/ID is available: discovery must restore
        # both equivalent candidates before selecting and indexing either one.
        assert not host.file(f"{audits.PREFIX}/rotation-intent.json").exists
        audits.run_unit(host, audits.VERIFY_UNIT)
        index = json.loads(host.file(f"{audits.PREFIX}/index-00000000000000000000.json").content)
        selected = min(first, second)
        assert index["snapshotId"] == selected
        duplicates = json.loads(host.file(f"{audits.PREFIX}/duplicates.json").content)
        assert duplicates["entries"][0]["snapshotIds"] == [max(first, second)]
        assert host.file(f"{audits.ROOT}/audit/segment-00000000000000000000.jsonl").exists
        assert "lowerduckpond_audit_protected_snapshots 3" in audits.health(host, succeeds=True)

        deleted = support._submit(
            tmp_path,
            *connection,
            support._request(
                "delete",
                str(uuid.uuid7()),
                tenantId=created["tenantId"],
            ),
        )
        assert deleted["status"] == "succeeded"  # real historical reader across the indexed overlap
        assert (
            host.run(
                "install -m 0600 /dev/null /var/cache/lowerduckpond-backup/audit/ordinary-fixture"
            ).rc
            == 0
        )
        ordinary = [
            audits.ordinary_snapshot(host, str(metadata["node"]), f"2020-01-01 0{hour}:00:00")
            for hour in (1, 2, 3)
        ]
        _failed_proof_preserves_ordinary_ids_and_index(host, selected, ordinary[1])
        _scheduled_retag_cannot_make_indexed_evidence_ordinary(host, selected, ordinary[1])

        audits.interrupt_maintenance(host, phase="forgotten")
        intent = json.loads(host.file(f"{audits.PREFIX}/maintenance-intent.json").content)
        assert intent["phase"] == "forgotten" and intent["removeIds"] == [ordinary[1]]
        assert ordinary[1] not in audits.snapshots(host)
        # Newly eligible work cannot expand the durable remove set after restart.
        additional = audits.ordinary_snapshot(host, str(metadata["node"]), "2020-01-01 02:30:00")
        audits.interrupt_maintenance(host, phase="pruning")
        intent = json.loads(host.file(f"{audits.PREFIX}/maintenance-intent.json").content)
        assert intent["phase"] == "pruning" and intent["removeIds"] == [ordinary[1]]
        audits.run_unit(host, audits.MAINTENANCE_UNIT)
        remaining = audits.snapshots(host)
        assert {first, second, ordinary[0], ordinary[2], additional} <= set(remaining)
        assert not host.file(f"{audits.PREFIX}/maintenance-intent.json").exists
        assert (
            host.file(f"{audits.PREFIX}/index-00000000000000000000.json").content
            == (json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        assert "lowerduckpond_audit_protection_verified 1" in audits.health(host, succeeds=True)
        assert host.run("systemctl start lowerduckpond-health.service").rc == 0
        assert host.file("/var/lib/prometheus/node-exporter/lowerduckpond.prom").contains(
            "lowerduckpond_audit_protected_snapshots 3"
        )
    finally:
        assert host.run(f"systemctl start {TIMERS}").rc == 0
