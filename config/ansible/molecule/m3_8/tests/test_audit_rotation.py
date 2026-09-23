"""Two production-size rotations, lost replies, publication faults and real reboot."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import audit_protection_support as audits
import audit_rotation_support as rotation
import test_backup_identity as identity
import test_lifecycle as support
import test_reboot as reboot
from independent_fixture import require_owned_fixture
from testinfra.host import Host

_TIMERS = (
    f"{rotation.TIMER} lowerduckpond-audit-verify.timer "
    "lowerduckpond-backup.timer lowerduckpond-backup-maintenance.timer"
)


def _assert_bounded_service(host: Host) -> None:
    content = host.run("systemctl cat %s", rotation.UNIT).stdout
    for value in (
        "TimeoutStartSec=5min",
        "MemoryMax=256M",
        "MemorySwapMax=0",
        "TasksMax=32",
        "LimitNOFILE=256",
        "CPUQuota=100%",
        "NoNewPrivileges=true",
        "InaccessiblePaths=-/etc/lowerduckpond/archive",
        "InaccessiblePaths=-/run/lowerduckpond-archive",
    ):
        assert value in content
    for user in ("ldp-provisioner", "ldp-operator"):
        assert host.user(user).exists
        assert (
            host.run(
                "runuser -u %s -- "
                "/usr/local/libexec/lowerduckpond/backup-audit-protection --rotate",
                user,
            ).rc
            != 0
        )
    for argument in ("--forget", "--rotate --force", "--rotate /other"):
        assert (
            host.run("/usr/local/libexec/lowerduckpond/backup-audit-protection " + argument).rc != 0
        )


def _assert_snapshot_inventory(host: Host, before: set[str], rotations: int) -> None:
    snapshots = audits.snapshots(host)
    assert before <= snapshots.keys()
    added = set(snapshots) - before
    assert len(added) == rotations
    for snapshot in added:
        assert "lowerduckpond-audit-archive" in snapshots[snapshot]["tags"]


def _assert_completed_rotation(host: Host, expected: list[str], before: set[str]) -> None:
    assert rotation.archived_digests(host) == expected
    assert not host.file(f"{audits.PREFIX}/rotation-intent.json").exists
    for number in range(len(expected)):
        assert not host.file(f"{audits.ROOT}/audit/segment-{number:020d}.jsonl").exists
    assert host.file(f"{audits.ROOT}/audit/segment-{len(expected):020d}.jsonl").exists
    assert "lowerduckpond_audit_protection_verified 1" in audits.health(host, succeeds=True)
    _assert_snapshot_inventory(host, before, len(expected))


def test_installed_rotation_interruptions_before_reboot(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    assert support._initialize_namespace(host)
    assert not host.service(rotation.TIMER).is_enabled
    audits.run_unit(host, identity.UNIT)
    support._assert_ansible_reapply_result(
        support._run_ansible_reapply(backup_recovery_enabled=True, audit_rotation_enabled=True),
        expected_changes=14,
    )
    assert host.service(rotation.TIMER).is_enabled
    assert "OnCalendar=hourly" in host.run("systemctl cat %s", rotation.TIMER).stdout
    _assert_bounded_service(host)
    # Keep owned failure injection deterministic across the actual restart.
    # Installed policy and service resource envelopes are unchanged.
    assert host.run(f"systemctl disable --now {_TIMERS}").rc == 0
    before = set(audits.snapshots(host))
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    request = support._request(
        "create",
        str(uuid.uuid7()),
        slug=f"m3-rotation-{uuid.uuid7().hex[-12:]}",
        quotas={"storageMiB": 1, "entries": 10},
    )
    created = support._submit(tmp_path, *connection, request)
    assert created["status"] == "succeeded"
    first = rotation.close_full_segment(host)
    assert first["number"] == 0
    source = f"{audits.ROOT}/audit/segment-00000000000000000000.jsonl"
    for point in ("prepared", "lost-response", "witness", "index", "head"):
        rotation.interrupt_rotation(host, point=point, number=0)
        assert host.file(source).size == first["bytes"]
        assert host.run("sha256sum %s", source).stdout.split()[0] == first["sha256"]
        if point != "prepared":
            _assert_snapshot_inventory(host, before, 1)
    rotation.interrupt_rotation(host, point="unlink", number=0)
    intent = json.loads(host.file(f"{audits.PREFIX}/rotation-intent.json").content)
    assert intent["phase"] == "indexed" and not host.file(source).exists
    assert rotation.archived_digests(host) == [first["sha256"]]
    _assert_snapshot_inventory(host, before, 1)
    reboot._preserve_volatile_test_fixtures(host)
    assert host.run("touch /run/lowerduckpond-audit-rotation-reboot").rc == 0
    reboot._write_expectation(
        host,
        {
            "archiveHostsLine": reboot._archive_hosts_line(host),
            "pidOneStartTicks": reboot._pid_one_start_ticks(host),
            "reconcileInvocation": reboot._property(
                host, "lowerduckpond-static-reconcile.service", "InvocationID"
            ),
            "request": request,
            "created": created,
            "first": first,
            "before": sorted(before),
        },
    )


def test_installed_rotation_reboot_and_second_full_segment(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    expected = reboot._read_expectation(host)
    assert not host.file("/run/lowerduckpond-audit-rotation-reboot").exists
    assert reboot._pid_one_start_ticks(host) != expected["pidOneStartTicks"]
    assert (
        reboot._property(host, "lowerduckpond-static-reconcile.service", "InvocationID")
        != expected["reconcileInvocation"]
    )
    reboot._assert_service_state(
        host,
        "lowerduckpond-static-reconcile.service",
        {"ActiveState=inactive", "SubState=dead", "Result=success", "ExecMainStatus=0"},
    )
    reboot._restore_archive_hosts_line(host, expected["archiveHostsLine"])
    reboot._restore_volatile_test_fixtures(host)
    assert host.file(f"{audits.PREFIX}/rotation-intent.json").exists
    audits.run_unit(host, rotation.UNIT)
    before = expected["before"]
    assert type(before) is list and all(type(value) is str for value in before)
    first = expected["first"]
    request = expected["request"]
    created = expected["created"]
    assert type(first) is dict and type(request) is dict and type(created) is dict
    _assert_completed_rotation(host, [str(first["sha256"])], set(before))
    # The post-reboot stage runs in a fresh pytest process with no pacer.
    support._initialize_admission_pacing(host)
    connection = support._operator_inputs(tmp_path)
    assert support._submit(tmp_path, *connection, request) == created
    deletion_request = support._request("delete", str(uuid.uuid7()), tenantId=created["tenantId"])
    deleted = support._submit(tmp_path, *connection, deletion_request)
    assert deleted["status"] == "succeeded"
    second = rotation.close_full_segment(host)
    assert second["number"] == 1
    # A fresh bounded service performs every phase with an existing archived
    # prefix and another real 8-MiB closed source. No test callback is involved.
    rotation.run_bounded_rotation(host)
    _assert_completed_rotation(host, [str(first["sha256"]), str(second["sha256"])], set(before))
    assert support._submit(tmp_path, *connection, request) == created
    assert support._submit(tmp_path, *connection, deletion_request) == deleted
    later = support._submit(
        tmp_path,
        *connection,
        support._request(
            "create",
            str(uuid.uuid7()),
            slug=f"m3-after-rotation-{uuid.uuid7().hex[-12:]}",
            quotas={"storageMiB": 1, "entries": 10},
        ),
    )
    assert later["status"] == "succeeded"
    retired = support._submit(
        tmp_path,
        *connection,
        support._request("delete", str(uuid.uuid7()), tenantId=later["tenantId"]),
    )
    assert retired["status"] == "succeeded"
    assert "lowerduckpond_audit_protected_snapshots 3" in audits.health(host, succeeds=True)
    # Re-enable the configured owned timers only after all injections and
    # historical replays complete; final accounting still runs independently.
    assert host.run(f"systemctl enable --now {_TIMERS}").rc == 0
