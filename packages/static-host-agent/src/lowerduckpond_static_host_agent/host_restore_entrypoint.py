"""Fixed administrative commands for fenced source and fresh destination hosts."""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import sys
import time

from lowerduckpond_static_contracts import canonical_json_bytes, validate_uuid7

from lowerduckpond_static_host_agent.backup_restic import inherit_restic_leases
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_activation import activation_pending
from lowerduckpond_static_host_agent.host_restore_authority import require_saved_authority
from lowerduckpond_static_host_agent.host_restore_coordinator import (
    COORDINATOR_SECONDS,
    HostRestore,
)
from lowerduckpond_static_host_agent.host_restore_diagnostics import diagnostic
from lowerduckpond_static_host_agent.host_restore_fence import source_fence_receipt
from lowerduckpond_static_host_agent.host_restore_gate import RECOVERY_ROOT
from lowerduckpond_static_host_agent.host_restore_inputs import (
    INPUT_ROOT,
    RestoreInputs,
    local_machine_id,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    MAX_RESTORE_BYTES,
    RestorePhase,
    RestoreStore,
    full_id,
)
from lowerduckpond_static_host_agent.host_restore_paths import RestorePaths
from lowerduckpond_static_host_agent.host_restore_process import require_command
from lowerduckpond_static_host_agent.host_restore_snapshot import select_restore_snapshot


def restore_cli_main(artifact: str) -> int:
    if os.geteuid() != 0:
        return 77
    parser = argparse.ArgumentParser(prog="restore-static-host")
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--snapshot", type=full_id)
    choice.add_argument("--status", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.snapshot is not None:
            inputs = RestoreInputs.load()
            inputs.require_destination(local_machine_id(), artifact, arguments.snapshot)
            require_command(
                ("/usr/bin/systemctl", "start", "lowerduckpond-host-restore.service"),
                timeout=COORDINATOR_SECONDS + 30,
                failure="restore_service_failed",
            )
        with DurableDirectory.open(
            RECOVERY_ROOT, expected_owner=0, expected_directory_mode=0o700
        ) as directory:
            store = RestoreStore(directory, 0)
            current = store.read()
            status: dict[str, object] = {"phase": "not-started"}
            if current is not None:
                status = {
                    "restoreId": current.restore_id,
                    "snapshotId": current.snapshot_id,
                    "phase": current.phase.value,
                    "activationPending": current.phase is not RestorePhase.COMPLETE
                    or activation_pending(store),
                }
        sys.stdout.buffer.write(canonical_json_bytes(status))
        return 0
    except Exception:
        print("restore_status_or_submission_unverified", file=sys.stderr)
        return 1


def restore_coordinator_main(selection_descriptor: int, artifact: str) -> int:
    if os.geteuid() != 0 or sys.argv[1:]:
        return 64
    deadline = time.monotonic() + COORDINATOR_SECONDS
    try:
        inputs = RestoreInputs.load()
        destination = local_machine_id()
        inputs.require_destination(destination, artifact, inputs.snapshot_id)
        with (
            inherit_restic_leases((9, selection_descriptor)),
            RestoreStore.locked(RECOVERY_ROOT) as store,
        ):
            current = store.read()
            if (
                current is not None
                and current.phase is RestorePhase.COMPLETE
                and not activation_pending(store)
            ):
                saved, _ = require_saved_authority(store)
                if saved != inputs:
                    raise ValueError("restore_completed_target_changed")
                return 0
            snapshot = select_restore_snapshot(inputs.snapshot_id, os.environ)
            with DurableDirectory.open(
                INPUT_ROOT, expected_owner=0, expected_directory_mode=0o700
            ) as directory:
                fence = directory.read_regular(
                    (f"source-fence-{inputs.restore_id}.json",),
                    expected_owner=0,
                    expected_mode=0o600,
                    maximum_bytes=MAX_RESTORE_BYTES,
                )
            caddy_group = grp.getgrnam("caddy").gr_gid
            HostRestore(
                store,
                snapshot,
                inputs,
                RestorePaths(inputs.restore_id, caddy_group),
                os.environ,
                selection_descriptor,
                artifact,
                pwd.getpwnam("caddy").pw_uid,
                destination,
                fence,
                deadline,
            ).run()
    except Exception as error:
        print("host_restore_unverified " + diagnostic(error), file=sys.stderr)
        return 1
    print("host_restore_complete")
    return 0


def source_fence_main(selection_descriptor: int, artifact: str) -> int:
    if os.geteuid() != 0:
        return 77
    parser = argparse.ArgumentParser(prog="fence-static-host")
    parser.add_argument("--snapshot", type=full_id, required=True)
    parser.add_argument("--restore-id", type=validate_uuid7, required=True)
    arguments = parser.parse_args()
    try:
        with (
            inherit_restic_leases((9, selection_descriptor)),
            RestoreStore.locked(RECOVERY_ROOT) as store,
        ):
            snapshot = select_restore_snapshot(arguments.snapshot, os.environ)
            source_fence_receipt(
                store, snapshot, arguments.restore_id, local_machine_id(), artifact
            )
    except Exception:
        print("restore_source_fence_unverified", file=sys.stderr)
        return 1
    # Receipt content remains in its private root file for explicit operator
    # transfer. Neither credentials nor repository locations enter diagnostics.
    print(f"restore_source_fenced {arguments.restore_id}")
    return 0
