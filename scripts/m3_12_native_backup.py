"""Native action adapter for the one-time production canary's final backup."""

from __future__ import annotations

import fcntl
import grp
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from lowerduckpond_static_host_agent import production_rollout_backup as rollout
from lowerduckpond_static_host_agent.production_backup import BackupAuthority

from scripts import m3_11_production_initialize as locks
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as predecessor
from scripts.m3_12_backup_evidence import capture_verified_restore
from scripts.m3_12_contracts import CANARY_TRANSACTION, decode, digest, require
from scripts.m3_12_successor import accepted_predecessor

if TYPE_CHECKING:
    from scripts.m3_12_contracts import AdmissionContext, Document
    from scripts.m3_12_native import NativeAuthority
    from scripts.m3_12_successor_journal import SuccessorJournal

CACHE = Path("/var/cache/lowerduckpond-backup")
PREDECESSOR = Path("/var/lib/lowerduckpond/convergence/m3-11")
SELECTION = Path("/opt/lowerduckpond/static-host-agent/current")


def run(
    journal: SuccessorJournal,
    observe: Callable[[], NativeAuthority],
    observe_dark: Callable[[], None],
) -> Document:
    """Caller holds the native action lease in its descendant-tracked systemd unit."""
    owner = os.geteuid()
    require(owner == 0 and journal.owner == owner, "native-backup-root-required")
    with (
        locks._lock(locks.REPOSITORY_LOCK, fcntl.LOCK_EX, owner) as repository,
        locks._lock(locks.SELECTION_LOCK, fcntl.LOCK_SH, owner) as selection,
    ):
        trusted = observe()
        current = journal.snapshot()
        original = decode(current.original, "transaction")
        require(
            original["transactionId"] == trusted.context.transaction_id == CANARY_TRANSACTION
            and current.history.head_sha256 is not None,
            "native-backup-canary-required",
        )
        phase_sha = current.history.head_sha256
        if phase_sha is None:
            raise ValueError("native-backup-phase-required")
        record = predecessor.operate(PREDECESSOR, ["read"], b"", owner=owner)
        chain = predecessor.decode(record)
        accepted, earlier = accepted_predecessor(chain)
        require(accepted == trusted.predecessor, "native-backup-predecessor-changed")
        lineage = json.loads(dict(chain)["lineage"])["observations"]
        namespace = earlier["namespace"]
        require(digest(namespace) == trusted.platform["namespaceSha256"], "native-backup-namespace")
        artifact = trusted.candidate["hostAgentSha256"]
        expected = SELECTION.parent / artifact
        configuration = probe.read(probe.BACKUP, owner=owner, mode=0o600)
        values = probe.configuration(configuration)
        environment = probe.environment(
            configuration,
            region=values.get("AWS_DEFAULT_REGION", ""),
            locator=values.get("RESTIC_REPOSITORY", ""),
            recovery=True,
            rotation=True,
        )
        environment.update(
            {
                "LOWERDUCKPOND_BACKUP_NODE_NAME": probe.NODE,
                "LOWERDUCKPOND_BACKUP_STATUS_SCOPE": values.get(
                    "LOWERDUCKPOND_BACKUP_STATUS_SCOPE", ""
                ),
                "RESTIC_CACHE_DIR": str(CACHE / "restic-cache"),
            }
        )
        authority = BackupAuthority(
            current.history.transaction_sha256,
            phase_sha,
            trusted.context.authority_sha256,
            artifact,
            earlier["repository_binding"],
            lineage["lineage_sha256"],
            namespace,
            None,
        )

        def reopen() -> AdmissionContext:
            fresh = observe()
            require(
                fresh.predecessor == accepted
                and fresh.candidate == trusted.candidate
                and SELECTION.is_symlink()
                and SELECTION.resolve(strict=True) == expected
                and probe.read(probe.BACKUP, owner=owner, mode=0o600) == configuration,
                "native-backup-live-binding-changed",
            )
            observe_dark()
            return fresh.context

        def capture() -> dict[str, str]:
            directory = CACHE / "m3-12"
            rollout._private(directory, owner)
            return rollout.run(
                directory / CANARY_TRANSACTION,
                authority,
                environment,
                (repository, selection),
                genesis_snapshot_id=lineage["genesis_snapshot_id"],
                audit_head_sha256=lineage["audit_head_sha256"],
                owner=owner,
                content_group=grp.getgrnam("caddy").gr_gid,
            )

        receipt, readback = capture_verified_restore(
            journal,
            reopen,
            authority,
            capture,
            now=lambda: datetime.now(UTC),
            expected_index_sha256=lineage["audit_head_sha256"],
        )
        phase = journal.advance("committed", reopen(), readback)
        return {"receipt": receipt, "phase": phase}
