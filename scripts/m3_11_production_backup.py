"""Authorize the original production capture inside its leased backup action."""

from __future__ import annotations

import fcntl
import grp
import json
import sys
from pathlib import Path
from typing import cast

from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_initialize as initialize
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as records

CACHE = Path("/var/cache/lowerduckpond-backup")


def _authority(owner: int) -> list[tuple[str, bytes]]:
    chain = records.decode(records.operate(records.ROOT, ["read"], b"", owner=owner))
    if journal.validate(chain)["phase"] != "backup-verified.started":
        raise ValueError("production journal does not authorize a backup proof")
    return chain


def _conditions(original: bytes, owner: int) -> None:
    # Backup/protection timers remain fenced until this proof is acknowledged.
    # Repository EX also serializes independently invoked repository operations.
    for unit, phase in fence.FENCES.items():
        if probe.read(
            fence.UNITS / (unit + ".d") / fence.NAME, owner=owner, mode=0o400
        ) != fence.content(original, phase):
            raise ValueError("production backup lost its original service conditions")
        fence.conditions(unit, phase)


def _candidate(
    chain: list[tuple[str, bytes]], environment: dict[str, str], descriptors: tuple[int, int]
) -> dict[str, str]:
    # The selected artifact has been checked before importing any candidate code.
    from lowerduckpond_static_host_agent.production_backup import BackupAuthority  # noqa: PLC0415
    from lowerduckpond_static_host_agent.production_rollout_backup import run  # noqa: PLC0415

    original = json.loads(chain[0][1])
    candidate = original["candidate"]
    lineage = json.loads(dict(chain)["lineage"])["observations"]
    authority = BackupAuthority(
        original_sha256=journal.digest(chain[0][1]),
        phase_sha256=journal.digest(chain[-1][1]),
        report_sha256=candidate["report_sha256"],
        artifact_sha256=candidate["artifact_sha256"],
        repository_binding=original["repository_binding"],
        lineage_sha256=lineage["lineage_sha256"],
        namespace=original["namespace"],
        launch=None,
    )
    return run(
        CACHE / "m3-11" / original["transaction_id"],
        authority,
        environment,
        descriptors,
        genesis_snapshot_id=lineage["genesis_snapshot_id"],
        audit_head_sha256=lineage["audit_head_sha256"],
        owner=0,
        content_group=grp.getgrnam("caddy").gr_gid,
    )


def verify(*, owner: int = 0) -> bytes:
    """Caller holds the genuine action lease and fixed backup resource profile."""
    with (
        initialize._lock(initialize.REPOSITORY_LOCK, fcntl.LOCK_EX, owner) as repository,
        initialize._lock(initialize.SELECTION_LOCK, fcntl.LOCK_SH, owner) as selection,
    ):
        chain = _authority(owner)
        original = cast(dict[str, object], json.loads(chain[0][1]))
        selected = initialize._host(original, owner)
        _conditions(chain[0][1], owner)
        fence.run(
            ["/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact", str(selected)]
        )
        configuration = probe.read(probe.BACKUP, owner=owner, mode=0o600)
        values = probe.configuration(configuration)
        environment = probe.environment(
            configuration,
            region=values.get("AWS_DEFAULT_REGION", ""),
            locator=values.get("RESTIC_REPOSITORY", ""),
            recovery=True,
            rotation=False,
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
        previous_path = sys.path[:]
        sys.path.insert(0, str(selected / "site-packages"))
        try:
            result = _candidate(chain, environment, (repository, selection))
        finally:
            sys.path[:] = previous_path
        if (
            _authority(owner) != chain
            or initialize._host(original, owner) != selected
            or probe.read(probe.BACKUP, owner=owner, mode=0o600) != configuration
        ):
            raise ValueError("production backup authority changed")
        _conditions(chain[0][1], owner)
        return journal.canonical(dict(result))
