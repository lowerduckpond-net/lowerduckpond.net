"""Fixed-source Restic capture and independent recovery-descriptor readback."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final, cast

from lowerduckpond_static_contracts import decode_json_object

from lowerduckpond_static_host_agent.backup_descriptor import (
    MAX_BACKUP_DESCRIPTOR_BYTES,
    decode_backup_descriptor,
)
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import _restic, _run_restic, discover_repository
from lowerduckpond_static_host_agent.backup_sources import EXCLUDE_PATHS, SOURCE_PATHS, STAGED_PATHS

STATIC_BACKUP_TAG: Final = "lowerduckpond-static-backup"
CAPTURE_TIMEOUT_SECONDS: Final = 30 * 60
_MAX_CAPTURE_OUTPUT: Final = 32 * 1024
_HEX: Final = re.compile(r"[0-9a-f]{64}", re.ASCII)


def create_coherent_snapshot(raw: bytes, environment: Mapping[str, str]) -> str:
    """Caller holds repository/selection/publication/state through this call.

    A partial Restic snapshot (exit 3), lost response, ambiguous capture identity,
    or failed independent readback never records local backup success. There is
    no retry, ordinary snapshot deletion, or missing-lineage initialization.
    """

    document = decode_backup_descriptor(raw)
    lineage = cast(dict[str, object], document["lineage"])
    repository = cast(dict[str, object], lineage["repository"])
    binding = cast(dict[str, str], lineage["repositoryBinding"])
    scope = environment.get("LOWERDUCKPOND_BACKUP_STATUS_SCOPE", "")
    if (
        _HEX.fullmatch(scope) is None
        or environment.get("LOWERDUCKPOND_BACKUP_NODE_NAME") != repository["nodeName"]
    ):
        raise BackupIdentityError("backup capture configuration is unbound")
    capture_tag = f"capture-{document['captureId']}"
    tags = (
        "scheduled",
        f"scope-{scope}",
        STATIC_BACKUP_TAG,
        capture_tag,
        f"lineage-{lineage['lineageId']}",
        f"repository-{binding['value']}",
    )
    arguments = ["backup", "--json", "--quiet", "--host", cast(str, repository["nodeName"])]
    for tag in tags:
        arguments.extend(("--tag", tag))
    for exclusion in EXCLUDE_PATHS:
        arguments.extend(("--exclude", exclusion))
    arguments.extend((*SOURCE_PATHS.values(), *STAGED_PATHS.values()))
    output = _run_restic(
        tuple(arguments),
        environment,
        _MAX_CAPTURE_OUTPUT,
        None,
        timeout_seconds=CAPTURE_TIMEOUT_SECONDS,
    )
    summary = decode_json_object(output, maximum_bytes=_MAX_CAPTURE_OUTPUT)
    snapshot_id = summary.get("snapshot_id")
    if (
        summary.get("message_type") != "summary"
        or type(snapshot_id) is not str
        or _HEX.fullmatch(snapshot_id) is None
    ):
        raise BackupIdentityError("backup capture did not return a full snapshot identity")
    identity, snapshots = discover_repository(environment)
    candidates = [snapshot for snapshot in snapshots if capture_tag in snapshot.tags]
    if (
        identity.document() != repository
        or len(candidates) != 1
        or candidates[0].snapshot_id != snapshot_id
        or candidates[0].hostname != identity.node_name
        or set(candidates[0].tags) != set(tags)
    ):
        raise BackupIdentityError("backup snapshot identity is ambiguous or unbound")
    restored = _restic(
        ("dump", snapshot_id, STAGED_PATHS["descriptor"]),
        environment,
        MAX_BACKUP_DESCRIPTOR_BYTES,
    )
    if restored != raw:
        raise BackupIdentityError("backup descriptor readback disagrees with captured authority")
    return snapshot_id
