from __future__ import annotations

from copy import deepcopy

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.host_restore_audit import require_captured_timeline
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from test_audit_archive_formats import descriptor, entry


@pytest.mark.parametrize("fault", [None, "future", "crossing", "terminal", "lineage", "binding"])
def test_remote_rotation_never_replays_future_entries_into_old_tenant_state(
    fault: str | None,
) -> None:
    record = descriptor(canonical_json_bytes(entry()))
    backup: dict[str, object] = {
        "lineage": {
            "lineageId": record["lineageId"],
            "repositoryBinding": record["repositoryBinding"],
        },
        "audit": {"entryCount": 1, "terminalEntryDigest": record["terminalEntryDigest"]},
    }
    changed = deepcopy(record)
    if fault == "future":
        backup["audit"] = {"entryCount": 0, "terminalEntryDigest": None}
    elif fault == "crossing":
        changed["entryCount"] = 2
        changed["lastSequence"] = 1
    elif fault == "terminal":
        backup["audit"] = {"entryCount": 1, "terminalEntryDigest": None}
    elif fault == "lineage":
        backup["lineage"] = {
            "lineageId": "another-lineage",
            "repositoryBinding": record["repositoryBinding"],
        }
    elif fault == "binding":
        backup["lineage"] = {"lineageId": record["lineageId"], "repositoryBinding": None}
    if fault is None:
        require_captured_timeline([changed], backup)
    else:
        with pytest.raises(HostRestoreError):
            require_captured_timeline([changed], backup)
