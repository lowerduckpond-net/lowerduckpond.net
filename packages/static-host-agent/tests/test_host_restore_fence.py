from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import host_restore_fence as fence
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_gate import restore_admission
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore
from lowerduckpond_static_host_agent.host_restore_services import (
    ORDINARY_ACTIVATORS,
    ORDINARY_SERVICES,
    TEMPLATES,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - pytest fixture
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414


def test_source_fence_precedes_service_control_and_binds_the_transferred_receipt(
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    configuration: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, _ = restic
    root = tmp_path / "source-fence"
    root.mkdir(mode=0o700)
    masks = tuple(sorted((*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES, "caddy.service")))
    events: list[str] = []

    def closed() -> None:
        assert not restore_admission(root, owner=os.geteuid())
        events.append("firewall")

    def quiescent() -> None:
        assert events[-1] == "masked-and-stopped"
        events.append("quiescent")

    def stop() -> tuple[str, ...]:
        assert events[-1] == "firewall"
        events.append("masked-and-stopped")
        return masks

    monkeypatch.setattr(fence, "close_public_ingress", closed)
    monkeypatch.setattr(fence, "quiesce_host", stop)
    monkeypatch.setattr(fence, "require_quiescent", quiescent)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        raw = fence.source_fence_receipt(
            store, snapshot, cast(str, configuration["restoreId"]), "a" * 32, "b" * 64
        )
        assert (
            fence.source_fence_receipt(
                store, snapshot, cast(str, configuration["restoreId"]), "a" * 32, "b" * 64
            )
            == raw
        )
    configuration["repositoryBinding"] = snapshot.identity.binding()
    configuration["sourceFenceDigest"] = framed_digest(fence.FENCE_SCHEMA, raw)
    inputs = RestoreInputs.from_bytes(canonical_json_bytes(configuration))
    assert (
        fence.require_source_fence(raw, inputs, snapshot)["snapshotId"]
        == snapshot.snapshot.snapshot_id
    )
    configuration["sourceMachineId"] = "c" * 32
    with pytest.raises(HostRestoreError, match="fence_mismatch"):
        fence.require_source_fence(
            raw, RestoreInputs.from_bytes(canonical_json_bytes(configuration)), snapshot
        )
    assert not restore_admission(root, owner=os.geteuid(), caddy=True)
