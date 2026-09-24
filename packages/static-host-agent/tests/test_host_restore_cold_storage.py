from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.host_restore_cold_storage import require_cold_storage
from lowerduckpond_static_host_agent.host_restore_journal import (
    PHASES,
    HostRestoreError,
    RestoreJournal,
    RestorePhase,
    RestoreStore,
)
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414


def test_cold_storage_receipt_requires_empty_source_and_keeps_acquired_state_after_start(
    root: Path, journal: RestoreJournal, tmp_path: Path
) -> None:
    storage = tmp_path / "caddy"
    storage.mkdir(mode=0o700)
    with RestoreStore.locked(root, owner=os.geteuid()) as store:
        store.begin(journal)
        stale = storage / "stale-account"
        stale.write_bytes(b"preserved unknown account")
        with pytest.raises(HostRestoreError, match="not_fresh"):
            require_cold_storage(store, storage, caddy_owner=os.geteuid(), caddy_group=os.getegid())
        assert stale.read_bytes() == b"preserved unknown account"
        stale.unlink()  # Fixture operator explicitly prepares a fresh destination.
        receipt = require_cold_storage(
            store, storage, caddy_owner=os.geteuid(), caddy_group=os.getegid()
        )
        for phase in PHASES[1 : PHASES.index(RestorePhase.INSTALLED)]:
            journal = store.advance(journal, phase, {})
            assert (
                require_cold_storage(
                    store, storage, caddy_owner=os.geteuid(), caddy_group=os.getegid()
                )
                == receipt
            )
        stale.write_bytes(b"unadmitted issuance")
        with pytest.raises(HostRestoreError, match="before_installation"):
            require_cold_storage(store, storage, caddy_owner=os.geteuid(), caddy_group=os.getegid())
        stale.rename(tmp_path / "retained-unadmitted-issuance")
        journal = store.advance(journal, RestorePhase.INSTALLED, {})
        stale.write_bytes(b"acquired account")
        assert (
            require_cold_storage(store, storage, caddy_owner=os.geteuid(), caddy_group=os.getegid())
            == receipt
        )
        assert stale.read_bytes() == b"acquired account"
        storage.rename(tmp_path / "retained-caddy")
        storage.mkdir(mode=0o700)
        with pytest.raises(HostRestoreError, match="identity_changed"):
            require_cold_storage(store, storage, caddy_owner=os.geteuid(), caddy_group=os.getegid())
        assert (tmp_path / "retained-caddy/stale-account").read_bytes() == b"acquired account"
