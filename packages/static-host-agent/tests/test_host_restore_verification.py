from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.host_restore_inputs import RestoreInputs
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreJournal
from lowerduckpond_static_host_agent.host_restore_verification import verify_settled_state
from lowerduckpond_static_host_agent.repository import StateRepository
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - real capture fixture
from test_backup_capture import Capture
from test_backup_inventory import DEPLOYMENT, TENANT
from test_host_restore_mapping import capture as capture  # noqa: PLC0414
from test_host_restore_mapping import configuration as configuration  # noqa: PLC0414
from test_host_restore_mapping import fixture as fixture  # noqa: PLC0414
from test_host_restore_mapping import journal as journal  # noqa: PLC0414
from test_host_restore_mapping import setup


@pytest.mark.parametrize("suspended", [False, True])
@pytest.mark.parametrize("damage", ["none", "release-bytes", "release-missing", "namespace"])
def test_settled_state_requires_complete_selected_release_and_reviewed_platform(  # noqa: PLR0913,PLR0917
    capture: Capture,
    configuration: dict[str, object],
    journal: RestoreJournal,
    tmp_path: Path,
    suspended: bool,
    damage: str,
) -> None:
    _, inputs, _, _ = setup(capture, configuration, journal, tmp_path, suspended=suspended)
    release = capture.roots["content"] / "sites" / TENANT / "releases" / DEPLOYMENT
    if damage == "release-bytes":
        (release / "index.html").write_bytes(b"unrecorded mutation")
    elif damage == "release-missing":
        release.rename(tmp_path / "retained-release")
    elif damage == "namespace":
        altered = deepcopy(inputs.document)
        altered["namespace"] = {}
        inputs = RestoreInputs(altered)
    with StateRepository(
        capture.state.root,
        expected_owner=os.geteuid(),
        tenant_release_root=capture.roots["content"] / "sites",
    ) as repository:

        def verify() -> dict[str, object]:
            return verify_settled_state(
                repository,
                capture.state.root,
                capture.roots["content"],
                inputs,
                capture.state.lineage,
                owner=os.geteuid(),
                content_group=os.getegid(),
            )

        if damage == "none":
            assert verify()["tenantCount"] == 1
        else:
            with pytest.raises((HostRestoreError, BackupIdentityError)):
                verify()
