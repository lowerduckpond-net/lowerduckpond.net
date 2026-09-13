from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


@pytest.mark.parametrize("rollback", ["", "/private/reviewed-m3-5-artifact.tar"])
def test_production_inventory_disables_new_services_for_the_explicit_legacy_artifact(
    tmp_path: Path, rollback: str
) -> None:
    playbook = tmp_path / "selection.json"
    playbook.write_text(
        json.dumps(
            [
                {
                    "name": "Prove production artifact capability selection without remote access",
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars_files": [
                        str(ROOT / "config/ansible/roles/static_host_agent/defaults/main.yml"),
                        str(
                            ROOT
                            / "config/ansible/inventories/production/group_vars/hosting_nodes.yml"
                        ),
                    ],
                    "tasks": [
                        {
                            "ansible.builtin.assert": {
                                "that": [
                                    "static_host_agent_archive_lifecycle_enabled is boolean",
                                    "static_host_agent_archive_lifecycle_enabled == "
                                    + ("false" if rollback else "true"),
                                    "static_host_agent_archive_configuration is mapping",
                                    (
                                        "static_host_agent_archive_configuration == {}"
                                        if rollback
                                        else "static_host_agent_archive_configuration.accessKeyId "
                                        "== 'fixture-archive-key'"
                                    ),
                                ]
                            }
                        }
                    ],
                }
            ]
        )
    )
    result = subprocess.run(  # noqa: S603 - localhost-only playbook, no production state or contact
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "--inventory",
            "localhost,",
            "--connection",
            "local",
            str(playbook),
        ],
        env={
            **os.environ,
            "M3_DARK_HOST_ROLLBACK_ARTIFACT_PATH": rollback,
            "SPACES_ARCHIVE_ACCESS_KEY_ID": "fixture-archive-key",
            "SPACES_ARCHIVE_SECRET_ACCESS_KEY": "fixture-archive-secret",
        },
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
