"""Regression tests for the fail-closed M3.0 Ansible inventory."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PLAYBOOK = REPOSITORY_ROOT / "config/ansible/playbooks/m3-qualification.yml"
QUALIFICATION_INVENTORY = REPOSITORY_ROOT / "config/ansible/inventories/qualification/hosts.yml"
DEVELOPMENT_INVENTORY = REPOSITORY_ROOT / "config/ansible/inventories/development/hosts.yml"
PREFLIGHT_TAG = "m3_qualification_inventory_preflight"
QUALIFICATION_ENVIRONMENT = {
    "ANSIBLE_CONFIG": str(REPOSITORY_ROOT / "config/ansible/ansible.cfg"),
    "M3_QUALIFICATION_EXPECTED_IPV4": "192.0.2.1",
    "M3_QUALIFICATION_EXPECTED_DROPLET_ID": "123456789",
    "M3_QUALIFICATION_EXPECTED_RUN_ID": "0198d17f-6f4a-7000-8000-000000000001",
    "M3_QUALIFICATION_EXPECTED_SOURCE_REVISION": "0" * 40,
}


def _run_preflight(inventory: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(QUALIFICATION_ENVIRONMENT)
    ansible_playbook = shutil.which("ansible-playbook")
    assert ansible_playbook is not None
    return subprocess.run(  # noqa: S603 -- the resolved executable and every argument are fixed.
        [
            ansible_playbook,
            "--inventory",
            str(inventory),
            "--tags",
            PREFLIGHT_TAG,
            str(PLAYBOOK),
        ],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_qualification_inventory_resolves_the_exact_target() -> None:
    result = _run_preflight(QUALIFICATION_INVENTORY)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Require exactly one state-bound qualification target" in result.stdout
    assert "failed=0" in result.stdout


def test_qualification_playbook_rejects_an_inventory_without_its_target() -> None:
    result = _run_preflight(DEVELOPMENT_INVENTORY)

    assert result.returncode != 0
    assert "Refusing to configure without the exact state-bound M3.0 qualification target" in (
        result.stdout + result.stderr
    )
