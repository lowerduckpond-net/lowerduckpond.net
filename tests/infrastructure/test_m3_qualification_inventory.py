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
REMOTE_GATE_TAG = "m3_qualification_remote_preflight_gate"
QUALIFICATION_ENVIRONMENT = {
    "ANSIBLE_CONFIG": str(REPOSITORY_ROOT / "config/ansible/ansible.cfg"),
    "M3_QUALIFICATION_EXPECTED_IPV4": "192.0.2.1",
    "M3_QUALIFICATION_EXPECTED_DROPLET_ID": "123456789",
    "M3_QUALIFICATION_EXPECTED_RUN_ID": "0198d17f-6f4a-7000-8000-000000000001",
    "M3_QUALIFICATION_EXPECTED_SOURCE_REVISION": "0" * 40,
}


def _run_playbook(inventory: Path, *, tags: str | None = None) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(QUALIFICATION_ENVIRONMENT)
    ansible_playbook = shutil.which("ansible-playbook")
    assert ansible_playbook is not None
    command = [ansible_playbook, "--inventory", str(inventory)]
    if tags is not None:
        command.extend(("--tags", tags))
    command.append(str(PLAYBOOK))
    return subprocess.run(  # noqa: S603 -- the resolved executable and every argument are fixed.
        command,
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_qualification_inventory_resolves_the_exact_target() -> None:
    result = _run_playbook(QUALIFICATION_INVENTORY, tags=PREFLIGHT_TAG)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Require exactly one state-bound qualification target" in result.stdout
    assert "Require successful controller inventory preflight" in result.stdout
    assert "failed=0" in result.stdout


def test_qualification_playbook_rejects_an_inventory_without_its_target() -> None:
    result = _run_playbook(DEVELOPMENT_INVENTORY, tags=PREFLIGHT_TAG)

    assert result.returncode != 0
    assert "Refusing to configure without the exact state-bound M3.0 qualification target" in (
        result.stdout + result.stderr
    )


def test_failed_preflight_blocks_every_remote_target(tmp_path: Path) -> None:
    inventory = tmp_path / "extra-target.yml"
    inventory.write_text(
        """---
all:
  children:
    qualification_nodes:
      hosts:
        m3_qualification:
          ansible_connection: local
        unexpected_qualification:
          ansible_connection: local
""",
        encoding="utf-8",
    )

    result = _run_playbook(inventory)
    output = result.stdout + result.stderr

    assert result.returncode != 0
    assert "Refusing to configure without the exact state-bound M3.0 qualification target" in output
    assert "Read the connected Droplet identity from DigitalOcean metadata" not in output

    forced_continuation = _run_playbook(inventory, tags=REMOTE_GATE_TAG)
    forced_output = forced_continuation.stdout + forced_continuation.stderr

    assert forced_continuation.returncode != 0
    assert "Refusing remote access without a successful M3.0 inventory preflight" in forced_output
    assert "m3_qualification" in forced_output
    assert "unexpected_qualification" in forced_output
    assert "Read the connected Droplet identity from DigitalOcean metadata" not in forced_output
