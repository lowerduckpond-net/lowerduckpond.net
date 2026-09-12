from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import test_export_import as exports
from testinfra.host import Host

from config.ansible.molecule.default.tests.test_host import _run_installed_boundary_probe


@pytest.mark.parametrize("operation", ["export", "construction", "cleanup"])
def test_installed_archive_credentials_stay_inside_the_network_boundary(
    host: Host, operation: str
) -> None:
    credential = "/etc/lowerduckpond/archive/credentials.json"
    assert host.file("/etc/lowerduckpond/archive").mode == 0o700  # noqa: PLR2004
    assert host.file(credential).mode == 0o600  # noqa: PLR2004
    assert host.file(credential).user == "root"
    socket_path = f"/run/lowerduckpond-archive/{operation}.sock"
    for account in ("ldp-provisioner", "ldp-operator", "ldp-runtime", "caddy"):
        assert host.run("runuser -u %s -- test -r %s", account, credential).rc != 0
        outcome = host.run(
            "runuser -u %s -- /usr/bin/python3 -I -c %s",
            account,
            f"import socket; socket.socket(socket.AF_UNIX).connect({socket_path!r})",
        )
        assert outcome.rc != 0 and "PermissionError" in outcome.stderr
    probe = exports._selected_python(
        host,
        "import os; "
        "from lowerduckpond_static_host_agent.archive_configuration "
        "import load_archive_configuration; "
        "configuration=load_archive_configuration(); "
        "inventory=configuration.remote_store().inventory(); "
        "assert not inventory.versions and not inventory.multipart_uploads; "
        "assert not os.path.exists('/etc/lowerduckpond/backup.env'); "
        "assert not os.path.exists('/etc/caddy/Caddyfile'); "
        "assert not os.path.exists('/srv/lowerduckpond/sites'); "
        "assert os.statvfs('/').f_flag & os.ST_RDONLY",
    )
    _run_installed_boundary_probe(host, f"lowerduckpond-archive-{operation}@.service", probe)


@pytest.mark.parametrize(
    "unit",
    [
        "lowerduckpond-backup.service",
        "lowerduckpond-backup-maintenance.service",
        "lowerduckpond-static-reconcile.service",
        "lowerduckpond-static-worker@.service",
    ],
)
def test_installed_ordinary_units_cannot_see_archive_credentials(host: Host, unit: str) -> None:
    probe = "import os; assert not os.path.exists('/etc/lowerduckpond/archive/credentials.json')"
    _run_installed_boundary_probe(host, unit, probe)


def test_installed_emergency_recovery_clears_quarantine_without_a_remaining_intent(
    host: Host,
) -> None:
    probe = exports._selected_python(
        host,
        """from pathlib import Path
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.emergency_entrypoint import emergency_delete_main
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.locks import LockName
from lowerduckpond_static_host_agent.repository import StateRepository
root = Path('/var/lib/lowerduckpond/static')
remote = load_archive_configuration().remote_store()
with (
    StateRepository(root, expected_owner=0) as repository,
    ExportSpool(root, expected_owner=0) as spool,
):
    with spool.locks.acquire(LockName.EXPORT, blocking=True):
        assert not repository.measure_intent_records().records
        inventory = remote.inventory()
        assert not inventory.versions and not inventory.multipart_uploads
        quarantine = ArchiveQuarantine(
            root, bucket=remote.bucket, expected_owner=0, locks=spool.locks
        )
        quarantine.record(None)
assert emergency_delete_main(['--recover']) == 0
assert not (root / 'platform/archive-quarantine.json').exists()
""",
    )
    _run_installed_boundary_probe(host, "lowerduckpond-static-emergency-reconcile.service", probe)


def test_installed_idle_emergency_recovery_needs_no_archive_credentials(host: Host) -> None:
    probe = exports._selected_python(
        host,
        "import os; "
        "from lowerduckpond_static_host_agent.emergency_entrypoint import emergency_delete_main; "
        "assert not os.path.exists('/etc/lowerduckpond/archive/credentials.json'); "
        "assert emergency_delete_main(['--recover']) == 0",
    )
    _run_installed_boundary_probe(
        host,
        "lowerduckpond-static-emergency-reconcile.service",
        probe,
        replacements={"BindReadOnlyPaths=/etc/lowerduckpond/archive": ""},
    )


def test_installed_empty_configuration_withdraws_existing_archive_credentials(
    host: Host, tmp_path: Path
) -> None:
    credential = "/etc/lowerduckpond/archive/credentials.json"
    assert host.file(credential).exists
    task_file = Path(__file__).parents[3] / "roles/static_host_agent/tasks/archive_credentials.yml"
    inventory = tmp_path / "withdrawal-inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        "lowerduckpond-ubuntu-2604": {
                            "ansible_connection": "community.docker.docker",
                            "ansible_python_interpreter": "/usr/bin/python3",
                        }
                    }
                }
            }
        )
    )
    withdraw = {
        "name": "Withdraw the configured archive authority",
        "ansible.builtin.include_tasks": str(task_file),
        "vars": {"static_host_agent_archive_configuration": {}},
    }
    playbook = tmp_path / "withdrawal.json"
    playbook.write_text(
        json.dumps(
            [
                {
                    "name": "Qualify archive credential withdrawal on the disposable host",
                    "hosts": "all",
                    "gather_facts": False,
                    "tasks": [
                        {
                            "name": "Retain the private configuration only for restoration",
                            "ansible.builtin.slurp": {"src": credential},
                            "register": "saved_archive_configuration",
                            "no_log": True,
                        },
                        {
                            "name": "Verify withdrawal and restore the fixture",
                            "block": [
                                withdraw,
                                {
                                    "name": "Inspect the withdrawn credential path",
                                    "ansible.builtin.stat": {"path": credential},
                                    "register": "withdrawn_credential",
                                },
                                {
                                    "name": "Require credential withdrawal",
                                    "ansible.builtin.assert": {
                                        "that": "not withdrawn_credential.stat.exists"
                                    },
                                },
                                withdraw,
                                {
                                    "name": "Require idempotent withdrawal",
                                    "ansible.builtin.assert": {
                                        "that": (
                                            "not "
                                            "static_host_agent_archive_credential_withdrawal.changed"
                                        )
                                    },
                                },
                            ],
                            "always": [
                                {
                                    "name": "Restore the private disposable archive configuration",
                                    "ansible.builtin.include_tasks": str(task_file),
                                    "vars": {
                                        "static_host_agent_archive_configuration": (
                                            "{{ saved_archive_configuration.content | "
                                            "b64decode | from_json }}"
                                        )
                                    },
                                    "no_log": True,
                                }
                            ],
                        },
                    ],
                }
            ]
        )
    )
    result = subprocess.run(  # noqa: S603 - fixed task-owned disposable inventory and task file
        [sys.executable, "-m", "ansible.cli.playbook", "-i", str(inventory), str(playbook)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert host.file(credential).exists
    assert host.file(credential).mode == 0o600  # noqa: PLR2004


def test_installed_legacy_selection_disables_only_the_new_service_family(
    host: Host, tmp_path: Path
) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        "lowerduckpond-ubuntu-2604": {
                            "ansible_connection": "community.docker.docker",
                            "ansible_python_interpreter": "/usr/bin/python3",
                        }
                    }
                }
            }
        )
    )
    playbook = tmp_path / "selection.json"
    task_file = Path(__file__).parents[3] / "roles/static_host_agent/tasks/archive_services.yml"
    units = [
        "lowerduckpond-static-emergency-reconcile.timer",
        "lowerduckpond-archive-export.socket",
        "lowerduckpond-archive-construction.socket",
        "lowerduckpond-archive-cleanup.socket",
    ]

    def select(enabled: bool) -> str:
        playbook.write_text(
            json.dumps(
                [
                    {
                        "name": "Exercise the installed archive service selection",
                        "hosts": "all",
                        "gather_facts": False,
                        "vars": {"static_host_agent_archive_lifecycle_enabled": enabled},
                        "tasks": [{"ansible.builtin.include_tasks": str(task_file)}],
                    }
                ]
            )
        )
        result = subprocess.run(  # noqa: S603 - fixed task-owned disposable inventory and task file
            [sys.executable, "-m", "ansible.cli.playbook", "-i", str(inventory), str(playbook)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    try:
        select(False)
        for unit in units:
            assert host.run("systemctl is-active --quiet %s", unit).rc != 0
            assert host.run("systemctl is-enabled --quiet %s", unit).rc != 0
        assert host.run("systemctl is-active --quiet lowerduckpond-static-reconcile.timer").rc == 0
        assert "changed=0" in select(False)
    finally:
        select(True)
    for unit in units:
        assert host.run("systemctl is-active --quiet %s", unit).rc == 0
        assert host.run("systemctl is-enabled --quiet %s", unit).rc == 0
