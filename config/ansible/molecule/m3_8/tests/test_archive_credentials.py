from __future__ import annotations

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import test_export_import as exports
import yaml
from testinfra.host import Host

from config.ansible.molecule.default.tests.test_host import _run_installed_boundary_probe
from scripts.qualification_context import host_name


def test_installed_ordinary_reconciler_cannot_connect_to_archive_services(host: Host) -> None:
    for name in ("export", "construction", "cleanup"):
        assert host.file(f"/run/lowerduckpond-archive/{name}.sock").exists
    _run_installed_boundary_probe(
        host,
        "lowerduckpond-static-reconcile.service",
        """
import socket
for name in ('export', 'construction', 'cleanup'):
    with socket.socket(socket.AF_UNIX) as client:
        try:
            client.connect(f'/run/lowerduckpond-archive/{name}.sock')
        except (PermissionError, FileNotFoundError):
            pass
        else:
            raise AssertionError('ordinary reconciler reached archive authority')
""",
    )


@pytest.mark.parametrize("prepare_before_start", [False, True])
def test_installed_reconciler_masks_entries_created_after_namespace_start(
    host: Host, tmp_path: Path, prepare_before_start: bool
) -> None:
    role = Path(__file__).parents[3] / "roles/static_host_agent"
    tasks = yaml.safe_load((role / "tasks/main.yml").read_text())
    names = [task["name"] for task in tasks]
    prepare = names.index(
        "Create the private archive socket directory before ordinary service isolation"
    )
    assert prepare < names.index("Reconcile the dedicated archive credential")
    assert prepare < names.index("Start bounded static authorization reconciliation")
    # Use an isolated path so this namespace proof cannot disturb real sockets.
    parent = f"/run/lowerduckpond-m3-10-mask-{tmp_path.name}"
    protected = parent + "/archive"
    socket_mask = "InaccessiblePaths=-/run/lowerduckpond-archive"
    assert not host.file(parent).exists
    task = json.loads(json.dumps(tasks[prepare]))
    assert task["ansible.builtin.file"]["path"] == "/run/lowerduckpond-archive"
    task["ansible.builtin.file"]["path"] = protected
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        host_name(): {
                            "ansible_connection": "community.docker.docker",
                            "ansible_python_interpreter": "/usr/bin/python3",
                        }
                    }
                }
            }
        )
    )
    playbook = tmp_path / "prepare.json"
    playbook.write_text(json.dumps([{"hosts": "all", "gather_facts": False, "tasks": [task]}]))
    probe = f"""from pathlib import Path
import time
parent = Path({parent!r})
(parent / 'ready').touch()
deadline = time.monotonic() + 30
while not (parent / 'release').exists():
    assert time.monotonic() < deadline, 'fixture never created its protected entry'
    time.sleep(0.05)
try:
    Path({protected + "/later-entry"!r}).stat()
except (PermissionError, FileNotFoundError):
    pass
else:
    raise AssertionError('archive mask was skipped')
"""
    try:
        host.run_expect([0], "install -d -m 0700 %s", parent)
        if prepare_before_start:
            result = subprocess.run(  # noqa: S603 - actual task, isolated disposable path
                [sys.executable, "-m", "ansible.cli.playbook", "-i", str(inventory), str(playbook)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 0, result.stdout + result.stderr
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                _run_installed_boundary_probe,
                host,
                "lowerduckpond-static-reconcile.service",
                probe,
                replacements={
                    socket_mask: f"InaccessiblePaths=-{protected}",
                    "ProtectSystem=strict": f"ProtectSystem=strict\nReadWritePaths={parent}",
                },
            )
            deadline = time.monotonic() + 30
            while not host.file(parent + "/ready").exists:
                if future.done():
                    future.result()
                assert time.monotonic() < deadline, "reconciler probe did not start"
                time.sleep(0.05)
            host.run_expect([0], "install -d -m 0700 %s", protected)
            host.run_expect([0], "touch %s", protected + "/later-entry")
            host.run_expect([0], "touch %s", parent + "/release")
            if prepare_before_start:
                future.result()
            else:
                # Negative control reproduces systemd skipping an absent '-'
                # mask and exposing entries created after the process started.
                with pytest.raises(pytest.fail.Exception, match="archive mask was skipped"):
                    future.result()
    finally:
        host.run("rm -rf -- %s", parent)


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


@pytest.mark.parametrize(
    "unit",
    [
        "lowerduckpond-backup.service",
        "lowerduckpond-backup-maintenance.service",
        "lowerduckpond-static-reconcile.service",
    ],
)
@pytest.mark.parametrize("written_before_retry", [False, True])
def test_installed_credentials_drain_ordinary_processes_using_the_previous_isolation(
    host: Host, tmp_path: Path, unit: str, written_before_retry: bool
) -> None:
    credential = "/etc/lowerduckpond/archive/credentials.json"
    directory = "/run/lowerduckpond-m3-10-credential-drain"
    dropin = f"/etc/systemd/system/{unit}.d/00-m3-10-install-proof.conf"
    protection = f"/etc/systemd/system/{unit}.d/m3-10-archive-isolation.conf"
    protected_content = (
        "[Service]\nInaccessiblePaths=-/etc/lowerduckpond/archive\n"
        "InaccessiblePaths=-/run/lowerduckpond-archive\n"
    )
    task_file = Path(__file__).parents[3] / "roles/static_host_agent/tasks/archive_credentials.yml"
    install = {
        "name": "Install the saved disposable credential through the production task",
        "ansible.builtin.include_tasks": str(task_file),
        "vars": {
            "static_host_agent_archive_configuration": "{{ saved.content | b64decode | from_json }}"
        },
        "no_log": True,
    }
    proof = f"""import pathlib,time
credential=pathlib.Path({credential!r})
pathlib.Path({directory + "/ready"!r}).touch()
while True:
    if credential.exists():
        pathlib.Path({directory + "/leaked"!r}).touch()
    time.sleep(0.01)
"""
    tasks: list[dict[str, object]] = [
        {"ansible.builtin.file": {"path": credential, "state": "absent"}, "no_log": True},
        {"ansible.builtin.file": {"path": directory, "state": "directory", "mode": "0700"}},
        {
            "ansible.builtin.file": {
                "path": f"/etc/systemd/system/{unit}.d",
                "state": "directory",
                "mode": "0755",
            }
        },
        {"ansible.builtin.file": {"path": protection, "state": "absent"}},
        {
            "ansible.builtin.copy": {
                "content": proof,
                "dest": directory + "/probe.py",
                "mode": "0600",
            }
        },
        {
            "ansible.builtin.copy": {
                "dest": dropin,
                "mode": "0644",
                "content": (
                    "[Service]\nType=simple\nInaccessiblePaths=\nExecStart=\n"
                    f"ExecStart=/usr/bin/python3 {directory}/probe.py\nReadWritePaths={directory}\n"
                ),
            }
        },
        {
            "ansible.builtin.systemd_service": {
                "name": unit,
                "state": "started",
                "daemon_reload": True,
            }
        },
        {"ansible.builtin.wait_for": {"path": directory + "/ready", "timeout": 30}},
    ]
    if written_before_retry:
        # Simulate interruption after writing isolation, before reloading or
        # draining the invocation that still has the older mount namespace.
        tasks.append(
            {
                "ansible.builtin.copy": {
                    "dest": protection,
                    "content": protected_content,
                    "mode": "0644",
                }
            }
        )
    tasks.extend(
        [
            install,
            {
                "ansible.builtin.command": {
                    "argv": ["systemctl", "show", "--property=MainPID", "--value", unit]
                },
                "register": "main_pid",
                "changed_when": False,
            },
            {"ansible.builtin.stat": {"path": directory + "/leaked"}, "register": "leaked"},
            {"ansible.builtin.stat": {"path": credential}, "register": "installed"},
            {
                "ansible.builtin.assert": {
                    "that": [
                        "main_pid.stdout | trim == '0'",
                        "not leaked.stat.exists",
                        "installed.stat.exists",
                    ]
                }
            },
        ]
    )
    playbook = tmp_path / "credential-drain.json"
    playbook.write_text(
        json.dumps(
            [
                {
                    "name": "Prove older ordinary processes exit before credential publication",
                    "hosts": "all",
                    "gather_facts": False,
                    "tasks": [
                        {
                            "ansible.builtin.slurp": {"src": credential},
                            "register": "saved",
                            "no_log": True,
                        },
                        {
                            "block": tasks,
                            "always": [
                                {
                                    "ansible.builtin.systemd_service": {
                                        "name": unit,
                                        "state": "stopped",
                                    }
                                },
                                {"ansible.builtin.file": {"path": dropin, "state": "absent"}},
                                {"ansible.builtin.file": {"path": directory, "state": "absent"}},
                                install,
                                {"ansible.builtin.systemd_service": {"daemon_reload": True}},
                            ],
                        },
                    ],
                }
            ]
        )
    )
    inventory = tmp_path / "credential-drain-inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "all": {
                    "hosts": {
                        host_name(): {
                            "ansible_connection": "community.docker.docker",
                            "ansible_python_interpreter": "/usr/bin/python3",
                        }
                    }
                }
            }
        )
    )
    timers = [
        "lowerduckpond-backup.timer",
        "lowerduckpond-backup-maintenance.timer",
        "lowerduckpond-static-reconcile.timer",
    ]
    active = [
        timer for timer in timers if host.run("systemctl is-active --quiet %s", timer).rc == 0
    ]
    try:
        assert (
            host.run(
                "systemctl stop lowerduckpond-backup.timer "
                "lowerduckpond-backup-maintenance.timer lowerduckpond-backup.service "
                "lowerduckpond-backup-maintenance.service lowerduckpond-static-reconcile.timer "
                "lowerduckpond-static-reconcile.service"
            ).rc
            == 0
        )
        result = subprocess.run(  # noqa: S603 - fixed disposable host and task-owned playbook
            [sys.executable, "-m", "ansible.cli.playbook", "-i", str(inventory), str(playbook)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stdout + result.stderr
    finally:
        for timer in active:
            assert host.run("systemctl start %s", timer).rc == 0


@pytest.mark.parametrize(
    "service,already_unlinked",
    [(None, False)]
    + [
        (service, unlinked)
        for service in ("export", "construction", "cleanup", "emergency")
        for unlinked in (False, True)
    ],
)
def test_installed_empty_configuration_withdraws_existing_archive_credentials(
    host: Host, tmp_path: Path, service: str | None, already_unlinked: bool
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
                        host_name(): {
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
    before: list[dict[str, object]] = []
    drained: list[dict[str, object]] = []
    cleanup: list[dict[str, object]] = []
    activation_units = [
        f"lowerduckpond-archive-{kind}.socket" for kind in ("export", "construction", "cleanup")
    ] + ["lowerduckpond-static-emergency-reconcile.timer"]
    active_units = [
        unit
        for unit in activation_units
        if host.run("systemctl is-active --quiet %s", unit).rc == 0
    ]
    if service is not None:
        unit = (
            "lowerduckpond-static-emergency-reconcile.service"
            if service == "emergency"
            else f"lowerduckpond-archive-{service}@m3-10-withdrawal-proof.service"
        )
        directory = "/run/lowerduckpond-m3-10-withdrawal-proof"
        dropin_directory = f"/etc/systemd/system/{unit}.d"
        assert not host.file(dropin_directory).exists
        program = (
            "from pathlib import Path\nimport time\n"
            f"private_configuration = Path({credential!r}).read_bytes()\n"
            f"Path({directory + '/ready'!r}).write_text('loaded')\n"
            "while True: time.sleep(1)\n"
        )
        before = [
            {"ansible.builtin.file": {"path": directory, "state": "directory", "mode": "0700"}},
            {
                "ansible.builtin.file": {
                    "path": dropin_directory,
                    "state": "directory",
                    "mode": "0755",
                }
            },
            {
                "ansible.builtin.copy": {
                    "content": program,
                    "dest": directory + "/probe.py",
                    "mode": "0600",
                }
            },
            {
                "ansible.builtin.copy": {
                    "content": (
                        "[Service]\nType=simple\nStandardInput=null\nExecStart=\n"
                        f"ExecStart=/usr/bin/python3 -I -B {directory}/probe.py\n"
                        f"BindPaths={directory}\n"
                    ),
                    "dest": dropin_directory + "/00-m3-10-withdrawal-proof.conf",
                    "mode": "0644",
                }
            },
            {
                "ansible.builtin.systemd_service": {
                    "name": unit,
                    "state": "started",
                    "daemon_reload": True,
                }
            },
            {"ansible.builtin.wait_for": {"path": directory + "/ready", "timeout": 30}},
        ]
        if already_unlinked:
            before.append(
                {"ansible.builtin.file": {"path": credential, "state": "absent"}, "no_log": True}
            )
        drained = [
            {
                "ansible.builtin.command": {
                    "argv": ["systemctl", "show", "--property=MainPID", "--value", unit]
                },
                "register": "archive_pid",
                "changed_when": False,
            },
            {"ansible.builtin.assert": {"that": "archive_pid.stdout | trim == '0'"}},
        ]
        cleanup = [
            {"ansible.builtin.systemd_service": {"name": unit, "state": "stopped"}},
            {"ansible.builtin.file": {"path": dropin_directory, "state": "absent"}},
            {"ansible.builtin.file": {"path": directory, "state": "absent"}},
            {"ansible.builtin.systemd_service": {"daemon_reload": True}},
        ]
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
                                *before,
                                withdraw,
                                *drained,
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
                                *cleanup,
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
                                },
                                {
                                    "ansible.builtin.systemd_service": {
                                        "name": "{{ item }}",
                                        "state": "started",
                                    },
                                    "loop": active_units,
                                },
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
                        host_name(): {
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
