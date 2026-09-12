from __future__ import annotations

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
