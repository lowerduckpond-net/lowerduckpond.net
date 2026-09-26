"""A real failed restore retains every host and backup while retiring exact archives."""

from __future__ import annotations

import os
import time
from pathlib import Path

import restore_scenarios as restore
from lowerduckpond_static_host_agent.host_restore_coordinator import COORDINATOR_SECONDS
from restore_fixture import UNIT, checked
from testinfra.host import Host

from scripts.m3_11_private_inputs import write_private
from scripts.qualification_context import ARTIFACT_ENV


def test_installed_failed_archive_retirement(host: Host, tmp_path: Path) -> None:
    fixture, _tenants, replay = restore.source(
        host, tmp_path, archived_prefix=True, full_history=False
    )
    # A real private helper failure leaves the coordinator validated and gated;
    # no journal or completed assertion is manufactured for the failed restore.
    checked(
        fixture.destination,
        """
from pathlib import Path
root = Path('/etc/systemd/system/lowerduckpond-host-restore-archive-private.service.d')
root.mkdir(mode=0o755, exist_ok=True)
(root / 'qualification-fault.conf').write_text(
    '[Service]\\nExecStart=\\nExecStart=/usr/bin/false\\n'
)
""",
    )
    assert fixture.destination.run("systemctl daemon-reload").rc == 0
    fixture.start()
    deadline = time.monotonic() + COORDINATOR_SECONDS + 30
    while time.monotonic() < deadline:
        if (
            fixture.destination.run(
                "systemctl show --value --property=ActiveState %s", UNIT
            ).stdout.strip()
            == "failed"
        ):
            break
        time.sleep(0.5)
    else:
        raise AssertionError("faulted restore did not terminate within its coordinator deadline")
    assert fixture.status()["phase"] == "validated"
    restore.gate_closed(fixture)
    root = Path(os.environ[ARTIFACT_ENV]).parent.parent
    failure = {
        "format": "lowerduckpond-retirement-installed-original-failure-v1",
        "phase": "validated",
        "outcome": "failed",
        "job": replay["missingJob"],
    }
    write_private(root / "retirement-original-failure.json", failure)
    # Imported only by this fixed installed node, never by the operator CLI.
    from retirement_fixture import retire_failed_fixture  # noqa: PLC0415

    retire_failed_fixture(fixture, root, failure)
