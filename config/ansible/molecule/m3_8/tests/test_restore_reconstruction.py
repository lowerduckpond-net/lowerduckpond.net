"""Fresh-host native Restic/systemd reconstruction and ordinary result replay."""

from pathlib import Path

import restore_scenarios as restore
from testinfra.host import Host


def test_installed_restore_reconstruction(host: Host, tmp_path: Path) -> None:
    fixture, tenants, replay = restore.source(host, tmp_path, archived_prefix=True)
    restore.gate_closed(fixture)
    fixture.start()
    restore.finish(fixture, tenants, replay)
    fixture.reboot()
    assert fixture.destination.service("caddy").is_running
    assert fixture.status()["phase"] == "complete"
