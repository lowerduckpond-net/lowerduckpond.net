"""Real cold issuance with DNS failure, process health, interrupted wait and boot."""

from pathlib import Path

import restore_scenarios as restore
from restore_fixture import UNIT, checked
from testinfra.host import Host


def test_installed_restore_tls_bootstrap(host: Host, tmp_path: Path) -> None:
    fixture, tenants, replay = restore.source(host, tmp_path)
    fixture.fault("dns")
    fixture.start()
    fixture.wait({"installed"})
    fixture.fault_observed("deniedDns")
    restore.gate_closed(fixture)
    # Native Caddy process/admin readiness is insufficient certificate proof.
    assert fixture.destination.service("caddy").is_running
    assert fixture.status()["phase"] == "installed"
    assert fixture.destination.run("systemctl stop %s", UNIT).rc == 0
    fixture.fault("acme")
    fixture.reboot()
    restore.gate_closed(fixture)
    fixture.start()
    fixture.wait({"installed"})
    fixture.fault_observed("deniedAcme")
    restore.gate_closed(fixture)
    assert fixture.destination.run("systemctl stop %s", UNIT).rc == 0
    # Repair only the external cause; never reset start-limit counters, change
    # the issuer policy, seed a certificate, or delete acquired Caddy storage.
    fixture.fault("none")
    fixture.start()
    restore.finish(fixture, tenants, replay)
    checked(
        fixture.destination,
        """
from pathlib import Path
assert len(list(Path('/var/lib/caddy/caddy/certificates').rglob('*.crt'))) == 4
assert len(list(Path('/var/lib/caddy/caddy/acme').rglob('*.json'))) >= 1
""",
    )
