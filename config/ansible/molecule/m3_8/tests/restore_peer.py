"""Exercise restored ingress from the existing, owned controlled-CA peer."""

from __future__ import annotations

from ipaddress import IPv4Address

from restore_fixture import Fixture, checked

from scripts import qualification_restore as owned


def check(fixture: Fixture, *, opened: bool) -> None:
    identities = owned.identities(fixture.environment)
    if identities != {"destination": fixture.destination_id, "acme": fixture.acme_id}:
        raise ValueError("ingress probe differs from its owned restore peers")
    peer_address = str(IPv4Address(fixture.address(fixture.acme_id)))
    address = str(IPv4Address(fixture.address(fixture.destination_id)))
    # The ordinary firewall requires a Cloudflare source even with the restore
    # gate open. The controlled CA intentionally runs without NET_ADMIN. Docker
    # cannot add one capability to exec, so drop every other capability before
    # executing this fixed address setup. PID 1 and later probes stay unchanged.
    fixture.command(
        "docker",
        "exec",
        "--privileged",
        fixture.acme_id,
        "/usr/bin/setpriv",
        "--bounding-set=-all,+net_admin",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--",
        "/usr/sbin/ip",
        "address",
        "replace",
        "173.245.48.1/32",
        "dev",
        "lo",
        timeout=20,
    )
    result = fixture.destination.run(
        "/usr/sbin/ip route replace 173.245.48.1/32 via %s", peer_address
    )
    assert result.rc == 0, result.stderr
    checked(
        fixture.acme,
        f"""
import socket
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.settimeout(2)
connection.bind(('173.245.48.1', 0))
try:
    connection.connect(({address!r}, 443))
except OSError:
    assert not {opened!r}, 'verified public probe did not open ingress'
else:
    assert {opened!r}, 'public probe exposed ingress before verification'
finally:
    connection.close()
""",
    )
