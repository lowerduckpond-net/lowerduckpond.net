"""Reversible faults confined to a fenced, run-owned reconstruction fixture."""

from __future__ import annotations

import json
import time

import restore_scenarios as restore
import test_export_import as exports
from restore_fixture import SCENARIO, Fixture, checked, private

from scripts import qualification_restore as owned
from scripts.qualification_context import ARCHIVE_ENV


def downloads(fixture: Fixture, record: dict[str, str]) -> None:
    # Both TLS legs use the existing disposable archive certificate. No trust,
    # credentials, version identity, production code, or helper unit is changed.
    archive = owned.inspect(fixture.environment, fixture.environment[ARCHIVE_ENV])
    address = fixture.address(str(archive["id"]))
    assert fixture.acme.run("install -d -m 0700 /root/restore-archive").rc == 0
    for name in ("public.crt", "private.key", "ca.crt"):
        fixture.copy_in(
            fixture.ephemeral / "archive-tls" / name,
            fixture.acme_id,
            f"/root/restore-archive/{name}",
        )
    fixture.copy_in(
        SCENARIO / "restore_archive_proxy.py",
        fixture.acme_id,
        "/root/restore-archive/proxy.py",
    )
    assert (
        fixture.acme.run(
            "sh -c %s", f"printf '%s\\n' '{address} ams3.digitaloceanspaces.com' >> /etc/hosts"
        ).rc
        == 0
    )
    assert (
        fixture.acme.run(
            "systemd-run --unit restore-fixture-archive "
            "/usr/bin/python3 -I -B /root/restore-archive/proxy.py"
        ).rc
        == 0
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if fixture.acme.run("sh -c 'ss -lnt | grep -q :8443'").rc == 0:
            break
        time.sleep(0.1)
    else:
        raise AssertionError("owned archive proxy did not listen")
    rules = fixture.root / "archive-fault.nft"
    private(
        rules,
        (
            "table ip restore_fixture_archive { chain output { "
            "type nat hook output priority -111; "
            f"ip daddr {address} tcp dport 443 dnat to {fixture.acme_address}:8443; "
            "} }\n"
        ).encode(),
    )
    fixture.copy_in(rules, fixture.destination_id, "/root/restore-archive-fault.nft")
    assert fixture.destination.run("nft -f /root/restore-archive-fault.nft").rc == 0
    for fault in ("deny", "corrupt"):
        policy = {"bucket": "molecule-tenant-archives", **record, "fault": fault}
        local = fixture.root / f"archive-{fault}.json"
        private(local, json.dumps(policy).encode())
        fixture.copy_in(local, fixture.acme_id, "/root/restore-archive/fault.json")
        assert fixture.acme.run("rm -f /root/restore-archive/observed").rc == 0
        fixture.start()
        restore.wait_failed(fixture)
        expected = "deny" if fault == "deny" else "corrupt-downloaded"
        assert fixture.acme.file("/root/restore-archive/observed").content_string == expected
    # This removes only the test-owned redirection after both observed failures.
    assert fixture.destination.run("nft delete table ip restore_fixture_archive").rc == 0
    assert fixture.acme.run("systemctl stop restore-fixture-archive.service").rc == 0


def audit_fork(fixture: Fixture) -> None:
    root = f"/var/lib/lowerduckpond/.restore-{fixture.restore_id}-state/candidate/audit"
    name = checked(
        fixture.destination,
        f"from pathlib import Path; print(next(Path({root!r}).glob('segment-*.jsonl')))",
    ).strip()
    original = fixture.destination.file(name).content
    checked(
        fixture.destination,
        exports._selected_python(
            fixture.destination,
            f"""
import json
from pathlib import Path
from lowerduckpond_static_contracts import canonical_json_bytes, audit_entry_digest
path = Path({name!r})
entries = [json.loads(line) for line in path.read_bytes().splitlines()]
assert entries[0]['sequence'] == 0
entries[0]['timestamp'] = '2026-08-28T12:00:00Z'
for index, entry in enumerate(entries):
    if index:
        entry['previousEntryDigest'] = audit_entry_digest(entries[index - 1]).to_dict()
raw = b''.join(canonical_json_bytes(entry) for entry in entries)
assert raw != path.read_bytes()
path.write_bytes(raw)
""",
        ),
    )
    # A fully rehashed local fork still cannot replace the captured audit prefix.
    fixture.start()
    restore.wait_failed(fixture)
    checked(
        fixture.destination,
        f"from pathlib import Path; Path({name!r}).write_bytes(bytes.fromhex({original.hex()!r}))",
    )


def mixed_roots(fixture: Fixture) -> None:
    # Move exactly one original candidate into the installed location, without
    # rename authority for the other roots. Retain both inodes for restoration.
    candidate = f"/srv/.restore-{fixture.restore_id}-content/candidate"
    held = f"/srv/.restore-{fixture.restore_id}-content/test-held-bootstrap"
    swap = f"""
from pathlib import Path
candidate, installed, held = map(Path, ({candidate!r}, '/srv/lowerduckpond', {held!r}))
assert candidate.is_dir() and installed.is_dir() and not held.exists()
installed.rename(held)
candidate.rename(installed)
"""
    checked(fixture.destination, swap)
    fixture.start()
    restore.wait_failed(fixture)
    checked(
        fixture.destination,
        f"""
from pathlib import Path
candidate, installed, held = map(Path, ({candidate!r}, '/srv/lowerduckpond', {held!r}))
assert not candidate.exists() and installed.is_dir() and held.is_dir()
installed.rename(candidate)
held.rename(installed)
""",
    )
