"""Negative reconstruction preserves the source and all installed destination roots."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import restore_negative_faults as faults
import restore_scenarios as restore
import test_archive_lifecycle as archives
from lowerduckpond_static_contracts import canonical_json_bytes
from restore_fixture import REPO, checked
from testinfra.host import Host

from scripts import qualification_restore as owned
from scripts.qualification_case import private_document


def test_installed_restore_negative(host: Host, tmp_path: Path) -> None:  # noqa: PLR0915
    fixture, tenants, _replay = restore.source(host, tmp_path, full_history=False)
    destination = fixture.destination
    original_roots = owned.installed_roots_digest(fixture.environment, fixture.destination_id)
    target = "/etc/lowerduckpond/host-restore/target.json"
    original = destination.file(target).content
    assert (
        destination.run(
            "/usr/local/sbin/restore-static-host --snapshot %s", fixture.snapshot[:12]
        ).rc
        != 0
    )
    for field, value in (
        ("destinationMachineId", "e" * 32),
        ("originalArtifactSha256", "e" * 64),
        ("repositoryBinding", {**fixture.target["repositoryBinding"], "value": "e" * 64}),
        ("sourceFenceDigest", {**fixture.target["sourceFenceDigest"], "value": "e" * 64}),
        ("namespace", {**fixture.target["namespace"], "initializedAt": "2026-08-28T12:00:00Z"}),
        (
            "launch",
            json.loads(
                (REPO / "tests/static-publication/fixtures/accepted/launch-record.json").read_text()
            ),
        ),
    ):
        changed = copy.deepcopy(fixture.target)
        changed[field] = value
        checked(
            destination,
            "from pathlib import Path; "
            f"Path({target!r}).write_bytes(bytes.fromhex({canonical_json_bytes(changed).hex()!r}))",
        )
        assert (
            destination.run(
                "/usr/local/sbin/restore-static-host --snapshot %s", fixture.snapshot
            ).rc
            != 0
        )
        restore.gate_closed(fixture)
        assert fixture.status()["phase"] == "not-started"
        checked(
            destination,
            "from pathlib import Path; "
            f"Path({target!r}).write_bytes(bytes.fromhex({original.hex()!r}))",
        )
    assert (
        owned.installed_roots_digest(fixture.environment, fixture.destination_id) == original_roots
    )

    # An otherwise valid original archive cannot authorize an unknown newer
    # remote object. The coordinator must preserve it, not perform broad cleanup.
    remote = """
import json
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_remote import make_archive_client
config = load_archive_configuration()
client = make_archive_client(region=config.region, access_key_id=config.access_key_id,
    secret_access_key=config.secret_access_key)
"""
    key = "archives/negative-" + fixture.restore_id
    version = json.loads(
        archives._installed_python(
            destination,
            remote
            + f"""
print(json.dumps(client.put_object(Bucket=config.bucket, Key={key!r}, Body=b'owned unknown object',
    ContentLength=20)['VersionId']))
""",
        )
    )
    fixture.start()
    restore.wait_failed(fixture)
    assert {"key": key, "versionId": version} in archives._remote_versions(destination)
    archives._installed_python(
        destination,
        remote + f"client.delete_object(Bucket=config.bucket, Key={key!r}, VersionId={version!r})",
    )

    versions = archives._remote_versions(destination)
    assert len(versions) == 1
    faults.downloads(fixture, versions[0])
    assert archives._remote_versions(destination) == versions
    faults.audit_fork(fixture)
    faults.mixed_roots(fixture)
    assert (
        owned.installed_roots_digest(fixture.environment, fixture.destination_id) == original_roots
    )

    # Trust/configuration corruption cannot turn the already validated snapshot
    # into different runtime authority or replace any installed root.
    environment = destination.file("/etc/caddy/environment").content
    checked(
        destination,
        "from pathlib import Path; Path('/etc/caddy/environment').write_bytes(b'corrupt\\n')",
    )
    fixture.start()
    restore.wait_failed(fixture)
    checked(
        destination,
        "from pathlib import Path; "
        f"Path('/etc/caddy/environment').write_bytes(bytes.fromhex({environment.hex()!r}))",
    )

    # Corrupt one retained private release after Restic's real restore/verification.
    root = f"/srv/.restore-{fixture.restore_id}-content/candidate/sites/{tenants[0]}/releases"
    name = checked(
        destination, f"from pathlib import Path; print(next(Path({root!r}).glob('*/index.html')))"
    ).strip()
    original_file = destination.file(name).content
    checked(destination, f"from pathlib import Path; Path({name!r}).write_bytes(b'corrupt')")
    fixture.start()
    restore.wait_failed(fixture)
    checked(
        destination,
        "from pathlib import Path; "
        f"Path({name!r}).write_bytes(bytes.fromhex({original_file.hex()!r}))",
    )

    # Retire the captured exact VersionId using the explicitly disposable fixture
    # authority. No new version can substitute for it; this destination must stay
    # blocked and never produce a completed journal or public route.
    versions = archives._remote_versions(destination)
    assert len(versions) == 1
    record = versions[0]
    archives._installed_python(
        destination,
        remote + f"client.delete_object(Bucket=config.bucket, Key={record['key']!r}, "
        f"VersionId={record['versionId']!r})",
    )
    fixture.start()
    restore.wait_failed(fixture)
    assert not archives._remote_versions(destination)
    fixture.reboot()
    restore.gate_closed(fixture)
    assert (
        owned.installed_roots_digest(fixture.environment, fixture.destination_id) == original_roots
    )
    private_document(
        fixture.root,
        "completed.json",
        {
            "status": "passed",
            "outcome": "blocked-as-expected",
            "identities": owned.identities(fixture.environment),
            "installedRootsSha256": original_roots,
        },
    )
    owned.paired_proof(fixture.environment)
