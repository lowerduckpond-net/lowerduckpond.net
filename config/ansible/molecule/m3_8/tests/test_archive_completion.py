from __future__ import annotations

import json
import os
from pathlib import Path

import test_archive_lifecycle as archives
import test_lifecycle as support
from testinfra.host import Host


def test_installed_archive_qualification_has_no_unresolved_accounting(host: Host) -> None:
    assert not archives._remote_versions(host)
    for directory in (
        "/etc/caddy/intents",
        "/srv/lowerduckpond/sites/.staging",
        *(f"{support.STATE_ROOT}/{name}" for name in ("exports", "intake", "intents")),
    ):
        outcome = host.run("find %s -mindepth 1 -print -quit", directory)
        assert outcome.rc == 0 and not outcome.stdout
    assert not host.file(f"{support.STATE_ROOT}/platform/archive-quarantine.json").exists
    selected = host.run("readlink --canonicalize /opt/lowerduckpond/static-host-agent/current")
    assert selected.rc == 0
    artifact = selected.stdout.strip().rsplit("/", 1)[-1]
    assert len(artifact) == 64 and all(char in "0123456789abcdef" for char in artifact)  # noqa: PLR2004
    assert (
        host.run(
            "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact %s",
            selected.stdout.strip(),
        ).rc
        == 0
    )
    destination = os.environ.get("M3_10_INSTALLED_REPORT")
    if destination:
        report = {
            "artifact_sha256": artifact,
            "pending_intents": 0,
            "pending_intake": 0,
            "pending_exports": 0,
            "pending_staging": 0,
            "quarantine": False,
            "remote_versions_and_markers": 0,
            "remote_multipart_uploads": 0,
        }
        # The wrapper creates a private run directory and refuses stale reports.
        with Path(destination).open("x", encoding="ascii") as stream:
            stream.write(json.dumps(report, sort_keys=True) + "\n")
