"""Final accounting includes the fenced source and fresh destination identities."""

import os

from testinfra.host import Host

from scripts.qualification_restore import paired_proof


def test_installed_restore_paired_accounting(host: Host) -> None:
    assert host.file("/var/lib/lowerduckpond/recovery/restore-gate.json").exists
    assert paired_proof(dict(os.environ))
