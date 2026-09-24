"""One fresh native fixture combines backup contention, rotations, restore and reboot."""

from pathlib import Path

import combined_reconstruction as combined
from independent_fixture import require_owned_fixture
from testinfra.host import Host


def test_installed_combined_reconstruction(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    history = combined.backup_mutation(host, tmp_path)
    combined.protected_rotation(host, tmp_path, history)
    fixture, _ = combined.reconstruction(host, tmp_path, history)
    combined.reboot_and_replay(fixture, history)
