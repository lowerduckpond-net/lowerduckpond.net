"""One fresh native fixture combines backup contention, rotations, restore and reboot."""

from pathlib import Path

import combined_reconstruction as combined
from independent_fixture import require_owned_fixture
from testinfra.host import Host


def test_installed_combined_reconstruction(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    combined.run(host, tmp_path)


def test_complete_journey_combined_reconstruction(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    combined.run(host, tmp_path, existing_namespace=True)
