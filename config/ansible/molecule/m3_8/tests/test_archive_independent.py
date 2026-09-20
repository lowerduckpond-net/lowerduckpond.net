from __future__ import annotations

from pathlib import Path

import pytest
import test_archive_lifecycle as archives
from independent_fixture import require_owned_fixture
from test_archive_lifecycle import controlled_recovery_timer  # noqa: F401 - register pytest fixture
from testinfra.host import Host


@pytest.mark.usefixtures("controlled_recovery_timer")
def test_archive_cycles_capture_recovery_and_retirement(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    archives._exercise_archive_lifecycle(host, tmp_path, full_size_source=False)
