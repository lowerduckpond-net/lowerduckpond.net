from __future__ import annotations

from pathlib import Path

import test_lifecycle as support
from independent_fixture import require_owned_fixture
from testinfra.host import Host


def test_core_lifecycle_without_configuration_guard_repetition(host: Host, tmp_path: Path) -> None:
    require_owned_fixture()
    support._exercise_core_lifecycle(host, tmp_path, configuration_checks=False)
