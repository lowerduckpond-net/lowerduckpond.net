from pathlib import Path

import yaml
from lowerduckpond_static_host_agent.backup_sources import (
    EXCLUDE_PATHS,
    SOURCE_PATHS,
    STAGED_PATHS,
)


def test_health_scope_and_capture_command_bind_identical_sources() -> None:
    root = Path(__file__).parents[2]
    values = yaml.safe_load((root / "config/ansible/roles/backup/vars/main.yml").read_bytes())
    assert values["backup_recovery_source_paths"] == [
        *SOURCE_PATHS.values(),
        *STAGED_PATHS.values(),
    ]
    assert values["backup_recovery_exclude_paths"] == list(EXCLUDE_PATHS)
