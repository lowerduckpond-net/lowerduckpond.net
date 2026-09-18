"""Names shared by one owned local qualification and its child processes."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping

RUN_ENV = "LDP_QUALIFICATION_RUN_ID"
HOST_ENV = "LDP_QUALIFICATION_HOST"
ARCHIVE_ENV = "LDP_QUALIFICATION_ARCHIVE"
IMAGE_ENV = "LDP_QUALIFICATION_IMAGE"
PORT_ENV = "LDP_QUALIFICATION_SSH_PORT"
ARTIFACT_ENV = "LDP_QUALIFICATION_ARTIFACT"
RESOURCE_ENV = frozenset({RUN_ENV, HOST_ENV, ARCHIVE_ENV, IMAGE_ENV, PORT_ENV, ARTIFACT_ENV})
LEGACY_HOST = "lowerduckpond-ubuntu-2604"
LEGACY_ARCHIVE = "lowerduckpond-m3-10-minio"
RUN_PATTERN = re.compile(r"[0-9a-f]{12}7[0-9a-f]{3}[89ab][0-9a-f]{15}")


def resource_names(run_id: str) -> dict[str, str]:
    if RUN_PATTERN.fullmatch(run_id) is None:
        raise ValueError("invalid qualification run identity")
    prefix = f"ldp-m3-{run_id}"
    return {
        RUN_ENV: run_id,
        HOST_ENV: f"{prefix}-host",
        ARCHIVE_ENV: f"{prefix}-archive",
        IMAGE_ENV: f"{prefix}:ubuntu-2604",
        PORT_ENV: "0",
    }


def host_name(environment: Mapping[str, str] | None = None) -> str:
    values = os.environ if environment is None else environment
    run_id = values.get(RUN_ENV)
    if run_id:
        expected = resource_names(run_id)
        if any(values.get(key) != value for key, value in expected.items()):
            raise ValueError("qualification resource names disagree with their owner")
        return expected[HOST_ENV]
    if any(key in values for key in RESOURCE_ENV):
        raise ValueError("qualification resource overrides require an owned run")
    return LEGACY_HOST
