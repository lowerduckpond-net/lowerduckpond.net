"""Require the disposable owned boundary for independently selected diagnostics."""

from __future__ import annotations

import os

from scripts.qualification_context import RUN_ENV, host_name


def require_owned_fixture() -> None:
    assert os.environ.get(RUN_ENV), "independent diagnostics require an owned fixture"
    host_name()
    assert os.environ.get("M3_10_ARCHIVE_BACKEND", "minio") == "minio"
    assert not os.environ.get("M3_10_INSTALLED_REPORT")
