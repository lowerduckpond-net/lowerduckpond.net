"""Record each installed verification group without exposing test parameters."""

from __future__ import annotations

import os
import time
from collections.abc import Generator
from pathlib import Path

import pytest

from scripts.qualification_timing import CONTEXT_ENV, capture_fixture_identity, record_span

GROUPS = {
    "test_archive_credentials.py": "archive-credentials",
    "test_lifecycle.py": "core",
    "test_export_import.py": "export-import",
    "test_archive_lifecycle.py": "archive",
    "test_deletion.py": "deletion",
    "test_transport_recovery.py": "transport-recovery",
    "test_quarantine_recovery.py": "quarantine-recovery",
    "test_archive_completion.py": "accounting",
}


def pytest_sessionstart(session: pytest.Session) -> None:
    capture_fixture_identity()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, object, object]:
    group = GROUPS.get(Path(item.path).name, "unclassified")
    if (
        getattr(item, "originalname", None)
        == "test_installed_tls_storage_credentials_are_mutually_denied"
    ):
        group = "storage-credentials"
    elif getattr(item, "originalname", None) == "test_capture_installed_reboot_state":
        group = "reboot-capture"
    elif getattr(item, "originalname", None) == "test_verify_installed_reboot_state":
        group = "reboot-verify"
    previous = os.environ.get(CONTEXT_ENV)
    os.environ[CONTEXT_ENV] = group
    start = time.monotonic_ns()
    before = item.session.testsfailed
    outcome = "failed"
    try:
        result = yield
        outcome = "failed" if item.session.testsfailed > before else "completed"
        return result
    finally:
        record_span("group", start, outcome)
        if previous is None:
            os.environ.pop(CONTEXT_ENV, None)
        else:
            os.environ[CONTEXT_ENV] = previous
