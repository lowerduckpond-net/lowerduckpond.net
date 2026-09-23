"""Record each installed verification group without exposing test parameters."""

from __future__ import annotations

import os
import time
from collections.abc import Generator
from pathlib import Path

import pytest

from scripts.qualification_failure import TEST_FILES, capture_fixture, record_test_failure
from scripts.qualification_timing import CONTEXT_ENV, capture_fixture_identity, record_span

GROUPS = {
    "test_restore_reconstruction.py": "restore-reconstruction",
    "test_restore_negative.py": "restore-negative",
    "test_restore_tls_bootstrap.py": "restore-tls-bootstrap",
    "test_restore_accounting.py": "accounting",
    "test_archive_credentials.py": "archive-credentials",
    "test_lifecycle.py": "core",
    "test_core_independent.py": "core",
    "test_archive_independent.py": "archive",
    "test_cross_feature.py": "cross-feature",
    "test_recovery_independent.py": "transport-recovery",
    "test_export_import.py": "export-import",
    "test_archive_lifecycle.py": "archive",
    "test_archive_full_size.py": "full-size-archive",
    "test_deletion.py": "deletion",
    "test_transport_recovery.py": "transport-recovery",
    "test_quarantine_recovery.py": "quarantine-recovery",
    "test_archive_completion.py": "accounting",
    "test_audit_protection.py": "audit-protection",
    "test_audit_rotation.py": "audit-rotation",
}
OPERATOR_FAILURES = {
    "operator transport failed: correlation burst limit is exhausted": "admission-burst-exhausted",
    "operator transport failed: tenant lifecycle is not eligible for ordinary deletion": (
        "ordinary-delete-ineligible"
    ),
}

FUNCTION_GROUPS = {
    "test_restore_reconstruction.py": "restore-reconstruction",
    "test_restore_negative.py": "restore-negative",
    "test_restore_tls_bootstrap.py": "restore-tls-bootstrap",
    "test_restore_accounting.py": "accounting",
    "test_publication_and_operator_boundaries_preserve_the_live_tenant": (
        "configuration-publication"
    ),
    "test_generation_input_and_idempotence_preserve_the_live_tenant": "configuration-generation",
    "test_configuration_overlap_with_deploy_rollback_and_suspend": "overlap-deployment",
    "test_configuration_overlap_with_resume_rename_and_reconcile": "overlap-routing",
}


def pytest_sessionstart(session: pytest.Session) -> None:
    capture_fixture_identity()
    capture_fixture()


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
    group = FUNCTION_GROUPS.get(getattr(item, "originalname", ""), group)
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


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> None:
    if call.excinfo is None or call.excinfo.errisinstance(
        (pytest.skip.Exception, pytest.xfail.Exception)
    ):
        return
    from lowerduckpond_static_operator.client import (  # noqa: PLC0415
        OperatorClientError,
    )

    error = call.excinfo.value
    if isinstance(error, OperatorClientError):
        category = OPERATOR_FAILURES.get(str(error), "operator-transport")
    else:
        category = "assertion" if isinstance(error, AssertionError) else "test-error"
    location = next(
        (
            entry
            for entry in reversed(call.excinfo.traceback)
            if Path(entry.path).name in TEST_FILES
        ),
        None,
    )
    record_test_failure(
        category,
        file=Path(location.path).name if location else "unknown",
        line=location.lineno + 1 if location else "unknown",
    )
