from __future__ import annotations

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent.host_restore_diagnostics import diagnostic
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError


@pytest.mark.parametrize(
    "error",
    [
        HostRestoreError("private snapshot, credential, or remote key\nforged log"),
        ValueError("restore_required_archive_unavailable"),
    ],
)
def test_only_exact_restore_categories_can_enter_public_diagnostics(error: Exception) -> None:
    assert diagnostic(error) == "restore_unverified category=unexpected"


def test_restore_category_and_provider_rejection_remain_fixed_labels() -> None:
    assert diagnostic(HostRestoreError("restore_trusted_input_mismatch")) == (
        "restore_trusted_input_mismatch category=unexpected"
    )
    error = ClientError(
        {
            "Error": {"Code": "AccessDenied", "Message": "private credential or object key"},
            "ResponseMetadata": {"HTTPStatusCode": 403, "RequestId": "private request"},
        },
        "GetObject",
    )
    assert diagnostic(error) == (
        "restore_unverified category=provider_response "
        "operation=get_object code=access_denied http_status=403"
    )
