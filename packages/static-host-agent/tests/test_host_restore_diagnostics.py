from __future__ import annotations

import pytest
from botocore.exceptions import ClientError  # type: ignore[import-untyped]
from lowerduckpond_static_host_agent import host_restore_diagnostics as diagnostics
from lowerduckpond_static_host_agent.host_restore_diagnostics import (
    VERIFICATION_STEPS,
    diagnostic,
    verification_step,
)
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


@pytest.mark.parametrize("step", sorted(VERIFICATION_STEPS))
def test_failed_verification_preserves_exception_and_emits_only_its_fixed_step(
    step: str, capsys: pytest.CaptureFixture[str]
) -> None:
    error = ValueError("private credential, object key, or tenant content\nforged log")
    with pytest.raises(ValueError) as caught, verification_step(step):
        raise error
    assert caught.value is error
    assert capsys.readouterr().err == "host_restore_step_failed step=" + step + "\n"
    with verification_step(step):
        pass
    assert not capsys.readouterr().err


def test_unknown_verification_step_cannot_enter_journal(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        pytest.raises(ValueError, match="unknown restore verification step"),
        verification_step("private-value\nforged log"),
    ):
        pytest.fail("unknown diagnostic stage admitted")
    assert not capsys.readouterr().err


def test_unavailable_journal_cannot_replace_the_original_restore_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*args: object, **kwargs: object) -> None:
        raise OSError("journal unavailable")

    monkeypatch.setattr(diagnostics, "print", unavailable, raising=False)
    error = HostRestoreError("original restore failure")
    with pytest.raises(HostRestoreError) as caught, verification_step("installed-state"):
        raise error
    assert caught.value is error
