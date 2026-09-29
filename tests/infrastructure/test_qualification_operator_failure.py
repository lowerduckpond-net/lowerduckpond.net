"""Transport diagnosis remains useful without publishing arbitrary peer stderr."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from lowerduckpond_static_operator import client

from scripts import qualification_failure as failure
from scripts import qualification_operator_failure as detail
from scripts import qualification_probe as probe
from scripts import qualification_pytest_timing as plugin
from scripts import qualification_timing as timing

CANARY = "private-peer-and-credential-canary"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("operator transport timed out", "client-timeout"),
        ("operator transport failed: authorized job handoff failed", "job-handoff-failed"),
        (
            "operator transport failed: authorized job result disagrees with lifecycle authority",
            "job-authority-mismatch",
        ),
        (
            f"operator transport failed: ssh: connect to host {CANARY} port 32806: "
            "Connection refused",
            "ssh-refused",
        ),
        (
            f"operator transport failed: ssh: connect to host {CANARY} port 32806: "
            "Connection timed out",
            "ssh-connect-timeout",
        ),
        (
            f"operator transport failed: user@{CANARY}: Permission denied (publickey).",
            "ssh-authentication",
        ),
        ("operator transport failed: ssh_status_255", "ssh-exit-status"),
        ("operator transport failed: tenant-state.lock is busy", "host-lock-busy"),
        ("operator transport failed: " + CANARY, "unknown"),
        ("operator transport timed out\n" + CANARY, "unknown"),
    ],
)
def test_transport_reason_is_a_fixed_label(message: str, expected: str) -> None:
    assert detail.reason(message) == expected
    assert CANARY not in detail.reason(message)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        CANARY,
        {"reason": [], "client_function": {}},
        {"reason": CANARY, "client_function": CANARY, "client_line": True},
    ],
)
def test_untrusted_saved_detail_cannot_escape_allowlist(value: object) -> None:
    assert detail.sanitize(value) == dict.fromkeys(
        ("reason", "client_function", "client_line"), "unknown"
    )


def test_actual_client_exception_keeps_location_and_first_failure_without_message(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    monkeypatch.setenv(timing.EVENT_ENV, str(tmp_path / "timing-events.jsonl"))

    def expire() -> None:
        client._Deadline(0, 1, 0).timeout()

    call = pytest.CallInfo.from_call(expire, when="call")
    plugin.pytest_runtest_makereport(request.node, call)
    saved = json.loads((tmp_path / "failure-test.json").read_text())
    operator = saved["operator"]
    assert operator["reason"] == "client-timeout"
    assert operator["client_function"] == "timeout"
    assert type(operator["client_line"]) is int and operator["client_line"] > 0
    original = (tmp_path / "failure-test.json").read_bytes()
    failure.record_test_failure("test-error", operator={"reason": CANARY})
    assert (tmp_path / "failure-test.json").read_bytes() == original
    monkeypatch.setattr(failure, "_observe", lambda *args: ("unavailable", probe.sanitize({})))
    monkeypatch.setattr(failure, "required_tools", dict)
    monkeypatch.setattr(failure, "helper_check", lambda: "unknown")
    monkeypatch.setattr(failure, "filesystem", lambda path: "unknown")
    report = json.loads(failure.collect(tmp_path, 1).read_text())
    assert report["operator_failure"] == operator
    assert CANARY not in json.dumps(report)
