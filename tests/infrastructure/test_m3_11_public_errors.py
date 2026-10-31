"""Actual guest transport and fail-closed, secret-free public probe failures."""

from __future__ import annotations

import json
import sys
import traceback
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

from scripts import m3_11_public_errors as errors
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.model import digest
from scripts.qualification_probe import bounded_command

SECRET = "synthetic-private-payload-never-publish"  # noqa: S105 - synthetic sentinel
CONTEXT = "a" * 64


def receipt() -> dict[str, object]:
    return errors.failure("suspend", ValueError("unknown"), context_sha256=CONTEXT)


@pytest.mark.parametrize("message,code", errors.REASONS.items())
def test_exact_literal_assertions_have_fixed_codes(message: str, code: str) -> None:
    raw = errors.failure("suspend", ValueError(message), context_sha256=CONTEXT)
    with pytest.raises(errors.ProbeError) as caught:
        errors.observation(json.dumps(raw).encode(), action="suspend", context_sha256=CONTEXT)
    assert caught.value.receipt["code"] == code
    assert message not in str(caught.value)


def test_unknown_exception_content_and_chains_are_never_stringified() -> None:
    class PrivateError(Exception):
        def __str__(self) -> str:
            raise AssertionError("must not stringify private exception")

    try:
        try:
            raise ValueError(SECRET)
        except ValueError as cause:
            failure = PrivateError(SECRET)
            failure.add_note(SECRET)
            raise failure from cause
    except PrivateError as error:
        raw = errors.failure(SECRET, error, context_sha256=SECRET)
    assert raw[errors.KEY] == {
        "format": errors.FORMAT,
        "action": "unknown",
        "context_sha256": None,
        "code": "unclassified",
        "error_type": "unknown",
        "frames": [],
    }
    assert SECRET not in json.dumps(raw)


def test_attribute_error_keeps_only_the_fixed_type_label() -> None:
    raw = errors.failure("suspend", AttributeError(SECRET))
    assert cast("dict[str, object]", raw[errors.KEY])["error_type"] == "AttributeError"
    assert SECRET not in json.dumps(raw)


@pytest.mark.parametrize("code", sorted(errors.TLS_ERRORS))
def test_fixed_native_tls_assertions_survive_without_arbitrary_error_text(code: str) -> None:
    payload = errors.failure("suspend", HostRestoreError(code), context_sha256=CONTEXT)
    with pytest.raises(errors.ProbeError) as caught:
        errors.observation(json.dumps(payload).encode(), action="suspend", context_sha256=CONTEXT)
    assert caught.value.receipt["code"] == code
    private = errors.failure("suspend", HostRestoreError(code + SECRET))
    assert cast("dict[str, object]", private[errors.KEY])["code"] == "unclassified"
    assert SECRET not in json.dumps(private)


def test_frame_capture_uses_only_fixed_modules_and_numeric_lines() -> None:
    namespace: dict[str, object] = {"secret": SECRET}
    exec(  # noqa: S102 - synthetic fixed-source frame, no I/O
        compile("def fail():\n    raise ValueError(secret)\n", "m3_11_public_probe.py", "exec"),
        namespace,
    )
    try:
        cast("Callable[[], None]", namespace["fail"])()
    except ValueError as error:
        raw = errors.failure("suspend", error)
    assert cast("dict[str, object]", raw[errors.KEY])["frames"] == [
        {"module": "m3_11_public_probe.py", "line": 2}
    ]
    assert SECRET not in json.dumps(raw)


@pytest.mark.parametrize(
    "change",
    [
        {"action": "stop_failed"},
        {"context_sha256": "b" * 64},
        {"format": SECRET},
        {"code": SECRET},
        {"code": []},
        {"error_type": SECRET},
        {"frames": SECRET},
        {"frames": [{"module": SECRET, "line": 1}]},
        {"frames": [{"module": "m3_11_public_probe.py", "line": True}]},
        {"frames": [{"module": "m3_11_public_probe.py", "line": 0}]},
        {"frames": [{"module": "m3_11_public_probe.py", "line": errors.MAX_LINE + 1}]},
        {"frames": [{"module": "m3_11_public_probe.py", "line": 1, "locals": SECRET}]},
        {"frames": [{}] * (errors.MAX_FRAMES + 1)},
        {"payload": SECRET},
    ],
)
def test_untrusted_failure_fields_fail_closed_without_echo(change: dict[str, object]) -> None:
    raw = receipt()
    cast("dict[str, object]", raw[errors.KEY]).update(change)
    with pytest.raises(ValueError) as caught:
        errors.observation(json.dumps(raw).encode(), action="suspend", context_sha256=CONTEXT)
    assert type(caught.value) is ValueError
    assert SECRET not in str(caught.value)


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"[]",
        b"{}{}",
        b'{"ready":1,"ready":2}',
        b'{"public_probe_failure":null}',
        b'{"public_probe_failure":{},"ready":true}',
    ],
)
def test_malformed_transport_is_never_a_success(raw: bytes) -> None:
    with pytest.raises(ValueError):
        errors.observation(raw, action="ready")


def test_only_valid_failure_receipts_are_saved_once(
    installed_module: Callable[[str], ModuleType],
    tmp_path: Path,
) -> None:
    module = installed_module("public_ca_recovery")
    raw = json.dumps(receipt()).encode()
    for _ in range(2):
        with pytest.raises(errors.ProbeError):
            module.observation(raw, action="suspend", context_sha256=CONTEXT, directory=tmp_path)
    path = tmp_path / "public-probe-failure-suspend.json"
    assert read_private(path) == receipt()[errors.KEY]
    prior = path.read_bytes()
    changed = deepcopy(receipt())
    cast("dict[str, object]", changed[errors.KEY])["action"] = SECRET
    with pytest.raises(ValueError):
        module.observation(json.dumps(changed).encode(), action="suspend", directory=tmp_path)
    assert path.read_bytes() == prior
    assert SECRET.encode() not in prior


def test_receipt_io_failure_preserves_primary_failure_and_suppresses_private_context(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = installed_module("public_ca_recovery")
    monkeypatch.setattr(module, "write_private", Mock(side_effect=OSError(SECRET)))
    with pytest.raises(errors.ProbeError) as caught:
        module.observation(
            json.dumps(receipt()).encode(),
            action="suspend",
            context_sha256=CONTEXT,
            directory=tmp_path,
        )
    rendered = "".join(traceback.format_exception(caught.value))
    assert "failed: unclassified" in rendered
    assert "could not be retained" in rendered
    assert SECRET not in rendered


@pytest.mark.parametrize("fault", ["complete", "admin-response", "readback", "private-exception"])
def test_real_assembled_guest_preserves_suspension_assertion_through_bounded_transport(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fault: str,
) -> None:
    module = installed_module("public_ca_recovery")
    monkeypatch.setattr(module, "_selected_python", lambda host, body: body)
    program = module.program(Mock(), isolated=True)
    # Exercise actual _suspend in the selected guest code. Replace only external
    # fixture, disk/TLS and admin boundaries with synthetic offline observations.
    patch = """
module._guard = lambda context: {'nonce': '0198d17f-6f4a-7000-8000-000000000001'}
module._closed = lambda: None
module._document = lambda name: {}
module._record = lambda name, value: value
nonce = '0198d17f-6f4a-7000-8000-000000000001'
def read(path):
    return (module.policy.interruption_configuration(nonce)
            if path.name == 'interruption.json' else module.policy.configuration(nonce))
module._read = read
module.ready = lambda context: {'ready': FAULT == 'complete'}
active = module.policy.interruption_configuration(nonce)
def admin(method, path, body=None):
    global active
    if FAULT == 'admin-response':
        raise ValueError('public probe issuance suspension was not confirmed')
    if FAULT == 'private-exception':
        raise OSError(PRIVATE)
    if method == 'POST':
        active = b'{}' if FAULT == 'readback' else module.policy.suspended_configuration()
    return active
module._admin = admin
"""
    patch = "FAULT = " + repr(fault) + "\nPRIVATE = " + repr(SECRET) + "\n" + patch
    program = program.replace("action = None\n", patch + "\naction = None\n")
    # A direct/legacy consumer keeps nonzero failure semantics. It cannot
    # mistake this failure envelope for a successful stop/cleanup observation.
    assert (
        bounded_command(
            [sys.executable, "-c", program],
            stdin=json.dumps({"action": "suspend", "context_sha256": CONTEXT}).encode(),
            timeout=10,
        )
        is None
    )

    def command(*args: str, stdin: bytes, timeout: int) -> bytes:
        assert args[:3] == ("docker", "exec", "--interactive")
        request = json.loads(stdin)
        assert request["failure_protocol"] == errors.FORMAT
        assert request["context_sha256"] == CONTEXT
        raw = bounded_command(
            [sys.executable, "-c", program], stdin=stdin, timeout=timeout, check=True
        )
        assert raw is not None and SECRET.encode() not in raw
        return raw

    recovery = object.__new__(module.PublicRecovery)
    recovery.context_sha256 = CONTEXT
    recovery.directory, recovery.program = tmp_path, program
    recovery._remaining = Mock(return_value=10)
    recovery.fixture = Mock(command=command)
    expected = {
        "complete": "issuance-already-complete",
        "admin-response": "admin-response-unverified",
        "readback": "issuance-still-active",
        "private-exception": "unclassified",
    }[fault]
    with pytest.raises(errors.ProbeError) as caught:
        recovery._dispatch("suspend")
    assert caught.value.receipt["code"] == expected
    assert caught.value.receipt["frames"]
    assert SECRET not in "".join(traceback.format_exception(caught.value))


def test_raw_subprocess_failure_stays_generic_and_discards_both_payloads() -> None:
    assert (
        bounded_command(
            [
                sys.executable,
                "-c",
                "import sys; print(sys.argv[1]); print(sys.argv[1], file=sys.stderr); sys.exit(1)",
                SECRET,
            ],
            timeout=5,
        )
        is None
    )


def test_successful_probe_observation_is_unchanged() -> None:
    assert errors.observation(b'{"issuance_suspended":true}', action="suspend") == {
        "issuance_suspended": True,
    }


@pytest.mark.parametrize("fault", [None, "context", "receipt", "symlink"])
def test_retained_failure_summary_is_validated_and_cannot_block_cleanup(
    tmp_path: Path,
    fault: str | None,
) -> None:
    context: dict[str, object] = {"synthetic_context": True}
    write_private(tmp_path / "isolation-context.json", context)
    raw = errors.failure(
        "suspend",
        ValueError("public probe issuance suspension was not confirmed"),
        context_sha256=digest(context),
    )
    path = tmp_path / "public-probe-failure-suspend.json"
    write_private(path, cast("dict[str, object]", raw[errors.KEY]))
    if fault == "context":
        (tmp_path / "isolation-context.json").write_text(SECRET)
    if fault == "receipt":
        path.write_text(SECRET)
    if fault == "symlink":
        path.unlink()
        path.symlink_to(tmp_path / "missing-private-target")
    result = errors.retained_failures(tmp_path)
    assert SECRET not in json.dumps(result)
    if fault is None:
        assert result["failures"] == {"suspend": raw[errors.KEY]}
        assert result["unavailable_actions"] == []
    else:
        assert result["failures"] == {}
        assert result["unavailable_actions"] == ["suspend"]


def test_absent_failure_files_do_not_create_a_failure_or_read_credentials(tmp_path: Path) -> None:
    (tmp_path / "credentials").mkdir()
    (tmp_path / "credentials/issued.json").write_text("must not be read")
    assert errors.retained_failures(tmp_path) == {
        "format": "lowerduckpond-public-probe-diagnostics-v1",
        "failures": {},
        "unavailable_actions": [],
        "context_available": True,
    }


@pytest.mark.parametrize("action", ["start", "install_isolated", "stop_failed", "observe_prepared"])
def test_opt_in_cannot_change_legacy_or_cleanup_failure_into_success(
    installed_module: Callable[[str], ModuleType],
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    module = installed_module("public_ca_recovery")
    monkeypatch.setattr(module, "_selected_python", lambda host, body: body)
    program = module.program(Mock(), isolated=True)
    patch = (
        "def synthetic_failure(**kwargs):\n    raise ValueError('synthetic private input')\n"
        + f"actions[{action!r}] = synthetic_failure\n"
    )
    program = program.replace("action = None\n", patch + "action = None\n")
    for protocol in (None, "unsupported-protocol", errors.FORMAT):
        request = {"action": action}
        if protocol is not None:
            request["failure_protocol"] = protocol
        result = bounded_command(
            [sys.executable, "-c", program], stdin=json.dumps(request).encode(), timeout=10
        )
        if protocol != errors.FORMAT:
            assert result is None
        else:
            assert result is not None
            with pytest.raises(errors.ProbeError):
                errors.observation(result, action=action)
