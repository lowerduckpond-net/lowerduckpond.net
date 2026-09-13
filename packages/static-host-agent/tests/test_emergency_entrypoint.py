from __future__ import annotations

import os
import pwd
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import emergency_entrypoint

_DENIED_STATUS = 77
_USAGE_STATUS = 64


@pytest.mark.parametrize(
    "uid,sudo_user", [(1000, "ldp-admin"), (0, "ldp-provisioner"), (0, "ldp-control"), (0, None)]
)
def test_emergency_command_requires_actual_root_from_administrative_sudo(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    uid: int,
    sudo_user: str | None,
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: uid)
    monkeypatch.delenv("SUDO_USER", raising=False)
    if sudo_user is not None:
        monkeypatch.setenv("SUDO_USER", sudo_user)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1000))
    assert (
        emergency_entrypoint.emergency_delete_main(
            ["--tenant", "x", "--correlation", "x", "--reason", "reason"]
        )
        == _DENIED_STATUS
    )
    assert capsys.readouterr().err == "emergency_administrator_required\n"


@pytest.mark.parametrize(
    "values",
    [
        [],
        ["--recover", "reason"],
        ["--tenant", "x", "--correlation", "x", "--reason", " "],
        ["--tenant", "x", "--correlation", "x", "--reason", "x" * 1025],
    ],
)
def test_emergency_command_rejects_unfixed_invocations_before_opening_state(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], values: list[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "ldp-admin")
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1000))
    assert emergency_entrypoint.emergency_delete_main(values) == _USAGE_STATUS
    assert capsys.readouterr().err == "invalid_emergency_delete_invocation\n"


def test_emergency_recovery_is_not_available_to_provisioner_sudo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "ldp-provisioner")
    assert emergency_entrypoint.emergency_delete_main(["--recover"]) == _DENIED_STATUS
    assert capsys.readouterr().err == "emergency_administrator_required\n"
