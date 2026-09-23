from __future__ import annotations

import os
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

import pytest
from lowerduckpond_static_host_agent import backup_audit_entrypoint as entrypoint
from lowerduckpond_static_host_agent.audit_archive_coordinator import ProtectionPaths
from lowerduckpond_static_host_agent.audit_rotation_coordinator import RotationPaths


@pytest.mark.parametrize(
    "arguments", [[], ["--prune"], ["--maintain", "--force"], ["--verify", "/other"]]
)
def test_root_command_has_no_arbitrary_destructive_or_path_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], arguments: list[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", ["backup-audit-agent", *arguments])
    assert entrypoint.audit_main(-1) == 1
    assert capsys.readouterr().err == "backup_audit_invalid_invocation\n"


@pytest.mark.parametrize("argument", ["--maintain", "--rotate"])
def test_provisioner_cannot_invoke_even_fixed_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argument: str
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1234)
    monkeypatch.setattr(sys, "argv", ["backup-audit-agent", argument])
    assert entrypoint.audit_main(-1) == 1
    assert capsys.readouterr().err == "backup_audit_invalid_invocation\n"


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    observed: list[object] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    for name, value in (("DAILY", "7"), ("WEEKLY", "5"), ("MONTHLY", "12")):
        monkeypatch.setenv("LOWERDUCKPOND_BACKUP_KEEP_" + name, value)

    @contextmanager
    def leases(descriptors: tuple[int, ...]) -> Iterator[None]:
        observed.append(descriptors)
        yield

    def legacy(
        paths: ProtectionPaths, _environment: Mapping[str, str], *, expected_owner: int
    ) -> None:
        assert paths == ProtectionPaths() and expected_owner == 0
        observed.append("legacy")

    def protected(
        paths: ProtectionPaths,
        _environment: Mapping[str, str],
        *,
        expected_owner: int,
        expected_group: int,
    ) -> None:
        assert paths == ProtectionPaths() and expected_owner == expected_group == 0
        observed.append("protected")
        raise RuntimeError("private-provider-response-must-not-escape")

    def verify(
        paths: ProtectionPaths,
        _environment: Mapping[str, str],
        *,
        expected_owner: int,
        expected_group: int,
        initialize: bool,
    ) -> None:
        assert paths == ProtectionPaths() and expected_owner == expected_group == 0
        observed.append(("verify", initialize))

    monkeypatch.setattr(entrypoint, "inherit_restic_leases", leases)
    monkeypatch.setattr(entrypoint, "maintain_archive_free_repository", legacy)
    monkeypatch.setattr(entrypoint, "maintain_archive", protected)
    monkeypatch.setattr(entrypoint, "verify_archive", verify)
    return observed


@pytest.mark.parametrize("coherent", ["true", "false", "unknown"])
@pytest.mark.parametrize("rotation", ["true", "false", "TRUE", None])
def test_rotation_requires_both_explicit_modes_and_fixed_root_paths(
    calls: list[object], monkeypatch: pytest.MonkeyPatch, coherent: str, rotation: str | None
) -> None:
    def rotate(
        paths: RotationPaths,
        _environment: Mapping[str, str],
        *,
        expected_owner: int,
        expected_group: int,
    ) -> bool:
        assert paths == RotationPaths() and expected_owner == expected_group == 0
        calls.append("rotate")
        return True

    monkeypatch.setattr(entrypoint, "rotate_archive", rotate)
    monkeypatch.setattr(sys, "argv", ["backup-audit-agent", "--rotate"])
    monkeypatch.setenv("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED", coherent)
    if rotation is None:
        monkeypatch.delenv("LOWERDUCKPOND_AUDIT_ROTATION_ENABLED", raising=False)
    else:
        monkeypatch.setenv("LOWERDUCKPOND_AUDIT_ROTATION_ENABLED", rotation)
    accepted = coherent == rotation == "true"
    assert entrypoint.audit_main(10) == (0 if accepted else 1)
    assert calls == ([(9, 10), "rotate"] if accepted else [(9, 10)])


@pytest.mark.parametrize("mode", ["true", "false", "unknown"])
def test_protected_failure_never_falls_back_to_legacy_and_diagnostics_are_fixed(
    calls: list[object],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    monkeypatch.setattr(sys, "argv", ["backup-audit-agent", "--maintain"])
    monkeypatch.setenv("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED", mode)
    result = entrypoint.audit_main(10)
    expected: list[object] = [(9, 10)]
    if mode != "unknown":
        expected.append("protected" if mode == "true" else "legacy")
    assert calls == expected
    output = capsys.readouterr()
    assert result == (0 if mode == "false" else 1)
    assert output.out == ("backup_audit_verified\n" if mode == "false" else "")
    assert output.err == ("" if mode == "false" else "backup_audit_unverified\n")


@pytest.mark.parametrize("argument", ["--initialize", "--verify"])
def test_explicit_initialization_never_creates_a_new_lineage(
    calls: list[object], monkeypatch: pytest.MonkeyPatch, argument: str
) -> None:
    monkeypatch.setattr(sys, "argv", ["backup-audit-agent", argument])
    assert entrypoint.audit_main(10) == 0
    assert calls == [(9, 10), ("verify", argument == "--initialize")]


def test_unqualified_retention_policy_never_reaches_either_coordinator(
    calls: list[object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["backup-audit-agent", "--maintain"])
    monkeypatch.setenv("LOWERDUCKPOND_BACKUP_KEEP_DAILY", "1")
    monkeypatch.setenv("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED", "true")
    assert entrypoint.audit_main(10) == 1
    assert calls == [(9, 10)]
