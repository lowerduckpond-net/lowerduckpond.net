from __future__ import annotations

import ssl
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartIntent,
    CaddyStartMode,
    CaddyStartPhase,
    start_target,
)

_DISABLED_STATUS = 78
_USAGE_STATUS = 64


def test_disabled_operator_checks_the_gate_before_opening_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    gate = tmp_path / "publication-gate"
    gate.write_text(
        "#!/bin/sh\nprintf 'publication_disabled\\n' >&2\nexit 78\n",
        encoding="utf-8",
    )
    gate.chmod(0o700)
    monkeypatch.setattr(entrypoints, "_PUBLICATION_GATE", gate)
    monkeypatch.setattr(entrypoints, "_STATE_ROOT", tmp_path / "absent-state")

    status = entrypoints.operator_main(["--principal", "operator@example.test"])

    assert status == _DISABLED_STATUS
    assert capfd.readouterr().err == "publication_disabled\n"


def test_caddy_bootstrap_and_launcher_reject_unfixed_invocations(
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert entrypoints.caddy_launcher_main(["unexpected"]) == _USAGE_STATUS
    assert entrypoints.caddy_bootstrap_main(["relative", "bad"]) == _USAGE_STATUS
    assert entrypoints.caddy_start_gate_main(["unexpected"]) == 1
    assert entrypoints.caddy_start_verifier_main(["unexpected"]) == 1
    assert entrypoints.caddy_start_recovery_main(["unexpected"]) == 1

    assert capfd.readouterr().err == (
        "invalid_caddy_launcher_invocation\n"
        "invalid_caddy_bootstrap_invocation\n"
        "caddy_start_gate_failed\n"
        "caddy_start_verification_failed\n"
        "caddy_start_recovery_failed\n"
    )


def test_origin_pull_pem_conversion_returns_the_exact_der_bytes() -> None:
    expected = b"review-only-DER-certificate"
    pem = ssl.DER_cert_to_PEM_cert(expected).encode("ascii")

    assert entrypoints._pem_certificate_der(pem) == expected


def test_caddy_recovery_selects_and_commits_before_queuing_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    candidate = start_target("0198d17f-6f4a-7000-8000-000000000001", b"candidate")
    previous = start_target("0198d17f-6f4a-7000-8000-000000000002", b"previous")
    invocations = tuple(f"{value:032x}" for value in range(3))
    intent = CaddyStartIntent(
        mode=CaddyStartMode.TRANSACTIONAL,
        phase=CaddyStartPhase.CANDIDATE_STARTING,
        candidate=candidate,
        previous=previous,
        candidate_invocations=invocations,
        invocation_id=invocations[-1],
    )

    class Runtime:
        def __enter__(self) -> Runtime:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def locked(self) -> nullcontext[None]:
            return nullcontext()

        def select_active(self, generation_id: str) -> None:
            assert generation_id == previous.generation_id
            order.append("select")

    class Startup:
        def __enter__(self) -> Startup:
            return self

        def __exit__(self, *_exception: object) -> None:
            pass

        def reconcile_temporaries(self) -> int:
            return 0

        def require_rollback_target(self) -> CaddyStartIntent:
            return intent

        def mark_rollback_restart_required(
            self,
            expected: CaddyStartIntent,
        ) -> CaddyStartIntent:
            assert expected == intent
            assert order == ["select"]
            order.append("commit")
            return replace(
                intent,
                phase=CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
                invocation_id=None,
            )

    class StartupType:
        @staticmethod
        def open(_path: Path, *, expected_owner: int) -> Startup:
            assert expected_owner == 0
            return Startup()

    def run(command: list[str], **_arguments: object) -> SimpleNamespace:
        order.append("reset" if "reset-failed" in command else "start")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(entrypoints, "_open_systemd_caddy_runtime", Runtime)
    monkeypatch.setattr(entrypoints, "CaddyStartupStore", StartupType)
    monkeypatch.setattr(entrypoints.subprocess, "run", run)

    assert entrypoints.caddy_start_recovery_main([]) == 0
    assert order == ["select", "commit", "reset", "start"]
