from __future__ import annotations

import ssl
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import entrypoints

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
    assert entrypoints.caddy_launcher_main([]) == _USAGE_STATUS
    assert entrypoints.caddy_bootstrap_main(["relative", "bad"]) == _USAGE_STATUS

    assert capfd.readouterr().err == (
        "invalid_caddy_launcher_invocation\ninvalid_caddy_bootstrap_invocation\n"
    )


def test_origin_pull_pem_conversion_returns_the_exact_der_bytes() -> None:
    expected = b"review-only-DER-certificate"
    pem = ssl.DER_cert_to_PEM_cert(expected).encode("ascii")

    assert entrypoints._pem_certificate_der(pem) == expected
