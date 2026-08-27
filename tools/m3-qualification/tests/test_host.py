from __future__ import annotations

import time
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace

import pytest
from lowerduckpond_m3_qualification import host

RUN_ID = "0198d17f-6f4a-7000-8000-000000000001"


def test_sudo_probe_reports_all_nine_rejections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = iter([0, *([1] * (len(host.UUID_REJECTION_ARGUMENTS) + 1))])
    monkeypatch.setattr(
        host,
        "_quiet_run",
        lambda command: SimpleNamespace(returncode=next(outcomes)),
    )

    assert host._check_sudo_uuid() == {"accepted": 1, "rejected": 9}


def test_systemd_recovery_accepts_exact_start_limit_exhaustion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(host, "QUALIFICATION_ROOT", tmp_path)
    monkeypatch.setattr(host, "_quiet_run", lambda command: SimpleNamespace(returncode=1))
    monkeypatch.setattr(host, "_checked_run", lambda command: None)
    monkeypatch.setattr(host, "_poll_systemd_state", lambda unit, expected: None)
    properties = iter(
        (
            {"NRestarts": "3", "StartLimitBurst": "3"},
            {"NRestarts": "0", "Result": "success"},
        )
    )
    monkeypatch.setattr(host, "_systemd_properties", lambda unit, names: next(properties))
    times = iter((1.0, 1.01))
    monkeypatch.setattr(time, "monotonic", lambda: next(times))

    assert host._check_systemd_recovery() == {
        "handoff_ms": 10,
        "nonblocking": True,
        "reset_recovered": True,
    }


def test_certificate_check_requires_each_apex_and_wildcard_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_names = dict(host.CERTIFICATE_PROBES)
    monkeypatch.setattr(host, "_route_addresses", lambda: "192.0.2.1")
    monkeypatch.setattr(
        host,
        "_certificate_dns_names",
        lambda _address, server_name: frozenset({expected_names[server_name]}),
    )

    assert host._check_caddy_certificates() == {"certificate_paths": len(host.CERTIFICATE_PROBES)}


def test_certificate_check_rejects_exact_leaf_in_place_of_wildcard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(host, "_route_addresses", lambda: "192.0.2.1")
    monkeypatch.setattr(
        host,
        "_certificate_dns_names",
        lambda _address, server_name: frozenset({server_name}),
    )

    with pytest.raises(RuntimeError):
        host._check_caddy_certificates()


def test_log_check_ignores_entries_before_the_current_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log_path = tmp_path / "caddy.json"
    log_path.write_text(f'{host.CANARY_VALUE} "Cookie"\n', encoding="utf-8")

    def append_safe_proof(
        _host: str, _path: str, *, include_state: bool
    ) -> tuple[int, dict[str, str], bytes]:
        assert include_state
        with log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(f'{{"request":{{"uri":"{host.LOG_PROOF_PATH}"}}}}\n')
        return HTTPStatus.NOT_FOUND, {"cache-control": "no-store, no-transform"}, b""

    monkeypatch.setattr(host, "CADDY_LOG_PATH", log_path)
    monkeypatch.setattr(host, "_curl_route", append_safe_proof)

    assert host._check_caddy_log_safety() == {"structured": True, "values_omitted": True}


def test_generation_path_requires_one_uuid_keyed_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    generation_root = tmp_path / "generations"
    monkeypatch.setattr(host, "CADDY_GENERATION_ROOT", generation_root)

    assert host._is_generation_path(generation_root / f"{RUN_ID}-dual")
    assert host._is_generation_path(generation_root / f"{RUN_ID}-replacement")
    assert not host._is_generation_path(generation_root / RUN_ID)
    assert not host._is_generation_path(generation_root / "m3-qualification")
    assert not host._is_generation_path(generation_root / RUN_ID / "nested")
