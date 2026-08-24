from __future__ import annotations

import pytest
from lowerduckpond_m3_qualification import host


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
