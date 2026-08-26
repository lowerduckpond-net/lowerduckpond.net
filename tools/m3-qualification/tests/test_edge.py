from __future__ import annotations

import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lowerduckpond_m3_qualification import edge

ZONE_IDS = {"lowerduckpond_net": "a" * 32, "lowerduckpond_com": "b" * 32}
CERTIFICATE_IDS = {
    "primary": {
        "lowerduckpond_net": "11111111-1111-4111-8111-111111111111",
        "lowerduckpond_com": "22222222-2222-4222-8222-222222222222",
    },
    "replacement": {
        "lowerduckpond_net": "33333333-3333-4333-8333-333333333333",
        "lowerduckpond_com": "44444444-4444-4444-8444-444444444444",
    },
}
TEST_API_VALUE = "test-cloudflare-value-0000000000"


def inputs() -> edge.EdgeInputs:
    return edge.EdgeInputs(
        origin_ipv4="8.8.8.8",
        zone_ids=ZONE_IDS,
        certificate_ids=CERTIFICATE_IDS,
        api_token=TEST_API_VALUE,
        ssh_target="ldp-admin@8.8.8.8",
    )


def test_edge_inputs_require_four_distinct_certificate_ids() -> None:
    duplicated = {generation: dict(values) for generation, values in CERTIFICATE_IDS.items()}
    duplicated["replacement"]["lowerduckpond_net"] = duplicated["primary"]["lowerduckpond_net"]

    with pytest.raises(edge.EdgeQualificationError, match="four distinct"):
        edge.EdgeInputs(
            origin_ipv4="8.8.8.8",
            zone_ids=ZONE_IDS,
            certificate_ids=duplicated,
            api_token=TEST_API_VALUE,
            ssh_target="ldp-admin@8.8.8.8",
        )


def test_preflight_requires_strict_ssl_offline_fallback_and_fresh_leaves(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)

    class FakeClient:
        def __init__(self, token: str) -> None:
            assert token

        def get(self, path: str) -> object:
            if path.endswith("/settings/ssl"):
                return {"value": "strict"}
            if path.endswith("/settings/always_online"):
                return {"value": "off"}
            if path.endswith("/rulesets"):
                return []
            if path.endswith("/hostnames/certificates"):
                zone_key = "lowerduckpond_net" if f"/{'a' * 32}/" in path else "lowerduckpond_com"
                return [
                    {
                        "id": CERTIFICATE_IDS[generation][zone_key],
                        "status": "active",
                        "uploaded_on": now.isoformat(),
                        "expires_on": (now + timedelta(days=30)).isoformat(),
                        "certificate": "test certificate",
                    }
                    for generation in ("primary", "replacement")
                ]
            raise AssertionError(path)

    monkeypatch.setattr(edge, "CloudflareClient", FakeClient)
    monkeypatch.setattr(edge, "_require_ca_certificate", lambda path, *, now: None)
    observed_leaves: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        edge,
        "_require_leaf_certificate",
        lambda certificate, *, ca_path, expected_zone: observed_leaves.append(
            (ca_path, expected_zone)
        ),
    )
    primary_ca = tmp_path / "primary.pem"
    replacement_ca = tmp_path / "replacement.pem"
    primary_ca.write_text("public primary", encoding="utf-8")
    replacement_ca.write_text("public replacement", encoding="utf-8")

    edge.run_preflight(
        zone_ids=ZONE_IDS,
        certificate_ids=CERTIFICATE_IDS,
        ca_paths={"primary": primary_ca, "replacement": replacement_ca},
        api_token=TEST_API_VALUE,
        now=now,
    )
    assert observed_leaves == [
        (primary_ca, "lowerduckpond.net"),
        (replacement_ca, "lowerduckpond.net"),
        (primary_ca, "lowerduckpond.com"),
        (replacement_ca, "lowerduckpond.com"),
    ]


@pytest.mark.parametrize("status", (520, 525))
def test_retired_primary_stage_accepts_documented_aop_rejection_from_both_zones(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    monkeypatch.setattr(edge, "CloudflareClient", lambda token: object())
    observed_generations: list[str] = []
    monkeypatch.setattr(
        edge,
        "_require_associations",
        lambda client, values, generation: observed_generations.append(generation),
    )
    monkeypatch.setattr(
        edge,
        "_origin_certificate",
        lambda values, hostname: f"origin:{hostname}".encode(),
    )
    monkeypatch.setattr(
        edge,
        "_request",
        lambda hostname, path: edge.EdgeResponse(status=status, fields={}, content=b"provider"),
    )

    checks = edge.run_rollover_stage(inputs(), stage="retired-primary")

    assert checks[0].check_id == "m3.0.edge.aop-retired-primary"
    assert checks[0].status == "passed"
    assert checks[0].evidence == {
        "both_zones_checked": True,
        "old_leaf_rejected": True,
        "origin_tls_stable": True,
    }
    assert observed_generations == ["primary", "primary"]


@pytest.mark.parametrize("status", (521, 522, 523, 524, 526, 527))
def test_retired_primary_stage_rejects_other_edge_failures(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    monkeypatch.setattr(edge, "CloudflareClient", lambda token: object())
    monkeypatch.setattr(edge, "_require_associations", lambda client, values, generation: None)
    monkeypatch.setattr(edge, "AOP_PROPAGATION_ATTEMPTS", 1)
    monkeypatch.setattr(edge, "_origin_certificate", lambda values, hostname: b"origin")
    monkeypatch.setattr(
        edge,
        "_request",
        lambda hostname, path: edge.EdgeResponse(status=status, fields={}, content=b"provider"),
    )

    with pytest.raises(edge.EdgeQualificationError, match="old origin-pull leaf"):
        edge.run_rollover_stage(inputs(), stage="retired-primary")


def test_retired_primary_stage_rejects_an_origin_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(edge, "CloudflareClient", lambda token: object())
    monkeypatch.setattr(edge, "_require_associations", lambda client, values, generation: None)
    monkeypatch.setattr(edge, "AOP_PROPAGATION_ATTEMPTS", 1)
    monkeypatch.setattr(edge, "_origin_certificate", lambda values, hostname: b"origin")
    monkeypatch.setattr(
        edge,
        "_request",
        lambda hostname, path: edge.EdgeResponse(
            status=520,
            fields={"x-m3-origin-reached": "true"},
            content=b"provider",
        ),
    )

    with pytest.raises(edge.EdgeQualificationError, match="old origin-pull leaf"):
        edge.run_rollover_stage(inputs(), stage="retired-primary")


def test_retired_primary_stage_requires_a_live_origin_tls_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(edge, "CloudflareClient", lambda token: object())
    monkeypatch.setattr(edge, "_require_associations", lambda client, values, generation: None)

    def unavailable(values: edge.EdgeInputs, hostname: str) -> bytes:
        raise edge.EdgeQualificationError("origin certificate could not be observed")

    monkeypatch.setattr(edge, "_origin_certificate", unavailable)

    with pytest.raises(edge.EdgeQualificationError, match="origin certificate"):
        edge.run_rollover_stage(inputs(), stage="retired-primary")


def test_retired_primary_stage_waits_for_both_zones_to_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(edge, "CloudflareClient", lambda token: object())
    monkeypatch.setattr(edge, "_require_associations", lambda client, values, generation: None)
    monkeypatch.setattr(edge, "AOP_PROPAGATION_ATTEMPTS", 2)
    monkeypatch.setattr(edge, "_origin_certificate", lambda values, hostname: b"origin")
    responses = iter(
        (
            edge.EdgeResponse(
                status=200,
                fields={"x-m3-origin-reached": "true"},
                content=b"origin",
            ),
            edge.EdgeResponse(status=520, fields={}, content=b"provider"),
            edge.EdgeResponse(status=520, fields={}, content=b"provider"),
            edge.EdgeResponse(status=525, fields={}, content=b"provider"),
        )
    )
    monkeypatch.setattr(edge, "_request", lambda hostname, path: next(responses))
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)

    checks = edge.run_rollover_stage(inputs(), stage="retired-primary")

    assert checks[0].status == "passed"
    assert sleeps == [edge.AOP_PROPAGATION_RETRY_DELAY_SECONDS]


def test_retired_primary_stage_requires_a_stable_origin_tls_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(edge, "CloudflareClient", lambda token: object())
    monkeypatch.setattr(edge, "_require_associations", lambda client, values, generation: None)
    certificates = iter((b"net-before", b"com-before", b"net-after", b"com-changed"))
    monkeypatch.setattr(edge, "_origin_certificate", lambda values, hostname: next(certificates))
    monkeypatch.setattr(
        edge,
        "_request",
        lambda hostname, path: edge.EdgeResponse(status=520, fields={}, content=b"provider"),
    )

    with pytest.raises(edge.EdgeQualificationError, match="listener changed"):
        edge.run_rollover_stage(inputs(), stage="retired-primary")


@pytest.mark.parametrize(
    ("address", "expected"),
    [("104.16.0.1", True), ("2606:4700::1", True), ("8.8.8.8", False)],
)
def test_cloudflare_address_classifier(address: str, expected: bool) -> None:
    assert edge._is_cloudflare_address(address) is expected


def test_http_policy_requires_exact_method_preserving_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str, str]] = []

    def fake_request(  # noqa: PLR0913 - mirrors the bounded probe interface.
        hostname: str,
        path: str,
        *,
        https: bool = True,
        method: str = "GET",
        fields: dict[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> edge.EdgeResponse:
        assert https is False
        assert fields is None
        assert follow_redirects is False
        observed.append((method, hostname, path))
        return edge.EdgeResponse(
            status=308,
            fields={"location": f"https://{hostname}{path}"},
            content=b"",
        )

    monkeypatch.setattr(edge, "_request", fake_request)

    evidence = edge._check_http_policy()

    assert evidence == {"redirect_only": True}
    assert any(method == "POST" for method, _, _ in observed)
    assert all("?m3=" in path for _, _, path in observed)


def test_origin_certificate_is_observed_before_expected_client_auth_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate = b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"

    def fake_ssh(
        values: edge.EdgeInputs, *command: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        assert values == inputs()
        assert command[1:3] == ("openssl", "s_client")
        assert check is False
        return subprocess.CompletedProcess(command, 1, stdout=certificate, stderr=b"alert")

    monkeypatch.setattr(edge, "_ssh", fake_ssh)

    assert edge._origin_certificate(inputs(), edge.PLATFORM_HOST) == b"abc"


def test_uploaded_leaf_must_chain_to_the_matching_client_ca(tmp_path: Path) -> None:
    ca_key = tmp_path / "ca.key"
    ca_certificate = tmp_path / "ca.pem"
    leaf_key = tmp_path / "leaf.key"
    leaf_request = tmp_path / "leaf.csr"
    leaf_certificate = tmp_path / "leaf.pem"
    subprocess.run(  # noqa: S603 - fixed OpenSSL test boundary.
        (
            edge.OPENSSL_EXECUTABLE,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_certificate),
            "-subj",
            "/CN=M3 test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-days",
            "32",
        ),
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        (
            edge.OPENSSL_EXECUTABLE,
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(leaf_key),
            "-out",
            str(leaf_request),
            "-subj",
            "/CN=lowerduckpond.net",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "extendedKeyUsage=clientAuth",
            "-addext",
            "subjectAltName=DNS:lowerduckpond.net",
        ),
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        (
            edge.OPENSSL_EXECUTABLE,
            "x509",
            "-req",
            "-in",
            str(leaf_request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-copy_extensions",
            "copy",
            "-days",
            "1",
            "-out",
            str(leaf_certificate),
        ),
        check=True,
        capture_output=True,
    )

    edge._require_ca_certificate(ca_certificate, now=datetime.now(UTC))
    edge._require_leaf_certificate(
        {"certificate": leaf_certificate.read_text(encoding="ascii")},
        ca_path=ca_certificate,
        expected_zone="lowerduckpond.net",
    )
    with pytest.raises(edge.EdgeQualificationError, match="constraints are unsafe"):
        edge._require_leaf_certificate(
            {"certificate": leaf_certificate.read_text(encoding="ascii")},
            ca_path=ca_certificate,
            expected_zone="lowerduckpond.com",
        )
