from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import check_m3_7_production_edge
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError

REPOSITORY_ROOT = Path(__file__).parents[2]
PREFLIGHT = (REPOSITORY_ROOT / "scripts/preflight-m3-7-production").resolve()
JUSTFILE = (REPOSITORY_ROOT / "justfile").resolve()
RUNBOOK = (REPOSITORY_ROOT / "docs/operations/m3-public-edge-rollout.md").resolve()
OPENSSL = "/usr/bin/openssl"
INPUT_ERROR_STATUS = 2


class _CloudflareResponse:
    def __init__(self, payload: dict[str, object], *, status: int = 200) -> None:
        self.status = status
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> _CloudflareResponse:
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def read(self, _maximum_bytes: int) -> bytes:
        return self._payload


def _run_openssl(*arguments: str) -> None:
    result = subprocess.run(  # noqa: S603 -- fixed test-only OpenSSL executable.
        (OPENSSL, *arguments),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def _certificate_fixture(tmp_path: Path, *, leaf_days: int = 365) -> tuple[Path, dict[str, str]]:
    ca_key = tmp_path / "ca.key"
    ca_certificate = tmp_path / "ca.pem"
    leaf_key = tmp_path / "leaf.key"
    leaf_request = tmp_path / "leaf.csr"
    leaf_certificate = tmp_path / "leaf.pem"
    _run_openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1825",
        "-subj",
        "/CN=production-test-ca",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        os.fspath(ca_key),
        "-out",
        os.fspath(ca_certificate),
    )
    _run_openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=lowerduckpond.net",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext",
        "extendedKeyUsage=clientAuth",
        "-addext",
        "subjectAltName=DNS:lowerduckpond.net",
        "-keyout",
        os.fspath(leaf_key),
        "-out",
        os.fspath(leaf_request),
    )
    _run_openssl(
        "x509",
        "-req",
        "-in",
        os.fspath(leaf_request),
        "-CA",
        os.fspath(ca_certificate),
        "-CAkey",
        os.fspath(ca_key),
        "-CAcreateserial",
        "-sha256",
        "-days",
        str(leaf_days),
        "-copy_extensions",
        "copy",
        "-out",
        os.fspath(leaf_certificate),
    )
    not_after = check_m3_7_production_edge._certificate_dates(leaf_certificate.read_bytes())[1]
    return ca_certificate, {
        "id": "2" * 32,
        "certificate": leaf_certificate.read_text(encoding="ascii"),
        "expires_on": not_after.isoformat().replace("+00:00", "Z"),
        "status": "active",
    }


def test_production_certificate_policy_accepts_one_year_leaf(tmp_path: Path) -> None:
    ca_path, leaf = _certificate_fixture(tmp_path)
    now = datetime.now(UTC)

    check_m3_7_production_edge.validate_ca_certificate(ca_path, ca_path.read_bytes(), now=now)
    check_m3_7_production_edge.validate_leaf_certificate(
        leaf,
        ca_path=ca_path,
        expected_zone="lowerduckpond.net",
        expected_id="2" * 32,
        now=now,
    )


def test_production_certificate_policy_rejects_short_remaining_leaf(tmp_path: Path) -> None:
    ca_path, leaf = _certificate_fixture(tmp_path, leaf_days=30)

    with pytest.raises(ProductionEdgePreflightError, match="validity is outside policy"):
        check_m3_7_production_edge.validate_leaf_certificate(
            leaf,
            ca_path=ca_path,
            expected_zone="lowerduckpond.net",
            expected_id="2" * 32,
            now=datetime.now(UTC),
        )


def test_cloudflare_collection_follows_and_validates_every_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = iter(
        (
            {
                "success": True,
                "result": [{"id": "first"}],
                "result_info": {"page": 1, "count": 1, "total_pages": 2, "total_count": 2},
            },
            {
                "success": True,
                "result": [{"id": "second"}],
                "result_info": {"page": 2, "count": 1, "total_pages": 2, "total_count": 2},
            },
        )
    )
    requested_urls: list[str] = []

    def fake_urlopen(request: object, *, timeout: int) -> _CloudflareResponse:
        assert timeout == check_m3_7_production_edge.API_TIMEOUT_SECONDS
        requested_urls.append(request.full_url)  # type: ignore[attr-defined]
        return _CloudflareResponse(next(payloads))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = check_m3_7_production_edge.CloudflareClient("x" * 20)
    collection = client.get_collection("/zones/zone/rulesets")

    assert collection == [{"id": "first"}, {"id": "second"}]
    assert "page=1" in requested_urls[0]
    assert "page=2" in requested_urls[1]


def test_cloudflare_collection_accepts_proven_empty_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "success": True,
        "result": [],
        "result_info": {"page": 1, "count": 0, "total_pages": 0, "total_count": 0},
    }

    def fake_urlopen(_request: object, *, timeout: int) -> _CloudflareResponse:
        assert timeout == check_m3_7_production_edge.API_TIMEOUT_SECONDS
        return _CloudflareResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = check_m3_7_production_edge.CloudflareClient("x" * 20)

    assert client.get_collection("/zones/zone/origin_tls_client_auth") == []


def test_aop_setting_alone_accepts_cloudflare_live_202(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {"success": True, "result": {"enabled": False}}

    def fake_urlopen(_request: object, *, timeout: int) -> _CloudflareResponse:
        assert timeout == check_m3_7_production_edge.API_TIMEOUT_SECONDS
        return _CloudflareResponse(payload, status=202)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = check_m3_7_production_edge.CloudflareClient("x" * 20)
    zone_id = "1" * 32

    assert client.get_aop_setting(zone_id) == {"enabled": False}
    with pytest.raises(ProductionEdgePreflightError, match="unexpected HTTP status"):
        client.get(f"/zones/{zone_id}/origin_tls_client_auth/settings")


def test_cloudflare_cursor_collection_follows_every_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = iter(
        (
            {
                "success": True,
                "result": [{"id": "first"}],
                "result_info": {"cursors": {"after": "next-page"}},
            },
            {
                "success": True,
                "result": [{"id": "second"}],
                "result_info": {"cursors": {}},
            },
        )
    )
    requested_urls: list[str] = []

    def fake_urlopen(request: object, *, timeout: int) -> _CloudflareResponse:
        assert timeout == check_m3_7_production_edge.API_TIMEOUT_SECONDS
        requested_urls.append(request.full_url)  # type: ignore[attr-defined]
        return _CloudflareResponse(next(payloads))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = check_m3_7_production_edge.CloudflareClient("x" * 20)
    collection = client.get_cursor_collection("/zones/zone/rulesets")

    assert collection == [{"id": "first"}, {"id": "second"}]
    assert "cursor=" not in requested_urls[0]
    assert "cursor=next-page" in requested_urls[1]


@pytest.mark.parametrize(
    "terminal_metadata",
    (
        {},
        {"result_info": {}},
    ),
)
def test_cloudflare_cursor_collection_accepts_optional_terminal_metadata(
    monkeypatch: pytest.MonkeyPatch,
    terminal_metadata: dict[str, object],
) -> None:
    payload = {
        "success": True,
        "result": [{"id": "only"}],
        **terminal_metadata,
    }

    def fake_urlopen(_request: object, *, timeout: int) -> _CloudflareResponse:
        assert timeout == check_m3_7_production_edge.API_TIMEOUT_SECONDS
        return _CloudflareResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = check_m3_7_production_edge.CloudflareClient("x" * 20)

    assert client.get_cursor_collection("/zones/zone/rulesets") == [{"id": "only"}]


@pytest.mark.parametrize(
    "malformed_metadata",
    (
        {"result_info": None},
        {"result_info": {"cursors": None}},
        {"result_info": {"cursors": "not-an-object"}},
        {"result_info": {"cursors": {"after": ""}}},
    ),
)
def test_cloudflare_cursor_collection_rejects_malformed_present_metadata(
    monkeypatch: pytest.MonkeyPatch,
    malformed_metadata: dict[str, object],
) -> None:
    payload = {"success": True, "result": [], **malformed_metadata}

    def fake_urlopen(_request: object, *, timeout: int) -> _CloudflareResponse:
        assert timeout == check_m3_7_production_edge.API_TIMEOUT_SECONDS
        return _CloudflareResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = check_m3_7_production_edge.CloudflareClient("x" * 20)

    with pytest.raises(ProductionEdgePreflightError, match="metadata is malformed"):
        client.get_cursor_collection("/zones/zone/rulesets")


def test_direct_dns_rejects_competing_record_types() -> None:
    class CompetingDnsClient:
        def get_collection(
            self, _path: str, *, query: dict[str, str] | None = None
        ) -> list[object]:
            assert query is None
            hostname = "lowerduckpond.net"
            return [
                {"name": hostname, "type": "A", "content": "192.0.2.1", "proxied": False},
                {"name": hostname, "type": "AAAA", "content": "2001:db8::1"},
            ]

    with pytest.raises(ProductionEdgePreflightError, match="DNS inventory is not exact"):
        check_m3_7_production_edge._require_direct_dns(
            CompetingDnsClient(),  # type: ignore[arg-type]
            zone_id="1" * 32,
            zone_name="lowerduckpond.net",
            origin_ipv4="192.0.2.1",
            records_expected=True,
        )


def test_account_token_policy_requires_exact_permissions_and_resources() -> None:
    token_id = "1" * 32
    zone_resources = frozenset(
        {
            f"com.cloudflare.api.account.zone.{'2' * 32}",
            f"com.cloudflare.api.account.zone.{'3' * 32}",
        }
    )
    token = {
        "id": token_id,
        "status": "active",
        "policies": [
            {
                "effect": "allow",
                "permission_groups": [
                    {"id": "4" * 32, "name": "Zone Read"},
                    {"id": "5" * 32, "name": "DNS Write"},
                ],
                "resources": dict.fromkeys(zone_resources, "*"),
            }
        ],
    }

    check_m3_7_production_edge.validate_account_token_policy(
        token,
        expected_id=token_id,
        expected_permissions={"4" * 32: "Zone Read", "5" * 32: "DNS Write"},
        expected_resources=zone_resources,
        label="test",
    )

    insufficient_token = {
        **token,
        "policies": [
            {
                "effect": "allow",
                "permission_groups": [{"id": "4" * 32, "name": "Zone Read"}],
                "resources": dict.fromkeys(zone_resources, "*"),
            }
        ],
    }
    with pytest.raises(ProductionEdgePreflightError, match="exact reviewed policy"):
        check_m3_7_production_edge.validate_account_token_policy(
            insufficient_token,
            expected_id=token_id,
            expected_permissions={"4" * 32: "Zone Read", "5" * 32: "DNS Write"},
            expected_resources=zone_resources,
            label="test",
        )

    split_scope_token = {
        **token,
        "policies": [
            {
                "effect": "allow",
                "permission_groups": [{"id": "4" * 32, "name": "Zone Read"}],
                "resources": {sorted(zone_resources)[0]: "*"},
            },
            {
                "effect": "allow",
                "permission_groups": [{"id": "5" * 32, "name": "DNS Write"}],
                "resources": {sorted(zone_resources)[1]: "*"},
            },
        ],
    }
    with pytest.raises(ProductionEdgePreflightError, match="exact reviewed policy"):
        check_m3_7_production_edge.validate_account_token_policy(
            split_scope_token,
            expected_id=token_id,
            expected_permissions={"4" * 32: "Zone Read", "5" * 32: "DNS Write"},
            expected_resources=zone_resources,
            label="test",
        )

    expiring_token = {**token, "expires_on": "2027-01-01T00:00:00Z"}
    with pytest.raises(ProductionEdgePreflightError, match="unexpectedly expires"):
        check_m3_7_production_edge.validate_non_expiring_account_token(expiring_token, label="test")


def test_production_gate_is_read_only_and_composes_existing_gate() -> None:
    preflight = PREFLIGHT.read_text(encoding="utf-8")
    justfile = JUSTFILE.read_text(encoding="utf-8")
    runbook = RUNBOOK.read_text(encoding="utf-8")

    assert '"${repository_root}/scripts/preflight-m3-6-production"' in preflight
    assert 'tofu -chdir="${production_root}" state list' in preflight
    assert "output -raw reserved_ip_address" in preflight
    assert "output -raw edge_rollout_phase" in preflight
    assert "gh variable list --env production" in preflight
    assert "gh secret list --env production" in preflight
    assert "M3_7_TOKEN_AUDIT_TOKEN" in preflight
    assert "tofu plan" not in preflight
    assert "tofu apply" not in preflight
    assert "ansible-playbook" not in preflight
    assert "--request POST" not in preflight
    assert "--request PUT" not in preflight
    assert "--request DELETE" not in preflight
    assert "preflight-m3-7-production:" in justfile
    assert "if ! lowerduckpond_net_certificate_id=$(" in runbook
    assert "if ! lowerduckpond_com_certificate_id=$(" in runbook
    assert '--output "$response_path"' in runbook
    assert "(-[0-9a-f]{4}){3}" in runbook


def test_production_gate_rejects_missing_inputs_before_network_access() -> None:
    environment = {"PATH": os.environ["PATH"]}

    result = subprocess.run(  # noqa: S603 -- reviewed absolute repository helper.
        [os.fspath(PREFLIGHT)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == INPUT_ERROR_STATUS
    assert result.stdout == ""
    assert "ANSIBLE_PRIVATE_KEY_FILE is not set" in result.stderr
