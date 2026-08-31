from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts import check_m3_7_production_edge
from scripts.check_m3_7_production_edge import ProductionEdgePreflightError

REPOSITORY_ROOT = Path(__file__).parents[2]
PREFLIGHT = (REPOSITORY_ROOT / "scripts/preflight-m3-7-production").resolve()
JUSTFILE = (REPOSITORY_ROOT / "justfile").resolve()
OPENSSL = "/usr/bin/openssl"
INPUT_ERROR_STATUS = 2


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


def test_production_gate_is_read_only_and_composes_existing_gate() -> None:
    preflight = PREFLIGHT.read_text(encoding="utf-8")
    justfile = JUSTFILE.read_text(encoding="utf-8")

    assert '"${repository_root}/scripts/preflight-m3-6-production"' in preflight
    assert 'tofu -chdir="${production_root}" state list' in preflight
    assert "output -raw reserved_ip_address" in preflight
    assert "output -raw edge_rollout_phase" in preflight
    assert "gh variable list --env production" in preflight
    assert "gh secret list --env production" in preflight
    assert "tofu plan" not in preflight
    assert "tofu apply" not in preflight
    assert "ansible-playbook" not in preflight
    assert "--request POST" not in preflight
    assert "--request PUT" not in preflight
    assert "--request DELETE" not in preflight
    assert "preflight-m3-7-production:" in justfile


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
