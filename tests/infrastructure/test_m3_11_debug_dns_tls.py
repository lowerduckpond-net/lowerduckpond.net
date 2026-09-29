"""Real stored TLS validation must work after the diagnostic issuer is stopped."""

from __future__ import annotations

import os
import pwd
import subprocess
import uuid
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_static_host_agent import host_restore_tls as tls
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError

from scripts import m3_11_debug_dns_probe as guest
from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe


def openssl(*arguments: str) -> None:
    subprocess.run(  # noqa: S603 - fixed executable, owned generated certificate fixture
        ("/usr/bin/openssl", *arguments), check=True, capture_output=True, timeout=10
    )


def expire(tmp_path: Path, certificate: Path) -> None:
    (tmp_path / "index").touch()
    (tmp_path / "serial").write_text("01\n")
    configuration = tmp_path / "ca.conf"
    configuration.write_text(
        "[ca]\ndefault_ca=diagnostic\n[diagnostic]\n"
        f"database={tmp_path}/index\nserial={tmp_path}/serial\n"
        f"new_certs_dir={tmp_path}\ncertificate={tmp_path}/roots.pem\n"
        f"private_key={tmp_path}/ca.key\ndefault_md=sha256\npolicy=names\n"
        "[names]\ncommonName=supplied\n"
    )
    openssl(
        "ca",
        "-batch",
        "-notext",
        "-config",
        str(configuration),
        "-in",
        str(tmp_path / "leaf.csr"),
        "-startdate",
        "20000101000000Z",
        "-enddate",
        "20000102000000Z",
        "-extfile",
        str(tmp_path / "extensions"),
        "-out",
        str(certificate),
    )


@pytest.mark.parametrize("fault", [None, "key", "trust", "name", "missing", "expired", "symlink"])
def test_stopped_issuer_cleanup_checks_real_certificates_before_provider_calls(  # noqa: PLR0915 - real certificate setup and fault matrix
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str | None
) -> None:
    nonce = str(uuid.uuid7())
    subjects = policy.disposable_subjects(nonce)
    storage = tmp_path / "certificates" / policy.ISSUER_STORAGE
    pair = storage / "owned"
    pair.mkdir(mode=0o700, parents=True)
    storage.chmod(0o700)
    roots, ca_key = tmp_path / "roots.pem", tmp_path / "ca.key"
    certificate, key = pair / "owned.crt", pair / "owned.key"
    request, extensions = tmp_path / "leaf.csr", tmp_path / "extensions"
    openssl(
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=diagnostic-owned-ca",
        "-keyout",
        str(ca_key),
        "-out",
        str(roots),
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        "/CN=diagnostic-owned-leaf",
        "-keyout",
        str(key),
        "-out",
        str(request),
    )
    extensions.write_text(
        "subjectAltName="
        + ",".join("DNS:" + name for name in subjects)
        + "\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(request),
        "-CA",
        str(roots),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        str(extensions),
        "-out",
        str(certificate),
    )
    roots.chmod(0o644)
    certificate.chmod(0o600)
    key.chmod(0o600)
    marker = {"nonce": str(uuid.uuid7()) if fault == "name" else nonce}
    if fault == "key":
        key.write_bytes(ca_key.read_bytes())
    elif fault == "trust":
        openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=unrelated-ca",
            "-keyout",
            str(tmp_path / "other.key"),
            "-out",
            str(roots),
        )
    elif fault == "missing":
        certificate.unlink()
    elif fault == "expired":
        expire(tmp_path, certificate)
    elif fault == "symlink":
        certificate.rename(tmp_path / "saved.crt")
        certificate.symlink_to(tmp_path / "saved.crt")
    monkeypatch.setattr(policy, "STORAGE", tmp_path)
    monkeypatch.setattr(policy, "INPUTS", tmp_path)
    monkeypatch.setattr(
        pwd, "getpwnam", Mock(return_value=Mock(pw_uid=os.geteuid(), pw_gid=os.getegid()))
    )
    # Only adapt root ownership for this unprivileged fixture. All certificate,
    # key, subject, expiry and trust checks run through the real verifier.
    verify = tls.verify_cold_tls
    monkeypatch.setattr(
        tls,
        "verify_cold_tls",
        lambda *args, **kwargs: verify(*args, **kwargs, trust_owner=os.geteuid()),
    )
    monkeypatch.setattr(probe, "_guard", Mock(return_value=marker))
    monkeypatch.setattr(probe, "_closed", Mock())
    stopped = Mock()
    monkeypatch.setattr(probe, "_inactive", stopped)
    live = Mock(side_effect=AssertionError("the issuer is stopped; no live TLS probe is allowed"))
    monkeypatch.setattr(probe, "_tls", live)
    monkeypatch.setattr(guest, "_clean_dependencies", Mock())
    (tmp_path / "environment").write_bytes(policy.credential_environment("a" * 40))
    original_read = probe._read
    monkeypatch.setattr(probe, "_read", lambda path: original_read(path, owner=os.geteuid()))
    wanted = [
        {
            "zone_id": "1" * 32,
            "id": "2" * 32,
            "name": "_acme-challenge." + subjects[-1],
            "type": "TXT",
            "content": "A" * 43,
        }
    ]
    provider = Mock(
        side_effect=[
            {"id": "1" * 32, "name": "lowerduckpond.net"},
            {key: wanted[0][key] for key in guest.FIELDS},
            {"id": "2" * 32},
        ]
    )
    monkeypatch.setattr(guest, "_request", provider)
    if fault:
        with pytest.raises((HostRestoreError, OSError)):
            guest.retire("original", wanted)
        provider.assert_not_called()
    else:
        assert guest.retire("original", wanted)["retired_records"] == 1
        assert [call.args[0] for call in provider.call_args_list] == ["GET", "GET", "DELETE"]
    live.assert_not_called()
    stopped.assert_any_call(policy.UNIT)
