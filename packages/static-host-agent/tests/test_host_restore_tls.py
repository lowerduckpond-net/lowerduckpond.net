from __future__ import annotations

import os
import socket
import ssl
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import host_restore_tls as tls
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_process import RestoreCommandResult, run_bounded


def openssl(*arguments: str) -> None:
    subprocess.run(  # noqa: S603 - fixed openssl on owned key/certificate fixture files
        ("/usr/bin/openssl", *arguments),
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )


@pytest.fixture
def certificates(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    storage = tmp_path / "certificates"
    issuer = storage / "controlled-issuer"
    pair = issuer / "example.test"
    pair.mkdir(mode=0o700, parents=True)
    issuer.chmod(0o700)
    ca = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
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
        "/CN=owned-restore-test-ca",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca),
    )
    ca.chmod(0o644)
    key = pair / "example.test.key"
    cert = pair / "example.test.crt"
    request = tmp_path / "leaf.csr"
    extensions = tmp_path / "extensions"
    extensions.write_text(
        "subjectAltName=DNS:example.test,DNS:*.example.test\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n"
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
        "/CN=example.test",
        "-keyout",
        str(key),
        "-out",
        str(request),
    )
    openssl(
        "x509",
        "-req",
        "-in",
        str(request),
        "-CA",
        str(ca),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        str(extensions),
        "-out",
        str(cert),
    )
    key.chmod(0o600)
    cert.chmod(0o600)
    return storage, ca, cert, key


@contextmanager
def origin(
    cert: Path, key: Path, ca: Path, *, client_rejects_server: bool = False
) -> Iterator[int]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.load_verify_locations(ca)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.socket() as listener, ThreadPoolExecutor(max_workers=1) as executor:
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        listener.settimeout(10)

        def serve() -> None:
            for _ in range(2):
                connection, _address = listener.accept()
                with connection:
                    try:
                        with context.wrap_socket(connection, server_side=True):
                            pytest.fail(
                                "origin accepted a client without an origin-pull certificate"
                            )
                    except ssl.SSLError as error:
                        if client_rejects_server:
                            assert "ALERT_UNKNOWN_CA" in str(error)
                        else:
                            assert "PEER_DID_NOT_RETURN_A_CERTIFICATE" in str(error)

        future = executor.submit(serve)
        yield listener.getsockname()[1]
        future.result(timeout=10)


def test_actual_presented_certificates_pass_without_weakening_origin_pull_authentication(
    certificates: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, ca, cert, key = certificates
    run = run_bounded
    with origin(cert, key, ca) as port:

        def local(command: tuple[str, ...], **kwargs: object) -> RestoreCommandResult:
            if command[1] == "s_client":
                command = tuple(
                    f"127.0.0.1:{port}" if item == "127.0.0.1:443" else item for item in command
                )
            return run(command, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(tls, "run_bounded", local)
        receipt = tls.verify_cold_tls(
            storage,
            issuer="controlled-issuer",
            subjects=("*.example.test", "example.test"),
            trust=ca,
            owner=os.geteuid(),
            trust_owner=os.geteuid(),
            group=os.getegid(),
        )
    assert len(receipt["certificates"]) == 2  # type: ignore[arg-type]  # noqa: PLR2004
    assert "PRIVATE KEY" not in str(receipt)


@pytest.mark.parametrize("boundary", ["peer", "stored-chain"])
def test_another_system_trust_directory_cannot_widen_the_pinned_bundle(
    certificates: tuple[Path, Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    storage, ca, cert, key = certificates
    other = ca.parent / "other.crt"
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
        "/CN=only-pinned-root",
        "-keyout",
        str(ca.parent / "other.key"),
        "-out",
        str(other),
    )
    directory = ca.parent / "system-roots"
    directory.mkdir()
    (directory / "unselected-root.crt").write_bytes(ca.read_bytes())
    openssl("rehash", str(directory))
    port = 0

    def inherited_system_roots(
        command: tuple[str, ...],
        *,
        descriptors: tuple[int, ...] = (),
        timeout: int = 10,
        maximum: int = 128 * 1024,
    ) -> RestoreCommandResult:
        # Supply an isolated default trust directory to real OpenSSL. Never
        # install a test root in the workstation's actual system trust store.
        command = tuple(
            f"127.0.0.1:{port}" if item == "127.0.0.1:443" else item for item in command
        )
        result = subprocess.run(  # noqa: S603 - fixed production commands, owned trust fixture
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            pass_fds=descriptors,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SSL_CERT_DIR": str(directory)},
        )
        assert len(result.stdout) <= maximum
        return RestoreCommandResult(result.returncode, result.stdout)

    # Establish that this default-directory fallback really would accept the
    # otherwise untrusted certificate with only an explicit -CAfile option.
    control = inherited_system_roots(
        ("/usr/bin/openssl", "verify", "-CAfile", str(other), str(cert))
    )
    assert control.status == 0, control.output
    monkeypatch.setattr(tls, "run_bounded", inherited_system_roots)
    if boundary == "peer":
        with origin(cert, key, ca, client_rejects_server=True) as port:
            for _ in range(2):
                with pytest.raises(HostRestoreError, match="peer_unverified"):
                    tls.presented_certificate("example.test", other)
    else:
        with pytest.raises(HostRestoreError, match="chain_or_validity_invalid"):
            tls.verify_cold_tls(
                storage,
                issuer="controlled-issuer",
                subjects=("*.example.test", "example.test"),
                trust=other,
                owner=os.geteuid(),
                group=os.getegid(),
                trust_owner=os.geteuid(),
                peer_source=lambda name, trust: ssl.PEM_cert_to_DER_cert(cert.read_text()),
            )


@pytest.mark.parametrize("fault", ["missing", "key", "name", "peer", "trust", "symlink", "expired"])
def test_process_health_cannot_substitute_for_valid_current_keys_names_and_presented_chain(
    certificates: tuple[Path, Path, Path, Path],
    fault: str,
) -> None:
    storage, ca, cert, key = certificates
    peer = ssl.PEM_cert_to_DER_cert(cert.read_text())
    subjects = ("*.example.test", "example.test")
    if fault == "missing":
        cert.unlink()
    elif fault == "key":
        key.write_bytes((ca.parent / "ca.key").read_bytes())
    elif fault == "name":
        subjects = ("*.other.test", "other.test")
    elif fault == "peer":
        peer = ssl.PEM_cert_to_DER_cert(ca.read_text())
    elif fault == "trust":
        ca = ca.parent / "other-ca.crt"
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
            "/CN=wrong-root",
            "-keyout",
            str(ca.with_suffix(".key")),
            "-out",
            str(ca),
        )
        ca.chmod(0o644)
    elif fault == "symlink":
        cert.rename(cert.with_suffix(".preserved"))
        cert.symlink_to(cert.with_suffix(".preserved"))
    elif fault == "expired":
        (ca.parent / "index").touch()
        (ca.parent / "serial").write_text("01\n")
        configuration = ca.parent / "ca.conf"
        configuration.write_text(
            "[ca]\ndefault_ca=restore\n[restore]\n"
            f"database={ca.parent}/index\nserial={ca.parent}/serial\n"
            f"new_certs_dir={ca.parent}\ncertificate={ca}\nprivate_key={ca.parent}/ca.key\n"
            "default_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n"
        )
        openssl(
            "ca",
            "-batch",
            "-notext",
            "-config",
            str(configuration),
            "-in",
            str(ca.parent / "leaf.csr"),
            "-startdate",
            "20000101000000Z",
            "-enddate",
            "20000102000000Z",
            "-extfile",
            str(ca.parent / "extensions"),
            "-out",
            str(cert),
        )
        cert.chmod(0o600)
        peer = ssl.PEM_cert_to_DER_cert(cert.read_text())
    with pytest.raises((HostRestoreError, OSError)):
        tls.verify_cold_tls(
            storage,
            issuer="controlled-issuer",
            subjects=subjects,
            trust=ca,
            owner=os.geteuid(),
            trust_owner=os.geteuid(),
            group=os.getegid(),
            peer_source=lambda name, trust: peer,
        )
