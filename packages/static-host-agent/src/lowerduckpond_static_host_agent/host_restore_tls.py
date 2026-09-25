"""Cold-origin TLS evidence, without an unauthenticated application request."""

from __future__ import annotations

import hashlib
import os
import re
import ssl
import stat
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_inputs import file_identity
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_process import run_bounded

MAX_CERTIFICATE_BYTES: Final = 32 * 1024
MAX_CERTIFICATE_DIRECTORIES: Final = 64
_CERTIFICATE: Final = re.compile(
    rb"-----BEGIN CERTIFICATE-----\r?\n.+?-----END CERTIFICATE-----", re.DOTALL
)
_DNS: Final = re.compile(r"(?:\*\.)?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", re.ASCII)
PeerSource = Callable[[str, Path], bytes]


def presented_certificate(hostname: str, trust: Path) -> bytes:
    """TLS only: origin-pull client authentication stays required and untouched.

    OpenSSL exposes and verifies the server certificate before reporting the
    expected missing-client-certificate alert. Independently bind that leaf to
    a validated stored key/chain below. No HTTP bytes or credential are sent.
    """
    result = run_bounded(
        (
            "/usr/bin/openssl",
            "s_client",
            "-connect",
            "127.0.0.1:443",
            "-servername",
            hostname,
            "-verify_hostname",
            hostname,
            "-verify_return_error",
            "-CAfile",
            str(trust),
            "-no-CApath",
            "-no-CAstore",
            "-showcerts",
        ),
        timeout=10,
        maximum=128 * 1024,
    )
    match = _CERTIFICATE.search(result.output)
    if (
        match is None
        or re.search(rb"(?m)^\s*Verify return code: 0 \(ok\)\s*$", result.output) is None
    ):
        raise HostRestoreError("restore_tls_peer_unverified")
    if result.status and b"alert certificate required" not in result.output:
        raise HostRestoreError("restore_tls_peer_unavailable")
    return ssl.PEM_cert_to_DER_cert(match.group().decode("ascii"))


def _open_key_or_chain(parent: int, name: str, owner: int, group: int) -> int:
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_gid != group
        or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004 - Caddy private key/chain mode
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= MAX_CERTIFICATE_BYTES
    ):
        os.close(descriptor)
        raise HostRestoreError("restore_tls_storage_unsafe")
    return descriptor


def _pair_subjects(certificate: int, key: int) -> tuple[bytes, frozenset[str]]:
    raw = os.pread(certificate, MAX_CERTIFICATE_BYTES + 1, 0)
    match = _CERTIFICATE.match(raw)
    if match is None:
        raise HostRestoreError("restore_tls_certificate_invalid")
    # OpenSSL verifies the private/public key match without exporting the key.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(f"/proc/self/fd/{certificate}", f"/proc/self/fd/{key}")
    except ssl.SSLError as error:
        raise HostRestoreError("restore_tls_key_mismatch") from error
    result = run_bounded(
        (
            "/usr/bin/openssl",
            "x509",
            "-in",
            f"/proc/self/fd/{certificate}",
            "-noout",
            "-ext",
            "subjectAltName",
        ),
        descriptors=(certificate,),
        timeout=10,
        maximum=MAX_CERTIFICATE_BYTES,
    )
    if result.status:
        raise HostRestoreError("restore_tls_certificate_invalid")
    names = frozenset(re.findall(r"DNS:([^,\s]+)", result.output.decode("ascii")))
    return ssl.PEM_cert_to_DER_cert(match.group().decode("ascii")), names


def verify_cold_tls(  # noqa: PLR0912,PLR0913 - explicit policy, trust and certificate proof
    storage: Path,
    *,
    issuer: str,
    subjects: tuple[str, ...],
    trust: Path,
    owner: int,
    group: int,
    peer_source: PeerSource = presented_certificate,
    trust_owner: int = 0,
) -> dict[str, object]:
    """Require a current trusted certificate/key for every configured subject.

    The caller independently verifies the selected Caddy generation and binds
    issuer, subjects and trust to trusted host inputs. Installed production uses
    its reviewed ACME issuer and public trust store; no fallback is attempted.
    """
    if (
        not issuer
        or issuer in {".", ".."}
        or "/" in issuer
        or not subjects
        or tuple(sorted(set(subjects))) != subjects
        or any(_DNS.fullmatch(name) is None for name in subjects)
    ):
        raise HostRestoreError("restore_tls_policy_invalid")
    # Trust may contain many roots. It is a pinned administrator input, not a
    # Caddy-owned file or recovered snapshot input. Both OpenSSL checks disable
    # default CA directories/stores so restored roots cannot widen this input.
    trust_metadata = trust.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(trust_metadata.st_mode)
        or trust_metadata.st_mode & 0o022
        or trust_metadata.st_uid != trust_owner
        or trust_metadata.st_nlink != 1
    ):
        raise HostRestoreError("restore_tls_trust_unsafe")
    observed: dict[str, bytes] = {}
    for name in subjects:
        probe = "restore-probe." + name[2:] if name.startswith("*.") else name
        observed[name] = peer_source(probe, trust)
    matched: set[str] = set()
    with DurableDirectory.open(
        storage / issuer, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        parent = directory.duplicate_descriptor()
        try:
            names = []
            with os.scandir(parent) as iterator:
                for entry in iterator:
                    names.append(entry.name)
                    if len(names) > MAX_CERTIFICATE_DIRECTORIES:
                        raise HostRestoreError("restore_tls_storage_limit")
            for name in sorted(names):
                with directory.open_descendant((name,)) as child, ExitStack() as resources:
                    descriptor = child.duplicate_descriptor()
                    resources.callback(os.close, descriptor)
                    certificate = _open_key_or_chain(descriptor, name + ".crt", owner, group)
                    resources.callback(os.close, certificate)
                    key = _open_key_or_chain(descriptor, name + ".key", owner, group)
                    resources.callback(os.close, key)
                    before = (file_identity(os.fstat(certificate)), file_identity(os.fstat(key)))
                    leaf, dns_names = _pair_subjects(certificate, key)
                    for subject in subjects:
                        if subject not in dns_names or observed[subject] != leaf:
                            continue
                        probe = (
                            "restore-probe." + subject[2:] if subject.startswith("*.") else subject
                        )
                        result = run_bounded(
                            (
                                "/usr/bin/openssl",
                                "verify",
                                "-purpose",
                                "sslserver",
                                "-verify_hostname",
                                probe,
                                "-CAfile",
                                str(trust),
                                "-no-CApath",
                                "-no-CAstore",
                                "-untrusted",
                                f"/proc/self/fd/{certificate}",
                                f"/proc/self/fd/{certificate}",
                            ),
                            descriptors=(certificate,),
                            timeout=10,
                            maximum=MAX_CERTIFICATE_BYTES,
                        )
                        if result.status:
                            raise HostRestoreError("restore_tls_chain_or_validity_invalid")
                        matched.add(subject)
                    if before != (
                        file_identity(os.fstat(certificate)),
                        file_identity(os.fstat(key)),
                    ) or before != (
                        file_identity(
                            os.stat(name + ".crt", dir_fd=descriptor, follow_symlinks=False)
                        ),
                        file_identity(
                            os.stat(name + ".key", dir_fd=descriptor, follow_symlinks=False)
                        ),
                    ):
                        raise HostRestoreError("restore_tls_storage_changed")
        finally:
            os.close(parent)
    if file_identity(trust_metadata) != file_identity(trust.stat(follow_symlinks=False)):
        raise HostRestoreError("restore_tls_trust_changed")
    if matched != set(subjects):
        raise HostRestoreError("restore_tls_subjects_unavailable")
    return {
        "issuer": issuer,
        "certificates": [
            {"subject": name, "leafSha256": hashlib.sha256(observed[name]).hexdigest()}
            for name in subjects
        ],
    }
