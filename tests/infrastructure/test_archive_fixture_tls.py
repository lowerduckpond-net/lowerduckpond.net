from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from config.ansible.molecule.m3_8.prepare_archive_storage import _certificates


def test_disposable_archive_chain_passes_strict_tls_without_replacing_existing_certificates(
    tmp_path: Path,
) -> None:
    root = tmp_path / "certificates"
    _certificates(root)
    original = {path.name: path.read_bytes() for path in root.iterdir()}
    _certificates(root)
    assert {path.name: path.read_bytes() for path in root.iterdir()} == original
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(root / "public.crt", root / "private.key")
    client_context = ssl.create_default_context(cafile=str(root / "ca.crt"))
    client_context.verify_flags |= ssl.VERIFY_X509_STRICT
    with socket.socket() as listener:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def serve() -> None:
            connection, _ = listener.accept()
            connection.settimeout(5)
            with server_context.wrap_socket(connection, server_side=True) as stream:
                assert stream.recv(1) == b"?"
                stream.sendall(b"!")

        with ThreadPoolExecutor(max_workers=1) as executor:
            serving = executor.submit(serve)
            with (
                socket.create_connection(listener.getsockname(), timeout=5) as connection,
                client_context.wrap_socket(
                    connection, server_hostname="ams3.digitaloceanspaces.com"
                ) as stream,
            ):
                stream.sendall(b"?")
                assert stream.recv(1) == b"!"
            serving.result(timeout=5)
