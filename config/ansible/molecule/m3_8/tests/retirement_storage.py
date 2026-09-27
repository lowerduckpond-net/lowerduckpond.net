"""Private local MinIO transport for the fixed installed retirement case only."""

from __future__ import annotations

import select
import socket
import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

import botocore.session  # type: ignore[import-untyped]
from botocore.config import Config  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import S3Client


@contextmanager
def clients(address: str, ca: Path) -> Iterator[tuple[S3Client, S3Client]]:
    # The original fixture certificate covers 127.0.0.1. Forward opaque TLS to
    # this owned MinIO address; do not disable certificate verification or DNS.
    class Forward(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            with socket.create_connection((address, 443), timeout=15) as remote:
                self.request.settimeout(15)
                while True:
                    ready, _, _ = select.select((self.request, remote), (), (), 15)
                    if not ready:
                        return
                    for origin in ready:
                        data = origin.recv(65536)
                        if not data:
                            return
                        (remote if origin is self.request else self.request).sendall(data)

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Forward) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        result = []
        try:
            for kind in ("archive", "root"):
                result.append(  # noqa: PERF401 - close clients on partial construction failure
                    botocore.session.get_session().create_client(
                        "s3",
                        endpoint_url=f"https://127.0.0.1:{server.server_address[1]}",
                        verify=str(ca),
                        region_name="ams3",
                        aws_access_key_id=f"molecule-m3-10-{kind}",
                        aws_secret_access_key=f"molecule-m3-10-disposable-{kind}-secret",
                        config=Config(
                            connect_timeout=5,
                            read_timeout=15,
                            retries={"total_max_attempts": 1},
                            s3={"addressing_style": "path"},
                        ),
                    )
                )
            yield cast(S3Client, result[0]), cast(S3Client, result[1])
        finally:
            for client in result:
                client.close()
            server.shutdown()
            thread.join(timeout=5)
