"""Serve one queued archive connection per bounded root service invocation."""

from __future__ import annotations

import os
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.archive_cleanup_service import serve_archive_cleanup
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_construction_service import serve_archive_construction
from lowerduckpond_static_host_agent.archive_diagnostics import archive_failure_diagnostic
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_service import serve_archive_export
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.repository import StateRepository

_STATE_ROOT: Final = Path("/var/lib/lowerduckpond/static")
_ACCEPT_TIMEOUT: Final = 30.0


@contextmanager
def _accept_connection() -> Iterator[socket.socket]:
    # Accept=no keeps the next request in the socket's bounded backlog until
    # the previous service has exited. Accept=yes/MaxConnections=1 instead
    # drops it during the gap between a helper's reply and its process exit.
    with socket.socket(fileno=os.dup(0)) as listener:
        if (
            listener.family != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        ):
            raise ValueError("archive activation requires a listening Unix stream")
        listener.settimeout(_ACCEPT_TIMEOUT)
        stream, _address = listener.accept()
        with stream:
            yield stream


def archive_export_main(arguments: list[str] | None = None) -> int:
    """Accept from systemd's listening socket on stdin, with no caller options."""

    return _archive_main(arguments, operation="export")


def archive_construction_main(arguments: list[str] | None = None) -> int:
    """Run the separately mounted one-shot construction service."""

    return _archive_main(arguments, operation="construction")


def archive_cleanup_main(arguments: list[str] | None = None) -> int:
    """Verify or retire only the exact archive authorized by one durable job."""
    return _archive_main(arguments, operation="cleanup")


def _archive_main(arguments: list[str] | None, *, operation: str) -> int:

    values = sys.argv[1:] if arguments is None else arguments
    if values or os.geteuid() != 0:
        print("invalid_archive_service_invocation", file=sys.stderr)
        return 64
    try:
        with (
            _accept_connection() as stream,
            StateRepository(_STATE_ROOT, expected_owner=0) as repository,
            ExportSpool(_STATE_ROOT, expected_owner=0) as spool,
        ):
            configuration = load_archive_configuration()
            remote = configuration.remote_store()
            if operation in {"construction", "cleanup"}:
                service = (
                    serve_archive_construction
                    if operation == "construction"
                    else serve_archive_cleanup
                )
                service(
                    stream,
                    repository,
                    spool,
                    remote,
                    quarantine=ArchiveQuarantine(
                        _STATE_ROOT,
                        bucket=configuration.bucket,
                        expected_owner=0,
                        locks=spool.locks,
                    ),
                )
            else:
                serve_archive_export(stream, repository, spool, remote)
        return 0
    except Exception as error:
        # Classify failures using fixed labels, never private exception details.
        print(
            f"archive_{operation}_service_failed {archive_failure_diagnostic(error)}",
            file=sys.stderr,
        )
        return 1
