"""Fixed socket-activated root entry point for archived export reads."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.archive_cleanup_service import serve_archive_cleanup
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_construction_service import serve_archive_construction
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.archive_service import serve_archive_export
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.repository import StateRepository

_STATE_ROOT: Final = Path("/var/lib/lowerduckpond/static")


def archive_export_main(arguments: list[str] | None = None) -> int:
    """Accept only systemd's connected socket on stdin, with no caller options."""

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
            socket.socket(fileno=os.dup(0)) as stream,
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
    except Exception:
        # Provider exceptions can contain sensitive request details. This is
        # the process boundary, so diagnostics deliberately use one fixed code.
        print(f"archive_{operation}_service_failed", file=sys.stderr)
        return 1
