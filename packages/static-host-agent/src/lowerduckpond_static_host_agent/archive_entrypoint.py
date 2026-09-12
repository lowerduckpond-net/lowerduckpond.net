"""Fixed socket-activated root entry point for archived export reads."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Final

from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_service import serve_archive_export
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.repository import StateRepository

_STATE_ROOT: Final = Path("/var/lib/lowerduckpond/static")


def archive_export_main(arguments: list[str] | None = None) -> int:
    """Accept only systemd's connected socket on stdin, with no caller options."""

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
            serve_archive_export(stream, repository, spool, configuration.remote_store())
        return 0
    except Exception:
        # Provider exceptions can contain sensitive request details. This is
        # the process boundary, so diagnostics deliberately use one fixed code.
        print("archive_export_service_failed", file=sys.stderr)
        return 1
