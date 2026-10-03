"""Local death detection in a separate container; only credential cleanup is authorized."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.docker import Docker, controller_name
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import Credential, identity, instant
from scripts.m3_11_unattended.state import RunState
from scripts.m3_11_unattended.worker import retained_credentials


def reconcile_processes(lifecycle: Lifecycle, root: Path, docker: Docker) -> dict[str, Credential]:
    available: dict[str, Credential] = {}
    for directory in root.glob("*"):
        run_id = identity(directory.name)
        if not (directory / "attempt.json").exists():
            continue
        state = RunState(directory)
        attempt = read_private(directory / "attempt.json")
        try:
            container = docker.owned(controller_name(run_id))
            status = container.get("State")
            alive = isinstance(status, dict) and status.get("Running") is True
        except RuntimeError, OSError, ValueError:
            # A failed daemon read is uncertainty, never proof of process death.
            alive = True
        expired = datetime.now(UTC) > instant(attempt["started_at"]) + timedelta(hours=12)
        terminal = (directory / "journey-result.json").exists()
        if not alive or terminal or expired:
            lifecycle.request_revocation(run_id)
            available.update(retained_credentials(directory))
        if not alive and not terminal:
            state.interrupted()
        if expired and alive and not terminal:
            state.cancel()
            # Stop only the owned controller. Never remove guest containers/data.
            docker.command("kill", "--signal=TERM", controller_name(run_id))
    return available
