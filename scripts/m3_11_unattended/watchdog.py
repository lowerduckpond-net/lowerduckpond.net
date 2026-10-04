"""Local death detection in a separate container; only credential cleanup is authorized."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import qualification_deadline
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.docker import Docker, controller_name
from scripts.m3_11_unattended.lifecycle import Lifecycle
from scripts.m3_11_unattended.model import Credential, identity, instant
from scripts.m3_11_unattended.state import RunState
from scripts.m3_11_unattended.worker import retained_credentials


def due_processes(root: Path, docker: Docker) -> list[Path]:
    """Detect local death/deadline changes without a 1Password request."""
    due = []
    for directory in root.glob("*"):
        run_id = identity(directory.name)
        if not (directory / "attempt.json").exists():
            continue
        state = RunState(directory)
        if (directory / "status.json").exists():
            progress = state.status()
            if progress["phase"] == "finished" and progress["credential_cleanup"] == "verified":
                continue
        attempt = read_private(directory / "attempt.json")
        try:
            container = docker.owned(controller_name(run_id))
            status = container.get("State")
            alive = isinstance(status, dict) and status.get("Running") is True
        except RuntimeError, OSError, ValueError:
            # A failed daemon read is uncertainty, never proof of process death.
            alive = True
        elapsed = datetime.now(UTC) - instant(attempt["started_at"])
        expired = elapsed > timedelta(seconds=qualification_deadline.LIVE_SECONDS)
        reporting_expired = elapsed > timedelta(
            seconds=qualification_deadline.LIVE_SECONDS
            + qualification_deadline.REPORT_SECONDS
            + 4 * qualification_deadline.GRACE_SECONDS
        )
        terminal = (directory / "journey-result.json").exists()
        if not alive or terminal or reporting_expired:
            due.append(directory)
        if not alive and not terminal:
            state.interrupted()
        if expired and alive and not terminal:
            state.cancel()
            # Stop only the owned controller. Never remove guest containers/data.
            docker.command("kill", "--signal=TERM", controller_name(run_id))
    return due


def reconcile_processes(lifecycle: Lifecycle, root: Path, docker: Docker) -> dict[str, Credential]:
    available: dict[str, Credential] = {}
    for directory in due_processes(root, docker):
        lifecycle.request_revocation(identity(directory.name))
        available.update(retained_credentials(directory))
    return available
