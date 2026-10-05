"""Local death detection in a separate container; only credential cleanup is authorized."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import qualification_deadline
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.docker import Docker, controller_name
from scripts.m3_11_unattended.lifecycle import Lifecycle, intents
from scripts.m3_11_unattended.model import Credential, identity, instant
from scripts.m3_11_unattended.state import RunState
from scripts.m3_11_unattended.worker import (
    persist_terminal_result,
    restore_created,
    retained_credentials,
)


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


def reconcile_processes(
    lifecycle: Lifecycle, root: Path, docker: Docker, *, directories: set[Path] | None = None
) -> dict[str, Credential]:
    available: dict[str, Credential] = {}
    selected = due_processes(root, docker) if directories is None else directories
    for directory in selected:
        restore_created(lifecycle, directory, run_id=identity(directory.name))
        lifecycle.request_revocation(identity(directory.name))
        available.update(retained_credentials(directory))
    return available


def finish_reconciled(
    lifecycle: Lifecycle, directories: set[Path], receipt: dict[str, object]
) -> None:
    """Stop terminal retries only after complete, freshly verified owned cleanup."""
    results = receipt.get("results")
    if not isinstance(results, list):
        return
    owned = intents(lifecycle.journal)
    for directory in directories:
        # A living controller still collecting diagnostics must finish its
        # immutable journey before a new start can consider this attempt closed.
        if not (directory / "journey-result.json").exists():
            continue
        state = RunState(directory)
        # This sweep may predate a concurrent successful controller revocation.
        state.update("finished", cleanup="unresolved", preserve_verified=True)
        run_id = identity(directory.name)
        expected = {intent.sha256 for intent in owned if intent.run_id == run_id}
        local = {path.stem for path in (directory / "credential-intents").glob("*.json")}
        available = retained_credentials(directory)
        if not local <= expected or not set(available) <= expected:
            continue
        verified = [
            value
            for value in results
            if isinstance(value, dict)
            and value.get("intent_sha256") in expected
            and value.get("status") == "verified"
            and (
                value["intent_sha256"] not in available
                or value.get("negative_authentication") == "denied"
            )
        ]
        if (
            len(verified) != len(expected)
            or {value["intent_sha256"] for value in verified} != expected
        ):
            continue
        try:
            persist_terminal_result(lifecycle, directory)
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            continue
        proof = {
            "format": "lowerduckpond-m3-11-watchdog-revocation-v1",
            "binding": read_private(directory / "attempt.json")["binding"],
            "helper_revision": receipt["helper_revision"],
            "observed_at": receipt["observed_at"],
            "results": verified,
        }
        # An interrupted write leaves its original evidence intact. A later
        # successful sweep adds another receipt rather than rewriting that file.
        write_private(directory / f"watchdog-revocation-{uuid.uuid7()}.json", proof)
        for path in (directory / "credential-cleanup").glob("*.json"):
            path.unlink()
        (directory / "runtime-inputs.json").unlink(missing_ok=True)
        state.update("finished", cleanup="verified")
