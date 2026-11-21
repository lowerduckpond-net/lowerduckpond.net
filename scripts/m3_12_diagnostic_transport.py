"""Installed transport evidence and scoped actions on an owned retained guest."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any

from scripts.m3_12_diagnostic_store import ATTEMPT_ENV, Attempt, clock, failure, publish
from scripts.qualification_case import owned_containers
from scripts.qualification_context import HOST_ENV, RUN_ENV, run_lease
from scripts.qualification_disposable_cleanup import FORMAT, cleanup, daemon_id
from scripts.qualification_probe import bounded_command, document
from scripts.qualification_retirement import environment_for

GUEST_FILE = "/var/lib/lowerduckpond-m3-12-diagnostics"


def checkpoint(
    operation: str,
    status: int | None = None,
    *,
    stage: str = "preparation",
    started: tuple[str, int] | None = None,
    error: BaseException | None = None,
) -> None:
    directory = os.environ.get(ATTEMPT_ENV)
    if not directory:
        return
    try:
        attempt = Attempt(Path(directory))
        category = "transport" if isinstance(error, ConnectionError) else "process"
        incident = (
            failure("primary", category, operation, error or RuntimeError()) if status else None
        )
        attempt.append(stage, operation, started or clock(), status=status, incident=incident)
    except Exception:
        print("M3.12 transport checkpoint unavailable.", file=sys.stderr)


def bound_host(directory: Path) -> tuple[dict[str, str], str]:
    environment = environment_for(directory)
    endpoint = environment["DOCKER_HOST"]
    if not endpoint.startswith("unix:///"):
        raise ValueError("retained diagnostics require the enrolled local daemon")
    expected = {
        "format": FORMAT,
        "run_id": environment[RUN_ENV],
        "endpoint": endpoint,
        "daemon_id": daemon_id(environment),
    }
    if document(directory / "disposable-cleanup-binding.json") != expected:
        raise ValueError("retained fixture daemon changed")
    identity = owned_containers(environment, allow_missing=True).get(HOST_ENV)
    if identity is None:
        raise ValueError("retained fixture host unavailable")
    # Capture uses the actual selected container ID, not a copied name or label.
    legacy = document(directory / "failure-fixture.json")
    if legacy.get("container_id") != identity:
        raise ValueError("retained fixture host changed")
    return environment, identity


def read_guest(
    attempt: Attempt, environment: dict[str, str], host: str, slot: str
) -> dict[str, Any]:
    from scripts.m3_12_contracts import validate_diagnostic  # noqa: PLC0415 - installed environment

    if slot not in {"start", "result"}:
        raise ValueError("invalid guest checkpoint kind")
    root = f"{GUEST_FILE}/{attempt.directory.name}"
    # The installed source locally validates the allowlisted record before
    # writing it to the transfer pipe. Controller validation is independent.
    payload = bounded_command(
        [
            "docker",
            "exec",
            host,
            "/usr/bin/python3",
            "-I",
            "-B",
            f"{root}/scripts/m3_12_diagnostic_guest.py",
            "export",
            attempt.directory.parent.name,
            attempt.directory.name,
            slot,
        ],
        environment=environment,
        check=True,
        timeout=55,
    )
    if payload is None:
        raise ValueError("guest checkpoint unavailable")
    record = validate_diagnostic(payload)
    if (
        record["runId"] != attempt.directory.parent.name
        or record["invocationId"] != attempt.directory.name
        or record["operation"] != "systemd"
        or record["terminalEvidence"] != ("missing" if slot == "start" else "recorded")
    ):
        raise ValueError("guest checkpoint binding changed")
    try:
        publish(attempt.directory, f"guest-{slot}.json", record)
    except FileExistsError:
        if attempt.record(f"guest-{slot}.json") != record:
            raise ValueError("guest checkpoint conflict") from None
    return record


def collect_guest(attempt: Attempt, slot: str) -> dict[str, Any]:
    from scripts.m3_12_diagnostics import secondary  # noqa: PLC0415

    try:
        with run_lease(attempt.directory):
            environment, host = bound_host(attempt.directory)
            return read_guest(attempt, environment, host, slot)
    except Exception as error:
        secondary(attempt, "transfer", "docker", error)
        raise


def inspect_guest(environment: dict[str, str], host: str) -> None:
    result = bounded_command(
        ["docker", "exec", host, "systemctl", "show", "--property=SystemState", "--value"],
        environment=environment,
        check=False,
    )
    # Only a closed recognition of the health observation may leave this layer.
    if result not in {b"running\n", b"degraded\n"}:
        raise ValueError("retained guest health is uncertain")


def retained(attempt: Attempt, action: str, *, shell: bool = False) -> dict[str, object]:
    from scripts.m3_12_diagnostics import secondary, status  # noqa: PLC0415 - private CLI boundary

    if action == "cancel":
        with attempt.lock("dispatch.lock"), suppress(FileExistsError):
            publish(attempt.directory, "cancel.json", {"requested": True})
        return {**status(attempt), "cancelRequested": True}
    if action == "resume":
        # Read back the original outcome. This slice has no authority to replay
        # an installed mutation after losing its caller.
        return {**status(attempt), "resume": "readback-only"}
    with attempt.lock("controller.lock", blocking=False):
        if attempt.result().get("terminalEvidence") != "recorded":
            raise ValueError("original installed action has no terminal evidence")
        if action == "cleanup":
            try:
                cleanup(attempt.directory)
            except Exception as error:
                secondary(attempt, "cleanup", "docker", error)
                raise
            return {**status(attempt), "fixtureCleanup": "complete"}
        with run_lease(attempt.directory):
            environment, host = bound_host(attempt.directory)
            if shell:
                if not (sys.stdin.isatty() and sys.stdout.isatty()):
                    raise ValueError("retained shell requires an attached operator")
                attempt.append("inspection", "docker", clock())
                with suppress(FileExistsError):
                    publish(attempt.directory, "diagnostic-only.json", {"edited": "possible"})
                docker = shutil.which("docker")
                if docker is None:
                    raise ValueError("Docker unavailable")
                code = subprocess.call(  # noqa: S603 - exact owned disposable container
                    [docker, "exec", "--interactive", "--tty", host, "/bin/sh"],
                    env=environment,
                )
                if code:
                    raise ValueError("attended debugging ended unsuccessfully")
            else:
                inspect_guest(environment, host)
        return {**status(attempt), "ownership": "verified"}
