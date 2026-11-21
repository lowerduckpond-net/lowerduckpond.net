"""Read and seal the owned installed fixture's native allocation for P3."""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import cast
from uuid import UUID

from scripts.m3_11_production_journal import PHASES, RECORDS
from scripts.m3_12_contracts import Document, digest, require
from scripts.m3_12_diagnostic_store import clock, publish
from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV, host_name
from scripts.qualification_disposable_cleanup import BINDING_IDENTITY_TIMEOUT_SECONDS, FORMAT
from scripts.qualification_probe import bounded_command, document

RECEIPT = "m3-12-installed-allocation.json"
LABEL = "lowerduckpond.qualification.run"
SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
DAEMON = ("ID", "Name", "DockerRootDir", "ServerVersion")
MAX_DAEMON_FIELD = 1024
ROLES = {"host": HOST_ENV, "archive": ARCHIVE_ENV}
PROGRESS_DIRECTORY = "m3-12-successor-progress"
APPLY_STAGES = frozenset({"dark-staging", "dark-repeat", "enabled-convergence", "enabled-repeat"})
APPLY_STAGE_ENV = "LDP_M3_12_SUCCESSOR_APPLY_STAGE"
PROGRESS_ROOT_ENV = "LDP_M3_12_SUCCESSOR_PROGRESS_ROOT"
PROGRESS_STAGES = frozenset(
    {
        "predecessor-preparation",
        "predecessor-rollout",
        "m3-11-original",
        "candidate-preparation",
        *APPLY_STAGES,
        "durable-launch",
        "rollback-handoff",
        "rollback-resume",
        "same-policy-reactivation",
        "post-reboot",
        "backup-readback",
        *(f"m3-11-{phase}" for phase in PHASES),
    }
)


def _successor_progress(directory: Path, stage: str, state: str) -> None:
    if stage not in PROGRESS_STAGES or state not in {"started", "completed"}:
        raise ValueError("invalid installed successor progress label")
    target = directory / PROGRESS_DIRECTORY
    utc, monotonic_ms = clock()
    try:
        target.mkdir(mode=0o700, exist_ok=True)
        publish(
            target,
            f"{stage}-{state}.json",
            {
                "format": "lowerduckpond-m3-12-successor-progress-v1",
                "authority": "diagnostic-only",
                "stage": stage,
                "state": state,
                "utc": utc,
                "monotonicMs": monotonic_ms,
            },
        )
    except OSError, ValueError:
        with suppress(OSError):
            print("Installed successor progress unavailable.", file=sys.stderr, flush=True)


def predecessor_progress(directory: Path, receipt: str) -> None:
    if receipt not in RECORDS:
        raise ValueError("invalid installed predecessor progress label")
    phase = receipt.removesuffix(".started")
    _successor_progress(directory, f"m3-11-{phase}", "completed" if receipt == phase else "started")


@contextmanager
def successor_stage(directory: Path, stage: str) -> Iterator[None]:
    _successor_progress(directory, stage, "started")
    yield
    _successor_progress(directory, stage, "completed")


def _docker(environment: dict[str, str], *arguments: str, identity: bool = False) -> bytes:
    raw = bounded_command(
        ["docker", *arguments],
        environment=environment,
        check=True,
        timeout=BINDING_IDENTITY_TIMEOUT_SECONDS if identity else None,
    )
    if raw is None:
        raise ValueError("installed fixture observation unavailable")
    return raw


def _daemon(environment: dict[str, str]) -> Document:
    projection = "{" + ",".join(f'"{key}":{{{{json .{key}}}}}' for key in DAEMON) + "}"
    value = json.loads(_docker(environment, "info", "--format", projection, identity=True))
    require(
        type(value) is dict
        and set(value) == set(DAEMON)
        and all(type(item) is str and 0 < len(item) <= MAX_DAEMON_FIELD for item in value.values()),
        "installed-daemon-metadata-unavailable",
    )
    return cast(Document, value)


def _roles(environment: dict[str, str], expected: dict[str, object]) -> Document:
    run = environment[RUN_ENV]
    inventory = (
        _docker(
            environment,
            "ps",
            "--all",
            "--filter",
            f"label={LABEL}={run}",
            "--no-trunc",
            "--format",
            "{{.ID}}",
        )
        .decode("ascii")
        .splitlines()
    )
    require(
        len(inventory) == len(ROLES)
        and set(inventory) == set(expected.values())
        and set(expected) == set(ROLES.values()),
        "installed-inventory-changed",
    )
    roles = {}
    for role, key in ROLES.items():
        identifier = expected[key]
        if not isinstance(identifier, str):
            raise ValueError("installed role identity is invalid")
        require(SHA256.fullmatch(identifier) is not None, "installed-container-id-invalid")
        template = (
            '{"id":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},'
            '"runLabel":{{json (index .Config.Labels "' + LABEL + '")}},'
            '"running":{{json .State.Running}},'
            '"networkMode":{{json .HostConfig.NetworkMode}}}'
        )
        row = json.loads(_docker(environment, "inspect", "--format", template, identifier))
        image = row["image"].removeprefix("sha256:")
        require(
            row["id"] == identifier
            and row["name"] == "/" + environment[key]
            and row["runLabel"] == run
            and row["running"] is True
            and row["networkMode"] != "host"
            and SHA256.fullmatch(image) is not None,
            "installed-role-changed",
        )
        roles[role] = {"id": identifier, "image": image, "runLabel": run}
    return roles


def observe_installed(directory: Path, environment: dict[str, str]) -> Document:
    """Observe Docker metadata from the controller, with no socket in the guest."""
    host_name(environment)
    endpoint = environment["DOCKER_HOST"]
    require(
        endpoint.startswith("unix:///") and environment["M3_10_ARCHIVE_BACKEND"] == "minio",
        "installed-fixture-requires-local-minio",
    )
    owner = document(directory / "fixture.json")
    bind = document(directory / "disposable-cleanup-binding.json")
    create = document(directory / "case-create.json")
    expected = document(directory / "case-containers.json")
    daemon = _daemon(environment)
    require(
        bind
        == {
            "format": FORMAT,
            "run_id": environment[RUN_ENV],
            "endpoint": endpoint,
            "daemon_id": daemon["ID"],
        }
        and create == {"exit_status": 0}
        and owner["run_id"] == environment[RUN_ENV]
        and owner["docker_endpoint"] == endpoint,
        "installed-allocation-uncertain",
    )
    return {
        "format": "lowerduckpond-m3-12-installed-allocation-v1",
        "runId": str(UUID(environment[RUN_ENV])),
        "docker": {
            "endpointSha256": digest({"endpoint": endpoint}),
            "daemonObservationSha256": digest(daemon),
            "ownerManifestSha256": digest(owner),
            "runLabel": environment[RUN_ENV],
            "drainedAllocationSha256": digest({"create": create, "roles": expected}),
            "roles": _roles(environment, expected),
        },
    }


def pin_installed(directory: Path, environment: dict[str, str]) -> Document:
    """Called only by the controller after its original creation has drained."""
    allocation = observe_installed(directory, environment)
    publish(directory, RECEIPT, allocation)
    return allocation


def recheck_installed(directory: Path, environment: dict[str, str]) -> Document:
    original = document(directory / RECEIPT)
    require(original == observe_installed(directory, environment), "installed-fixture-replaced")
    return original
