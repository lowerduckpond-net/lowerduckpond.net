"""Invoke the verified candidate under original migration and repository authority."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as records

REPOSITORY_LOCK = Path("/var/cache/lowerduckpond-backup/repository.lock")
SELECTION_LOCK = Path("/opt/lowerduckpond/static-host-agent/selection.lock")
STATIC = Path("/var/lib/lowerduckpond/static")
LOCK_MODE = 0o600


def _require_lock(path: Path, descriptor: int, owner: int) -> None:
    opened, named = os.fstat(descriptor), path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_uid != owner
        or opened.st_gid != owner
        or stat.S_IMODE(opened.st_mode) != LOCK_MODE
        or opened.st_nlink != 1
        or opened.st_size != 0
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise ValueError("production initialization lock changed or is unsafe")


@contextmanager
def _lock(path: Path, mode: int, owner: int) -> Iterator[int]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _require_lock(path, descriptor, owner)
        fcntl.flock(descriptor, mode)
        _require_lock(path, descriptor, owner)
        yield descriptor
        _require_lock(path, descriptor, owner)
    finally:
        os.close(descriptor)


def _authority(phase: str, owner: int) -> list[tuple[str, bytes]]:
    chain = records.decode(records.operate(records.ROOT, ["read"], b"", owner=owner))
    if (
        phase not in {"namespace", "lineage"}
        or journal.validate(chain)["phase"] != phase + ".started"
    ):
        raise ValueError("production journal does not authorize initialization")
    return chain


def _host(original: dict[str, object], owner: int) -> Path:
    candidate = cast(dict[str, str], original["candidate"])
    selected = probe.SELECTION.parent / candidate["artifact_sha256"]
    if (
        probe.read(probe.COMPLETION, owner=owner, mode=0o400)
        != cast(str, original["predecessor"]).encode()
        or not probe.SELECTION.is_symlink()
        or probe.SELECTION.resolve(strict=True) != selected
    ):
        raise ValueError("production initialization changed its predecessor or candidate")
    publication = json.loads(
        probe.read(probe.PUBLICATION, owner=owner, mode=0o400),
        object_pairs_hook=probe.unique_object,
    )
    if (
        publication
        != {
            "format": "lowerduckpond-static-publication-gate-v1",
            "static_publication_enabled": False,
        }
        or publication["static_publication_enabled"] is not False
    ):
        raise ValueError("production initialization requires disabled publication")
    return selected


def _idle(original: bytes, owner: int) -> None:
    for unit, phase in fence.FENCES.items():
        if probe.read(
            fence.UNITS / (unit + ".d") / fence.NAME, owner=owner, mode=0o400
        ) != fence.content(original, phase):
            raise ValueError("production initialization lost its original service conditions")
        fence.conditions(unit, phase)
    active = json.loads(
        fence.run(
            [
                "/usr/bin/systemctl",
                "list-units",
                "--output=json",
                "--no-pager",
                "--state=active,activating,deactivating,reloading,refreshing,maintenance",
                *(unit.replace("@.", "@*.") for unit in fence.FENCES),
            ]
        )
    )
    if active:
        raise ValueError("production migration services are not stopped")
    result = subprocess.run(  # noqa: S603 - fixed observation, never signal unrelated processes
        ["/usr/bin/pgrep", "--full", "--", fence.PROCESS_PATTERN],
        capture_output=True,
        check=False,
        timeout=5,
    )
    if result.returncode != 1:
        raise ValueError("production commands remain outside fenced services")


def _candidate(
    phase: str,
    original: dict[str, object],
    environment: dict[str, str],
    descriptors: tuple[int, int],
) -> dict[str, str]:
    # Imports happen only after the exact selected artifact has been verified
    # under its shared selection lease. The predecessor need not have these
    # packages or the newer backup identity launcher installed beforehand.
    from lowerduckpond_static_host_agent import (  # noqa: PLC0415
        production_lineage,
        production_namespace,
    )
    from lowerduckpond_static_host_agent.backup_restic import inherit_restic_leases  # noqa: PLC0415
    from lowerduckpond_static_host_agent.host_restore_gate import (  # noqa: PLC0415
        require_restore_admission,
    )

    require_restore_admission()
    namespace = journal.canonical(cast(dict[str, object], original["namespace"]))
    with inherit_restic_leases(descriptors):
        if phase == "namespace":
            production_namespace.initialize_namespace(STATIC, namespace, expected_owner=0)
            return {
                "namespace_sha256": journal.digest(namespace),
                "artifact_sha256": cast(dict[str, str], original["candidate"])["artifact_sha256"],
            }
        return production_lineage.initialize(
            STATIC, namespace, cast(str, original["repository_binding"]), environment, owner=0
        )


def initialize(phase: str, *, owner: int = 0) -> bytes:
    """The remote dispatcher must hold the genuine root action lease throughout."""
    with (
        _lock(REPOSITORY_LOCK, fcntl.LOCK_EX, owner) as repository,
        _lock(SELECTION_LOCK, fcntl.LOCK_SH, owner) as selection,
    ):
        chain = _authority(phase, owner)
        original = json.loads(chain[0][1])
        selected = _host(original, owner)
        _idle(chain[0][1], owner)
        fence.run(
            ["/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact", str(selected)]
        )
        configuration = probe.read(probe.BACKUP, owner=owner, mode=0o600)
        values = probe.configuration(configuration)
        environment = probe.environment(
            configuration,
            region=values.get("AWS_DEFAULT_REGION", ""),
            locator=values.get("RESTIC_REPOSITORY", ""),
        )
        environment["LOWERDUCKPOND_BACKUP_NODE_NAME"] = probe.NODE
        # Use the fixed installed cache path; no inherited environment or shell
        # evaluation can redirect repository commands or expose credentials.
        environment["RESTIC_CACHE_DIR"] = "/var/cache/lowerduckpond-backup/restic-cache"
        previous_path = sys.path[:]
        sys.path.insert(0, str(selected / "site-packages"))
        try:
            result = _candidate(phase, original, environment, (repository, selection))
        finally:
            sys.path[:] = previous_path
        if (
            _authority(phase, owner) != chain
            or _host(original, owner) != selected
            or probe.read(probe.BACKUP, owner=owner, mode=0o600) != configuration
        ):
            raise ValueError("production initialization authority changed")
        _idle(chain[0][1], owner)
        return journal.canonical(dict(result))
