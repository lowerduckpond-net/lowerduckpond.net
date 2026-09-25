"""Read the empty rollout host at any original phase without completing it."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from contextlib import ExitStack
from pathlib import Path
from typing import cast

from scripts import m3_11_production_fence as fence
from scripts import m3_11_production_initialize as initialize
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as records

LOCKS = ("intake.lock", "export.lock", "publication.lock", "tenant-state.lock")
DIRECTORY_MODE = 0o700
EMPTY = (
    "tenants",
    "intents",
    "intake",
    "exports",
    "authorization/jobs",
    "authorization/results",
    "authorization/correlations",
)


def _directory(path: Path, owner: int) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    value = os.fstat(fd)
    if value.st_uid != owner or stat.S_IMODE(value.st_mode) != DIRECTORY_MODE:
        os.close(fd)
        raise ValueError("production observation found unsafe state storage")
    return fd


def _empty(owner: int) -> None:
    with ExitStack() as stack:
        opened = []
        for path in (
            initialize.STATIC,
            initialize.STATIC / "locks",
            initialize.STATIC / "authorization",
        ):
            fd = _directory(path, owner)
            stack.callback(os.close, fd)
            opened.append((path, fd))
        for name in LOCKS:
            stack.enter_context(
                initialize._lock(initialize.STATIC / "locks" / name, fcntl.LOCK_SH, owner)
            )
        for name in EMPTY:
            path = initialize.STATIC / name
            fd = _directory(path, owner)
            stack.callback(os.close, fd)
            opened.append((path, fd))
            with os.scandir(fd) as entries:
                if next(entries, None) is not None:
                    raise ValueError("production observation found retained tenant work")
        for path, fd in opened:
            original, named = os.fstat(fd), path.stat(follow_symlinks=False)
            if (original.st_dev, original.st_ino) != (named.st_dev, named.st_ino):
                raise ValueError("production observation state storage changed")


def _selection(state: dict[str, object], owner: int) -> tuple[str, str]:
    original = cast(dict[str, object], state["original"])
    candidate = cast(dict[str, str], original["candidate"])
    predecessor = cast(str, original["predecessor"])
    prior_artifact, prior_source, *_ = predecessor.split()
    if probe.read(probe.COMPLETION, owner=owner, mode=0o400) != predecessor.encode():
        raise ValueError("production observation lost its original predecessor")
    permitted = {candidate["artifact_sha256"]: candidate["source_revision"]}
    phase = state["phase"]
    if phase in {"original", "drained.started", "drained"}:
        permitted = {prior_artifact: prior_source}
    elif phase == "namespace.started":
        permitted[prior_artifact] = prior_source
    if not probe.SELECTION.is_symlink():
        raise ValueError("production observation lost its artifact selector")
    selected = probe.SELECTION.resolve(strict=True)
    if selected.name not in permitted or selected != probe.SELECTION.parent / selected.name:
        raise ValueError("production observation selected an unrelated artifact")
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
        raise ValueError("production observation requires disabled publication")
    return selected.name, permitted[selected.name]


def _modes(phase: str) -> set[tuple[bool, bool]]:
    if phase in {
        "original",
        "drained.started",
        "drained",
        "namespace.started",
        "namespace",
        "lineage.started",
        "lineage",
    }:
        return {(False, False)}
    if phase == "converged.started":
        return {(False, False), (True, False)}
    if phase in {"converged", "backup-verified.started", "backup-verified"}:
        return {(True, False)}
    if phase == "rotation-enabled.started":
        return {(True, False), (True, True)}
    return {(True, True)}


def observe(*, owner: int = 0) -> bytes:
    """Caller owns the genuine action lease; no host authority is written here."""
    with (
        initialize._lock(initialize.REPOSITORY_LOCK, fcntl.LOCK_EX, owner),
        initialize._lock(initialize.SELECTION_LOCK, fcntl.LOCK_SH, owner),
    ):
        chain = records.decode(records.operate(records.ROOT, ["read"], b"", owner=owner))
        state = journal.validate(chain)
        if state["phase"] == "absent":
            raise ValueError("production observation lacks original rollout authority")
        artifact, source = _selection(state, owner)
        fence.run(
            [
                "/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact",
                str(probe.SELECTION.parent / artifact),
            ]
        )
        raw = probe.read(probe.BACKUP, owner=owner, mode=0o600)
        values = probe.configuration(raw)
        mode = (
            values.get("LOWERDUCKPOND_BACKUP_STATIC_RECOVERY_ENABLED", "false"),
            values.get("LOWERDUCKPOND_AUDIT_ROTATION_ENABLED", "false"),
        )
        if mode not in {
            (str(recovery).lower(), str(rotation).lower())
            for recovery, rotation in _modes(str(state["phase"]))
        }:
            raise ValueError("production observation found configuration outside its phase")
        environment = probe.environment(
            raw,
            region=values.get("AWS_DEFAULT_REGION", ""),
            locator=values.get("RESTIC_REPOSITORY", ""),
            recovery=mode[0] == "true",
            rotation=mode[1] == "true",
        )
        config = json.loads(
            probe.repository_config(environment), object_pairs_hook=probe.unique_object
        )
        if (
            type(config) is not dict
            or type(config.get("version")) is not int
            or config["version"] != probe.RESTIC_VERSION
        ):
            raise ValueError("production observation found an unsupported repository")
        journal._hex(config.get("id"))
        _empty(owner)
        if (
            records.decode(records.operate(records.ROOT, ["read"], b"", owner=owner)) != chain
            or _selection(state, owner) != (artifact, source)
            or probe.read(probe.BACKUP, owner=owner, mode=0o600) != raw
        ):
            raise ValueError("production authority changed during observation")
        return journal.canonical(
            {
                "format": "lowerduckpond-m3-11-production-observation-v1",
                "original_sha256": state["original_sha256"],
                "last_sha256": state["last_sha256"],
                "repository_config_id": config["id"],
                "repository_node": probe.NODE,
                "repository_locator": environment["RESTIC_REPOSITORY"],
                "archive_authority": {
                    "format": "lowerduckpond-m3-10-archive-authority-v1",
                    "artifactSha256": artifact,
                    "sourceRevision": source,
                    "archives": [],
                },
            }
        )
