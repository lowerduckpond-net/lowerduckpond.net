"""Managed fixture execution exclusions survive qualification directory disposal.

The registry lives beside ``runs`` and ``leases``, outside every fixture deletion
scope. Path ownership precedes immutable fixture-ID ownership. Both are shared
for ordinary operations and exclusive for retirement/disposal. Even a partial
tombstone excludes execution; no parser or repair can reopen a retired identity.
"""

from __future__ import annotations

import fcntl
import os
import stat
import uuid
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes, uuid7
from scripts.m3_11_retirement_files import digest, directory, sync

REGISTRY = "fixture-dispositions"


def registry(run: Path) -> Path | None:
    """Only managed M3.11 roots can have an external retirement disposition."""
    if len(run.parents) < 4 or run.parent.name != "qualification":  # noqa: PLR2004
        return None
    if run.parents[2].name != "runs" or not run.name.startswith("spaces-"):
        return None
    uuid7(run.parents[1].name)
    root = run.parents[3]
    if not run.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError("fixture registry root is not canonical")
    return root / REGISTRY


def keys(run: Path) -> list[str]:
    result = ["path-" + digest(str(run))]
    path = run / "fixture.json"
    if path.exists() or path.is_symlink():
        result.append("identity-" + uuid7(read_private(path)["run_id"]).hex)
    return result


def require_unfenced(run: Path) -> None:
    root = registry(run)
    if root is None or (not root.exists() and not root.is_symlink()):
        return
    directory(root)
    # One atomic intent binds both the original path and immutable identity.
    # It precedes both tombstones and also fences copies and path recreation
    # after an interruption between their separate publications.
    fixture_keys = keys(run)
    for path in root.glob("identity-*.intent.json"):
        intent = read_private(path)
        if intent.get("original_run") == str(run) or (
            "identity-" + uuid7(intent["fixture_id"]).hex in fixture_keys
        ):
            raise ValueError("frozen fixture retirement permanently excludes execution")
    for key in fixture_keys:
        path = root / (key + ".retired")
        if path.exists() or path.is_symlink():
            raise ValueError("frozen fixture retirement permanently excludes execution")


@contextmanager
def lock(path: Path, *, exclusive: bool, create: bool = True) -> Iterator[None]:
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags | (os.O_CREAT if create else 0), 0o600)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600  # noqa: PLR2004
            or before.st_nlink != 1
        ):
            raise ValueError("fixture operation lock is unsafe")
        fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        current = path.lstat()
        if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("fixture operation lock changed during acquisition")
        yield
    finally:
        os.close(descriptor)


@contextmanager
def ownership(
    run: Path, *, exclusive: bool, fixture_id: str | None = None, create: bool = True
) -> Iterator[None]:
    if fixture_id is not None and not exclusive:
        raise ValueError("explicit immutable identity is only valid for exclusive disposal")
    root = registry(run)
    if root is None:
        yield
        return
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    directory(root)
    if create:
        sync(root.parent)
    with ExitStack() as held:
        # The path lock is always acquired, even before fixture.json exists or
        # after it was removed. Immutable identity additionally fences copies.
        path_key = keys(run)[0]
        held.enter_context(lock(root / (path_key + ".lock"), exclusive=exclusive, create=create))
        identities = keys(run)[1:]
        if fixture_id is not None:
            expected = "identity-" + uuid7(fixture_id).hex
            if identities and identities != [expected]:
                raise ValueError("fixture immutable identity differs from original ownership")
            identities = [expected]
        for key in identities:
            held.enter_context(lock(root / (key + ".lock"), exclusive=exclusive, create=create))
        if not exclusive:
            require_unfenced(run)
        yield


def record(path: Path, value: dict[str, object]) -> None:
    """Atomic append-only metadata; interrupted temporaries remain evidence.

    No exclusion/effect is committed by an unpublished scratch file. A complete
    authoritative intent allows later explicit normalization of missing marker
    records, without overwriting either partial bytes or conflicting finals.
    """
    # CI's read-only selection and receipt gate import the execution fence before
    # workspace packages are installed. Publication alone needs this primitive.
    from lowerduckpond_static_host_agent.durable import _rename_noreplace  # noqa: PLC0415

    directory(path.parent)
    if path.exists() or path.is_symlink():
        if read_private(path) != value:
            raise ValueError("fixture exclusion original metadata conflicts")
        return
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = path.name + ".unpublished-" + uuid.uuid7().hex
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        _rename_noreplace(parent, temporary, path.name)
        os.fsync(parent)
    finally:
        os.close(parent)


def commit(
    run: Path, *, plan_sha256: str, authorization_sha256: str, continuing: bool = False
) -> dict[str, object]:
    """Called only by the native retirement holder under exclusive ownership.

    The identity tombstone is first, fencing aliases as well as the original.
    Disposal cannot begin until the path tombstone also survives removal of
    fixture.json. A crash at either publication leaves execution fenced. No provider
    operation is allowed until both complete records have been reread.
    """
    root = registry(run)
    selected = keys(run)
    if root is None or len(selected) != 2:  # noqa: PLR2004
        raise ValueError("permanent retirement requires a managed immutable fixture")
    directory(root)
    value: dict[str, object] = {
        "format": "lowerduckpond-fixture-execution-exclusion-v1",
        "original_run": str(run),
        "producing_attempt": run.parents[1].name,
        "fixture_id": str(uuid7(read_private(run / "fixture.json")["run_id"])),
        "plan_sha256": plan_sha256,
        "authorization_sha256": authorization_sha256,
        "execution": "permanently-excluded",
        "disposal": "separate-verified-staged-closeout",
    }
    intent = root / (selected[1] + ".intent.json")
    if continuing:
        if read_private(intent) != value:
            raise ValueError("fixture fence continuation lacks exact original intent")
    else:
        require_unfenced(run)
        record(intent, value)
    for key in reversed(selected):
        path = root / (key + ".retired")
        path.mkdir(mode=0o700, exist_ok=True)
        directory(path)
        sync(root)
        record(path / "identity.json", value)
    return value


def require_committed(run: Path, expected: dict[str, object]) -> None:
    root = registry(run)
    if root is None:
        raise ValueError("fixture lacks its persistent execution exclusion")
    directory(root)
    identity_key = "identity-" + uuid7(expected["fixture_id"]).hex
    if read_private(root / (identity_key + ".intent.json")) != expected:
        raise ValueError("persistent fixture intent binding differs")
    for key in ("path-" + digest(str(run)), identity_key):
        path = root / (key + ".retired")
        directory(path)
        if read_private(path / "identity.json") != expected:
            raise ValueError("persistent fixture exclusion binding differs")
