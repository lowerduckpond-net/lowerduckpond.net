"""Read-only digest of excluded pending inputs on the original fenced source."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from contextlib import ExitStack
from pathlib import Path

STATE = Path("/var/lib/lowerduckpond/static")
ROOTS = {
    "intents": STATE / "intents",
    "intake": STATE / "intake",
    "exports": STATE / "exports",
    "caddy-intents": Path("/etc/caddy/intents"),
    "staging": Path("/srv/lowerduckpond/sites/.staging"),
}
MAX_ENTRIES = 10000
MAX_BYTES = 256 * 1024 * 1024


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _file_digest(path: Path, before: os.stat_result) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        if _identity(before) != _identity(os.fstat(descriptor)):
            raise ValueError("source pending input changed before its read")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("source pending input was truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if stream.read(1) or _identity(before) != _identity(os.fstat(descriptor)):
            raise ValueError("source pending input changed during its read")
        return digest.hexdigest()


def capture(roots: dict[str, Path]) -> dict[str, object]:
    """The fixed installed caller holds all state read leases and source fencing."""
    observations: list[dict[str, object]] = []
    files: dict[str, int] = {}
    total = 0
    for name, root in sorted(roots.items()):
        for ancestor in (root, *root.parents):
            if not stat.S_ISDIR(ancestor.lstat().st_mode):
                raise ValueError("source pending-input path is not a real directory")
        files[name] = 0
        pending = [root]
        while pending:
            path = pending.pop()
            before = path.lstat()
            entry: dict[str, object] = {
                "root": name,
                "path": str(path.relative_to(root)),
                "identity": list(_identity(before)),
            }
            if len(observations) >= MAX_ENTRIES:
                raise ValueError("source pending-input inventory exceeds its entry bound")
            if stat.S_ISDIR(before.st_mode):
                with os.scandir(path) as iterator:
                    for child in iterator:
                        pending.append(path / child.name)
                        if len(observations) + len(pending) >= MAX_ENTRIES:
                            raise ValueError(
                                "source pending-input inventory exceeds its entry bound"
                            )
            elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                total += before.st_size
                if total > MAX_BYTES:
                    raise ValueError("source pending-input inventory exceeds its byte bound")
                entry["sha256"] = _file_digest(path, before)
                files[name] += 1
            else:
                raise ValueError("source pending input is not a private regular file or directory")
            if _identity(before) != _identity(path.lstat()):
                raise ValueError("source pending input changed during inventory")
            observations.append(entry)
    raw = json.dumps(
        sorted(observations, key=lambda item: (str(item["root"]), str(item["path"]))),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "files": files, "bytes": total}


def main() -> None:
    from lowerduckpond_static_host_agent.host_restore_gate import (  # noqa: PLC0415
        restore_admission,
    )
    from lowerduckpond_static_host_agent.host_restore_services import (  # noqa: PLC0415
        require_quiescent,
    )
    from lowerduckpond_static_host_agent.locks import (  # noqa: PLC0415
        LockManager,
        LockMode,
        LockName,
    )

    if os.geteuid() != 0 or restore_admission():
        raise ValueError("source pending-input proof requires the original root fence")
    require_quiescent()
    with LockManager(STATE / "locks", expected_owner=0) as locks, ExitStack() as held:
        for name in LockName:
            held.enter_context(locks.acquire(name, mode=LockMode.SHARED, blocking=True))
        before = capture(ROOTS)
        if before != capture(ROOTS):
            raise ValueError("fenced source pending inputs changed between observations")
        require_quiescent()
    print(json.dumps(before, sort_keys=True))


if __name__ == "__main__":
    main()
