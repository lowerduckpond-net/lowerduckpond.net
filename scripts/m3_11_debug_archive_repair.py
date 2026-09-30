"""Opt-in archive tracing on a retained Docker destination; no runtime policy changes.

The native launchers and selected artifact remain intact. Diagnostic copies keep
their selection lock and entry point, with stderr captured without journald.
Run only through m3-11-debug --repair.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

OPERATIONS = ("construction", "cleanup", "export")
LAUNCHERS = Path("/usr/local/libexec/lowerduckpond")
SYSTEMD = Path("/etc/systemd/system")
LOGS = Path("/var/log/lowerduckpond-debug-archive")
MAXIMUM = 128 * 1024
OBSERVER = """import json
import os
import sys
import traceback
from pathlib import Path
from lowerduckpond_static_host_agent import archive_entrypoint

original_diagnostic = archive_entrypoint.archive_failure_diagnostic
def observed_failure(error):
    category = original_diagnostic(error)
    try:
        chain, seen = [], set()
        current = error
        while current is not None and id(current) not in seen and len(chain) < 4:
            seen.add(id(current))
            chain.append({
                "exception": type(current).__name__,
                "locations": [
                    {"file": Path(frame.f_code.co_filename).name, "line": line}
                    for frame, line in traceback.walk_tb(current.__traceback__)
                ][-12:],
            })
            current = current.__cause__ or (
                None if current.__suppress_context__ else current.__context__)
        print("ldp_debug_archive " + json.dumps({
            "helper": HELPER, "invocation": os.environ.get("INVOCATION_ID", ""),
            "chain": chain}), file=sys.stderr, flush=True)
    except Exception:
        pass
    return category
archive_entrypoint.archive_failure_diagnostic = observed_failure
"""


def directory(path: Path, *, owner: int) -> None:
    if path.parent.resolve() != path.parent:
        raise ValueError("archive diagnostic parent is redirected")
    path.mkdir(mode=0o700, exist_ok=True)
    item = path.lstat()
    if (
        path.resolve() != path
        or not stat.S_ISDIR(item.st_mode)
        or item.st_uid != owner
        or item.st_gid != os.getegid()
        or stat.S_IMODE(item.st_mode) != 0o700  # noqa: PLR2004 - private diagnostic directory
    ):
        raise ValueError("archive diagnostic directory is unsafe")


def read(path: Path, *, owner: int, empty: bool = False) -> bytes:
    if path.resolve() != path:
        raise ValueError("archive diagnostic path is redirected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or before.st_gid != os.getegid()
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not (0 if empty else 1) <= before.st_size <= MAXIMUM
        ):
            raise ValueError("archive diagnostic file is unsafe")
        raw = stream.read(MAXIMUM + 1)
        after = os.fstat(stream.fileno())
        if len(raw) != before.st_size or (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("archive diagnostic file changed")
        return raw


def once(path: Path, raw: bytes, mode: int, *, owner: int) -> None:
    if path.exists() or path.is_symlink():
        if read(path, owner=owner, empty=not raw) != raw:
            raise ValueError("archive diagnostic input differs from its captured bytes")
        if stat.S_IMODE(path.stat().st_mode) != mode:
            raise ValueError("archive diagnostic input permissions changed")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def instrument(original: bytes, operation: str) -> bytes:
    if operation not in OPERATIONS:
        raise ValueError("unknown archive diagnostic helper")
    tail = f"raise SystemExit(archive_{operation}_main())"
    source = original.decode()
    if source.count(tail) != 1 or "ldp_debug_archive" in source:
        raise ValueError("unrecognized native archive launcher")
    observer = "HELPER = " + repr(operation) + "\n" + OBSERVER
    result = source.replace(
        tail,
        f"exec(compile({observer!r}, 'm3_11_debug_archive_observer.py', 'exec'), {{}})\n{tail}",
    )
    compile(result, f"archive-{operation}-service", "exec")
    return result.encode()


def install(restore_id: str, *, owner: int = 0) -> dict[str, str]:
    from lowerduckpond_static_contracts import validate_uuid7  # noqa: PLC0415

    validate_uuid7(restore_id)
    target = LAUNCHERS / ("archive-diagnostic-" + restore_id)
    directory(target, owner=owner)
    directory(LOGS, owner=owner)
    hashes = {}
    for operation in OPERATIONS:
        name = f"archive-{operation}-service"
        original = read(LAUNCHERS / name, owner=owner)
        once(target / (name + ".original"), original, 0o600, owner=owner)
        once(target / name, instrument(original, operation), 0o700, owner=owner)
        log = LOGS / (operation + ".log")
        if log.exists() or log.is_symlink():
            read(log, owner=owner, empty=True)
            if stat.S_IMODE(log.stat().st_mode) != 0o600:  # noqa: PLR2004
                raise ValueError("archive diagnostic log permissions changed")
        else:
            once(log, b"", 0o600, owner=owner)
        parent = SYSTEMD / (f"lowerduckpond-archive-{operation}@request.service.d")
        directory(parent, owner=owner)
        dropin = (
            f"[Service]\nExecStart=\nExecStart={target / name}\nStandardError=append:{log}\n"
        ).encode()
        once(parent / "90-diagnostic.conf", dropin, 0o600, owner=owner)
        hashes[operation] = hashlib.sha256(original).hexdigest()
    return hashes


def main() -> None:
    from lowerduckpond_static_host_agent.host_restore_journal import (  # noqa: PLC0415
        RestorePhase,
        RestoreStore,
    )

    if os.geteuid() != 0 or Path("/run/systemd/container").read_text().strip() != "docker":
        raise ValueError("archive tracing requires the retained Docker destination")
    busy = subprocess.run(
        [
            "/usr/bin/systemctl",
            "list-units",
            "--no-legend",
            "--plain",
            "--state=active,activating,deactivating",
            "lowerduckpond-static-worker@*.service",
            "lowerduckpond-archive-*@*.service",
            "lowerduckpond-host-restore.service",
        ],
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    if busy.strip():
        raise ValueError("archive tracing requires settled workers and helpers")
    with RestoreStore.locked(Path("/var/lib/lowerduckpond/recovery")) as store:
        current = store.read()
        if current is None or current.phase is not RestorePhase.COMPLETE:
            raise ValueError("archive tracing requires completed reconstruction")
        hashes = install(current.restore_id)
    subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True, timeout=30)
    print(json.dumps({"original_launchers": hashes, "qualification_authority": "none"}))


if __name__ == "__main__":
    main()
