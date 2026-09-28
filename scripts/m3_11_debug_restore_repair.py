"""Explicit retained-Docker repair: health quiescence and bounded restore tracing.

Run only through m3-11-debug --repair. The selected artifact and restore deadlines
are unchanged; the original administrative launcher is retained byte for byte.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path("/var/lib/lowerduckpond/recovery")
LAUNCHER = Path("/usr/local/libexec/lowerduckpond/host-restore-coordinator")
TAIL = "raise SystemExit(restore_coordinator_main(_SELECTION_FD, _ARTIFACT.name))"
UNITS = ("lowerduckpond-health.timer", "lowerduckpond-health.service")
MARKER = "# Retained-fixture diagnostic observer; original artifact remains selected."
MAXIMUM = 128 * 1024

# This program runs only after the original launcher acquired its selection lease
# and verified its immutable artifact. It records no locals, arguments or values
# from restored records. The daemon exits with its coordinator; no guest helper
# outlives the native unit. Sixty-two samples cover its unchanged 30-minute bound.
OBSERVER = """import contextlib
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from lowerduckpond_static_host_agent import host_restore_coordinator as coordinator
from lowerduckpond_static_host_agent import host_restore_services as services

timer = "lowerduckpond-health.timer"
service = "lowerduckpond-health.service"
for name, extra in (("ORDINARY_ACTIVATORS", (timer,)),
                    ("ORDINARY_SERVICES", (service,)),
                    ("_PATTERNS", (timer, service))):
    previous = getattr(services, name)
    setattr(services, name, previous + tuple(unit for unit in extra if unit not in previous))

started, cpu_started = time.monotonic(), time.process_time()
main = threading.main_thread().ident
step = "startup"

def emit(event):
    try:
        frames = []
        frame = sys._current_frames().get(main)
        while frame is not None and len(frames) < 12:
            filename, function = Path(frame.f_code.co_filename).name, frame.f_code.co_name
            if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}\\.py|host-restore-coordinator", filename)
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}|"
                                     r"<(module|listcomp|dictcomp|setcomp|genexpr|lambda)>",
                                     function)):
                frames.append({"file": filename, "line": frame.f_lineno, "function": function})
            frame = frame.f_back
        print("ldp_debug_restore " + json.dumps({
            "event": event, "step": step,
            "invocation": os.environ.get("INVOCATION_ID", ""),
            "elapsed_seconds": round(time.monotonic() - started, 1),
            "cpu_seconds": round(time.process_time() - cpu_started, 1),
            "stack": frames}), file=sys.stderr, flush=True)
    except Exception:
        pass

original = coordinator.verification_step
@contextlib.contextmanager
def observed_step(name):
    global step
    previous, step = step, name
    emit("begin")
    try:
        with original(name):
            yield
    finally:
        emit("end")
        step = previous

def sample():
    for _ in range(62):
        time.sleep(30)
        emit("sample")

coordinator.verification_step = observed_step
emit("start")
threading.Thread(target=sample, name="restore-diagnostic", daemon=True).start()
"""


def read_root(path: Path) -> bytes:
    if path.resolve() != path:
        raise ValueError("diagnostic repair path is redirected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAXIMUM
        ):
            raise ValueError("diagnostic repair input has unsafe metadata")
        raw = stream.read(MAXIMUM + 1)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(raw) != before.st_size:
            raise ValueError("diagnostic repair input changed")
        return raw


def publish(path: Path, raw: bytes, *, mode: int) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete_on_close=False) as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
        Path(stream.name).replace(path)


def instrument(original: bytes) -> bytes:
    source = original.decode()
    if source.count(TAIL) != 1 or MARKER in source:
        raise ValueError("diagnostic repair does not recognize the original launcher")
    injection = (
        MARKER
        + "\nexec(compile("
        + repr(OBSERVER)
        + ", 'm3_11_debug_restore_observer.py', 'exec'), {})\n"
        + TAIL
    )
    result = source.replace(TAIL, injection)
    compile(result, str(LAUNCHER), "exec")
    return result.encode()


def admission(unit: str) -> bytes:
    value = (
        "[Unit]\nRequires=lowerduckpond-restore-gate.service\n"
        "After=lowerduckpond-restore-gate.service\n"
    )
    if unit.endswith(".timer"):
        value += (
            "ConditionPathExists=|!/var/lib/lowerduckpond/recovery/restore-gate.json\n"
            "ConditionPathExists=|/run/lowerduckpond-host-restore/schedules-ready\n"
        )
    else:
        value += (
            "ConditionPathExists=!/var/lib/lowerduckpond/recovery/restore-gate.json\n"
            "[Service]\nBindReadOnlyPaths=/var/lib/lowerduckpond/recovery\n"
            "ExecStartPre=!/usr/local/libexec/lowerduckpond/host-restore-gate --ordinary\n"
        )
    return value.encode()


def main() -> None:
    # Import from the original selected artifact supplied by the debug controller.
    from lowerduckpond_static_host_agent.host_restore_gate import gate_pending  # noqa: PLC0415
    from lowerduckpond_static_host_agent.host_restore_journal import (  # noqa: PLC0415
        RestorePhase,
        RestoreStore,
    )

    if os.geteuid() != 0 or Path("/run/systemd/container").read_text().strip() != "docker":
        raise ValueError("diagnostic repair requires its retained Docker destination")
    state = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            "lowerduckpond-host-restore.service",
            "--property=ActiveState",
            "--value",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
    if state not in {"inactive", "failed"}:
        raise ValueError("stop the coordinator before applying its diagnostic repair")
    with RestoreStore.locked(ROOT) as store:
        current = store.read()
        if (
            current is None
            or current.phase is not RestorePhase.INSTALLED
            or not gate_pending(store)
        ):
            raise ValueError("diagnostic repair requires the installed, gated restore")
        directory = ROOT / "diagnostic-launcher"
        directory.mkdir(mode=0o700, exist_ok=True)
        metadata = directory.lstat()
        if (
            directory.resolve() != directory
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004 - private diagnostic directory
        ):
            raise ValueError("diagnostic launcher directory is unsafe")
        saved = directory / "original.py"
        existing = read_root(LAUNCHER)
        if not (saved.exists() or saved.is_symlink()):
            instrument(existing)
            with saved.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(existing)
                stream.flush()
                os.fsync(stream.fileno())
        original = read_root(saved)
        updated = instrument(original)
        if existing not in (original, updated):
            raise ValueError("diagnostic launcher changed outside this repair")
        for unit in UNITS:
            parent = Path("/etc/systemd/system") / (unit + ".d")
            parent.mkdir(mode=0o755, exist_ok=True)
            metadata = parent.lstat()
            if (
                parent.resolve() != parent
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise ValueError("diagnostic health admission path is redirected")
            path = parent / "restore-admission.conf"
            if path.exists() or path.is_symlink():
                if read_root(path) != admission(unit):
                    raise ValueError("diagnostic health admission differs from reviewed repair")
            else:
                publish(path, admission(unit), mode=0o644)
        publish(LAUNCHER, updated, mode=0o755)
        subprocess.run(
            ["/usr/bin/systemctl", "daemon-reload"],
            check=True,
            timeout=30,
        )
        print(
            json.dumps(
                {
                    "original_launcher_sha256": hashlib.sha256(original).hexdigest(),
                    "diagnostic_launcher_sha256": hashlib.sha256(updated).hexdigest(),
                    "qualification_authority": "none",
                }
            )
        )


if __name__ == "__main__":
    main()
