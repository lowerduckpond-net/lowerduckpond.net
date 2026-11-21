"""Private, append-only M3.12 checkpoints, available before dependency setup."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import UUID

ATTEMPT_ENV = "LDP_M3_12_ATTEMPT"
FORMAT = "lowerduckpond-m3-12-diagnostic-v1"
SUMMARY = "lowerduckpond-m3-12-diagnostic-summary-v1"
UUID7 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
CHECKPOINT = re.compile(r"[0-9]{10}\.json")
MAX_BYTES = 256 * 1024
MAX_SEQUENCE = 2**31 - 1
PRIVATE_DIR = 0o700
PRIVATE_FILE = 0o600
MAX_CAUSES = 32
MAX_EXIT = 255
MAX_SIGNAL = 127
MAX_ERRNO = 4095
MAX_SYMBOL = 65535
MAX_LINE = 1_000_000
SOURCES = frozenset(
    {
        "m3_12_diagnostic_store.py",
        "qualification_case.py",
        "qualification_local.py",
        "m3_12_diagnostics.py",
        "m3_12_diagnostic_guest.py",
        "m3_12_guest_witness.py",
        "m3_12_diagnostic_transport.py",
        "ldp_timing.py",
    }
)
STAGES = frozenset(
    {
        "allocation",
        "dependencies",
        "source-validation",
        "provisioning",
        "bootstrap",
        "preparation",
        "dark-staging",
        "dark-repeat",
        "final-backup-verification",
        "activation-preparation",
        "durable-launch",
        "enabled-convergence",
        "enabled-repeat",
        "canary",
        "accounting",
        "acceptance",
        "cleanup",
        "packaging",
        "inspection",
    }
)
OPERATIONS = frozenset(
    {
        "git",
        "controller",
        "ssh",
        "docker",
        "ansible",
        "systemd",
        "dns",
        "tls",
        "provider",
        "storage",
        "filesystem",
        "collector",
        "lease",
    }
)
CATEGORIES = frozenset(
    {
        "prerequisite",
        "dependencies",
        "transport",
        "provider",
        "process",
        "controller",
        "authority",
        "integrity",
        "capacity",
        "interrupted",
        "unknown",
    }
)
OUTCOMES = frozenset({"known", "uncertain", "interrupted", "not-submitted"})
RESULTS = frozenset({"passed", "failed", "unknown"})
ROLES = frozenset({"primary", "collection", "transfer", "cleanup", "lease-release", "finalization"})
ROOT = Path(__file__).resolve().parents[1]


def identity() -> str:
    # The bootstrap can run on the runner's system Python before the pinned tools exist.
    value = bytearray(os.urandom(16))
    value[:6] = (time.time_ns() // 1_000_000).to_bytes(6, "big")
    value[6] = (value[6] & 0x0F) | 0x70
    value[8] = (value[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(value)))


def encode(value: object) -> bytes:
    # Closed records contain ASCII schema tokens, integers and booleans only.
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def private_directory(path: Path) -> int:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("invalid diagnostic directory")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIR:
        os.close(descriptor)
        raise ValueError("diagnostic directory is not private")
    return descriptor


def publish(directory: Path, name: str, value: object) -> None:
    data = encode(value)
    if len(data) > MAX_BYTES:
        raise ValueError("diagnostic record exceeds its resource bound")
    parent = private_directory(directory)
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".checkpoint-", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(Path(temporary).name, name, src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            os.unlink(Path(temporary).name, dir_fd=parent)
    finally:
        os.close(parent)


def read(directory: Path, name: str) -> dict[str, Any]:
    parent = private_directory(directory)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE
                or not 0 < metadata.st_size <= MAX_BYTES
            ):
                raise ValueError("unsafe diagnostic record")
            raw = stream.read(MAX_BYTES + 1)
    finally:
        os.close(parent)
    try:
        record = json.loads(raw)
        if type(record) is not dict or len(raw) > MAX_BYTES or encode(record) != raw:
            raise ValueError("invalid diagnostic record")
    except ValueError, RecursionError, OverflowError:
        raise ValueError("invalid diagnostic record") from None
    return record


def clock() -> tuple[str, int]:
    return (
        datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        time.monotonic_ns() // 1_000_000,
    )


def safe_frames(error: BaseException) -> list[dict[str, object]]:
    frames = []
    cursor = error.__traceback__
    while cursor:
        code = cursor.tb_frame.f_code
        path = Path(code.co_filename)
        if (
            path.name in SOURCES
            and path.is_absolute()
            and path.is_relative_to(ROOT)
            and 0 < code.co_firstlineno <= MAX_SYMBOL
            and 0 < cursor.tb_lineno <= MAX_LINE
        ):
            try:
                if path.resolve(strict=True) == path:
                    with path.open("rb") as source:
                        raw = source.read(MAX_BYTES + 1)
                    if len(raw) <= MAX_BYTES:
                        frames.append(
                            {
                                "sourceSha256": sha256(raw).hexdigest(),
                                "symbolId": code.co_firstlineno,
                                "line": cursor.tb_lineno,
                            }
                        )
            except OSError:
                pass
        cursor = cursor.tb_next
    return frames[-MAX_CAUSES:]


def cause_type(error: BaseException) -> str:
    for kind, label in (
        (FileNotFoundError, "missing"),
        (PermissionError, "permission"),
        (FileExistsError, "conflict"),
        ((TimeoutError, subprocess.TimeoutExpired), "timeout"),
        (ConnectionError, "connection"),
        (subprocess.CalledProcessError, "process"),
        (ValueError, "schema"),
    ):
        if isinstance(error, kind):
            return label
    return "unexpected"


def failure(role: str, category: str, operation: str, error: BaseException) -> dict[str, Any]:
    causes: list[dict[str, Any]] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(causes) < MAX_CAUSES:
        seen.add(id(current))
        cause: dict[str, Any] = {
            "type": cause_type(current),
            "operation": operation,
            "frames": safe_frames(current),
        }
        if (
            isinstance(current, OSError)
            and type(current.errno) is int
            and 0 < current.errno <= MAX_ERRNO
        ):
            cause["errno"] = current.errno
        causes.append(cause)
        current = current.__cause__ or (
            None if current.__suppress_context__ else current.__context__
        )
    prerequisite = {
        "dependencies": "toolchain",
        "authority": "ownership",
        "transport": "binding",
        "interrupted": "terminal-evidence",
    }.get(category, "other")
    return {"role": role, "category": category, "prerequisite": prerequisite, "causes": causes}


def process_status(status: int) -> dict[str, int]:
    if 0 <= status <= MAX_EXIT:
        return {"exit": status}
    if -MAX_SIGNAL <= status < 0:
        return {"signal": -status}
    raise ValueError("invalid process status")


class Attempt:
    def __init__(self, directory: Path) -> None:
        if not UUID7.fullmatch(directory.name) or not UUID7.fullmatch(directory.parent.name):
            raise ValueError("invalid diagnostic attempt identity")
        for path in (directory.parent, directory):
            os.close(private_directory(path))
        self.directory = directory

    @classmethod
    def allocate(cls, root: Path) -> Attempt:
        if not root.is_absolute() or root.resolve() != root:
            raise ValueError("invalid diagnostic root")
        root.mkdir(parents=True, mode=PRIVATE_DIR, exist_ok=True)
        os.close(private_directory(root))
        parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        run = root / identity()
        run.mkdir(mode=PRIVATE_DIR)
        directory = run / identity()
        directory.mkdir(mode=PRIVATE_DIR)
        for created in (root, run):
            parent = private_directory(created)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        attempt = cls(directory)
        attempt.append("allocation", "controller", clock(), outcome="not-submitted")
        return attempt

    @contextmanager
    def lock(self, name: str, *, blocking: bool = True) -> Iterator[None]:
        parent = private_directory(self.directory)
        try:
            descriptor = os.open(
                name,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                PRIVATE_FILE,
                dir_fd=parent,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE
                    or metadata.st_nlink != 1
                ):
                    raise ValueError("invalid diagnostic lock")
                fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                yield
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)

    def names(self) -> list[str]:
        return sorted(
            path.name for path in self.directory.iterdir() if CHECKPOINT.fullmatch(path.name)
        )

    def append(  # noqa: PLR0913 - one structured diagnostic boundary
        self,
        stage: str,
        operation: str,
        started: tuple[str, int],
        *,
        status: int | None = None,
        outcome: str = "uncertain",
        incident: dict[str, Any] | None = None,
        original: bool = False,
    ) -> dict[str, Any]:
        if stage not in STAGES or operation not in OPERATIONS or outcome not in OUTCOMES:
            raise ValueError("invalid diagnostic context")
        with self.lock("journal.lock"):
            names = self.names()
            sequence = int(names[-1][:-5]) + 1 if names else 0
            if sequence > MAX_SEQUENCE:
                raise ValueError("diagnostic sequence exceeds its resource bound")
            record: dict[str, Any] = {
                "format": FORMAT,
                "runId": self.directory.parent.name,
                "invocationId": self.directory.name,
                "sequence": sequence,
                "stage": stage,
                "operation": operation,
                "startedAt": started[0],
                "startedMonotonicMs": started[1],
                "terminalEvidence": "missing",
                "outcome": outcome,
                "result": "unknown",
                "attempts": 1,
                "failures": [incident] if incident else [],
                "omissions": ["no-terminal-evidence"],
                "inspection": "inspect",
            }
            if status is not None:
                now = clock()
                record.update(
                    finishedAt=max(now[0], started[0]),
                    finishedMonotonicMs=now[1],
                    terminalEvidence="recorded",
                    outcome="known",
                    result="passed" if status == 0 else "failed",
                    process=process_status(status),
                    omissions=[],
                )
            if original:
                publish(self.directory, "original.json", record)
            publish(self.directory, f"{sequence:010}.json", record)
            return record

    def record(self, name: str) -> dict[str, Any]:
        record = read(self.directory, name)
        if (
            record.get("format") != FORMAT
            or record.get("runId") != self.directory.parent.name
            or record.get("invocationId") != self.directory.name
        ):
            raise ValueError("diagnostic record binding changed")
        return record

    def result(self) -> dict[str, Any]:
        try:
            return self.record("original.json")
        except FileNotFoundError:
            for name in reversed(self.names()):
                record = self.record(name)
                if record.get("terminalEvidence") == "missing" and not record.get("failures"):
                    return record
        raise ValueError("missing diagnostic start")


def projection(record: dict[str, Any]) -> dict[str, Any]:
    stage = record.get("stage")
    outcome = record.get("outcome")
    result = record.get("result")
    sequence = record.get("sequence")
    if (
        not isinstance(stage, str)
        or stage not in STAGES
        or not isinstance(outcome, str)
        or outcome not in OUTCOMES
        or not isinstance(result, str)
        or result not in RESULTS
        or type(sequence) is not int
        or not 0 <= sequence <= MAX_SEQUENCE
        or (result == "unknown") != (outcome != "known")
    ):
        raise ValueError("invalid diagnostic summary input")
    summary = {
        "format": SUMMARY,
        "runId": record["runId"],
        "invocationId": record["invocationId"],
        "stage": stage,
        "outcome": outcome,
        "result": result,
        "checkpoint": sequence,
        "omissionCount": len(record.get("omissions", [])),
        "inspection": "inspect",
    }
    for item in record.get("failures", []):
        if not isinstance(item, dict) or item.get("role") != "primary":
            continue
        category = item.get("category")
        if isinstance(category, str) and category in CATEGORIES:
            summary["category"] = category
            break
    return summary
