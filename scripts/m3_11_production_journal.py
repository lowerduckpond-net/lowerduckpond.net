"""Append-only production rollout records, usable before artifact replacement.

The controller retains every exact proposal before sending it to the host. This
module uses only the standard library so the fixed program can run on the
verified predecessor without installing candidate packages. It validates local
record integrity and ordering; the controller must still perform the actual
qualification, fresh provider checks, host actions, and phase assertions.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import cast

FORMAT = "lowerduckpond-m3-11-production-transaction-v1"
RECEIPT_FORMAT = "lowerduckpond-m3-11-production-phase-v1"
MAX_BYTES = 16 * 1024
UUID_VERSION = 7
BOUND_PREDECESSOR_FIELDS = 3
PHASES: dict[str, dict[str, object]] = {
    "drained": {"services_sha256": None, "static_state_sha256": None, "predecessor_sha256": None},
    "namespace": {"namespace_sha256": None, "artifact_sha256": None},
    "lineage": {
        "repository_binding": None,
        "lineage_sha256": None,
        "genesis_snapshot_id": None,
        "audit_head_sha256": None,
    },
    "converged": {
        "first_converge_sha256": None,
        "second_converge_sha256": None,
        "artifact_sha256": None,
        "changed": 0,
        "recovery_enabled": True,
        "rotation_enabled": False,
        "publication_enabled": False,
    },
    "backup-verified": {
        "snapshot_id": None,
        "descriptor_sha256": None,
        "index_sha256": None,
        "restored_tree_sha256": None,
        "report_sha256": None,
    },
    "rotation-enabled": {
        "first_converge_sha256": None,
        "second_converge_sha256": None,
        "changed": 0,
        "rotation_enabled": True,
        "publication_enabled": False,
    },
    "accepted": {
        "acceptance_sha256": None,
        "artifact_sha256": None,
        "namespace_sha256": None,
        "lineage_sha256": None,
        "snapshot_id": None,
        "publication_enabled": False,
    },
}
RECORDS = ("original", *(name for phase in PHASES for name in (phase + ".started", phase)))
CANDIDATE = frozenset(
    {
        "source_revision",
        "artifact_sha256",
        "input_policy",
        "qualification_inputs_sha256",
        "storage_target_sha256",
        "report_sha256",
    }
)


def canonical(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fields(value: object, names: set[str] | frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("production journal fields are invalid")
    return cast(dict[str, object], value)


def _hex(value: object, length: int = 64) -> None:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError("production journal identity is invalid")


def _time(value: object) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value) is None
    ):
        raise ValueError("production journal timestamp is invalid")
    return datetime.fromisoformat(value)


def _original(document: dict[str, object]) -> datetime:
    _fields(
        document,
        {
            "format",
            "transaction_id",
            "started_at",
            "candidate",
            "predecessor",
            "repository_binding",
            "namespace",
        },
    )
    if document["format"] != FORMAT:
        raise ValueError("production journal format is invalid")
    identity = document["transaction_id"]
    if (
        not isinstance(identity, str)
        or str(uuid.UUID(identity)) != identity
        or uuid.UUID(identity).version != UUID_VERSION
    ):
        raise ValueError("production transaction requires a canonical UUIDv7")
    candidate = _fields(document["candidate"], CANDIDATE)
    for name, value in candidate.items():
        if name == "input_policy":
            if value != "lowerduckpond-production-inputs-v1":
                raise ValueError("production input policy is unsupported")
        else:
            _hex(value, 40 if name == "source_revision" else 64)
    predecessor = document["predecessor"]
    if (
        not isinstance(predecessor, str)
        or re.fullmatch(r"[0-9a-f]{64} [0-9a-f]{40}( [0-9a-f]{64})?\n", predecessor) is None
    ):
        raise ValueError("production requires original M3.10 completion bytes")
    parts = predecessor.split()
    if len(parts) == BOUND_PREDECESSOR_FIELDS and parts[2] != candidate["storage_target_sha256"]:
        raise ValueError("production storage target differs from its completed predecessor")
    _hex(document["repository_binding"])
    namespace = _fields(
        document["namespace"], {"apiVersion", "kind", "tenantOriginSuffix", "initializedAt"}
    )
    if namespace != {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": document["started_at"],
    }:
        raise ValueError("production namespace must retain its original initialization")
    return _time(document["started_at"])


def _observations(
    phase: str, value: object, original: dict[str, object], completed: dict[str, dict[str, object]]
) -> None:
    fields = _fields(value, set(PHASES[phase]))
    for name, expected in PHASES[phase].items():
        if expected is None:
            _hex(fields[name])
        elif type(fields[name]) is not type(expected) or fields[name] != expected:
            raise ValueError("production phase failed its required assertion")
    candidate = _fields(original["candidate"], CANDIDATE)
    bindings = {
        "artifact_sha256": candidate["artifact_sha256"],
        "report_sha256": candidate["report_sha256"],
        "repository_binding": original["repository_binding"],
        "namespace_sha256": digest(canonical(cast(dict[str, object], original["namespace"]))),
        "predecessor_sha256": digest(cast(str, original["predecessor"]).encode()),
    }
    if phase == "accepted":
        bindings.update(
            lineage_sha256=completed["lineage"]["lineage_sha256"],
            snapshot_id=completed["backup-verified"]["snapshot_id"],
        )
    if any(fields[name] != expected for name, expected in bindings.items() if name in fields):
        raise ValueError("production phase changed its original authority")


def validate(records: list[tuple[str, bytes]]) -> dict[str, object]:
    """A complete record chain is a rollout receipt, not fresh live verification."""
    if not records:
        return {"phase": "absent"}
    original: dict[str, object] = {}
    completed: dict[str, dict[str, object]] = {}
    previous = ""
    clock: datetime | None = None
    for index, (name, raw) in enumerate(records):
        if index >= len(RECORDS) or name != RECORDS[index] or len(raw) > MAX_BYTES:
            raise ValueError("production phases are missing or out of order")
        value = json.loads(raw)
        if not isinstance(value, dict) or canonical(value) != raw:
            raise ValueError("production journal is not canonical")
        document = cast(dict[str, object], value)
        if index == 0:
            original = document
            clock = _original(original)
        else:
            started = name.endswith(".started")
            phase = name.removesuffix(".started")
            keys = {"format", "original_sha256", "previous_sha256", "phase", "observed_at"}
            _fields(document, keys if started else keys | {"observations"})
            observed = _time(document["observed_at"])
            if (
                document["format"] != RECEIPT_FORMAT
                or document["original_sha256"] != digest(records[0][1])
                or document["previous_sha256"] != previous
                or document["phase"] != phase
                or clock is None
                or observed < clock
            ):
                raise ValueError("production phase changed its chain or original chronology")
            if not started:
                _observations(phase, document["observations"], original, completed)
                completed[phase] = cast(dict[str, object], document["observations"])
            clock = observed
        previous = digest(raw)
    return {
        "phase": "complete" if len(records) == len(RECORDS) else records[-1][0],
        "original": original,
        "original_sha256": digest(records[0][1]),
        "last_sha256": previous,
    }


def _metadata(value: os.stat_result, owner: int, mode: int, *, directory: bool = False) -> None:
    if (
        (not stat.S_ISDIR(value.st_mode) if directory else not stat.S_ISREG(value.st_mode))
        or value.st_uid != owner
        or stat.S_IMODE(value.st_mode) != mode
        or (not directory and value.st_nlink != 1)
    ):
        raise ValueError("production journal metadata is unsafe")


class Journal:
    def __init__(self, directory: Path, descriptor: int, lock: int, owner: int) -> None:
        self.directory, self.descriptor, self.lock, self.owner = directory, descriptor, lock, owner

    def _guard(self) -> None:
        opened = os.fstat(self.lock)
        named = os.stat("lock", dir_fd=self.descriptor, follow_symlinks=False)
        root, current = os.fstat(self.descriptor), self.directory.stat(follow_symlinks=False)
        for value in (opened, named):
            _metadata(value, self.owner, 0o600)
            if value.st_size:
                raise ValueError("production journal lock is not empty")
        for value in (root, current):
            _metadata(value, self.owner, 0o700, directory=True)
        if (opened.st_dev, opened.st_ino, root.st_dev, root.st_ino) != (
            named.st_dev,
            named.st_ino,
            current.st_dev,
            current.st_ino,
        ):
            raise ValueError("production journal lock or directory was replaced")

    def _read(self, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.descriptor)
        try:
            before = os.fstat(fd)
            _metadata(before, self.owner, 0o400)
            if before.st_size > MAX_BYTES:
                raise ValueError("production journal record exceeds its bound")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_BYTES + 1)
            after = os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)
            if (
                any(
                    getattr(before, field) != getattr(after, field)
                    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                )
                or len(raw) != before.st_size
            ):
                raise ValueError("production journal changed while reading")
            return raw
        finally:
            os.close(fd)

    def _records(self, pending: str | None = None) -> list[tuple[str, bytes]]:
        self._guard()
        allowed = {name + ".json" for name in RECORDS} | {"lock"}
        if pending is not None:
            allowed.add(pending)
        names: set[str] = set()
        # scandir(fd) shares the open directory offset. A separate open prevents
        # later inspections from silently starting at the previous scan's end.
        scan = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=self.descriptor)
        try:
            with os.scandir(scan) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > len(allowed) or entry.name not in allowed:
                        raise ValueError("production journal contains unfinished or unknown files")
                    names.add(entry.name)
        finally:
            os.close(scan)
        records = [
            (name, self._read(name + ".json")) for name in RECORDS if name + ".json" in names
        ]
        validate(records)
        self._guard()
        return records

    def inspect(self) -> dict[str, object]:
        return validate(self._records())

    def records(self, *, proposal: tuple[str, bytes] | None = None) -> list[tuple[str, bytes]]:
        """Read completed bytes, optionally beside one exact retained proposal."""
        pending = None
        if proposal is not None:
            name, raw = proposal
            if name not in RECORDS or len(raw) > MAX_BYTES:
                raise ValueError("invalid pending production proposal")
            pending = "." + name + "." + digest(raw) + ".pending"
        return self._records(pending)

    def sync(self) -> None:
        """Confirm a visible publication after an interrupted directory fsync."""
        self._guard()
        os.fsync(self.descriptor)
        self._guard()

    def publish(
        self, name: str, raw: bytes, *, failure_hook: Callable[[str], None] = lambda _: None
    ) -> bool:
        """Resume the exact retained proposal; never replace original or completed bytes."""
        if name not in RECORDS:
            raise ValueError("unknown production phase")
        destination = name + ".json"
        # Bind even a zero-byte interrupted write to the entire original proposal.
        temporary = "." + name + "." + digest(raw) + ".pending"
        records = self._records(temporary)
        existing = dict(records).get(name)
        if existing is not None:
            if existing != raw:
                raise ValueError("production journal proposal changed")
            # A pending copy alongside a published record is never expected.
            self._records()
            os.fsync(self.descriptor)
            return False
        validate([*records, (name, raw)])
        try:
            partial = self._read(temporary)
        except FileNotFoundError:
            pass
        else:
            if not raw.startswith(partial):
                raise ValueError("production journal pending proposal changed")
            os.unlink(temporary, dir_fd=self.descriptor)
            os.fsync(self.descriptor)
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=self.descriptor,
        )
        try:
            os.fchmod(fd, 0o400)
            remaining = memoryview(raw)
            while remaining:
                size = os.write(fd, remaining)
                if size <= 0:
                    raise OSError("production journal short write")
                remaining = remaining[size:]
                failure_hook("write")
            os.fsync(fd)
            failure_hook("file-sync")
        finally:
            os.close(fd)
        self._guard()
        os.rename(temporary, destination, src_dir_fd=self.descriptor, dst_dir_fd=self.descriptor)
        failure_hook("rename")
        os.fsync(self.descriptor)
        failure_hook("directory-sync")
        self._guard()
        return True


@contextmanager
def locked(directory: Path, *, owner: int, create: bool = False) -> Iterator[Journal]:
    """The caller creates only the fixed rollout directory after its live preflight."""
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    lock: int | None = None
    try:
        _metadata(os.fstat(descriptor), owner, 0o700, directory=True)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        if create:
            # Only a completely empty new directory can acquire a new lock.
            with os.scandir(descriptor) as entries:
                if next(entries, None) is None:
                    flags |= os.O_CREAT | os.O_EXCL
        lock = os.open("lock", flags, 0o600, dir_fd=descriptor)
        _metadata(os.fstat(lock), owner, 0o600)
        if os.fstat(lock).st_size:
            raise ValueError("production journal lock is not empty")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal = Journal(directory, descriptor, lock, owner)
        journal._guard()
        if create:
            os.fsync(lock)
            os.fsync(descriptor)
        yield journal
    finally:
        if lock is not None:
            os.close(lock)
        os.close(descriptor)
