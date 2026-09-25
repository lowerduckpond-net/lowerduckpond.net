"""Retain one bounded SQL dump for the original production rollout capture."""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_sources import MAX_TREE_BYTES
from lowerduckpond_static_host_agent.capacity import (
    CapacityReservation,
    ReleaseCapacityUsage,
    admit_release_capacity,
    measure_filesystem_capacity_descriptor,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, validate_regular_state_file
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore, full_id
from lowerduckpond_static_host_agent.production_backup import BackupAuthority
from lowerduckpond_static_host_agent.production_capture import _database, _sync

DUMP = (
    "/usr/sbin/runuser",
    "--user",
    "ldp-backup",
    "--",
    "/usr/bin/mariadb-dump",
    "--all-databases",
    "--single-transaction",
    "--quick",
    "--routines",
    "--events",
    "--triggers",
)
GZIP = ("/usr/bin/gzip", "--best")
DEADLINE_SECONDS = 30 * 60
MAX_ATTEMPTS = 16
CHUNK = 64 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024
FORMAT = "lowerduckpond-production-database-dump-v1"


def _reserve(descriptor: int, size: int, inodes: int = 0) -> None:
    filesystem = measure_filesystem_capacity_descriptor(descriptor)
    admit_release_capacity(
        ReleaseCapacityUsage(()),
        CapacityReservation(size + 2 * filesystem.fragment_size, inodes),
        filesystem,
    )


def _admit_directory(root: Path, owner: int, metadata_bytes: int) -> None:
    # Admit metadata and temporary inodes before even allocating the private
    # store lease. Stream writes also remeasure the remaining reserve.
    with DurableDirectory.open(
        root, expected_owner=owner, expected_directory_mode=0o700
    ) as directory:
        descriptor = directory.duplicate_descriptor()
        try:
            _reserve(descriptor, metadata_bytes + CHUNK, 6)
        finally:
            os.close(descriptor)


def _stream(
    processes: tuple[subprocess.Popen[bytes], subprocess.Popen[bytes]],
    output: BinaryIO,
    errors: BinaryIO,
    deadline: float,
    directory_descriptor: int,
) -> dict[str, object]:
    producer, compressor = processes
    sizes = {"sql": 0, "errors": 0}
    digest = hashlib.sha256()
    with selectors.DefaultSelector() as selector:
        for stream, kind in (
            (compressor.stdout, "sql"),
            (producer.stderr, "errors"),
            (compressor.stderr, "errors"),
        ):
            assert stream is not None  # noqa: S101 - all three streams are PIPEs
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ, kind)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BackupIdentityError("production database dump exceeded its deadline")
            for key, _ in selector.select(remaining):
                try:
                    raw = os.read(key.fd, CHUNK)
                except BlockingIOError:
                    continue
                if not raw:
                    selector.unregister(key.fd)
                    continue
                kind = key.data
                sizes[kind] += len(raw)
                maximum = MAX_TREE_BYTES if kind == "sql" else MAX_DIAGNOSTIC_BYTES
                if sizes[kind] > maximum:
                    raise BackupIdentityError("production database dump exceeds its bound")
                target = output if kind == "sql" else errors
                _reserve(directory_descriptor, len(raw))
                target.write(raw)
                target.flush()
                if kind == "sql":
                    digest.update(raw)
    if not sizes["sql"]:
        raise BackupIdentityError("production database dump is empty")
    return {"size": sizes["sql"], "sha256": digest.hexdigest()}


def _stop(process: subprocess.Popen[bytes]) -> None:
    # Every subprocess owns its session. Kill any surviving descendants too;
    # none may keep the repository/selection leases after this action fails.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def _dump(
    output: BinaryIO, errors: BinaryIO, descriptors: tuple[int, ...], directory_descriptor: int
) -> dict[str, object]:
    deadline = time.monotonic() + DEADLINE_SECONDS
    producer = subprocess.Popen(  # noqa: S603 - fixed installed database identity and dump arguments
        DUMP,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin"},
        pass_fds=descriptors,
        start_new_session=True,
    )
    compressor: subprocess.Popen[bytes] | None = None
    try:
        compressor = subprocess.Popen(  # noqa: S603 - fixed compressor, explicit byte stream
            GZIP,
            stdin=producer.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin"},
            pass_fds=descriptors,
            start_new_session=True,
        )
        assert producer.stdout is not None  # noqa: S101 - PIPE above
        producer.stdout.close()
        result = _stream((producer, compressor), output, errors, deadline, directory_descriptor)
        for process in (producer, compressor):
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
            if status:
                raise BackupIdentityError("production database dump pipeline failed")
        output.flush()
        os.fsync(output.fileno())
        return result
    except subprocess.TimeoutExpired:
        raise BackupIdentityError("production database dump exceeded its deadline") from None
    finally:
        if compressor is not None:
            _stop(compressor)
        _stop(producer)
        errors.flush()
        os.fsync(errors.fileno())


def _next(store: RestoreStore) -> int:
    descriptor = store.directory.duplicate_descriptor()
    try:
        attempts = set()
        with os.scandir(descriptor) as entries:
            for count, entry in enumerate(entries):
                if count >= 4 * MAX_ATTEMPTS:
                    raise BackupIdentityError("production database evidence exceeds its bound")
                match = re.fullmatch(r"dump-([0-9]{2})\.(?:sql\.gz|stderr)", entry.name)
                if match:
                    attempts.add(int(match[1]))
        attempt = 0 if not attempts else max(attempts) + 1
        if attempt >= MAX_ATTEMPTS:
            raise BackupIdentityError("production database attempts require operator inspection")
        _reserve(descriptor, 0, 3)
        return attempt
    finally:
        os.close(descriptor)


def retain_database(
    directory: Path, authority: BackupAuthority, *, owner: int, descriptors: tuple[int, ...]
) -> Path:
    """Caller holds the fixed backup-profile action and repository/selection FDs.

    Partial attempts and diagnostics remain private. A zero-exit compressor alone
    never proves the database dump completed: both real process exits are checked.
    A published original is revalidated and reused without running the dump again.
    """
    inputs = canonical_json_bytes(authority.document())
    _admit_directory(directory, owner, len(inputs))
    with RestoreStore.locked(directory, owner=owner) as store:
        store.immutable("database-inputs.json", inputs)
        try:
            raw = store.read_bytes("database-original.json")
        except FileNotFoundError:
            attempt = _next(store)
            name = f"dump-{attempt:02d}.sql.gz"
            parent = store.directory.duplicate_descriptor()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                with (
                    os.fdopen(os.open(name, flags, 0o600, dir_fd=parent), "wb") as output,
                    os.fdopen(
                        os.open(f"dump-{attempt:02d}.stderr", flags, 0o600, dir_fd=parent), "wb"
                    ) as errors,
                ):
                    metadata = _dump(output, errors, descriptors, parent)
            finally:
                os.close(parent)
            raw = canonical_json_bytes({"format": FORMAT, "file": name, **metadata})
            store.immutable("database-original.json", raw)
        value = decode_json_object(raw)
        if (
            set(value) != {"format", "file", "size", "sha256"}
            or value["format"] != FORMAT
            or type(value["file"]) is not str
            or re.fullmatch(r"dump-[0-9]{2}\.sql\.gz", value["file"]) is None
            or type(value["size"]) is not int
            or not 0 < value["size"] <= MAX_TREE_BYTES
            or canonical_json_bytes(value) != raw
        ):
            raise BackupIdentityError("production original database evidence is invalid")
        full_id(value["sha256"])
        original = directory / value["file"]
        if _database(original, owner) != {"size": value["size"], "sha256": value["sha256"]}:
            raise BackupIdentityError("production original database bytes changed")
        _sync(store)
        return original


def stage_database(original: Path, staging: Path, *, owner: int) -> None:
    """Copy the retained dump under repository EX; never rerun SQL on resumption."""
    expected = _database(original, owner)
    _admit_directory(staging, owner, 0)
    with RestoreStore.locked(staging, owner=owner) as store:
        parent = store.directory.duplicate_descriptor()
        source = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        temporary = "m3-11-database.partial"
        try:
            for name in (temporary, "mariadb.sql.gz"):
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                except FileNotFoundError:
                    continue
                try:
                    validate_regular_state_file(fd, expected_owner=owner, expected_mode=0o600)
                finally:
                    os.close(fd)
                if name == temporary:
                    os.unlink(name, dir_fd=parent)
            _reserve(parent, 0, 1)
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            with os.fdopen(fd, "wb") as output:
                remaining = cast(int, expected["size"])
                while remaining:
                    raw = os.read(source, min(CHUNK, remaining))
                    if not raw:
                        raise BackupIdentityError("retained production dump was truncated")
                    _reserve(parent, len(raw))
                    output.write(raw)
                    output.flush()
                    remaining -= len(raw)
                output.flush()
                os.fsync(output.fileno())
            if (
                _database(staging / temporary, owner) != expected
                or _database(original, owner) != expected
            ):
                raise BackupIdentityError("retained production dump changed during staging")
            os.rename(temporary, "mariadb.sql.gz", src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(source)
            os.close(parent)
