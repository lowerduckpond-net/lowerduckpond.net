"""Root-only credential separation with transferred, continuously held leases."""

from __future__ import annotations

import array
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object

from lowerduckpond_static_host_agent.host_restore_journal import (
    LOCK,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
    exact_object,
)

SOCKET_PATH = Path("/run/lowerduckpond-host-restore/archive.sock")
SELECTION_LOCK = Path("/opt/lowerduckpond/static-host-agent/selection.lock")
MAX_MESSAGE = 32 * 1024
MAX_LOCK_METADATA = 4096
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_SOCKET_MODE = 0o600
REQUEST_SCHEMA = "lowerduckpond-host-restore-archive-request-v1"
REPLY_SCHEMA = "lowerduckpond-host-restore-archive-reply-v1"
ACTIONS = frozenset({"verify", "cleanup", "verify-installed"})


def require_lease(path: Path, descriptor: int, *, exclusive: bool, owner: int = 0) -> None:
    opened = os.fstat(descriptor)
    named = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o600  # noqa: PLR2004
        or opened.st_uid != owner
        or opened.st_gid != owner
        or opened.st_nlink != 1
        or opened.st_size != 0
        or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
    ):
        raise HostRestoreError("restore_helper_lease_unsafe")
    with Path(f"/proc/self/fdinfo/{descriptor}").open("rb") as stream:
        raw = stream.read(MAX_LOCK_METADATA + 1)
    rows = [line.split() for line in raw.splitlines() if line.startswith(b"lock:")]
    if (
        len(raw) > MAX_LOCK_METADATA
        or len(rows) != 1
        or rows[0][2:5] != [b"FLOCK", b"ADVISORY", b"WRITE" if exclusive else b"READ"]
        or rows[0][7:] != [b"0", b"EOF"]
    ):
        raise HostRestoreError("restore_helper_lease_missing")


def _peer(stream: socket.socket, owner: int) -> None:
    _pid, uid, gid = struct.unpack(
        "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if uid != owner or gid != owner:
        raise HostRestoreError("restore_helper_peer_invalid")


def send_message(
    stream: socket.socket, message: dict[str, object], descriptors: tuple[int, ...] = ()
) -> None:
    raw = canonical_json_bytes(message, maximum_bytes=MAX_MESSAGE)
    ancillary = (
        []
        if not descriptors
        else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", descriptors))]
    )
    if stream.sendmsg([raw], ancillary) != len(raw):
        raise HostRestoreError("restore_helper_short_message")


def receive_message(
    stream: socket.socket, *, descriptor_count: int
) -> tuple[dict[str, object], tuple[int, ...]]:
    rights = array.array("i")
    raw, ancillary, flags, _address = stream.recvmsg(
        MAX_MESSAGE + 1, socket.CMSG_SPACE(2 * rights.itemsize), socket.MSG_CMSG_CLOEXEC
    )
    valid = True
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS or len(data) % rights.itemsize:
            valid = False
            continue
        rights.frombytes(data)
    try:
        if (
            not valid
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(rights) != descriptor_count
            or not raw
            or len(raw) > MAX_MESSAGE
        ):
            raise HostRestoreError("restore_helper_message_invalid")
        document = decode_json_object(raw, maximum_bytes=MAX_MESSAGE)
        if canonical_json_bytes(document, maximum_bytes=MAX_MESSAGE) != raw:
            raise HostRestoreError("restore_helper_message_noncanonical")
    except BaseException:
        for descriptor in rights:
            os.close(descriptor)
        raise
    return document, tuple(rights)


@contextmanager
def _archive_service(action: str) -> Iterator[None]:
    unit = (
        "lowerduckpond-host-restore-archive-installed.service"
        if action == "verify-installed"
        else "lowerduckpond-host-restore-archive-private.service"
    )
    # A reply precedes helper exit. Keep the blocking start job until the
    # oneshot finishes, so the next request cannot coalesce with this one.
    with subprocess.Popen(  # noqa: S603 - fixed root-owned service names
        ("/usr/bin/systemctl", "start", unit),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    ) as process:
        try:
            yield
            if process.wait(timeout=30):
                raise HostRestoreError("restore_archive_helper_start_failed")
        except subprocess.TimeoutExpired as error:
            raise HostRestoreError("restore_archive_helper_completion_deadline") from error
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


@contextmanager
def _listener(path: Path, owner: int) -> Iterator[socket.socket]:
    parent = path.parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != owner
        or parent.st_gid != owner
        or stat.S_IMODE(parent.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise HostRestoreError("restore_helper_socket_parent_unsafe")
    try:
        previous = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        # The continuously held root coordinator lease excludes any old helper.
        if (
            not stat.S_ISSOCK(previous.st_mode)
            or previous.st_uid != owner
            or previous.st_gid != owner
            or stat.S_IMODE(previous.st_mode) != PRIVATE_SOCKET_MODE
        ):
            raise HostRestoreError("restore_helper_socket_unsafe")
        path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(path))
        path.chmod(PRIVATE_SOCKET_MODE)
        listener.listen(1)
        listener.settimeout(30)
        try:
            yield listener
        finally:
            path.unlink(missing_ok=True)


def request_archive(  # noqa: PLR0913 - exact authority, action and separate held leases
    store: RestoreStore,
    selection_descriptor: int,
    artifact: str,
    action: str,
    *,
    recovery: Path,
    path: Path = SOCKET_PATH,
    selection: Path = SELECTION_LOCK,
    start: Callable[[str], AbstractContextManager[None]] = _archive_service,
) -> dict[str, object]:
    if store.lease_descriptor is None:
        raise HostRestoreError("restore_helper_coordinator_lease_missing")
    require_lease(recovery / LOCK, store.lease_descriptor, exclusive=True, owner=store.owner)
    require_lease(selection, selection_descriptor, exclusive=False, owner=store.owner)
    current = store.read()
    if current is None or action not in ACTIONS:
        raise HostRestoreError("restore_helper_request_invalid")
    allowed = (
        {RestorePhase.INSTALLED, RestorePhase.VERIFIED, RestorePhase.COMPLETE}
        if action == "verify-installed"
        else {RestorePhase.VALIDATED}
    )
    if current.phase not in allowed:
        raise HostRestoreError("restore_helper_request_phase_invalid")
    request: dict[str, object] = {
        "schema": REQUEST_SCHEMA,
        "nonce": secrets.token_hex(16),
        "action": action,
        "restoreId": current.restore_id,
        "journalDigest": current.digest,
        "artifactSha256": artifact,
    }
    with _listener(path, store.owner) as listener, start(action):
        connection, _address = listener.accept()
        with connection:
            _peer(connection, store.owner)
            connection.settimeout(300)
            send_message(connection, request, (store.lease_descriptor, selection_descriptor))
            reply, _ = receive_message(connection, descriptor_count=0)
    exact_object(reply, {"schema", "nonce", "verified", "evidence"})
    if (
        reply["schema"] != REPLY_SCHEMA
        or reply["nonce"] != request["nonce"]
        or reply["verified"] is not True
        or type(reply["evidence"]) is not dict
        or store.read() != current
    ):
        raise HostRestoreError("restore_archive_helper_unverified")
    return cast(dict[str, object], reply["evidence"])


def require_request(
    request: dict[str, object], store: RestoreStore, artifact: str, *, installed: bool
) -> str:
    exact_object(
        request, {"schema", "nonce", "action", "restoreId", "journalDigest", "artifactSha256"}
    )
    current = store.read()
    action, nonce = request["action"], request["nonce"]
    allowed = {"verify-installed"} if installed else {"verify", "cleanup"}
    phases = (
        {RestorePhase.INSTALLED, RestorePhase.VERIFIED, RestorePhase.COMPLETE}
        if installed
        else {RestorePhase.VALIDATED}
    )
    if (
        current is None
        or current.phase not in phases
        or request["schema"] != REQUEST_SCHEMA
        or type(nonce) is not str
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or type(action) is not str
        or action not in allowed
        or request["journalDigest"] != current.digest
        or request["restoreId"] != current.restore_id
        or request["artifactSha256"] != artifact
        or current.bindings["originalArtifact"]["value"] != artifact
    ):
        raise HostRestoreError("restore_helper_request_unbound")
    return action
