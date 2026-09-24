"""Read-only fingerprints of public dependencies on a fresh owned Ubuntu fixture."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

FILES = {
    "roots.pem": "/etc/ssl/certs/ca-certificates.crt",
    "hosts": "/etc/hosts",
    "resolv.conf": "/etc/resolv.conf",
}
MAXIMUM_BYTES = 1024 * 1024
CHUNK_BYTES = 32 * 1024


def require_fresh() -> None:
    # The wrapper calls this after create, before prepare or converge. A source
    # that already contains either qualification or runtime inputs is too late.
    if any(
        os.path.lexists(path)
        for path in (
            "/etc/caddy",
            "/etc/lowerduckpond",
            "/var/lib/lowerduckpond-m3-8-disks",
            "/root/restore-acme",
        )
    ) or any(Path("/usr/local/share/ca-certificates").iterdir()):
        raise ValueError("public trust must be captured before fixture preparation")


def read(name: str) -> tuple[dict[str, object], bytes]:
    require_fresh()
    descriptor = os.open(FILES[name], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & 0o022
            or not 0 < before.st_size <= MAXIMUM_BYTES
        ):
            raise ValueError("public dependency inputs have unsafe metadata")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAXIMUM_BYTES + 1)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if (
            identity
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(raw) != before.st_size
        ):
            raise ValueError("public dependency inputs changed during capture")
        return {"sha256": hashlib.sha256(raw).hexdigest(), "identity": identity}, raw
    finally:
        os.close(descriptor)


def observe() -> dict[str, object]:
    return {name: read(name)[0] for name in FILES}


def chunk(name: str, offset: int) -> dict[str, object]:
    fingerprint, raw = read(name)
    if not 0 <= offset < len(raw) or offset % CHUNK_BYTES:
        raise ValueError("public dependency chunk is outside its fixed boundary")
    return {
        "fingerprint": fingerprint,
        "content": base64.b64encode(raw[offset : offset + CHUNK_BYTES]).decode("ascii"),
    }


if __name__ == "__main__":
    value = observe() if len(sys.argv) == 1 else chunk(sys.argv[1], int(sys.argv[2]))
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
