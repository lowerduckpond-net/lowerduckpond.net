"""Private root-owned state reads; sent only to an already bound disposable host."""

from __future__ import annotations

import json
import os
import re
import signal
import stat
import sys

MAXIMUM = 1024 * 1024
IMAGES = {
    "/var/lib/lowerduckpond-m3-8-disks/state.ext4",
    "/root/restore-disks/var-lib.ext4",
}


def main() -> None:  # noqa: PLR0912 - standalone bounded root probe
    signal.alarm(15)
    action, path = sys.argv[1:]
    image = action == "image" and path in IMAGES
    if not image and (
        action not in {"read", "names"} or not path.startswith("/var/lib/lowerduckpond/")
    ):
        raise ValueError("invalid state observation")
    parts = path.split("/")[1:]
    if any(re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None or part in {".", ".."} for part in parts):
        raise ValueError("unsafe state observation path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    private_ancestor = False
    try:
        for index, part in enumerate(parts):
            child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            os.close(fd)
            fd = child
            value = os.fstat(fd)
            if (
                value.st_uid != 0
                or (value.st_mode & 0o022 and not (image and index == len(parts) - 1))
                or (index < len(parts) - 1 and not stat.S_ISDIR(value.st_mode))
            ):
                raise ValueError("unsafe state observation inode")
            if index < len(parts) - 1 and not value.st_mode & 0o077:
                private_ancestor = True
        if image:
            if (
                not private_ancestor
                or not stat.S_ISREG(value.st_mode)
                or value.st_nlink != 1
                or value.st_size != 8 * 1024 * 1024 * 1024
            ):
                raise ValueError("unsafe state backing image")
            print(
                json.dumps(
                    {
                        "size": value.st_size,
                        "uid": value.st_uid,
                        "mode": stat.S_IMODE(value.st_mode),
                        "links": value.st_nlink,
                        "device": value.st_dev,
                        "inode": value.st_ino,
                    }
                )
            )
        elif action == "read":
            if (
                not stat.S_ISREG(value.st_mode)
                or value.st_nlink != 1
                or not 0 < value.st_size <= MAXIMUM
            ):
                raise ValueError("unsafe state record")
            with os.fdopen(os.dup(fd), "rb") as stream:
                raw = stream.read(MAXIMUM + 1)
            current = os.fstat(fd)
            if len(raw) != value.st_size or (
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            ) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns):
                raise ValueError("state record changed")
            sys.stdout.buffer.write(raw)
        else:
            if not stat.S_ISDIR(value.st_mode):
                raise ValueError("state inventory is not a directory")
            result: dict[str, str] = {}
            with os.scandir(fd) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    if metadata.st_uid != 0 or metadata.st_mode & 0o022 or len(result) >= 10000:  # noqa: PLR2004
                        raise ValueError("unsafe state inventory")
                    result[entry.name] = (
                        "directory"
                        if stat.S_ISDIR(metadata.st_mode)
                        else "regular"
                        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                        else "unsafe"
                    )
            encoded = json.dumps(result).encode()
            if len(encoded) > MAXIMUM:
                raise ValueError("state inventory exceeds its bound")
            sys.stdout.buffer.write(encoded)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
