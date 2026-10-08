"""Durable ownership of short credential probes, never retirement authorization."""

from __future__ import annotations

import json
import os
import re
import stat
import uuid
from pathlib import Path


def remember_probe(  # noqa: PLR0913 - bind the attempt and both ownership targets
    prefix: str,
    *,
    path: Path,
    source_revision: str,
    run_id: str,
    region: str,
    archive_bucket: str,
    backup_bucket: str,
) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None or str(uuid.UUID(run_id)) != run_id:
        raise ValueError("probe source or attempt identity is invalid")
    info = path.parent.lstat()
    if (
        not path.is_absolute()
        or path.parent.resolve(strict=True) != path.parent
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700  # noqa: PLR2004 - private evidence
    ):
        raise ValueError("probe evidence directory is unsafe")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(
            {
                "format": "lowerduckpond-storage-probe-ownership-v1",
                "run_id": run_id,
                "source_revision": source_revision,
                "region": region,
                "archive_bucket": archive_bucket,
                "backup_bucket": backup_bucket,
                "prefix": prefix,
            },
            stream,
            sort_keys=True,
        )
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
