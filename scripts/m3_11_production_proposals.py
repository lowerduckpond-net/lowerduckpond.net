"""Keep complete proposals independently of an interrupted journal publication."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from scripts import m3_11_production_journal as journal
from scripts.m3_11_production_replica import Replica


class Proposals:
    """Caller holds the local journal lock, then the proposal directory lock."""

    def __init__(self, retained: journal.Journal, attempt: Path) -> None:
        self.retained, self.attempt = retained, attempt

    def recover(self, pair: Replica) -> list[tuple[str, bytes]]:
        records = self.retained.records()
        self.retained.sync()
        local = pair.local.records(proposal=records[-1] if records else None)
        if local != records and (not records or local != records[:-1]):
            raise ValueError("production proposals differ from the original journal")
        # Recover only the last unacknowledged proposal. An absent or
        # truncated host must not acquire a reconstructed phase history.
        current = pair.publish(*records[-1]) if records else pair.synchronize()
        if current != records:
            raise ValueError("production proposals differ from the original journal")
        return current

    def retain(
        self, name: str, raw: bytes, *, failure_hook: Callable[[str], None] = lambda _: None
    ) -> None:
        records = self.retained.records()
        if name in dict(records):
            if dict(records)[name] != raw:
                raise ValueError("production proposal changed")
            self.retained.sync()
            return
        journal.validate([*records, (name, raw)])
        directory = os.open(self.attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            journal._metadata(os.fstat(directory), self.retained.owner, 0o700, directory=True)
            temporary = name + ".proposal"
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
                dir_fd=directory,
            )
            try:
                remaining = memoryview(raw)
                while remaining:
                    size = os.write(fd, remaining)
                    if size <= 0:
                        raise OSError("production proposal short write")
                    remaining = remaining[size:]
                    failure_hook("write")
                os.fsync(fd)
                failure_hook("file-sync")
            finally:
                os.close(fd)
            self.retained._guard()
            # Before this atomic commit point, no journal publication can
            # occur. A failed staging write stays in its original attempt.
            os.rename(
                temporary,
                name + ".json",
                src_dir_fd=directory,
                dst_dir_fd=self.retained.descriptor,
            )
            failure_hook("rename")
            self.retained.sync()
            os.fsync(directory)
            failure_hook("directory-sync")
        finally:
            os.close(directory)

    def publish(self, pair: Replica, name: str, raw: bytes) -> None:
        self.recover(pair)
        self.retain(name, raw)
        pair.publish(name, raw)
