"""Retain a proposal locally before sending its exact bytes through the lease."""

from __future__ import annotations

from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_records as wire
from scripts.m3_11_production_session import Session


class Replica:
    """One locked local journal paired with one live remote controller session."""

    def __init__(self, local: journal.Journal, session: Session) -> None:
        self.local, self.session = local, session

    def synchronize(self) -> list[tuple[str, bytes]]:
        return self._synchronize()

    def _synchronize(self, proposal: tuple[str, bytes] | None = None) -> list[tuple[str, bytes]]:
        records = self.local.records(proposal=proposal)
        # A prior process may have died after rename but before directory fsync.
        # Confirm local durability before transmitting any visible record.
        self.local.sync()
        arguments = [
            "/usr/bin/python3",
            "-I",
            "-B",
            self.session.helper,
            "journal",
            self.session.token,
        ]
        raw = b""
        if records:
            # At most the last proposal can lack acknowledgement. Replaying
            # earlier phases into an empty/truncated host would invent history.
            name, raw = records[-1]
            arguments.extend(("publish", name))
        else:
            arguments.append("read")
        result = self.session.run("journal-sync", arguments, data=raw)
        if result.status:
            raise ValueError("production journal synchronization failed")
        if wire.decode(result.read(wire.MAX_WIRE_BYTES)) != records:
            raise ValueError("production journal differs from retained local proposals")
        return records

    def publish(self, name: str, raw: bytes) -> list[tuple[str, bytes]]:
        self._synchronize((name, raw))
        # Local file + directory fsync completes before sending the proposal.
        # On any subsequent failure, resume these bytes and original timestamps.
        self.local.publish(name, raw)
        return self.synchronize()
