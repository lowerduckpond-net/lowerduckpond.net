"""Controller view of the dynamically loaded installed fixture helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from testinfra.host import Host  # type: ignore[import-untyped]

from scripts.m3_11_live_storage import LiveStorage


class Fixture(Protocol):
    environment: dict[str, str]
    live_storage: LiveStorage
    root: Path
    inputs: Path
    ephemeral: Path
    transport: Path
    target: dict[str, object]
    restore_id: str
    snapshot: str
    binary: str
    fence: bytes
    source_id: str
    destination_id: str
    acme_id: str
    source: Host
    destination: Host
    acme: Host

    def status(self) -> dict[str, object]: ...
    def start(self) -> None: ...
    def wait(self, phases: set[str], *, seconds: int | None = None) -> dict[str, object]: ...
    def fault(self, fault: str) -> None: ...
    def reboot(self) -> None: ...
    def command(self, *args: str, timeout: int = 60, stdin: bytes = b"") -> bytes: ...
