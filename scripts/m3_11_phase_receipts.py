"""Original ordered observations from the fixed combined installed assertions.

This does not package a passing report. The controller additionally requires
exact pytest completion, all final proofs and owned teardown before packaging.
"""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_private_inputs import read_private, write_private

FORMAT = "lowerduckpond-m3-11-private-phase-v1"


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class Recorder:
    """One attempt; failed assertions/writes can never be retried into success."""

    def __init__(self, directory: Path, context: dict[str, object]) -> None:
        self.directory = directory
        self.context_raw = evidence.canonical_bytes(context)
        self.context_sha256 = hashlib.sha256(self.context_raw).hexdigest()
        self.previous = evidence.timestamp(
            context["captured_at"], now=_now(), maximum_age=timedelta(hours=24)
        )
        self._require_context()
        self.destination = directory / "combined-phases"
        self.destination.mkdir(mode=0o700)
        self._receipts: dict[str, dict[str, object]] = {}
        self._failed = False
        self._running = False

    def _require_context(self) -> None:
        if (
            evidence.canonical_bytes(read_private(self.directory / "combined-context.json"))
            != self.context_raw
        ):
            raise ValueError("combined phase context differs from the original capture")

    @contextmanager
    def phase(self, name: str) -> Iterator[dict[str, object]]:
        names = tuple(evidence.PHASE_CHECKS)
        if (
            self._failed
            or self._running
            or len(self._receipts) >= len(names)
            or name != names[len(self._receipts)]
        ):
            raise ValueError("combined phases require one ordered, uninterrupted attempt")
        self._failed = True
        self._running = True
        self._require_context()
        started = _now()
        if started < self.previous:
            raise ValueError("combined phase clock moved backwards")
        opening: dict[str, object] = {
            "format": FORMAT,
            "context_sha256": self.context_sha256,
            "phase": name,
            "started_at": _timestamp(started),
        }
        write_private(self.destination / f"{name}.started.json", opening)
        details: dict[str, object] = {}
        try:
            yield details
            self._require_context()
            completed = _now()
            if not details or completed < started:
                raise ValueError("combined phase omitted its observations or changed time")
            document: dict[str, object] = {
                **opening,
                "completed_at": _timestamp(completed),
                "observations": details,
            }
            write_private(self.destination / f"{name}.json", document)
            self._receipts[name] = {
                "started_at": _timestamp(started),
                "completed_at": _timestamp(completed),
                "evidence_sha256": hashlib.sha256(evidence.canonical_bytes(document)).hexdigest(),
                "checks": dict.fromkeys(evidence.PHASE_CHECKS[name], "passed"),
            }
            self.previous = completed
            self._failed = False
        finally:
            self._running = False

    def receipts(self) -> dict[str, dict[str, object]]:
        self._require_context()
        if self._failed or self._running or len(self._receipts) != len(evidence.PHASE_CHECKS):
            raise ValueError("combined phases are incomplete or failed")
        for name, receipt in self._receipts.items():
            raw = evidence.canonical_bytes(read_private(self.destination / f"{name}.json"))
            if hashlib.sha256(raw).hexdigest() != receipt["evidence_sha256"]:
                raise ValueError("combined phase original observations changed")
        return copy.deepcopy(self._receipts)
