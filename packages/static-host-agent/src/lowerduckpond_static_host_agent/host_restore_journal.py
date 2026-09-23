"""Root-owned, bounded provenance outside the roots a host restore replaces."""

from __future__ import annotations

import fcntl
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Final, cast

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.backup_identity import framed_digest, require_digest
from lowerduckpond_static_host_agent.durable import DurableDirectory, FailureHook

RESTORE_SCHEMA: Final = "lowerduckpond-host-restore-v1"
MAX_RESTORE_BYTES: Final = 256 * 1024
JOURNAL: Final = ("host-restore.json",)
GATE: Final = ("restore-gate.json",)
LOCK: Final = "host-restore.lock"
_HEX: Final = re.compile(r"[0-9a-f]{64}", re.ASCII)


class HostRestoreError(RuntimeError):
    """Recovery evidence is incomplete; public service must remain gated."""


class RestorePhase(StrEnum):
    PREPARED = "prepared"
    RESTORED = "restored"
    VALIDATED = "validated"
    RECONCILED = "reconciled"
    RUNTIME_PREPARED = "runtime-prepared"
    INSTALLED = "installed"
    VERIFIED = "verified"
    COMPLETE = "complete"


PHASES: Final = tuple(RestorePhase)
_BINDINGS: Final = {
    "backupDescriptor": "lowerduckpond-static-backup-v1",
    "repository": "lowerduckpond-backup-repository-binding-v1",
    "originalArtifact": "lowerduckpond-static-host-agent-artifact-v1",
    "trustedInputs": "lowerduckpond-host-restore-inputs-v1",
    "destination": "lowerduckpond-host-restore-destination-v1",
    "sourceFence": "lowerduckpond-host-restore-source-fence-v1",
}


def exact_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise HostRestoreError("restore object has unexpected members")
    return value


def full_id(value: object) -> str:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise HostRestoreError("restore requires a complete snapshot identity")
    return value


def receipt_format(phase: RestorePhase) -> str:
    return f"lowerduckpond-host-restore-{phase.value}-v1"


@dataclass(frozen=True)
class RestoreJournal:
    restore_id: str
    snapshot_id: str
    capture_id: str
    lineage_id: str
    bindings: dict[str, dict[str, str]]
    phase: RestorePhase = RestorePhase.PREPARED
    receipts: tuple[dict[str, str], ...] = ()
    previous: dict[str, str] | None = None

    def to_bytes(self) -> bytes:
        validate_uuid7(self.restore_id)
        full_id(self.snapshot_id)
        validate_uuid7(self.capture_id)
        validate_uuid7(self.lineage_id)
        exact_object(self.bindings, set(_BINDINGS))
        for name, format_identifier in _BINDINGS.items():
            require_digest(self.bindings[name], format_identifier)
        index = PHASES.index(self.phase)
        if len(self.receipts) != index:
            raise HostRestoreError("restore phase lacks complete receipt history")
        for phase, receipt in zip(PHASES[1 : index + 1], self.receipts, strict=True):
            require_digest(receipt, receipt_format(phase))
        if index == 0:
            if self.previous is not None:
                raise HostRestoreError("initial restore has a predecessor")
        else:
            require_digest(self.previous, RESTORE_SCHEMA)
        return canonical_json_bytes(
            {
                "schema": RESTORE_SCHEMA,
                "restoreId": self.restore_id,
                "snapshotId": self.snapshot_id,
                "captureId": self.capture_id,
                "lineageId": self.lineage_id,
                "bindings": self.bindings,
                "phase": self.phase.value,
                "receipts": list(self.receipts),
                "previousJournalDigest": self.previous,
            },
            maximum_bytes=MAX_RESTORE_BYTES,
        )

    @property
    def digest(self) -> dict[str, str]:
        return framed_digest(RESTORE_SCHEMA, self.to_bytes())

    @classmethod
    def from_bytes(cls, raw: bytes) -> RestoreJournal:
        value = exact_object(
            decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES),
            {
                "schema",
                "restoreId",
                "snapshotId",
                "captureId",
                "lineageId",
                "bindings",
                "phase",
                "receipts",
                "previousJournalDigest",
            },
        )
        if value["schema"] != RESTORE_SCHEMA or type(value["receipts"]) is not list:
            raise HostRestoreError("restore journal schema is unsupported")
        if type(value["phase"]) is not str:
            raise HostRestoreError("restore journal phase is invalid")
        result = cls(
            validate_uuid7(value["restoreId"]),
            full_id(value["snapshotId"]),
            validate_uuid7(value["captureId"]),
            validate_uuid7(value["lineageId"]),
            cast(dict[str, dict[str, str]], value["bindings"]),
            RestorePhase(value["phase"]),
            tuple(value["receipts"]),
            cast(dict[str, str] | None, value["previousJournalDigest"]),
        )
        if result.to_bytes() != raw:
            raise HostRestoreError("restore journal is not canonical")
        return result


class RestoreStore:
    """The coordinator lease protects every journal CAS and root installation.

    The lease and gate are never restored from a snapshot. A caller cannot
    advance a phase by writing a journal without its immutable receipt.
    """

    def __init__(
        self, directory: DurableDirectory, owner: int, *, lease_descriptor: int | None = None
    ) -> None:
        self.directory = directory
        self.owner = owner
        self.lease_descriptor = lease_descriptor

    @classmethod
    @contextmanager
    def locked(cls, root: Path, *, owner: int = 0) -> Iterator[RestoreStore]:
        with DurableDirectory.open(
            root, expected_owner=owner, expected_directory_mode=0o700
        ) as directory:
            parent = directory.duplicate_descriptor()
            descriptor = -1
            try:
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                try:
                    descriptor = os.open(LOCK, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent)
                    os.fsync(descriptor)
                    os.fsync(parent)
                except FileExistsError:
                    descriptor = os.open(LOCK, flags, dir_fd=parent)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or stat.S_IMODE(opened.st_mode) != 0o600  # noqa: PLR2004 - fixed private lease
                    or opened.st_uid != owner
                    or opened.st_nlink != 1
                    or opened.st_size != 0
                ):
                    raise HostRestoreError("restore coordinator lease is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                named = os.stat(LOCK, dir_fd=parent, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise HostRestoreError("restore coordinator lease changed")
                yield cls(directory, owner, lease_descriptor=descriptor)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent)

    def read_bytes(self, name: str) -> bytes:
        return self.directory.read_regular(
            (name,),
            expected_owner=self.owner,
            expected_mode=0o600,
            maximum_bytes=MAX_RESTORE_BYTES,
        )

    def read(self) -> RestoreJournal | None:
        try:
            raw = self.read_bytes(JOURNAL[0])
        except FileNotFoundError:
            return None
        journal = RestoreJournal.from_bytes(raw)
        predecessor: RestoreJournal | None = None
        for phase in PHASES[: PHASES.index(journal.phase) + 1]:
            historical = RestoreJournal.from_bytes(self.read_bytes(f"journal-{phase.value}.json"))
            if historical.phase is not phase:
                raise HostRestoreError("restore journal history has the wrong phase")
            if predecessor is not None and historical != replace(
                predecessor,
                phase=phase,
                receipts=journal.receipts[: PHASES.index(phase)],
                previous=predecessor.digest,
            ):
                raise HostRestoreError("restore journal history is discontinuous")
            predecessor = historical
        if predecessor != journal:
            raise HostRestoreError("restore journal differs from its immutable history")
        for phase, digest in zip(PHASES[1:], journal.receipts, strict=False):
            raw = self.read_bytes(phase.value + ".json")
            document = decode_json_object(raw, maximum_bytes=MAX_RESTORE_BYTES)
            if canonical_json_bytes(document, maximum_bytes=MAX_RESTORE_BYTES) != raw:
                raise HostRestoreError("restore receipt is not canonical")
            if framed_digest(receipt_format(phase), raw) != digest:
                raise HostRestoreError("restore receipt does not match its journal")
        return journal

    def immutable(self, name: str, raw: bytes, *, failure_hook: FailureHook | None = None) -> None:
        if len(raw) > MAX_RESTORE_BYTES:
            raise HostRestoreError("restore evidence exceeds its bound")
        try:
            existing = self.read_bytes(name)
        except FileNotFoundError:
            self.directory.create_immutable((name,), raw, mode=0o600, failure_hook=failure_hook)
        else:
            if existing != raw:
                raise HostRestoreError("restore immutable evidence conflicts")

    def begin(self, journal: RestoreJournal, *, failure_hook: FailureHook | None = None) -> None:
        if journal.phase is not RestorePhase.PREPARED:
            raise HostRestoreError("restore must begin at prepared")
        self.immutable("journal-prepared.json", journal.to_bytes(), failure_hook=failure_hook)
        self.immutable(JOURNAL[0], journal.to_bytes(), failure_hook=failure_hook)

    def advance(
        self,
        previous: RestoreJournal,
        phase: RestorePhase,
        receipt: dict[str, object],
        *,
        failure_hook: FailureHook | None = None,
    ) -> RestoreJournal:
        if self.read() != previous or PHASES.index(phase) != PHASES.index(previous.phase) + 1:
            raise HostRestoreError("restore journal compare-and-swap refused")
        raw = canonical_json_bytes(receipt, maximum_bytes=MAX_RESTORE_BYTES)
        self.immutable(phase.value + ".json", raw, failure_hook=failure_hook)
        current = replace(
            previous,
            phase=phase,
            receipts=(*previous.receipts, framed_digest(receipt_format(phase), raw)),
            previous=previous.digest,
        )
        self.immutable(f"journal-{phase.value}.json", current.to_bytes(), failure_hook=failure_hook)
        self.directory.replace(JOURNAL, current.to_bytes(), mode=0o600, failure_hook=failure_hook)
        return current
