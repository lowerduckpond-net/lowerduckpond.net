"""Durable, invocation-fenced Caddy startup and rollback recovery."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Final, Self

from lowerduckpond_static_contracts import (
    ContractError,
    canonical_json_bytes,
    decode_json_object,
    validate_uuid7,
)

from lowerduckpond_static_host_agent.durable import DurableDirectory, StatePathError

CADDY_START_INTENT_NAME: Final = "start.json"
CADDY_START_INTENT_MODE: Final = 0o600
CADDY_START_INTENT_DIRECTORY_MODE: Final = 0o700
MAX_CADDY_START_INTENT_BYTES: Final = 16 * 1024
MAX_CADDY_START_ATTEMPTS: Final = 3
MAX_CADDY_START_INTENT_ENTRIES: Final = 16
_SCHEMA: Final = "lowerduckpond-caddy-start-intent-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
_INVOCATION_ID = re.compile(r"[0-9a-f]{32}", flags=re.ASCII)


class CaddyStartupError(RuntimeError):
    """The durable Caddy startup state is missing, stale, or unsafe."""


class CaddyStartMode(StrEnum):
    """Authority available to one bounded startup operation."""

    ORDINARY = "ordinary"
    TRANSACTIONAL = "transactional"


class CaddyStartPhase(StrEnum):
    """Durable phases admitted by the frozen Caddy bootstrap."""

    CANDIDATE_PREPARED = "candidate-prepared"
    RESTART_REQUIRED = "restart-required"
    ORDINARY_STARTING = "ordinary-starting"
    CANDIDATE_STARTING = "candidate-starting"
    ROLLBACK_RESTART_REQUIRED = "rollback-restart-required"
    RECOVERY_STARTING = "recovery-starting"


@dataclass(frozen=True, slots=True)
class CaddyStartTarget:
    """One exact manifest-verified generation selected by an intent."""

    generation_id: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        try:
            validate_uuid7(self.generation_id)
        except ContractError as error:
            raise CaddyStartupError("startup target is not a UUIDv7 generation") from error
        if _SHA256.fullmatch(self.manifest_sha256) is None:
            raise CaddyStartupError("startup target manifest digest is invalid")

    def to_dict(self) -> dict[str, str]:
        return {
            "generationId": self.generation_id,
            "manifestSha256": self.manifest_sha256,
        }


@dataclass(frozen=True, slots=True)
class CaddyStartIntent:
    """One complete bounded startup or transactional recovery operation."""

    mode: CaddyStartMode
    phase: CaddyStartPhase
    candidate: CaddyStartTarget
    previous: CaddyStartTarget | None = None
    candidate_invocations: tuple[str, ...] = ()
    recovery_invocations: tuple[str, ...] = ()
    invocation_id: str | None = None

    def __post_init__(self) -> None:
        candidate_count = len(self.candidate_invocations)
        recovery_count = len(self.recovery_invocations)
        if self.mode is CaddyStartMode.ORDINARY:
            if (
                self.previous is not None
                or self.phase is not CaddyStartPhase.ORDINARY_STARTING
                or not 1 <= candidate_count <= MAX_CADDY_START_ATTEMPTS
                or recovery_count != 0
                or self.invocation_id != self.candidate_invocations[-1]
            ):
                raise CaddyStartupError("ordinary startup has transactional authority")
        else:
            if self.previous is None or self.previous == self.candidate:
                raise CaddyStartupError("transactional startup has no distinct predecessor")
            expected_shapes: dict[
                CaddyStartPhase,
                tuple[int | range, int | range, str | None],
            ] = {
                CaddyStartPhase.CANDIDATE_PREPARED: (0, 0, None),
                CaddyStartPhase.RESTART_REQUIRED: (0, 0, None),
                CaddyStartPhase.CANDIDATE_STARTING: (
                    range(1, MAX_CADDY_START_ATTEMPTS + 1),
                    0,
                    "candidate",
                ),
                CaddyStartPhase.ROLLBACK_RESTART_REQUIRED: (
                    MAX_CADDY_START_ATTEMPTS,
                    0,
                    None,
                ),
                CaddyStartPhase.RECOVERY_STARTING: (
                    MAX_CADDY_START_ATTEMPTS,
                    range(1, MAX_CADDY_START_ATTEMPTS + 1),
                    "recovery",
                ),
            }
            expected_shape = expected_shapes.get(self.phase)
            if expected_shape is None:
                raise CaddyStartupError("transactional startup has an ordinary phase")
            expected_candidate, expected_recovery, binding = expected_shape
            if not _count_matches(candidate_count, expected_candidate):
                raise CaddyStartupError("transactional candidate attempts disagree with phase")
            if not _count_matches(recovery_count, expected_recovery):
                raise CaddyStartupError("transactional recovery attempts disagree with phase")
            expected_invocation = (
                self.candidate_invocations[-1]
                if binding == "candidate"
                else self.recovery_invocations[-1]
                if binding == "recovery"
                else None
            )
            if self.invocation_id != expected_invocation:
                raise CaddyStartupError("transactional invocation disagrees with phase")
        all_invocations = (*self.candidate_invocations, *self.recovery_invocations)
        if any(_INVOCATION_ID.fullmatch(value) is None for value in all_invocations):
            raise CaddyStartupError("startup intent contains an invalid invocation ID")
        if len(set(all_invocations)) != len(all_invocations):
            raise CaddyStartupError("startup intent reuses an invocation ID")

    @property
    def selected_target(self) -> CaddyStartTarget:
        if self.phase in {
            CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
            CaddyStartPhase.RECOVERY_STARTING,
        }:
            if self.previous is None:  # pragma: no cover - constructor proves this
                raise CaddyStartupError("recovery has no previous generation")
            return self.previous
        return self.candidate

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "candidate": self.candidate.to_dict(),
                "candidateInvocations": list(self.candidate_invocations),
                "invocationId": self.invocation_id,
                "mode": self.mode.value,
                "phase": self.phase.value,
                "previous": None if self.previous is None else self.previous.to_dict(),
                "recoveryInvocations": list(self.recovery_invocations),
                "schema": _SCHEMA,
            },
            maximum_bytes=MAX_CADDY_START_INTENT_BYTES,
        )


class CaddyStartupStore:
    """Descriptor-relative durable storage for the single startup intent."""

    def __init__(self, directory: DurableDirectory, *, owner: int) -> None:
        self._directory = directory
        self._owner = owner

    @classmethod
    def open(cls, path: Path, *, expected_owner: int) -> Self:
        return cls(
            DurableDirectory.open(
                path,
                expected_owner=expected_owner,
                expected_directory_mode=CADDY_START_INTENT_DIRECTORY_MODE,
            ),
            owner=expected_owner,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    def close(self) -> None:
        self._directory.close()

    def read(self) -> CaddyStartIntent | None:
        try:
            data = self._directory.read_regular(
                (CADDY_START_INTENT_NAME,),
                expected_owner=self._owner,
                expected_mode=CADDY_START_INTENT_MODE,
                maximum_bytes=MAX_CADDY_START_INTENT_BYTES,
            )
        except FileNotFoundError:
            return None
        return _decode_intent(data)

    def reconcile_temporaries(self) -> int:
        """Remove only bounded, safely shaped crash-left intent writes."""

        removed = self._directory.remove_abandoned_publication_temporaries(
            expected_owner=self._owner,
            expected_mode=CADDY_START_INTENT_MODE,
            maximum_entries=MAX_CADDY_START_INTENT_ENTRIES,
        )
        self._inventory_names()
        return removed

    def inventory_is_empty(self) -> bool:
        """Report whether no intent or crash-left state occupies the namespace."""

        return not self._inventory_names()

    def begin_transaction(
        self,
        *,
        candidate: CaddyStartTarget,
        previous: CaddyStartTarget,
    ) -> CaddyStartIntent:
        if self.read() is not None:
            raise CaddyStartupError("another Caddy startup intent is active")
        intent = CaddyStartIntent(
            mode=CaddyStartMode.TRANSACTIONAL,
            phase=CaddyStartPhase.CANDIDATE_PREPARED,
            candidate=candidate,
            previous=previous,
        )
        self._write(intent)
        return intent

    def mark_restart_required(self, intent: CaddyStartIntent) -> CaddyStartIntent:
        current = self._require_current(intent)
        if current.phase is not CaddyStartPhase.CANDIDATE_PREPARED:
            raise CaddyStartupError("candidate is not awaiting selection")
        updated = replace(current, phase=CaddyStartPhase.RESTART_REQUIRED)
        self._write(updated)
        return updated

    def prepare_start(
        self,
        *,
        active: CaddyStartTarget,
        invocation_id: str,
    ) -> CaddyStartIntent:
        _require_invocation(invocation_id)
        current = self.read()
        if current is None:
            current = CaddyStartIntent(
                mode=CaddyStartMode.ORDINARY,
                phase=CaddyStartPhase.ORDINARY_STARTING,
                candidate=active,
                candidate_invocations=(invocation_id,),
                invocation_id=invocation_id,
            )
        elif current.selected_target != active:
            raise CaddyStartupError("active generation disagrees with startup intent")
        elif current.phase in {
            CaddyStartPhase.RESTART_REQUIRED,
            CaddyStartPhase.CANDIDATE_STARTING,
            CaddyStartPhase.ORDINARY_STARTING,
        }:
            if len(current.candidate_invocations) >= MAX_CADDY_START_ATTEMPTS:
                raise CaddyStartupError("candidate startup attempts are exhausted")
            phase = (
                CaddyStartPhase.ORDINARY_STARTING
                if current.mode is CaddyStartMode.ORDINARY
                else CaddyStartPhase.CANDIDATE_STARTING
            )
            current = replace(
                current,
                phase=phase,
                candidate_invocations=(*current.candidate_invocations, invocation_id),
                invocation_id=invocation_id,
            )
        elif current.phase in {
            CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
            CaddyStartPhase.RECOVERY_STARTING,
        }:
            if len(current.recovery_invocations) >= MAX_CADDY_START_ATTEMPTS:
                raise CaddyStartupError("recovery startup attempts are exhausted")
            current = replace(
                current,
                phase=CaddyStartPhase.RECOVERY_STARTING,
                recovery_invocations=(*current.recovery_invocations, invocation_id),
                invocation_id=invocation_id,
            )
        else:  # pragma: no cover - every enum member is handled above
            raise CaddyStartupError("startup intent phase is not recognized")
        self._write(current)
        return current

    def require_matching_success(
        self,
        *,
        active: CaddyStartTarget,
        invocation_id: str,
    ) -> CaddyStartIntent:
        current = self.read()
        if (
            current is None
            or current.invocation_id != invocation_id
            or current.selected_target != active
            or current.phase
            not in {
                CaddyStartPhase.ORDINARY_STARTING,
                CaddyStartPhase.CANDIDATE_STARTING,
                CaddyStartPhase.RECOVERY_STARTING,
            }
        ):
            raise CaddyStartupError("post-start callback is stale or mismatched")
        return current

    def commit_success(self, intent: CaddyStartIntent) -> None:
        self._require_current(intent)
        self._directory.remove((CADDY_START_INTENT_NAME,))

    def require_rollback_target(self) -> CaddyStartIntent | None:
        current = self.read()
        if current is None:
            return None
        if current.mode is CaddyStartMode.ORDINARY:
            return None
        if current.phase is CaddyStartPhase.ROLLBACK_RESTART_REQUIRED:
            return current
        if current.phase is CaddyStartPhase.RECOVERY_STARTING:
            return None
        if current.phase is CaddyStartPhase.CANDIDATE_STARTING:
            return (
                current if len(current.candidate_invocations) == MAX_CADDY_START_ATTEMPTS else None
            )
        if current.phase in {
            CaddyStartPhase.CANDIDATE_PREPARED,
            CaddyStartPhase.RESTART_REQUIRED,
        }:
            return None
        raise CaddyStartupError("candidate failure is not eligible for rollback")

    def clear_exhausted_ordinary_start(self) -> bool:
        """Release only an ordinary intent after its bounded retry cycle."""

        current = self.read()
        if current is None or current.mode is not CaddyStartMode.ORDINARY:
            return False
        if (
            current.phase is not CaddyStartPhase.ORDINARY_STARTING
            or len(current.candidate_invocations) != MAX_CADDY_START_ATTEMPTS
        ):
            return False
        self._directory.remove((CADDY_START_INTENT_NAME,))
        return True

    def mark_rollback_restart_required(
        self,
        intent: CaddyStartIntent,
    ) -> CaddyStartIntent:
        current = self._require_current(intent)
        if current.phase is CaddyStartPhase.ROLLBACK_RESTART_REQUIRED:
            return current
        if (
            current.phase is not CaddyStartPhase.CANDIDATE_STARTING
            or len(current.candidate_invocations) != MAX_CADDY_START_ATTEMPTS
        ):
            raise CaddyStartupError("candidate failure is not eligible for rollback")
        updated = replace(
            current,
            phase=CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
            invocation_id=None,
        )
        self._write(updated)
        return updated

    def _inventory_names(self) -> tuple[str, ...]:
        descriptor = self._directory.duplicate_descriptor()
        try:
            with os.scandir(descriptor) as iterator:
                names = tuple(sorted(entry.name for entry in iterator))
            if len(names) > MAX_CADDY_START_INTENT_ENTRIES:
                raise CaddyStartupError("startup intent namespace exceeds its bound")
            for name in names:
                if name != CADDY_START_INTENT_NAME:
                    if name.startswith(".ldp-state-"):
                        return names
                    raise CaddyStartupError("startup intent namespace is not recognized")
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != self._owner
                    or stat.S_IMODE(metadata.st_mode) != CADDY_START_INTENT_MODE
                    or metadata.st_nlink != 1
                    or not 0 < metadata.st_size <= MAX_CADDY_START_INTENT_BYTES
                ):
                    raise CaddyStartupError("startup intent inode is unsafe")
            if CADDY_START_INTENT_NAME in names:
                self.read()
            return names
        finally:
            os.close(descriptor)

    def _require_current(self, expected: CaddyStartIntent) -> CaddyStartIntent:
        current = self.read()
        if current != expected:
            raise CaddyStartupError("Caddy startup intent changed during transition")
        return current

    def _write(self, intent: CaddyStartIntent) -> None:
        self._directory.replace(
            (CADDY_START_INTENT_NAME,),
            intent.to_bytes(),
            mode=CADDY_START_INTENT_MODE,
        )


def start_target(generation_id: str, manifest_bytes: bytes) -> CaddyStartTarget:
    """Bind one generation ID to the exact verified manifest bytes."""

    return CaddyStartTarget(generation_id, hashlib.sha256(manifest_bytes).hexdigest())


def _require_invocation(invocation_id: str) -> None:
    if _INVOCATION_ID.fullmatch(invocation_id) is None:
        raise CaddyStartupError("systemd invocation ID is invalid")


def _count_matches(value: int, expected: int | range) -> bool:
    return value in expected if isinstance(expected, range) else value == expected


def _decode_intent(data: bytes) -> CaddyStartIntent:
    try:
        document = decode_json_object(data, maximum_bytes=MAX_CADDY_START_INTENT_BYTES)
        if canonical_json_bytes(document) != data:
            raise CaddyStartupError("Caddy startup intent is not canonical")
        if (
            set(document)
            != {
                "candidate",
                "candidateInvocations",
                "invocationId",
                "mode",
                "phase",
                "previous",
                "recoveryInvocations",
                "schema",
            }
            or document["schema"] != _SCHEMA
        ):
            raise CaddyStartupError("Caddy startup intent schema is not recognized")
        mode = document["mode"]
        phase = document["phase"]
        invocation_id = document["invocationId"]
        if (
            type(mode) is not str
            or type(phase) is not str
            or (invocation_id is not None and type(invocation_id) is not str)
        ):
            raise CaddyStartupError("Caddy startup intent fields are invalid")
        return CaddyStartIntent(
            mode=CaddyStartMode(mode),
            phase=CaddyStartPhase(phase),
            candidate=_decode_target(document["candidate"]),
            previous=(
                None if document["previous"] is None else _decode_target(document["previous"])
            ),
            candidate_invocations=_decode_invocations(document["candidateInvocations"]),
            recovery_invocations=_decode_invocations(document["recoveryInvocations"]),
            invocation_id=invocation_id,
        )
    except (ContractError, KeyError, TypeError, ValueError, StatePathError) as error:
        if isinstance(error, CaddyStartupError):
            raise
        raise CaddyStartupError("Caddy startup intent is invalid") from error


def _decode_target(value: object) -> CaddyStartTarget:
    if type(value) is not dict or set(value) != {"generationId", "manifestSha256"}:
        raise CaddyStartupError("startup target has unexpected members")
    generation_id = value["generationId"]
    digest = value["manifestSha256"]
    if type(generation_id) is not str or type(digest) is not str:
        raise CaddyStartupError("startup target fields are invalid")
    return CaddyStartTarget(generation_id, digest)


def _decode_invocations(value: object) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise CaddyStartupError("startup invocation evidence is invalid")
    return tuple(value)
