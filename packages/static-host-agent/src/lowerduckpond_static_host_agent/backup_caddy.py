"""Nonmutating capture of Caddy selection and startup recovery authority."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import canonical_json_bytes, decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError, require_digest
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_ROUTE_STATE_DIGEST_FORMAT,
    CaddyGenerationStore,
)
from lowerduckpond_static_host_agent.caddy_runtime import (
    CADDY_ACTIVE_REFERENCE_MODE,
    CADDY_ACTIVE_REFERENCE_NAME,
    CADDY_RUNTIME_ROOT_MODE,
)
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartIntent,
    CaddyStartTarget,
    CaddyStartupStore,
    decode_caddy_start_intent,
    start_target,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName

# This names the EXISTING raw SHA-256 of manifest bytes used by CaddyStartTarget.
# It is not the new M3.11 domain-framed H; changing it would break intent authority.
MANIFEST_DIGEST_FORMAT: Final = "lowerduckpond-caddy-start-target-v1"
_REFERENCE_BYTES: Final = 37
MAX_CADDY_EVIDENCE_BYTES: Final = 24 * 1024
MAX_CADDY_EVIDENCE_GENERATIONS: Final = 2


@dataclass(frozen=True)
class CaddyGenerationEvidence:
    target: CaddyStartTarget
    route_state_digest: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "generationId": self.target.generation_id,
            "manifestDigest": {
                "format": MANIFEST_DIGEST_FORMAT,
                "algorithm": "sha256",
                "value": self.target.manifest_sha256,
            },
            "routeStateDigest": self.route_state_digest,
        }


@dataclass(frozen=True)
class CaddyBackupEvidence:
    active: str
    intent: CaddyStartIntent | None
    generations: tuple[CaddyGenerationEvidence, ...]

    def __post_init__(self) -> None:
        validate_uuid7(self.active)
        targets = {item.target.generation_id: item.target for item in self.generations}
        if tuple(sorted(targets)) != tuple(item.target.generation_id for item in self.generations):
            raise BackupIdentityError("Caddy backup generation inventory is not canonical")
        required = {self.active}
        if self.intent is not None:
            references = (self.intent.candidate, self.intent.previous)
            for target in references:
                if target is not None:
                    required.add(target.generation_id)
                    if targets.get(target.generation_id) != target:
                        raise BackupIdentityError("Caddy startup target disagrees with manifest")
            if self.active not in {
                target.generation_id for target in references if target is not None
            }:
                raise BackupIdentityError("Caddy active generation is outside startup authority")
        if set(targets) != required:
            raise BackupIdentityError("Caddy backup generation inventory is incomplete")
        for item in self.generations:
            require_digest(item.route_state_digest, CADDY_ROUTE_STATE_DIGEST_FORMAT)

    @property
    def selected_target(self) -> CaddyStartTarget:
        if self.intent is not None:
            return self.intent.selected_target
        return next(
            item.target for item in self.generations if item.target.generation_id == self.active
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "active": self.active,
            "startIntent": None
            if self.intent is None
            else decode_json_object(self.intent.to_bytes()),
            "generations": [item.to_dict() for item in self.generations],
            "selectedTarget": self.selected_target.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> CaddyBackupEvidence:
        if type(value) is not dict or set(value) != {
            "active",
            "startIntent",
            "generations",
            "selectedTarget",
        }:
            raise BackupIdentityError("Caddy backup evidence schema is invalid")
        canonical_json_bytes(value, maximum_bytes=MAX_CADDY_EVIDENCE_BYTES)
        active, rows = value["active"], value["generations"]
        if (
            type(active) is not str
            or type(rows) is not list
            or not 1 <= len(rows) <= MAX_CADDY_EVIDENCE_GENERATIONS
        ):
            raise BackupIdentityError("Caddy backup generation inventory is invalid")
        generations: list[CaddyGenerationEvidence] = []
        for row in rows:
            if (
                type(row) is not dict
                or set(row) != {"generationId", "manifestDigest", "routeStateDigest"}
                or type(row["generationId"]) is not str
            ):
                raise BackupIdentityError("Caddy backup generation evidence is invalid")
            manifest = require_digest(row["manifestDigest"], MANIFEST_DIGEST_FORMAT)
            generations.append(
                CaddyGenerationEvidence(
                    CaddyStartTarget(row["generationId"], manifest["value"]),
                    require_digest(row["routeStateDigest"], CADDY_ROUTE_STATE_DIGEST_FORMAT),
                )
            )
        result = cls(
            active,
            None
            if value["startIntent"] is None
            else decode_caddy_start_intent(canonical_json_bytes(value["startIntent"])),
            tuple(generations),
        )
        if value["selectedTarget"] != result.selected_target.to_dict():
            raise BackupIdentityError("Caddy backup selected target is inconsistent")
        return result


def capture_caddy_evidence(
    root: Path,
    *,
    locks: LockManager,
    expected_owner: int,
    expected_group: int,
) -> CaddyBackupEvidence:
    """Verify payloads but retain only IDs/digests and exact non-secret intent.

    The shared publication lease also excludes Ansible's generation selection.
    No cleanup, startup, configuration adaptation, or attempt refund occurs here.
    """

    locks.require_held(LockName.PUBLICATION, mode=LockMode.SHARED)
    with DurableDirectory.open(
        root,
        expected_owner=expected_owner,
        expected_directory_mode=CADDY_RUNTIME_ROOT_MODE,
    ) as directory:
        descriptor = directory.duplicate_descriptor()
        try:
            if (
                os.fstat(descriptor).st_gid != expected_group
                or os.stat(
                    CADDY_ACTIVE_REFERENCE_NAME,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                ).st_gid
                != expected_group
            ):
                raise BackupIdentityError("Caddy selection group is unsafe")
        finally:
            os.close(descriptor)
        raw = directory.read_regular(
            (CADDY_ACTIVE_REFERENCE_NAME,),
            expected_owner=expected_owner,
            expected_mode=CADDY_ACTIVE_REFERENCE_MODE,
            maximum_bytes=_REFERENCE_BYTES,
        )
        if len(raw) != _REFERENCE_BYTES or not raw.endswith(b"\n"):
            raise BackupIdentityError("Caddy active generation reference is malformed")
        active = raw[:-1].decode("ascii")
        validate_uuid7(active)
    with CaddyStartupStore.open(root / "intents", expected_owner=expected_owner) as startup:
        intent = startup.read_for_backup()
    required = {active}
    if intent is not None:
        required.add(intent.candidate.generation_id)
        if intent.previous is not None:
            required.add(intent.previous.generation_id)
    generations: list[CaddyGenerationEvidence] = []
    with CaddyGenerationStore.open(
        root / "generations",
        expected_owner=expected_owner,
        expected_group=expected_group,
    ) as store:
        for generation_id in sorted(required):
            with store.open_verified(generation_id) as pinned:
                generations.append(
                    CaddyGenerationEvidence(
                        start_target(generation_id, pinned.manifest.to_bytes()),
                        pinned.manifest.route_state_digest.to_dict(),
                    )
                )
    return CaddyBackupEvidence(active, intent, tuple(generations))
