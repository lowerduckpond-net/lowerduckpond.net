from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import ContractError, canonical_json_bytes
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence, capture_caddy_evidence
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_ROUTE_METADATA_SCHEMA,
    CaddyBinarySource,
    CaddyGenerationError,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    caddy_route_state_digest,
)
from lowerduckpond_static_host_agent.caddy_startup import (
    CaddyStartIntent,
    CaddyStartMode,
    CaddyStartPhase,
    CaddyStartTarget,
    CaddyStartupError,
    start_target,
)
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, LockOrderError

A = "0198d17f-6f4a-7000-8000-000000000001"
B = "0198d17f-6f4a-7000-8000-000000000002"
C = "0198d17f-6f4a-7000-8000-000000000003"
INVOCATIONS = tuple(f"{value:032x}" for value in range(1, 7))


@dataclass
class Fixture:
    root: Path
    locks: Path
    targets: dict[str, CaddyStartTarget]

    def capture(self) -> CaddyBackupEvidence:
        with (
            LockManager(self.locks, expected_owner=os.geteuid()) as locks,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
        ):
            return capture_caddy_evidence(
                self.root,
                locks=locks,
                expected_owner=os.geteuid(),
                expected_group=os.getegid(),
            )

    def active(self, generation: str) -> None:
        path = self.root / "active"
        path.write_text(generation + "\n")
        path.chmod(0o640)

    def intent(self, intent: CaddyStartIntent) -> None:
        path = self.root / "intents/start.json"
        path.write_bytes(intent.to_bytes())
        path.chmod(0o600)


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    root = tmp_path / "caddy"
    root.mkdir(mode=0o750)
    (root / "generations").mkdir(mode=0o750)
    (root / "intents").mkdir(mode=0o700)
    lock_root = tmp_path / "locks"
    lock_root.mkdir(mode=0o700)
    with LockManager.initialize(lock_root, expected_owner=os.geteuid()):
        pass
    binary = tmp_path / "caddy-binary"
    binary.write_bytes(b"test caddy bytes")
    binary.chmod(0o755)
    state: dict[str, object] = {"platformRoutes": ["lowerduckpond.net"], "tenantRoutes": []}
    payload = CaddyGenerationPayload(
        binary=CaddyBinarySource(binary, owner=os.geteuid(), group=os.getegid()),
        environment=b"CLOUDFLARE_API_TOKEN=secret-environment-canary\n",
        configuration={"secret": "secret-configuration-canary"},
        route_metadata={
            "schema": CADDY_ROUTE_METADATA_SCHEMA,
            "routeState": state,
            "routeStateDigest": caddy_route_state_digest(state).to_dict(),
        },
    )
    targets = {}
    with CaddyGenerationStore.open(
        root / "generations",
        expected_owner=os.geteuid(),
        expected_group=os.getegid(),
    ) as store:
        for generation in (A, B, C):
            targets[generation] = start_target(
                generation, store.publish(generation, payload).to_bytes()
            )
    result = Fixture(root, lock_root, targets)
    result.active(A)
    return result


def test_shared_capture_is_nonsecret_and_keeps_crash_left_intent_bytes(fixture: Fixture) -> None:
    temporary = fixture.root / "intents" / (".ldp-state-" + "a" * 32)
    temporary.write_bytes(b"incomplete startup intent")
    temporary.chmod(0o600)
    metadata = temporary.stat()
    evidence = fixture.capture()
    serialized = canonical_json_bytes(evidence.to_dict())
    assert b"canary" not in serialized
    assert b"CLOUDFLARE" not in serialized
    assert evidence.active == A
    assert evidence.intent is None
    assert evidence.selected_target == fixture.targets[A]
    assert len(evidence.generations) == 1  # Unselected generations are not authority.
    assert CaddyBackupEvidence.from_dict(json.loads(serialized)) == evidence
    assert temporary.read_bytes() == b"incomplete startup intent"
    assert (temporary.stat().st_ino, temporary.stat().st_mtime_ns) == (
        metadata.st_ino,
        metadata.st_mtime_ns,
    )


@pytest.mark.parametrize("phase", list(CaddyStartPhase))
def test_every_interrupted_start_preserves_targets_and_attempt_history(
    fixture: Fixture,
    phase: CaddyStartPhase,
) -> None:
    ordinary = phase is CaddyStartPhase.ORDINARY_STARTING
    rollback = phase in {
        CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
        CaddyStartPhase.RECOVERY_STARTING,
    }
    starting = phase in {CaddyStartPhase.ORDINARY_STARTING, CaddyStartPhase.CANDIDATE_STARTING}
    recovery = phase is CaddyStartPhase.RECOVERY_STARTING
    intent = CaddyStartIntent(
        CaddyStartMode.ORDINARY if ordinary else CaddyStartMode.TRANSACTIONAL,
        phase,
        fixture.targets[B],
        None if ordinary else fixture.targets[A],
        INVOCATIONS[:3] if rollback else INVOCATIONS[:1] if starting else (),
        INVOCATIONS[3:5] if recovery else (),
        INVOCATIONS[4] if recovery else INVOCATIONS[0] if starting else None,
    )
    fixture.intent(intent)
    fixture.active(B if ordinary else A)
    # Capturing candidate-prepared before active selection and rollback-required
    # before predecessor selection is valid; recovery decides the transition.
    evidence = fixture.capture()
    assert evidence.intent == intent
    assert evidence.selected_target == (fixture.targets[A] if rollback else fixture.targets[B])
    assert CaddyBackupEvidence.from_dict(evidence.to_dict()) == evidence
    assert (fixture.root / "intents/start.json").read_bytes() == intent.to_bytes()


@pytest.mark.parametrize(
    "damage", ["manifest", "environment", "missing-generation", "target", "active"]
)
def test_missing_or_mismatched_runtime_authority_fails(fixture: Fixture, damage: str) -> None:
    intent = CaddyStartIntent(
        CaddyStartMode.TRANSACTIONAL,
        CaddyStartPhase.CANDIDATE_PREPARED,
        CaddyStartTarget(B, "0" * 64) if damage == "target" else fixture.targets[B],
        fixture.targets[A],
    )
    fixture.intent(intent)
    if damage == "active":
        fixture.active(C)
    elif damage == "missing-generation":
        (fixture.root / "generations" / B).rename(fixture.root / "generations/missing")
    elif damage in {"manifest", "environment"}:
        path = (
            fixture.root
            / "generations"
            / B
            / ("manifest.json" if damage == "manifest" else "environment")
        )
        path.chmod(0o600)
        path.write_bytes(b"corrupt")
        path.chmod(0o440)
    with pytest.raises(
        (BackupIdentityError, CaddyGenerationError, FileNotFoundError, ContractError)
    ):
        fixture.capture()


@pytest.mark.parametrize(
    "damage", ["unknown", "bad-temporary", "symlink", "hardlink", "too-many", "malformed"]
)
def test_intent_absence_is_never_inferred_from_unsafe_namespace(
    fixture: Fixture, damage: str
) -> None:
    root = fixture.root / "intents"
    path = root / "start.json"
    if damage == "unknown":
        path = root / "unknown.json"
    elif damage == "bad-temporary":
        path = root / ".ldp-state-invalid"
    if damage == "symlink":
        path.symlink_to(fixture.root / "active")
    else:
        path.write_bytes(b"{}\n")
        path.chmod(0o600)
        if damage == "hardlink":
            (fixture.root / "outside-link").hardlink_to(path)
        if damage == "too-many":
            for index in range(17):
                extra = root / f".ldp-state-{index:032x}"
                extra.write_bytes(b"incomplete")
                extra.chmod(0o600)
    names = sorted(item.name for item in root.iterdir())
    with pytest.raises((CaddyStartupError, StatePathError)):
        fixture.capture()
    assert sorted(item.name for item in root.iterdir()) == names


@pytest.mark.parametrize("damage", ["missing", "mode", "symlink", "hardlink", "malformed"])
def test_active_reference_must_be_safe_and_explicit(fixture: Fixture, damage: str) -> None:
    path = fixture.root / "active"
    if damage in {"missing", "symlink"}:
        path.unlink()
        if damage == "symlink":
            path.symlink_to(fixture.root / "generations" / A / "manifest.json")
    elif damage == "mode":
        path.chmod(0o600)
    elif damage == "hardlink":
        (fixture.root / "active-link").hardlink_to(path)
    else:
        path.write_bytes(b"invalid\n")
    with pytest.raises((FileNotFoundError, StatePathError, BackupIdentityError)):
        fixture.capture()


@pytest.mark.parametrize(
    "damage", ["selected", "duplicate", "omitted", "unknown", "digest-format", "secret-field"]
)
def test_descriptor_caddy_evidence_rejects_ambiguous_or_extended_authority(
    fixture: Fixture,
    damage: str,
) -> None:
    value = json.loads(canonical_json_bytes(fixture.capture().to_dict()))
    if damage == "selected":
        value["selectedTarget"] = fixture.targets[B].to_dict()
    elif damage == "duplicate":
        value["generations"] *= 2
    elif damage == "omitted":
        value["generations"] = []
    elif damage == "unknown":
        value["generations"][0]["generationId"] = B
    elif damage == "digest-format":
        value["generations"][0]["manifestDigest"]["format"] = "lowerduckpond-backup-file-v1"
    else:
        value["environment"] = "secret-canary"
    with pytest.raises(BackupIdentityError):
        CaddyBackupEvidence.from_dict(value)


def test_caddy_capture_requires_shared_publication_authority(fixture: Fixture) -> None:
    with (
        LockManager(fixture.locks, expected_owner=os.geteuid()) as locks,
        pytest.raises(LockOrderError),
    ):
        capture_caddy_evidence(
            fixture.root,
            locks=locks,
            expected_owner=os.geteuid(),
            expected_group=os.getegid(),
        )
