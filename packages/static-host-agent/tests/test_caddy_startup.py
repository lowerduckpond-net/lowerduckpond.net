from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent.caddy_startup import (
    CADDY_START_INTENT_DIRECTORY_MODE,
    MAX_CADDY_START_ATTEMPTS,
    CaddyStartIntent,
    CaddyStartMode,
    CaddyStartPhase,
    CaddyStartupError,
    CaddyStartupStore,
    start_target,
)

GENERATION_A = "0198d17f-6f4a-7000-8000-000000000001"
GENERATION_B = "0198d17f-6f4a-7000-8000-000000000002"
TARGET_A = start_target(GENERATION_A, b"manifest-a")
TARGET_B = start_target(GENERATION_B, b"manifest-b")
INVOCATIONS = tuple(f"{value:032x}" for value in range(1, 8))


def _store(tmp_path: Path) -> CaddyStartupStore:
    root = tmp_path / "intents"
    root.mkdir(mode=CADDY_START_INTENT_DIRECTORY_MODE)
    return CaddyStartupStore.open(root, expected_owner=os.geteuid())


def test_ordinary_start_is_fenced_to_one_target_and_three_attempts(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        for attempt in range(MAX_CADDY_START_ATTEMPTS):
            intent = store.prepare_start(active=TARGET_A, invocation_id=INVOCATIONS[attempt])
            assert intent.phase is CaddyStartPhase.ORDINARY_STARTING
            assert len(intent.candidate_invocations) == attempt + 1
        with pytest.raises(CaddyStartupError, match="attempts are exhausted"):
            store.prepare_start(active=TARGET_A, invocation_id=INVOCATIONS[3])
        assert store.require_rollback_target() is None
        with pytest.raises(CaddyStartupError, match="stale or mismatched"):
            store.require_matching_success(
                active=TARGET_A,
                invocation_id=INVOCATIONS[0],
            )


def test_exhausted_ordinary_start_can_be_released_for_later_operator_retry(
    tmp_path: Path,
) -> None:
    with _store(tmp_path) as store:
        assert not store.clear_exhausted_ordinary_start()
        for invocation_id in INVOCATIONS[:MAX_CADDY_START_ATTEMPTS]:
            store.prepare_start(active=TARGET_A, invocation_id=invocation_id)
        assert store.clear_exhausted_ordinary_start()
        assert store.read() is None
        assert not store.clear_exhausted_ordinary_start()

        retried = store.prepare_start(active=TARGET_A, invocation_id=INVOCATIONS[3])
        assert retried.candidate_invocations == (INVOCATIONS[3],)


def test_recovery_reconciliation_is_inert_without_rollback_authority(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        assert store.require_rollback_target() is None
        prepared = store.begin_transaction(candidate=TARGET_B, previous=TARGET_A)
        assert store.require_rollback_target() is None
        store.mark_restart_required(prepared)
        assert store.require_rollback_target() is None
        store.prepare_start(active=TARGET_B, invocation_id=INVOCATIONS[0])
        assert store.require_rollback_target() is None


def test_transaction_rolls_back_once_then_bounds_recovery_attempts(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        prepared = store.begin_transaction(candidate=TARGET_B, previous=TARGET_A)
        required = store.mark_restart_required(prepared)
        assert required.phase is CaddyStartPhase.RESTART_REQUIRED

        for attempt in range(MAX_CADDY_START_ATTEMPTS):
            intent = store.prepare_start(active=TARGET_B, invocation_id=INVOCATIONS[attempt])
            assert intent.phase is CaddyStartPhase.CANDIDATE_STARTING
        rollback_target = store.require_rollback_target()
        assert rollback_target is not None
        assert rollback_target.phase is CaddyStartPhase.CANDIDATE_STARTING
        assert store.read() == rollback_target
        rollback = store.mark_rollback_restart_required(rollback_target)
        assert rollback is not None
        assert rollback.phase is CaddyStartPhase.ROLLBACK_RESTART_REQUIRED
        assert rollback.selected_target == TARGET_A
        assert store.require_rollback_target() == rollback

        for attempt in range(MAX_CADDY_START_ATTEMPTS):
            recovery = store.prepare_start(
                active=TARGET_A,
                invocation_id=INVOCATIONS[attempt + MAX_CADDY_START_ATTEMPTS],
            )
            assert recovery.phase is CaddyStartPhase.RECOVERY_STARTING
        assert store.require_rollback_target() is None
        with pytest.raises(CaddyStartupError, match="attempts are exhausted"):
            store.prepare_start(active=TARGET_A, invocation_id=INVOCATIONS[6])


def test_only_matching_post_start_callback_can_clear_intent(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        current = store.prepare_start(active=TARGET_A, invocation_id=INVOCATIONS[0])
        with pytest.raises(CaddyStartupError, match="stale or mismatched"):
            store.require_matching_success(
                active=TARGET_B,
                invocation_id=INVOCATIONS[0],
            )
        with pytest.raises(CaddyStartupError, match="stale or mismatched"):
            store.require_matching_success(
                active=TARGET_A,
                invocation_id=INVOCATIONS[1],
            )
        assert (
            store.require_matching_success(
                active=TARGET_A,
                invocation_id=INVOCATIONS[0],
            )
            == current
        )
        store.commit_success(current)
        assert store.read() is None


def test_prepared_candidate_can_advance_only_after_it_is_active(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        prepared = store.begin_transaction(candidate=TARGET_B, previous=TARGET_A)
        with pytest.raises(CaddyStartupError, match="phase is not recognized"):
            store.prepare_start(active=TARGET_B, invocation_id=INVOCATIONS[0])
        store.mark_restart_required(prepared)
        with pytest.raises(CaddyStartupError, match="active generation disagrees"):
            store.prepare_start(active=TARGET_A, invocation_id=INVOCATIONS[0])
        intent = store.prepare_start(active=TARGET_B, invocation_id=INVOCATIONS[0])
        assert intent.phase is CaddyStartPhase.CANDIDATE_STARTING


@pytest.mark.parametrize(
    ("phase", "candidate_invocations", "recovery_invocations", "invocation_id"),
    [
        (CaddyStartPhase.RESTART_REQUIRED, (INVOCATIONS[0],), (), None),
        (
            CaddyStartPhase.ROLLBACK_RESTART_REQUIRED,
            (INVOCATIONS[0],),
            (),
            None,
        ),
        (
            CaddyStartPhase.RECOVERY_STARTING,
            INVOCATIONS[:MAX_CADDY_START_ATTEMPTS],
            (INVOCATIONS[3],),
            INVOCATIONS[0],
        ),
    ],
)
def test_impossible_transactional_intent_shapes_are_rejected(
    phase: CaddyStartPhase,
    candidate_invocations: tuple[str, ...],
    recovery_invocations: tuple[str, ...],
    invocation_id: str | None,
) -> None:
    with pytest.raises(CaddyStartupError):
        CaddyStartIntent(
            mode=CaddyStartMode.TRANSACTIONAL,
            phase=phase,
            candidate=TARGET_B,
            previous=TARGET_A,
            candidate_invocations=candidate_invocations,
            recovery_invocations=recovery_invocations,
            invocation_id=invocation_id,
        )
