from __future__ import annotations

import hashlib
import os
from io import BytesIO
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    CapacityRejectedError,
    IntakeError,
    IntakeOccupiedError,
    LockManager,
    VerifiedArtifact,
)

_CORRELATION_ID = "0198d17f-6f4a-7000-8000-000000000001"
_ARTIFACT_MODE = 0o600


def _mkdir(path: Path) -> None:
    path.mkdir()
    path.chmod(0o700)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root)
    _mkdir(root / "intake")
    _mkdir(root / "locks")
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _binding(payload: bytes) -> VerifiedArtifact:
    return VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())


@pytest.fixture(autouse=True)
def _capacity_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.intake.admit_release_capacity",
        lambda *_args, **_kwargs: None,
    )


def test_intake_publishes_only_after_sync_and_commit(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    payload = b"bounded artifact"
    source = BytesIO(payload)

    with (
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=source.read,
        ) as lease,
    ):
        target = root / "intake" / lease.artifact.filename
        assert target.read_bytes() == payload
        assert target.stat().st_mode & 0o777 == _ARTIFACT_MODE
        lease.commit()

    assert target.read_bytes() == payload


def test_intake_accepts_only_an_exact_retry_of_its_admitted_artifact(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    payload = b"bounded artifact"
    binding = _binding(payload)
    with ArtifactIntake(root, expected_owner=os.geteuid()) as intake:
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=binding,
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()

        target = root / "intake" / f"{_CORRELATION_ID}.artifact"
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=binding,
            read=BytesIO(payload).read,
            allow_existing=True,
        ) as retry:
            retry.commit()
        assert target.read_bytes() == payload

        with (
            pytest.raises(IntakeError, match="binding"),
            intake.admit(
                operation="deploy",
                correlation_id=_CORRELATION_ID,
                declared=binding,
                read=BytesIO(b"changed artifact").read,
                allow_existing=True,
            ),
        ):
            pass
        assert target.read_bytes() == payload

        with (
            pytest.raises(IntakeOccupiedError),
            intake.admit(
                operation="deploy",
                correlation_id=_CORRELATION_ID,
                declared=binding,
                read=BytesIO(payload).read,
            ),
        ):
            pass


def test_intake_removes_uncommitted_or_failed_upload_and_syncs_slot(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    payload = b"bounded artifact"
    with ArtifactIntake(root, expected_owner=os.geteuid()) as intake:
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ):
            pass
        assert list((root / "intake").iterdir()) == []

        with (
            pytest.raises(IntakeError, match="ended"),
            intake.admit(
                operation="deploy",
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
                read=BytesIO(payload[:-1]).read,
            ),
        ):
            pass
        assert list((root / "intake").iterdir()) == []


def test_intake_rejects_digest_mismatch_and_over_ceiling_before_publication(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    payload = b"bounded artifact"
    with ArtifactIntake(root, expected_owner=os.geteuid()) as intake:
        with (
            pytest.raises(IntakeError, match="digest"),
            intake.admit(
                operation="deploy",
                correlation_id=_CORRELATION_ID,
                declared=VerifiedArtifact(len(payload), "0" * 64),
                read=BytesIO(payload).read,
            ),
        ):
            pass
        with (
            pytest.raises(IntakeError, match="declared"),
            intake.admit(
                operation="deploy",
                correlation_id=_CORRELATION_ID,
                declared=VerifiedArtifact(100 * 1024 * 1024 + 1, "0" * 64),
                read=BytesIO(b"").read,
            ),
        ):
            pass

    assert list((root / "intake").iterdir()) == []


def test_intake_reconciles_only_safe_abandoned_temporary(tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    temporary = root / "intake" / ".ldp-intake-0123456789abcdef0123456789abcdef"
    temporary.write_bytes(b"abandoned")
    temporary.chmod(0o600)
    payload = b"new"

    with (
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ),
    ):
        assert not temporary.exists()

    assert list((root / "intake").iterdir()) == []


@pytest.mark.parametrize("name", ["unknown", f"{_CORRELATION_ID}.artifact"])
def test_intake_closes_on_unknown_or_admitted_slot(name: str, tmp_path: Path) -> None:
    root = _state_root(tmp_path)
    occupied = root / "intake" / name
    occupied.write_bytes(b"occupied")
    occupied.chmod(0o600)
    expected = IntakeOccupiedError if name.endswith(".artifact") else IntakeError

    with (
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(expected),
        intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(b"new"),
            read=BytesIO(b"new").read,
        ),
    ):
        pass

    assert occupied.read_bytes() == b"occupied"


def test_intake_preserves_capacity_rejection_without_partial_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _state_root(tmp_path)

    def reject(*_args: object, **_kwargs: object) -> None:
        raise CapacityRejectedError("reserve")

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.intake.admit_release_capacity",
        reject,
    )
    with (
        ArtifactIntake(root, expected_owner=os.geteuid()) as intake,
        pytest.raises(CapacityRejectedError, match="reserve"),
        intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(b"new"),
            read=BytesIO(b"new").read,
        ),
    ):
        pass

    assert list((root / "intake").iterdir()) == []
