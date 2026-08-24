from __future__ import annotations

from pathlib import Path

import pytest
from lowerduckpond_m3_qualification.session import (
    QualificationSession,
    UnsafeSessionError,
)

SOURCE_REVISION = "a" * 40
RUN_ID = "0198d17f-6f4a-7000-8000-000000000001"
SESSION_MODE = 0o600


def identity() -> dict[str, str]:
    return {
        "droplet_id": "42",
        "droplet_urn": "do:droplet:42",
        "ipv4_address": "8.8.8.8",
    }


def test_session_round_trip_binds_identity_revision_and_mode(tmp_path: Path) -> None:
    path = tmp_path / "session.json"
    session = QualificationSession.create(
        identity=identity(), source_revision=SOURCE_REVISION, run_id=RUN_ID
    )

    session.write(path)
    loaded = QualificationSession.read(path)

    assert loaded == session
    assert path.stat().st_mode & 0o777 == SESSION_MODE
    loaded.verify(identity=identity(), source_revision=SOURCE_REVISION)


@pytest.mark.parametrize("field", ["droplet_id", "droplet_urn", "ipv4_address"])
def test_session_rejects_changed_droplet_identity(field: str) -> None:
    session = QualificationSession.create(
        identity=identity(), source_revision=SOURCE_REVISION, run_id=RUN_ID
    )
    changed = identity()
    changed[field] = "43" if field == "droplet_id" else "invalid"

    with pytest.raises(UnsafeSessionError):
        session.verify(identity=changed, source_revision=SOURCE_REVISION)


def test_session_rejects_changed_source_revision() -> None:
    session = QualificationSession.create(
        identity=identity(), source_revision=SOURCE_REVISION, run_id=RUN_ID
    )

    with pytest.raises(UnsafeSessionError):
        session.verify(identity=identity(), source_revision="b" * 40)


@pytest.mark.parametrize(
    "invalid_identity",
    [
        {"droplet_id": "42", "droplet_urn": "do:droplet:41", "ipv4_address": "8.8.8.8"},
        {"droplet_id": "42", "droplet_urn": "do:droplet:42", "ipv4_address": "127.0.0.1"},
    ],
)
def test_session_rejects_unsafe_identity(invalid_identity: dict[str, str]) -> None:
    with pytest.raises(UnsafeSessionError):
        QualificationSession.create(
            identity=invalid_identity,
            source_revision=SOURCE_REVISION,
            run_id=RUN_ID,
        )
