from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import (
    ArtifactIntake,
    DeploymentReleaseStore,
    FilesystemCapacity,
    LockManager,
    LockMode,
    LockName,
    LockOrderError,
    ReleaseCapacityUsage,
    ReleaseStoreError,
    VerifiedArtifact,
)

_CORRELATION_ID = "0198d17f-6f4a-7000-8000-000000000001"
_TENANT_ID = "0198d17f-6f4a-7000-8000-000000000002"
_DEPLOYMENT_ID = "0198d17f-6f4a-7000-8000-000000000003"
_DIRECTORY_MODE = 0o755
_FILE_MODE = 0o644


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir()
    path.chmod(mode)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root, 0o700)
    _mkdir(root / "intake", 0o700)
    _mkdir(root / "staging", 0o700)
    _mkdir(root / "locks", 0o700)
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _release_root(tmp_path: Path) -> Path:
    root = tmp_path / "sites"
    _mkdir(root, 0o710)
    return root


def _deployment_zip() -> bytes:
    payload = BytesIO()
    with zipfile.ZipFile(payload, mode="w") as archive:
        for name, content in (
            ("index.html", b"home\n"),
            ("assets/site.txt", b"immutable release\n"),
        ):
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)
    return payload.getvalue()


def _binding(payload: bytes) -> VerifiedArtifact:
    return VerifiedArtifact(len(payload), hashlib.sha256(payload).hexdigest())


@pytest.fixture(autouse=True)
def _reported_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    def measure(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            device=os.fstat(descriptor).st_dev,
            fragment_size=4_096,
            total_blocks=4_000_000,
            available_blocks=3_000_000,
            total_inodes=4_000_000,
            available_inodes=3_000_000,
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.zip_structure.measure_filesystem_capacity_descriptor",
        measure,
    )
    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.intake.measure_filesystem_capacity_descriptor",
        measure,
    )


def test_release_store_extracts_verifies_and_durably_publishes(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()
        with (
            intake.claim(
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
            ) as claim,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        ):
            expected = intake.deployment_release_tree_digest(claim.artifact).to_dict()
            staged = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            outcome = store.publish(staged, publication_lock=locks)

    release = release_root / _TENANT_ID / "releases" / _DEPLOYMENT_ID
    assert outcome.created is True
    assert outcome.measurement.digest.to_dict() == expected
    assert (release / "assets" / "site.txt").read_bytes() == b"immutable release\n"
    assert stat.S_IMODE(release.stat().st_mode) == _DIRECTORY_MODE
    assert stat.S_IMODE((release / "assets" / "site.txt").stat().st_mode) == _FILE_MODE
    assert not any((state_root / "staging").iterdir())


def test_release_publication_exactly_replays_an_existing_identity(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()
        with (
            intake.claim(
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
            ) as claim,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        ):
            expected = intake.deployment_release_tree_digest(claim.artifact).to_dict()
            first = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            assert store.publish(first, publication_lock=locks).created is True
            replay = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            assert store.publish(replay, publication_lock=locks).created is False

    assert not any((state_root / "staging").iterdir())


def test_release_publication_refuses_an_existing_identity_with_other_content(
    tmp_path: Path,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()
        with (
            intake.claim(
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
            ) as claim,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        ):
            expected = intake.deployment_release_tree_digest(claim.artifact).to_dict()
            first = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            store.publish(first, publication_lock=locks)
            release_file = (
                release_root / _TENANT_ID / "releases" / _DEPLOYMENT_ID / "assets" / "site.txt"
            )
            release_file.write_bytes(b"other immutable release\n")
            replay = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            with pytest.raises(ReleaseStoreError, match="contains other content"):
                store.publish(replay, publication_lock=locks)


def test_release_store_reconciles_only_unprotected_safe_staging(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()
        with (
            intake.claim(
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
            ) as claim,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        ):
            expected = intake.deployment_release_tree_digest(claim.artifact).to_dict()
            staged = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            assert [path.name for path in (state_root / "staging").iterdir()] == [
                staged.staging_name
            ]
            assert (
                store.reconcile_staging(
                    {staged.staging_name: expected},
                    publication_lock=locks,
                )
                == 0
            )
            assert store.reconcile_staging({}, publication_lock=locks) == 1

    assert not any((state_root / "staging").iterdir())


def test_release_store_removes_staging_when_authority_digest_disagrees(
    tmp_path: Path,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()
        with (
            intake.claim(
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
            ) as claim,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
            pytest.raises(ReleaseStoreError, match="digest disagrees"),
        ):
            expected = intake.deployment_release_tree_digest(claim.artifact).to_dict()
            store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest={**expected, "value": "f" * 64},
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )

    assert not any((state_root / "staging").iterdir())


def test_release_store_requires_the_exclusive_publication_lock(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    with (
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
        pytest.raises(LockOrderError, match=r"publication\.lock"),
    ):
        store.reconcile_staging({}, publication_lock=locks)


def test_release_store_rejects_an_unsafe_staging_inventory(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    (state_root / "staging" / "unexpected").write_text("unsafe\n", encoding="utf-8")
    with (
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        pytest.raises(ReleaseStoreError, match="unrecognized entry"),
    ):
        store.reconcile_staging({}, publication_lock=locks)


def test_release_store_rejects_unsafe_root_metadata(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    release_root.chmod(0o755)
    with pytest.raises(ReleaseStoreError, match="unsafe inode shape"):
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        )


def test_release_store_removes_only_the_exact_authorized_release(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            state_root / "staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
    ):
        with intake.admit(
            operation="deploy",
            correlation_id=_CORRELATION_ID,
            declared=_binding(payload),
            read=BytesIO(payload).read,
        ) as lease:
            lease.commit()
        with (
            intake.claim(
                correlation_id=_CORRELATION_ID,
                declared=_binding(payload),
            ) as claim,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        ):
            expected = intake.deployment_release_tree_digest(claim.artifact).to_dict()
            staged = store.stage(
                intake,
                claim.artifact,
                tenant_id=_TENANT_ID,
                deployment_id=_DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                retained_usage=ReleaseCapacityUsage(()),
                publication_lock=locks,
            )
            store.publish(staged, publication_lock=locks)
            with pytest.raises(ReleaseStoreError, match="digest disagrees"):
                store.remove_release(
                    _TENANT_ID,
                    _DEPLOYMENT_ID,
                    expected_release_tree_digest={**expected, "value": "f" * 64},
                    publication_lock=locks,
                )
            store.remove_release(
                _TENANT_ID,
                _DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                publication_lock=locks,
            )

    assert not (release_root / _TENANT_ID / "releases" / _DEPLOYMENT_ID).exists()
