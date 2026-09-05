from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from io import BytesIO
from pathlib import Path

import lowerduckpond_static_host_agent.release_store as release_store_module
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
_ROOT_DESCRIPTOR_COUNT = 2


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir()
    path.chmod(mode)


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    _mkdir(root, 0o700)
    _mkdir(root / "intake", 0o700)
    _mkdir(root / "locks", 0o700)
    manager = LockManager.initialize(root / "locks", expected_owner=os.geteuid())
    manager.close()
    return root


def _release_root(tmp_path: Path) -> Path:
    root = tmp_path / "sites"
    _mkdir(root, 0o710)
    _mkdir(root / ".staging", 0o700)
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
            release_root / ".staging",
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
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE),
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
    assert not any((release_root / ".staging").iterdir())


def test_release_publication_exactly_replays_an_existing_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE),
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
            synced: list[Path] = []
            original_fsync = os.fsync

            def track_fsync(descriptor: int) -> None:
                synced.append(Path(f"/proc/self/fd/{descriptor}").resolve())
                original_fsync(descriptor)

            monkeypatch.setattr(os, "fsync", track_fsync)
            assert store.publish(replay, publication_lock=locks).created is False
            releases = release_root / _TENANT_ID / "releases"
            assert synced.index(releases) < synced.index(release_root / ".staging")

    assert not any((release_root / ".staging").iterdir())


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
            release_root / ".staging",
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
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE),
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


def test_release_staging_collision_preserves_the_existing_candidate(
    tmp_path: Path,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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
            with pytest.raises(ReleaseStoreError, match="could not be staged safely"):
                store.stage(
                    intake,
                    claim.artifact,
                    tenant_id=_TENANT_ID,
                    deployment_id=_DEPLOYMENT_ID,
                    expected_release_tree_digest=expected,
                    retained_usage=ReleaseCapacityUsage(()),
                    publication_lock=locks,
                )
            preserved = release_root / ".staging" / staged.staging_name
            assert (preserved / "assets" / "site.txt").read_bytes() == b"immutable release\n"
            store.discard_staged(staged, publication_lock=locks)


def test_release_store_reconciles_only_unprotected_safe_staging(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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
            assert [path.name for path in (release_root / ".staging").iterdir()] == [
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

    assert not any((release_root / ".staging").iterdir())


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
            release_root / ".staging",
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

    assert not any((release_root / ".staging").iterdir())


def test_release_store_requires_the_exclusive_publication_lock(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    with (
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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
    (release_root / ".staging" / "unexpected").write_text("unsafe\n", encoding="utf-8")
    with (
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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


def test_release_store_removes_restrictive_partial_staging(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    staging_name = f"{_TENANT_ID}--{_DEPLOYMENT_ID}"
    partial = release_root / ".staging" / staging_name
    _mkdir(partial, 0o700)
    _mkdir(partial / "assets", 0o700)
    partial_file = partial / "assets" / "site.txt"
    partial_file.write_bytes(b"partial")
    partial_file.chmod(0o600)
    with (
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
    ):
        assert store.reconcile_staging({}, publication_lock=locks) == 1

    assert not partial.exists()


def test_release_store_rejects_unsafe_root_metadata(tmp_path: Path) -> None:
    release_root = _release_root(tmp_path)
    release_root.chmod(0o755)
    with pytest.raises(ReleaseStoreError, match="unsafe inode shape"):
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        )


@pytest.mark.parametrize("partial", ["tenant", "releases"])
def test_release_namespace_repairs_a_restrictive_crash_left_directory(
    tmp_path: Path,
    partial: str,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    tenant = release_root / _TENANT_ID
    _mkdir(tenant, 0o700 if partial == "tenant" else 0o755)
    if partial == "releases":
        _mkdir(tenant / "releases", 0o700)

    with (
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE),
    ):
        descriptor = store._open_or_create_release_namespace(_TENANT_ID)
        os.close(descriptor)

    assert stat.S_IMODE(tenant.stat().st_mode) == _DIRECTORY_MODE
    assert stat.S_IMODE((tenant / "releases").stat().st_mode) == _DIRECTORY_MODE


def test_release_store_removes_only_the_exact_authorized_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE),
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

            def interrupt_removal(*_args: object, **_kwargs: object) -> None:
                raise RuntimeError("simulated interruption")

            original_remove = release_store_module._remove_tree
            monkeypatch.setattr(
                release_store_module,
                "_remove_tree",
                interrupt_removal,
            )
            with pytest.raises(RuntimeError, match="simulated interruption"):
                store.remove_release(
                    _TENANT_ID,
                    _DEPLOYMENT_ID,
                    expected_release_tree_digest=expected,
                    publication_lock=locks,
                )
            releases = release_root / _TENANT_ID / "releases"
            assert not (releases / _DEPLOYMENT_ID).exists()
            assert [path.name for path in releases.iterdir()] == [
                f".retired-{_DEPLOYMENT_ID}-{expected['value']}"
            ]
            monkeypatch.setattr(release_store_module, "_remove_tree", original_remove)
            store.remove_release(
                _TENANT_ID,
                _DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                publication_lock=locks,
            )

    assert not (release_root / _TENANT_ID / "releases" / _DEPLOYMENT_ID).exists()


def test_release_removal_requires_exclusive_tenant_state(tmp_path: Path) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    with (
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        ) as store,
        LockManager(
            state_root / "locks",
            expected_owner=os.geteuid(),
            expected_directory_mode=0o700,
        ) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE),
        pytest.raises(LockOrderError, match=r"tenant-state\.lock"),
    ):
        store.remove_release(
            _TENANT_ID,
            _DEPLOYMENT_ID,
            expected_release_tree_digest={
                "format": "lowerduckpond-release-tree-v1",
                "algorithm": "sha256",
                "value": "f" * 64,
            },
            publication_lock=locks,
        )


def test_release_removal_retry_syncs_an_already_absent_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = _state_root(tmp_path)
    release_root = _release_root(tmp_path)
    payload = _deployment_zip()
    with (
        ArtifactIntake(state_root, expected_owner=os.geteuid()) as intake,
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
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
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE),
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
            releases = release_root / _TENANT_ID / "releases"
            original_fsync = os.fsync

            def interrupt_final_parent_sync(descriptor: int) -> None:
                if Path(f"/proc/self/fd/{descriptor}").resolve() == releases and not any(
                    releases.iterdir()
                ):
                    raise RuntimeError("simulated post-rmdir interruption")
                original_fsync(descriptor)

            monkeypatch.setattr(os, "fsync", interrupt_final_parent_sync)
            with pytest.raises(RuntimeError, match="post-rmdir interruption"):
                store.remove_release(
                    _TENANT_ID,
                    _DEPLOYMENT_ID,
                    expected_release_tree_digest=expected,
                    publication_lock=locks,
                )
            assert not any(releases.iterdir())

            synced: list[Path] = []

            def track_retry_sync(descriptor: int) -> None:
                synced.append(Path(f"/proc/self/fd/{descriptor}").resolve())
                original_fsync(descriptor)

            monkeypatch.setattr(os, "fsync", track_retry_sync)
            store.remove_release(
                _TENANT_ID,
                _DEPLOYMENT_ID,
                expected_release_tree_digest=expected,
                publication_lock=locks,
            )
            assert releases in synced


def test_release_store_closes_both_roots_after_filesystem_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_root = _release_root(tmp_path)
    opened: list[int] = []
    original_open = release_store_module._open_validated_directory
    original_fstat = os.fstat

    def track_open(
        path: Path,
        *,
        expected_owner: int,
        expected_group: int | None,
        expected_mode: int,
        label: str,
    ) -> int:
        descriptor = original_open(
            path,
            expected_owner=expected_owner,
            expected_group=expected_group,
            expected_mode=expected_mode,
            label=label,
        )
        opened.append(descriptor)
        return descriptor

    def drift_staging_device(descriptor: int) -> os.stat_result:
        metadata = original_fstat(descriptor)
        if len(opened) == _ROOT_DESCRIPTOR_COUNT and descriptor == opened[1]:
            fields = list(metadata)
            fields[2] += 1
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(release_store_module, "_open_validated_directory", track_open)
    monkeypatch.setattr(os, "fstat", drift_staging_device)
    with pytest.raises(ReleaseStoreError, match="not on the release filesystem"):
        DeploymentReleaseStore(
            release_root,
            release_root / ".staging",
            expected_owner=os.geteuid(),
            expected_release_group=os.getegid(),
        )

    assert len(opened) == _ROOT_DESCRIPTOR_COUNT
    for descriptor in opened:
        with pytest.raises(OSError):
            original_fstat(descriptor)
