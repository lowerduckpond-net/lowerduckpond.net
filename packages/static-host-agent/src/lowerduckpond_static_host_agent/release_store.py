"""Durable publication and bounded cleanup of immutable tenant releases."""

from __future__ import annotations

import ctypes
import errno
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from lowerduckpond_static_contracts import ContractError, Digest, validate_uuid7

from lowerduckpond_static_host_agent.capacity import (
    DEFAULT_HOST_CAPACITY_LIMITS,
    HostCapacityLimits,
    ReleaseCapacityUsage,
)
from lowerduckpond_static_host_agent.intake import AdmittedArtifact, ArtifactIntake
from lowerduckpond_static_host_agent.locks import LockMode, LockName
from lowerduckpond_static_host_agent.release_tree import (
    RELEASE_TREE_FORMAT,
    ReleaseTreeMeasurement,
    measure_release_tree,
)

_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
)
_RENAME_NOREPLACE: Final = 1
_RELEASE_ROOT_MODE: Final = 0o710
_STAGING_ROOT_MODE: Final = 0o700
_RELEASE_DIRECTORY_MODE: Final = 0o755
_RELEASE_FILE_MODE: Final = 0o644
_MAXIMUM_STAGING_ENTRIES: Final = 2
_STAGING_NAME = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"--[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    flags=re.ASCII,
)
_DISCARDED_STAGING_NAME = re.compile(
    r"\.discarded-("
    r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r"--[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    r")",
    flags=re.ASCII,
)


class ReleaseStoreError(RuntimeError):
    """The immutable release namespace could not be changed safely."""


class PublicationLockProof(Protocol):
    """Proof surface for one held publication lock."""

    def require_held(
        self,
        name: LockName,
        *,
        mode: LockMode | None = None,
        descriptor: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class StagedDeploymentRelease:
    """One verified private extraction ready for no-replace publication."""

    tenant_id: str
    deployment_id: str
    staging_name: str
    measurement: ReleaseTreeMeasurement


@dataclass(frozen=True, slots=True)
class PublishedDeploymentRelease:
    """One exact immutable release and whether this call published it."""

    measurement: ReleaseTreeMeasurement
    created: bool


class DeploymentReleaseStore:
    """Own private staging and the Caddy-readable immutable release namespace."""

    def __init__(
        self,
        release_root: Path,
        staging_root: Path,
        *,
        expected_owner: int,
        expected_release_group: int,
        expected_staging_group: int,
    ) -> None:
        self._release_root = release_root
        self._staging_root = staging_root
        self._expected_owner = expected_owner
        self._expected_release_group = expected_release_group
        self._release_fd = _open_validated_directory(
            release_root,
            expected_owner=expected_owner,
            expected_group=expected_release_group,
            expected_mode=_RELEASE_ROOT_MODE,
            label="release root",
        )
        staging_fd: int | None = None
        try:
            staging_fd = _open_validated_directory(
                staging_root,
                expected_owner=expected_owner,
                expected_group=expected_staging_group,
                expected_mode=_STAGING_ROOT_MODE,
                label="release staging root",
            )
            if os.fstat(self._release_fd).st_dev != os.fstat(staging_fd).st_dev:
                raise ReleaseStoreError("release staging is not on the release filesystem")
        except BaseException:
            if staging_fd is not None:
                os.close(staging_fd)
            os.close(self._release_fd)
            raise
        self._staging_fd = staging_fd
        self._closed = False

    def __enter__(self) -> DeploymentReleaseStore:
        self._require_open()
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            os.close(self._staging_fd)
            os.close(self._release_fd)
            self._closed = True

    def stage(  # noqa: PLR0913 - every authority input remains explicit
        self,
        intake: ArtifactIntake,
        artifact: AdmittedArtifact,
        *,
        tenant_id: object,
        deployment_id: object,
        expected_release_tree_digest: Mapping[str, object],
        retained_usage: ReleaseCapacityUsage,
        publication_lock: PublicationLockProof,
        capacity_limits: HostCapacityLimits = DEFAULT_HOST_CAPACITY_LIMITS,
    ) -> StagedDeploymentRelease:
        """Extract and independently verify one private deployment candidate."""

        self._require_locked(publication_lock)
        canonical_tenant = validate_uuid7(tenant_id)
        canonical_deployment = validate_uuid7(deployment_id)
        staging_name = _staging_name(canonical_tenant, canonical_deployment)
        owns_staging = False
        try:
            intake.extract_deployment_release(
                artifact,
                staging_parent=self._staging_root,
                staging_name=staging_name,
                retained_usage=retained_usage,
                limits=capacity_limits,
            )
            owns_staging = True
            measurement = measure_release_tree(
                self._staging_root / staging_name,
                lock_manager=publication_lock,
                expected_owner=self._expected_owner,
            )
            if measurement.digest.to_dict() != dict(expected_release_tree_digest):
                raise ReleaseStoreError("extracted release digest disagrees with authority")
            return StagedDeploymentRelease(
                canonical_tenant,
                canonical_deployment,
                staging_name,
                measurement,
            )
        except BaseException as error:
            if owns_staging:
                try:
                    self._discard_name(staging_name)
                except BaseException as cleanup_error:
                    raise ReleaseStoreError(
                        "failed release staging could not be removed"
                    ) from cleanup_error
            if isinstance(error, ReleaseStoreError):
                raise
            raise ReleaseStoreError("deployment release could not be staged safely") from error

    def publish(
        self,
        staged: StagedDeploymentRelease,
        *,
        publication_lock: PublicationLockProof,
    ) -> PublishedDeploymentRelease:
        """Durably publish or exactly replay one verified immutable release."""

        self._require_mutation_locked(publication_lock)
        _validate_staged(staged)
        current = self._measure_staging(staged, publication_lock=publication_lock)
        if current != staged.measurement:
            raise ReleaseStoreError("staged release changed before publication")
        releases_fd = self._open_or_create_release_namespace(staged.tenant_id)
        try:
            try:
                _rename_no_replace(
                    self._staging_fd,
                    staged.staging_name,
                    releases_fd,
                    staged.deployment_id,
                )
            except FileExistsError:
                existing = self.measure(
                    staged.tenant_id,
                    staged.deployment_id,
                    publication_lock=publication_lock,
                )
                if existing.digest != staged.measurement.digest:
                    raise ReleaseStoreError(
                        "published release identity contains other content"
                    ) from None
                os.fsync(releases_fd)
                self._discard_name(staged.staging_name)
                return PublishedDeploymentRelease(existing, False)
            os.fsync(releases_fd)
            os.fsync(self._staging_fd)
        finally:
            os.close(releases_fd)
        published = self.measure(
            staged.tenant_id,
            staged.deployment_id,
            publication_lock=publication_lock,
        )
        if published != staged.measurement:
            raise ReleaseStoreError("published release changed across its durable rename")
        return PublishedDeploymentRelease(published, True)

    def measure(
        self,
        tenant_id: object,
        deployment_id: object,
        *,
        publication_lock: PublicationLockProof,
    ) -> ReleaseTreeMeasurement:
        """Remeasure one published release while publication is excluded."""

        self._require_locked(publication_lock)
        tenant = validate_uuid7(tenant_id)
        deployment = validate_uuid7(deployment_id)
        return measure_release_tree(
            self._release_root / tenant / "releases" / deployment,
            lock_manager=publication_lock,
            expected_owner=self._expected_owner,
        )

    def discard_staged(
        self,
        staged: StagedDeploymentRelease,
        *,
        publication_lock: PublicationLockProof,
    ) -> None:
        """Remove only the exact private tree represented by a staged result."""

        self._require_locked(publication_lock)
        _validate_staged(staged)
        self._discard_staged(staged, publication_lock=publication_lock)

    def reconcile_staging(
        self,
        protected: Mapping[str, Mapping[str, object]],
        *,
        publication_lock: PublicationLockProof,
    ) -> int:
        """Remove bounded unreferenced staging and verify every protected tree."""

        self._require_locked(publication_lock)
        names = _scan_names(self._staging_fd, maximum=_MAXIMUM_STAGING_ENTRIES)
        if any(
            _STAGING_NAME.fullmatch(name) is None
            and _DISCARDED_STAGING_NAME.fullmatch(name) is None
            for name in names
        ):
            raise ReleaseStoreError("release staging contains an unrecognized entry")
        discarded: set[str] = set()
        for name in names:
            match = _DISCARDED_STAGING_NAME.fullmatch(name)
            if match is None:
                continue
            staging_name = match.group(1)
            if staging_name in discarded:
                raise ReleaseStoreError("release staging has duplicate discard transitions")
            discarded.add(staging_name)
        recognized = {name for name in names if _STAGING_NAME.fullmatch(name) is not None}.union(
            discarded
        )
        if any(staging_name in names for staging_name in discarded):
            raise ReleaseStoreError("staging cleanup found canonical and discarded identities")
        unknown_protected = set(protected).difference(recognized)
        if unknown_protected:
            raise ReleaseStoreError("protected release staging is absent")
        removed = 0
        for name in names:
            if _DISCARDED_STAGING_NAME.fullmatch(name) is not None:
                _remove_staging_tree(
                    self._staging_fd,
                    name,
                    expected_owner=self._expected_owner,
                )
                removed += 1
                continue
            expected = protected.get(name)
            if expected is not None:
                measurement = measure_release_tree(
                    self._staging_root / name,
                    lock_manager=publication_lock,
                    expected_owner=self._expected_owner,
                )
                if measurement.digest.to_dict() != dict(expected):
                    raise ReleaseStoreError("protected release staging digest drifted")
                continue
            self._discard_name(name)
            removed += 1
        return removed

    def remove_release(
        self,
        tenant_id: object,
        deployment_id: object,
        *,
        expected_release_tree_digest: Mapping[str, object],
        publication_lock: PublicationLockProof,
    ) -> None:
        """Durably remove one exact unreferenced immutable release."""

        self._require_mutation_locked(publication_lock)
        tenant = validate_uuid7(tenant_id)
        deployment = validate_uuid7(deployment_id)
        expected_digest = _release_tree_digest(expected_release_tree_digest)
        retired_name = _retired_name(deployment, expected_digest)
        tenant_fd = _open_child_directory(
            self._release_fd,
            tenant,
            expected_owner=self._expected_owner,
            expected_mode=_RELEASE_DIRECTORY_MODE,
            label="tenant release namespace",
        )
        try:
            releases_fd = _open_child_directory(
                tenant_fd,
                "releases",
                expected_owner=self._expected_owner,
                expected_mode=_RELEASE_DIRECTORY_MODE,
                label="release namespace",
            )
            try:
                canonical_exists = _entry_exists(releases_fd, deployment)
                retired_exists = _entry_exists(releases_fd, retired_name)
                if canonical_exists:
                    if retired_exists:
                        raise ReleaseStoreError(
                            "release cleanup found canonical and retired identities"
                        )
                    measurement = self.measure(
                        tenant,
                        deployment,
                        publication_lock=publication_lock,
                    )
                    if measurement.digest != expected_digest:
                        raise ReleaseStoreError("release cleanup digest disagrees with authority")
                    _rename_no_replace(
                        releases_fd,
                        deployment,
                        releases_fd,
                        retired_name,
                    )
                    os.fsync(releases_fd)
                elif not retired_exists:
                    os.fsync(releases_fd)
                    return
                _remove_tree(
                    releases_fd,
                    retired_name,
                    expected_owner=self._expected_owner,
                )
            finally:
                os.close(releases_fd)
        finally:
            os.close(tenant_fd)

    def _open_or_create_release_namespace(self, tenant_id: str) -> int:
        tenant_fd = _open_or_create_directory(
            self._release_fd,
            tenant_id,
            expected_owner=self._expected_owner,
            mode=_RELEASE_DIRECTORY_MODE,
            label="tenant release namespace",
        )
        try:
            return _open_or_create_directory(
                tenant_fd,
                "releases",
                expected_owner=self._expected_owner,
                mode=_RELEASE_DIRECTORY_MODE,
                label="release namespace",
            )
        finally:
            os.close(tenant_fd)

    def _measure_staging(
        self,
        staged: StagedDeploymentRelease,
        *,
        publication_lock: PublicationLockProof,
    ) -> ReleaseTreeMeasurement:
        return measure_release_tree(
            self._staging_root / staged.staging_name,
            lock_manager=publication_lock,
            expected_owner=self._expected_owner,
        )

    def _discard_name(self, name: str) -> None:
        if _STAGING_NAME.fullmatch(name) is None:
            raise ReleaseStoreError("release staging name is not canonical")
        self._remove_discard_transition(name)

    def _discard_staged(
        self,
        staged: StagedDeploymentRelease,
        *,
        publication_lock: PublicationLockProof,
    ) -> None:
        discarded_name = _discarded_staging_name(staged.staging_name)
        canonical_exists = _entry_exists(self._staging_fd, staged.staging_name)
        discarded_exists = _entry_exists(self._staging_fd, discarded_name)
        if canonical_exists:
            if discarded_exists:
                raise ReleaseStoreError("staging cleanup found canonical and discarded identities")
            current = self._measure_staging(staged, publication_lock=publication_lock)
            if current != staged.measurement:
                raise ReleaseStoreError("staged release changed before cleanup")
            _rename_no_replace(
                self._staging_fd,
                staged.staging_name,
                self._staging_fd,
                discarded_name,
            )
            os.fsync(self._staging_fd)
        elif not discarded_exists:
            os.fsync(self._staging_fd)
            return
        self._remove_discard_transition(staged.staging_name)

    def _remove_discard_transition(self, staging_name: str) -> None:
        discarded_name = _discarded_staging_name(staging_name)
        canonical_exists = _entry_exists(self._staging_fd, staging_name)
        discarded_exists = _entry_exists(self._staging_fd, discarded_name)
        if canonical_exists:
            if discarded_exists:
                raise ReleaseStoreError("staging cleanup found canonical and discarded identities")
            _rename_no_replace(
                self._staging_fd,
                staging_name,
                self._staging_fd,
                discarded_name,
            )
            os.fsync(self._staging_fd)
        elif not discarded_exists:
            os.fsync(self._staging_fd)
            return
        _remove_staging_tree(
            self._staging_fd,
            discarded_name,
            expected_owner=self._expected_owner,
        )

    def _require_locked(self, publication_lock: PublicationLockProof) -> None:
        self._require_open()
        publication_lock.require_held(LockName.PUBLICATION, mode=LockMode.EXCLUSIVE)

    def _require_mutation_locked(self, publication_lock: PublicationLockProof) -> None:
        self._require_locked(publication_lock)
        publication_lock.require_held(LockName.TENANT_STATE, mode=LockMode.EXCLUSIVE)

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("release store is closed")


def _staging_name(tenant_id: str, deployment_id: str) -> str:
    name = f"{tenant_id}--{deployment_id}"
    if _STAGING_NAME.fullmatch(name) is None:  # pragma: no cover - validated inputs derive it
        raise ReleaseStoreError("derived release staging name is not canonical")
    return name


def _discarded_staging_name(staging_name: str) -> str:
    if _STAGING_NAME.fullmatch(staging_name) is None:
        raise ReleaseStoreError("release staging name is not canonical")
    return f".discarded-{staging_name}"


def _release_tree_digest(value: Mapping[str, object]) -> Digest:
    if set(value) != {"format", "algorithm", "value"}:
        raise ReleaseStoreError("release cleanup digest is not canonical")
    format_value = value["format"]
    algorithm = value["algorithm"]
    digest_value = value["value"]
    if type(format_value) is not str or type(algorithm) is not str or type(digest_value) is not str:
        raise ReleaseStoreError("release cleanup digest is not canonical")
    try:
        digest = Digest(format_value, algorithm, digest_value)
    except (ContractError, TypeError) as error:
        raise ReleaseStoreError("release cleanup digest is not canonical") from error
    if digest.format != RELEASE_TREE_FORMAT:
        raise ReleaseStoreError("release cleanup digest has the wrong format")
    return digest


def _retired_name(deployment_id: str, digest: Digest) -> str:
    return f".retired-{deployment_id}-{digest.value}"


def _entry_exists(parent_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ReleaseStoreError("release identity could not be inspected safely") from error
    return True


def _validate_staged(staged: StagedDeploymentRelease) -> None:
    if type(staged) is not StagedDeploymentRelease:
        raise TypeError("release publication requires one staged deployment")
    if (
        validate_uuid7(staged.tenant_id) != staged.tenant_id
        or validate_uuid7(staged.deployment_id) != staged.deployment_id
        or staged.staging_name != _staging_name(staged.tenant_id, staged.deployment_id)
    ):
        raise ReleaseStoreError("staged release identity is inconsistent")


def _open_validated_directory(
    path: Path,
    *,
    expected_owner: int,
    expected_group: int | None,
    expected_mode: int,
    label: str,
) -> int:
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except OSError as error:
        raise ReleaseStoreError(f"{label} cannot be opened safely") from error
    try:
        metadata = _validate_directory(
            os.fstat(descriptor),
            expected_owner=expected_owner,
            expected_mode=expected_mode,
            label=label,
        )
        if expected_group is not None and metadata.st_gid != expected_group:
            raise ReleaseStoreError(f"{label} has the wrong group")
        current = path.stat(follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
            raise ReleaseStoreError(f"{label} changed while it was opened")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_child_directory(
    parent_fd: int,
    name: str,
    *,
    expected_owner: int,
    expected_mode: int,
    label: str,
) -> int:
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise ReleaseStoreError(f"{label} cannot be opened safely") from error
    try:
        _validate_directory(
            os.fstat(descriptor),
            expected_owner=expected_owner,
            expected_mode=expected_mode,
            label=label,
        )
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise ReleaseStoreError(f"{label} changed while it was opened")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_directory(
    parent_fd: int,
    name: str,
    *,
    expected_owner: int,
    mode: int,
    label: str,
) -> int:
    created = False
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, mode=mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as error:
            raise ReleaseStoreError(f"{label} could not be created durably") from error
        else:
            created = True
        try:
            descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except OSError as error:
            raise ReleaseStoreError(f"{label} cannot be opened safely") from error
    except OSError as error:
        raise ReleaseStoreError(f"{label} cannot be opened safely") from error
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise ReleaseStoreError(f"{label} changed while it was opened")
        restrictive_mode = mode & 0o700
        opened_mode = stat.S_IMODE(opened.st_mode)
        if (
            stat.S_ISDIR(opened.st_mode)
            and opened.st_uid == expected_owner
            and opened_mode == restrictive_mode
            and restrictive_mode != mode
        ):
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            os.fsync(parent_fd)
            opened = os.fstat(descriptor)
        elif created and opened_mode != mode:
            raise ReleaseStoreError(f"{label} changed during creation")
        _validate_directory(
            opened,
            expected_owner=expected_owner,
            expected_mode=mode,
            label=label,
        )
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise ReleaseStoreError(f"{label} changed while it was normalized")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_directory(
    metadata: os.stat_result,
    *,
    expected_owner: int,
    expected_mode: int,
    label: str,
) -> os.stat_result:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_owner
        or stat.S_IMODE(metadata.st_mode) != expected_mode
    ):
        raise ReleaseStoreError(f"{label} has an unsafe inode shape")
    return metadata


def _scan_names(directory_fd: int, *, maximum: int) -> tuple[str, ...]:
    names: list[str] = []
    scan_fd = os.open(".", _DIRECTORY_FLAGS, dir_fd=directory_fd)
    try:
        with os.scandir(scan_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > maximum:
                    raise ReleaseStoreError("release staging exceeds its entry bound")
    finally:
        os.close(scan_fd)
    return tuple(sorted(names))


def _rename_no_replace(
    source_fd: int,
    source: str,
    destination_fd: int,
    destination: str,
) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:  # pragma: no cover - Linux/glibc host contract
        raise RuntimeError("renameat2 is required for release publication") from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            source_fd,
            os.fsencode(source),
            destination_fd,
            os.fsencode(destination),
            _RENAME_NOREPLACE,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(error_number, os.strerror(error_number), destination)
        raise OSError(error_number, os.strerror(error_number), destination)


def _remove_tree(parent_fd: int, name: str, *, expected_owner: int) -> None:
    try:
        root_fd = _open_child_directory(
            parent_fd,
            name,
            expected_owner=expected_owner,
            expected_mode=_RELEASE_DIRECTORY_MODE,
            label="release tree",
        )
    except ReleaseStoreError as error:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.fsync(parent_fd)
            return
        raise error
    try:
        _remove_directory_contents(root_fd, expected_owner=expected_owner)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _remove_directory_contents(directory_fd: int, *, expected_owner: int) -> None:
    with os.scandir(directory_fd) as iterator:
        names = tuple(sorted(entry.name for entry in iterator))
    for name in names:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = _open_child_directory(
                directory_fd,
                name,
                expected_owner=expected_owner,
                expected_mode=_RELEASE_DIRECTORY_MODE,
                label="release directory",
            )
            try:
                _remove_directory_contents(child, expected_owner=expected_owner)
                os.fsync(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) != _RELEASE_FILE_MODE
        ):
            raise ReleaseStoreError("release cleanup encountered an unsafe inode")
        os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _remove_staging_tree(parent_fd: int, name: str, *, expected_owner: int) -> None:
    try:
        root_fd = _open_staging_directory(
            parent_fd,
            name,
            expected_owner=expected_owner,
        )
    except ReleaseStoreError as error:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.fsync(parent_fd)
            return
        raise error
    try:
        _remove_staging_contents(root_fd, expected_owner=expected_owner)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    os.rmdir(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _remove_staging_contents(directory_fd: int, *, expected_owner: int) -> None:
    with os.scandir(directory_fd) as iterator:
        names = tuple(sorted(entry.name for entry in iterator))
    for name in names:
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = _open_staging_directory(
                directory_fd,
                name,
                expected_owner=expected_owner,
            )
            try:
                _remove_staging_contents(child, expected_owner=expected_owner)
                os.fsync(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory_fd)
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) not in {_RELEASE_FILE_MODE, 0o600}
        ):
            raise ReleaseStoreError("staging cleanup encountered an unsafe inode")
        os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _open_staging_directory(
    parent_fd: int,
    name: str,
    *,
    expected_owner: int,
) -> int:
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise ReleaseStoreError("staging directory cannot be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) not in {_RELEASE_DIRECTORY_MODE, 0o700}
        ):
            raise ReleaseStoreError("staging directory has an unsafe inode shape")
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ReleaseStoreError("staging directory changed while it was opened")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise
