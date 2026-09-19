from __future__ import annotations

import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from scripts import qualification_case as case
from scripts import qualification_local as local
from scripts import qualification_retirement as retirement
from scripts.qualification_context import HOST_ENV, IMAGE_ENV, resource_names, run_lease

IMAGE_ID = "sha256:" + "c" * 64


@pytest.mark.parametrize("lost_response", [False, True])
def test_cleanup_untags_only_the_owned_reference_and_preserves_shared_layers(
    monkeypatch: pytest.MonkeyPatch, lost_response: bool
) -> None:
    first, second = [resource_names(uuid.uuid7().hex) for _ in range(2)]
    reference = f"molecule_local/{first[IMAGE_ENV]}"
    other = f"molecule_local/{second[IMAGE_ENV]}"
    tags = {reference: IMAGE_ID, other: IMAGE_ID, "ubuntu:26.04": IMAGE_ID}
    monkeypatch.setattr(case, "owned_containers", lambda *args, **kwargs: {})
    commands: list[list[str]] = []

    def query(command: list[str], **kwargs: object) -> bytes | None:
        commands.append(command)
        assert kwargs["environment"] == first
        if command[1:3] == ["image", "rm"]:
            assert command == ["docker", "image", "rm", reference]
            del tags[reference]
            return None if lost_response else b"Untagged\n"
        assert command[1:3] == ["image", "ls"]
        assert command[command.index("--filter") + 1] == f"reference={reference}"
        return tags.get(reference, "").encode()

    monkeypatch.setattr(case, "bounded_command", query)
    case.remove_owned_image(first)
    assert tags == {other: IMAGE_ID, "ubuntu:26.04": IMAGE_ID}
    case.remove_owned_image(first)  # Already removed after a lost response is harmless.
    assert len([command for command in commands if "rm" in command]) == 1


@pytest.mark.parametrize(
    "inventory", [None, b"not-an-image", (IMAGE_ID + "\n" + IMAGE_ID).encode()]
)
def test_unknown_image_inventory_cannot_remove_anything(
    monkeypatch: pytest.MonkeyPatch, inventory: bytes | None
) -> None:
    monkeypatch.setattr(case, "owned_containers", lambda *args, **kwargs: {})

    def query(command: list[str], **kwargs: object) -> bytes | None:
        assert command[1:3] == ["image", "ls"]
        return inventory

    monkeypatch.setattr(case, "bounded_command", query)
    with pytest.raises(ValueError, match="inventory"):
        case.remove_owned_image(resource_names(uuid.uuid7().hex))


def test_retained_fixture_never_reaches_image_removal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(case, "owned_containers", lambda *args, **kwargs: {HOST_ENV: "a" * 64})

    def forbidden(*args: object, **kwargs: object) -> bytes:
        pytest.fail("retained fixture image must not be inspected or removed")

    monkeypatch.setattr(case, "bounded_command", forbidden)
    with pytest.raises(ValueError, match="containers remain"):
        case.remove_owned_image(resource_names(uuid.uuid7().hex))


def test_failed_removal_is_reported_without_force_or_prune(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(case, "owned_containers", lambda *args, **kwargs: {})

    def query(command: list[str], **kwargs: object) -> bytes | None:
        assert "--force" not in command and "prune" not in command
        return None if command[2] == "rm" else IMAGE_ID.encode()

    monkeypatch.setattr(case, "bounded_command", query)
    with pytest.raises(ValueError, match="did not complete"):
        case.remove_owned_image(resource_names(uuid.uuid7().hex))


@pytest.mark.parametrize("environment", [{}, {IMAGE_ENV: "ubuntu:26.04"}])
def test_unowned_images_cannot_be_cleaned(environment: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        case.remove_owned_image(environment)


@pytest.mark.parametrize("create_only,status", [(True, 0), (False, 17)])
def test_create_only_or_failed_complete_run_preserves_the_original_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, create_only: bool, status: int
) -> None:
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST", "unix:///disposable/docker.sock")
    monkeypatch.setenv("M3_10_ARCHIVE_BACKEND", "minio")
    monkeypatch.setattr(shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0 if command[1] == "info" else 1
        ),
    )
    monkeypatch.setattr(subprocess, "call", lambda *args, **kwargs: status)

    def cleanup(environment: dict[str, str]) -> None:
        assert not create_only, "create-only runs retain their image"
        raise ValueError("retained fixture image must remain available")

    monkeypatch.setattr(local, "remove_owned_image", cleanup)
    assert local.run(tmp_path, create_only=create_only) == status


def test_image_only_retry_does_not_reconstruct_destroyed_fixture_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)
    monkeypatch.setenv("DOCKER_HOST", "unix:///disposable/docker.sock")
    environment = local.create_environment(tmp_path)
    original = b"original diagnostic failure\n"
    (tmp_path / "failure.json").write_bytes(original)
    removed: list[dict[str, str]] = []
    monkeypatch.setattr(retirement, "remove_owned_image", removed.append)

    def forbidden(*args: object, **kwargs: object) -> str:
        pytest.fail("image-only cleanup cannot inspect or mutate destroyed host state")

    monkeypatch.setattr(retirement, "local_proof", forbidden)
    retirement.retire_image(tmp_path)
    retirement.retire_image(tmp_path)
    assert all(value[IMAGE_ENV] == environment[IMAGE_ENV] for value in removed)
    assert (tmp_path / "failure.json").read_bytes() == original
    assert not (tmp_path / "retirement.json").exists()


def test_active_run_blocks_image_only_cleanup(tmp_path: Path) -> None:
    with run_lease(tmp_path, create=True), pytest.raises(BlockingIOError):
        retirement.retire_image(tmp_path)
