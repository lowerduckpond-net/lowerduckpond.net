"""Private delivery crosses workspace/container user identities without copying ownership."""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended import docker, setup
from scripts.m3_11_unattended.config import Configuration, cleanup_configuration
from scripts.m3_11_unattended.model import stamp

from .test_m3_11_unattended_lifecycle import CANARY, TARGETS


def delivery_configuration(path: Path) -> None:
    manifest = setup.template()
    manifest["targets"], manifest["journal_vault"] = dataclasses.asdict(TARGETS), "a" * 26
    for role in ("provision", "cleanup", "production"):
        section = manifest[role]
        assert isinstance(section, dict)
        section["service_account_expires_at"] = stamp(datetime.now(UTC) + timedelta(days=7))
    write_private(
        path,
        setup.document(
            manifest, {role: CANARY + role for role in ("provision", "cleanup", "production")}
        ),
    )


class LocalDelivery:
    """Execute the real container delivery programs against isolated local directories."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.commands = 0
        self.removed = False
        for name in ("evidence", "configuration", "cleanup"):
            (root / name).mkdir(mode=0o700)

    def command(self, *arguments: str, stdin: bytes | None = None) -> bytes:
        self.commands += 1
        assert all(CANARY not in argument for argument in arguments)
        if arguments[0] == "run":
            return b"delivery-container"
        assert arguments[:2] == ("exec", "--interactive")
        index = arguments.index("-c") + 1
        program = arguments[index]
        for name in ("evidence", "configuration", "cleanup"):
            program = program.replace("'/" + name, "'" + str(self.root / name))
        completed = subprocess.run(  # noqa: S603 - actual fixed delivery program, isolated paths
            [sys.executable, "-c", program, *arguments[index + 1 :]],
            input=stdin,
            capture_output=True,
            check=True,
        )
        assert completed.stdout == completed.stderr == b""
        return completed.stdout

    def remove_controller(self, _name: str) -> None:
        self.removed = True


def test_private_delivery_and_replacement_use_container_owned_files(tmp_path: Path) -> None:
    host = LocalDelivery(tmp_path)
    config = tmp_path / "source.json"
    delivery_configuration(config)
    original = config.read_bytes()
    # Replacing an earlier delivery must not follow an existing symlink or
    # truncate its target. Fresh inodes also shed a copied workspace owner.
    for name, filename in (("configuration", "controller.json"), ("cleanup", "cleanup.json")):
        (tmp_path / name / filename).symlink_to(config)
    for _ in range(2):
        run_id = str(uuid.uuid7())
        docker.initialize_run(
            cast(docker.Docker, host),
            image="fake-image",
            request=b"{}\n",
            run_id=run_id,
            config=config,
        )
        assert read_private(tmp_path / "evidence/runs" / run_id / "request.json") == {}
        installed = tmp_path / "configuration/controller.json"
        selected = Configuration.load(installed)
        targets, vault, authority = cleanup_configuration(tmp_path / "cleanup/cleanup.json")
        assert (targets, vault, authority) == (
            selected.targets,
            selected.journal_vault,
            selected.cleanup,
        )
        assert installed.read_bytes() == original == config.read_bytes()
        for path in (installed, tmp_path / "cleanup/cleanup.json"):
            assert not path.is_symlink()
            assert path.stat().st_uid == os.geteuid()
            assert path.stat().st_mode & 0o777 == 0o600  # noqa: PLR2004 - required private mode
        assert set(read_private(tmp_path / "cleanup/cleanup.json")) == {
            "format",
            "targets",
            "journal_vault",
            "cleanup",
        }
    assert host.removed


def test_unsafe_source_configuration_is_rejected_before_docker_delivery(tmp_path: Path) -> None:
    host = LocalDelivery(tmp_path)
    config = tmp_path / "source.json"
    delivery_configuration(config)
    config.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe metadata"):
        docker.initialize_run(
            cast(docker.Docker, host),
            image="fake-image",
            request=b"{}\n",
            run_id=str(uuid.uuid7()),
            config=config,
        )
    assert host.commands == 0
