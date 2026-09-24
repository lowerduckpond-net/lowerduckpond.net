from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from scripts import qualification_restore_init as boot


def test_fixture_machine_identity_is_reset_only_before_first_boot(tmp_path: Path) -> None:
    for name in ("root", "etc", "var/lib/dbus"):
        (tmp_path / name).mkdir(parents=True)
    machine = tmp_path / "etc/machine-id"
    dbus = tmp_path / "var/lib/dbus/machine-id"
    machine.write_text("build-image-id")
    dbus.symlink_to(machine)
    boot.identity(tmp_path)
    assert machine.read_bytes() == b""
    assert not dbus.is_symlink()
    machine.write_text("first-boot-id")
    dbus.symlink_to(machine)
    boot.identity(tmp_path)
    assert machine.read_text() == "first-boot-id"
    assert dbus.read_text() == "first-boot-id"


def test_private_device_nodes_cover_kernel_pool_and_three_new_mounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = tmp_path / "sys/block"
    block.mkdir(parents=True)
    for index in (0, 7, 8):
        (block / f"loop{index}").mkdir()
    nodes: dict[Path, tuple[int, int]] = {}
    monkeypatch.setattr(
        os, "mknod", lambda path, mode, device: nodes.update({path: (mode, device)})
    )
    boot.loop_nodes(tmp_path)
    assert set(nodes) == {tmp_path / f"dev/loop{index}" for index in range(12)}
    for index in range(12):
        mode, device = nodes[tmp_path / f"dev/loop{index}"]
        assert stat.S_ISBLK(mode) and stat.S_IMODE(mode) == 0o600  # noqa: PLR2004
        assert os.major(device) == 7 and os.minor(device) == index  # noqa: PLR2004


def test_device_setup_refuses_a_preexisting_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev/loop0").write_bytes(b"foreign")

    def collision(*args: object) -> None:
        raise FileExistsError

    monkeypatch.setattr(os, "mknod", collision)
    with pytest.raises(ValueError, match="unexpected fixture loop device"):
        boot.loop_nodes(tmp_path)
    assert (tmp_path / "dev/loop0").read_bytes() == b"foreign"
