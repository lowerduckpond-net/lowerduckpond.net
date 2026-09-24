"""Initialize only the fresh, privileged reconstruction fixture before PID 1."""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

DISKS = ("etc", "srv", "var-lib", "var-cache")


def identity(root: Path = Path("/")) -> None:
    marker = root / "root/.restore-fixture-initialized"
    if not marker.exists():
        (root / "etc/machine-id").write_bytes(b"")
        (root / "var/lib/dbus/machine-id").unlink(missing_ok=True)
        marker.touch(mode=0o600)


def loop_nodes(root: Path = Path("/")) -> None:
    # Docker snapshots /dev at creation. The kernel can allocate further loop
    # devices without udev creating their nodes in this private /dev. Publish
    # the current kernel pool and room for our four images before mount(8),
    # including on reboot before systemd processes the persistent fstab.
    indices = [int(path.name[4:]) for path in (root / "sys/block").glob("loop[0-9]*")]
    for index in range(max(indices, default=-1) + len(DISKS) + 1):
        path = root / f"dev/loop{index}"
        device = os.makedev(7, index)
        try:
            os.mknod(path, stat.S_IFBLK | 0o600, device)
        except FileExistsError:
            metadata = path.lstat()
            if not stat.S_ISBLK(metadata.st_mode) or metadata.st_rdev != device:
                raise ValueError("unexpected fixture loop device") from None


def mounts() -> None:
    # systemd reads /etc unit definitions and enablement links before mounting
    # local filesystems. Present our persistent parents before it builds the
    # boot transaction, including the recovery gate and its ordering.
    root = Path("/root/restore-disks")
    if not root.exists():
        return
    for name in DISKS:
        subprocess.run(  # noqa: S603 - fixed paths in the owned privileged fixture
            [
                "/usr/bin/mount",
                "-t",
                "ext4",
                "-o",
                "loop,nodev,nosuid",
                str(root / f"{name}.ext4"),
                "/" + name.replace("-", "/"),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )


if __name__ == "__main__":
    if sys.argv[1:] == ["destination"]:
        loop_nodes()
        mounts()
        identity()
        os.execv("/sbin/init", ["/sbin/init"])  # noqa: S606 - fixed fixture PID 1
    elif sys.argv[1:] == ["acme"]:
        # Docker has assigned the container address by the time this runs.
        Path("/root/restore-acme/address").write_text(
            socket.gethostbyname(socket.gethostname()), encoding="ascii"
        )
        os.execv(  # noqa: S606 - fixed fixture process, supervised by Docker's init
            "/usr/bin/python3", ["python3", "-I", "-B", "/root/restore-acme/server.py"]
        )
    else:
        raise ValueError("unknown reconstruction fixture")
