"""Persist migration admission conditions before draining predecessor services."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import cast

from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_probe as probe
from scripts import m3_11_production_records as records

UNITS = Path("/etc/systemd/system")
CGROUPS = Path("/sys/fs/cgroup")
NAME = "90-lowerduckpond-m3-11-migration.conf"
MAX_BYTES = 4096
PUBLISHED_MODE = 0o400
STATIC = (
    "lowerduckpond-static-reconcile.service",
    "lowerduckpond-static-emergency-reconcile.service",
    "lowerduckpond-static-worker@.service",
    "lowerduckpond-archive-export@.service",
    "lowerduckpond-archive-construction@.service",
    "lowerduckpond-archive-cleanup@.service",
    "lowerduckpond-static-reconcile.timer",
    "lowerduckpond-static-emergency-reconcile.timer",
    "lowerduckpond-archive-export.socket",
    "lowerduckpond-archive-construction.socket",
    "lowerduckpond-archive-cleanup.socket",
)
BACKUP = (
    "lowerduckpond-backup.service",
    "lowerduckpond-backup-maintenance.service",
    "lowerduckpond-backup-identity.service",
    "lowerduckpond-audit-verify.service",
    "lowerduckpond-audit-rotate.service",
    "lowerduckpond-backup.timer",
    "lowerduckpond-backup-maintenance.timer",
    "lowerduckpond-audit-verify.timer",
    "lowerduckpond-audit-rotate.timer",
)
# Background backup/protection must not rewrite the source of a retained capture
# before its exact snapshot and restore proof have been durably acknowledged.
FENCES = {**dict.fromkeys(STATIC, "lineage"), **dict.fromkeys(BACKUP, "backup-verified")}
PROCESS_PATTERN = (
    r"[/]usr/local/libexec/lowerduckpond/(backup[^ /]*|restic-check|latest-backup-snapshot|"
    r"restore-smoke-test|static-operator-adapter|static-request-decoder|execute-authorized-job|"
    r"reconcile-authorized-jobs|archive-[^ /]*-service)|(^|/)[r]estic([[:space:]]|$)"
)


def content(original: bytes, phase: str) -> bytes:
    if phase not in {"lineage", "backup-verified"}:
        raise ValueError("invalid production service phase")
    return (
        "# Original M3.11 transaction: " + journal.digest(original) + "\n"
        "[Unit]\nConditionPathExists=" + str(records.ROOT / (phase + ".json")) + "\n"
    ).encode("ascii")


def _directory(value: os.stat_result, owner: int) -> None:
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != owner
        or stat.S_IMODE(value.st_mode) not in {0o700, 0o755}
    ):
        raise ValueError("production service directory is unsafe")


def _file(value: os.stat_result, owner: int, *, partial: bool = False) -> None:
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != owner
        or value.st_nlink != 1
        or value.st_size > MAX_BYTES
        or stat.S_IMODE(value.st_mode) not in ({0o400, 0o600} if partial else {0o400})
    ):
        raise ValueError("production service condition metadata is unsafe")


def publish(directory: Path, raw: bytes, *, owner: int) -> None:  # noqa: PLR0912,PLR0915 - one durable file transition
    """Preserve exact installed bytes or resume only their original partial prefix."""
    if not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("production service condition exceeds its bound")
    parent = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _directory(os.fstat(parent), owner)
        try:
            os.mkdir(directory.name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        root = os.open(
            directory.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        try:
            opened = os.fstat(root)
            _directory(opened, owner)
            temporary = ".m3-11-" + hashlib.sha256(raw).hexdigest() + ".partial"
            try:
                final = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
            except FileNotFoundError:
                pass
            else:
                try:
                    _file(os.fstat(final), owner)
                    if os.read(final, MAX_BYTES + 1) != raw:
                        raise ValueError("production service condition changed")
                finally:
                    os.close(final)
                os.fsync(root)
                return
            # No other interrupted proposal may be discarded or relabeled.
            names = os.listdir(root)  # noqa: PTH208 - scan the pinned open directory
            if any(name.startswith(".m3-11-") and name != temporary for name in names):
                raise ValueError("production service condition has another pending proposal")
            try:
                fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=root,
                )
            except FileExistsError:
                previous = os.open(
                    temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root
                )
                try:
                    metadata = os.fstat(previous)
                    _file(metadata, owner, partial=True)
                    prefix = os.read(previous, MAX_BYTES + 1)
                    if not raw.startswith(prefix):
                        raise ValueError("production service condition has changed partial bytes")
                    # A crash after chmod leaves a complete read-only proposal.
                    if stat.S_IMODE(metadata.st_mode) == PUBLISHED_MODE:
                        if prefix != raw:
                            raise ValueError("read-only production service proposal is incomplete")
                        os.fsync(previous)
                        fd = -1
                    else:
                        fd = os.open(temporary, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=root)
                        if os.fstat(fd).st_ino != metadata.st_ino:
                            os.close(fd)
                            raise ValueError("production service proposal was replaced")
                        os.lseek(fd, len(prefix), os.SEEK_SET)
                finally:
                    os.close(previous)
            if fd >= 0:
                try:
                    while (position := os.lseek(fd, 0, os.SEEK_CUR)) < len(raw):
                        if os.write(fd, raw[position:]) <= 0:
                            raise OSError("production service condition write made no progress")
                    os.fchmod(fd, 0o400)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            current = directory.stat(follow_symlinks=False)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("production service directory changed")
            os.rename(temporary, NAME, src_dir_fd=root, dst_dir_fd=root)
            os.fsync(root)
        finally:
            os.close(root)
    finally:
        os.close(parent)


def run(arguments: list[str], *, stop: bool = False) -> bytes:
    result = subprocess.run(  # noqa: S603 - fixed administrative commands and discovered unit names
        arguments, capture_output=True, timeout=300 if stop else 20, check=False
    )
    if result.returncode or len(result.stdout) > 128 * 1024:
        raise ValueError("production service observation or drain failed")
    return result.stdout


def conditions(unit: str, phase: str) -> None:
    # Templates need a concrete, unstarted instance to load their effective
    # conditions. No service command is executed by LoadUnit.
    unit = unit.replace("@.", "@m3-11-condition-probe.")
    if (
        run(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"])
        == b"not-found\n"
    ):
        return
    loaded = json.loads(
        run(
            [
                "/usr/bin/busctl",
                "--json=short",
                "call",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1",
                "org.freedesktop.systemd1.Manager",
                "LoadUnit",
                "s",
                unit,
            ]
        )
    )
    if loaded.get("type") != "o" or len(loaded.get("data", [])) != 1:
        raise ValueError("production service object is invalid")
    value = json.loads(
        run(
            [
                "/usr/bin/busctl",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                loaded["data"][0],
                "org.freedesktop.systemd1.Unit",
                "Conditions",
            ]
        )
    )
    expected = ["ConditionPathExists", False, False, str(records.ROOT / (phase + ".json"))]
    if value.get("type") != "a(sbbsi)" or not any(
        type(item) is list and item[:4] == expected for item in value.get("data", [])
    ):
        raise ValueError("production service lost its required migration condition")


def drain(*, owner: int = 0) -> bytes:  # noqa: PLR0912 - ordered predecessor fencing and observations
    chain = records.decode(records.operate(records.ROOT, ["read"], b"", owner=owner))
    authority = journal.validate(chain)
    if authority["phase"] != "drained.started":
        raise ValueError("production phase does not authorize predecessor drain")
    original = cast(dict[str, object], authority["original"])
    predecessor = cast(str, original["predecessor"]).encode()
    if probe.read(probe.COMPLETION, owner=owner, mode=0o400) != predecessor:
        raise ValueError("production predecessor completion changed")
    selected = probe.SELECTION.parent / predecessor.split()[0].decode()
    if not probe.SELECTION.is_symlink() or probe.SELECTION.resolve(strict=True) != selected:
        raise ValueError("production predecessor selection changed")
    publication_raw = probe.read(probe.PUBLICATION, owner=owner, mode=0o400)
    publication = json.loads(publication_raw, object_pairs_hook=probe.unique_object)
    if (
        publication
        != {
            "format": "lowerduckpond-static-publication-gate-v1",
            "static_publication_enabled": False,
        }
        or publication["static_publication_enabled"] is not False
    ):
        raise ValueError("production publication must remain disabled")
    run(["/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact", str(selected)])
    for unit, phase in FENCES.items():
        publish(UNITS / (unit + ".d"), content(chain[0][1], phase), owner=owner)
    run(["/usr/bin/systemctl", "daemon-reload"])
    for unit, phase in FENCES.items():
        conditions(unit, phase)
    patterns = [unit.replace("@.", "@*.") for unit in FENCES]
    units = json.loads(
        run(["/usr/bin/systemctl", "list-units", "--all", "--output=json", "--no-pager", *patterns])
    )
    groups: list[str] = []
    names: list[str] = []
    for value in units:
        name = value["unit"]
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
            raise ValueError("unexpected unit in production drain")
        names.append(name)
        group = (
            run(["/usr/bin/systemctl", "show", name, "--property=ControlGroup", "--value"])
            .decode()
            .strip()
        )
        if group:
            if not group.startswith("/system.slice/") or ".." in Path(group).parts:
                raise ValueError("production unit has an unexpected control group")
            groups.append(group)
    if names:
        run(["/usr/bin/systemctl", "stop", *names], stop=True)
    active = json.loads(
        run(
            [
                "/usr/bin/systemctl",
                "list-units",
                "--output=json",
                "--no-pager",
                "--state=active,activating,deactivating,reloading,refreshing,maintenance",
                *patterns,
            ]
        )
    )
    if active:
        raise ValueError("production predecessor units remain active")
    for group in groups:
        try:
            events = (CGROUPS / group.lstrip("/") / "cgroup.events").read_text(encoding="ascii")
        except FileNotFoundError:
            continue
        if "populated 0" not in events.splitlines():
            raise ValueError("production predecessor descendants remain")
    process = subprocess.run(  # noqa: S603 - fixed legacy process observation; never kill arbitrary PIDs
        ["/usr/bin/pgrep", "--full", "--", PROCESS_PATTERN],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if process.returncode != 1:
        raise ValueError("production predecessor commands remain outside drained services")
    if (
        probe.read(probe.COMPLETION, owner=owner, mode=0o400) != predecessor
        or probe.read(probe.PUBLICATION, owner=owner, mode=0o400) != publication_raw
        or probe.SELECTION.resolve(strict=True) != selected
    ):
        raise ValueError("production predecessor changed during drain")
    return journal.canonical(
        {
            "format": "lowerduckpond-m3-11-predecessor-drain-v1",
            "original_sha256": authority["original_sha256"],
            "predecessor_sha256": journal.digest(predecessor),
            "fences": {
                unit: journal.digest(content(chain[0][1], phase)) for unit, phase in FENCES.items()
            },
            "active_units": [],
            "external_commands": [],
            "populated_groups": [],
        }
    )
