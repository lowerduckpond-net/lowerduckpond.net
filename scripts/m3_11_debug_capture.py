"""Private pre/post-action journals and executable-input provenance for diagnosis."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import traceback
from pathlib import Path

from scripts import qualification_restore as owned
from scripts.m3_11_debug_files import MAX_FILE, fingerprint
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import MAX_BYTES
from scripts.production_qualification_inputs import git
from scripts.qualification_probe import document

REPOSITORY = Path(__file__).resolve().parents[1]
UNITS = (
    "lowerduckpond-host-restore.service",
    "lowerduckpond-host-restore-archive-private.service",
    "lowerduckpond-host-restore-archive-installed.service",
    "caddy.service",
    "lowerduckpond-m3-11-public-caddy.service",
)


def exception(error: BaseException) -> dict[str, object]:
    return {
        "exception": type(error).__name__,
        "locations": [
            {"file": Path(frame.filename).name, "line": frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)[-12:]
        ],
    }


def source_bytes(path: Path, *, maximum: int = MAX_FILE) -> bytes:
    """Observe checkout code, which can be group-writable or an empty module.

    Retained evidence and private executable copies still use fingerprint's
    stricter metadata rules. This observation grants no qualification authority.
    """
    if path.resolve() != path or not path.is_relative_to(REPOSITORY):
        raise ValueError("diagnostic source path is redirected or outside the checkout")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o002
            or before.st_nlink != 1
            or not 0 <= before.st_size <= maximum
        ):
            raise ValueError("diagnostic source has unsafe metadata")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or len(raw) != before.st_size:
            raise ValueError("diagnostic source changed while reading")
    return raw


def controller(attempt: Path, repair: Path | None) -> None:
    revision = git(REPOSITORY, "rev-parse", "HEAD").decode().strip()
    patch = git(REPOSITORY, "diff", "--binary", "HEAD")
    with (attempt / "controller.patch").open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(patch)
    # Include new controller modules during local development too. Only hashes
    # leave this private record; credentials are not executable inputs.
    paths = sorted(
        {
            *REPOSITORY.glob("scripts/*.py"),
            *REPOSITORY.glob("config/ansible/molecule/m3_8/tests/*.py"),
        }
    )
    value: dict[str, object] = {
        "revision": revision,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "helpers": {
            str(path.relative_to(REPOSITORY)): hashlib.sha256(source_bytes(path)).hexdigest()
            for path in paths
        },
    }
    if repair is not None:
        path = repair.absolute()
        if path.resolve() != path or not path.is_relative_to(REPOSITORY) or path.suffix != ".py":
            raise ValueError("repair must be a tracked Python script in this checkout")
        git(REPOSITORY, "ls-files", "--error-unmatch", "--", str(path.relative_to(REPOSITORY)))
        script = source_bytes(path, maximum=MAX_BYTES)
        if not script:
            raise ValueError("diagnostic repair script is empty")
        with (attempt / "repair.py").open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(script)
            stream.flush()
            os.fsync(stream.fileno())
        value["repair_sha256"] = fingerprint(attempt / "repair.py")
        if value["repair_sha256"] != hashlib.sha256(script).hexdigest():
            raise ValueError("diagnostic repair copy differs from captured source")
        value["repair_path"] = str(path.relative_to(REPOSITORY))
    write_private(attempt / "controller.json", value)


def checkpoint(root: Path, attempt: Path, label: str, environment: dict[str, str]) -> None:
    """Read bounded journals without restarting services or copying live databases."""
    destination = str(document(root / "restore/destination.json")["id"])
    with (attempt / (label + ".journals.log")).open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        for unit in UNITS:
            stream.write((unit + "\n").encode())
            stream.flush()
            for args in (
                (
                    "systemctl",
                    "show",
                    unit,
                    "--property=ActiveState,SubState,Result,ExecMainStatus,ExecMainStartTimestamp,ExecMainExitTimestamp,CPUUsageNSec",
                ),
                ("journalctl", "--unit=" + unit, "--no-pager", "--output=short-iso", "--lines=100"),
            ):
                subprocess.run(  # noqa: S603 - fixed read-only commands, validated owned ID
                    ["docker", "exec", destination, *args],  # noqa: S607 - Docker from the qualification toolchain
                    env=environment,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    timeout=25,
                    check=False,
                )
    write_private(attempt / (label + ".observation.json"), owned.observations(environment))
