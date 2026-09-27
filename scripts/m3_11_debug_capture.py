"""Private pre/post-action journals and executable-input provenance for diagnosis."""

from __future__ import annotations

import hashlib
import os
import subprocess
import traceback
from pathlib import Path

from scripts import qualification_restore as owned
from scripts.m3_11_debug_files import copy, fingerprint
from scripts.m3_11_private_inputs import write_private
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
        "helpers": {str(path.relative_to(REPOSITORY)): fingerprint(path) for path in paths},
    }
    if repair is not None:
        path = repair.absolute()
        if path.resolve() != path or not path.is_relative_to(REPOSITORY) or path.suffix != ".py":
            raise ValueError("repair must be a tracked Python script in this checkout")
        git(REPOSITORY, "ls-files", "--error-unmatch", "--", str(path.relative_to(REPOSITORY)))
        copy(path, attempt / "repair.py")
        value["repair_sha256"] = fingerprint(attempt / "repair.py")
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
