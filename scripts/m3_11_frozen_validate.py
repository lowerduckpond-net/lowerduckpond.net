"""Isolated offline full-byte proof child for a sealed staged caller.

Its parent verifies this file, interpreter, clean source and transitive inputs
before invocation. No network, provider operation, mount, or original-file write
is available. The 600-second parent deadline encloses the 300-second cumulative
debugfs parser budget; neither is a worker lifecycle limit.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import cast


def readonly(image: Path, scratch: Path) -> None:
    def below(value: object) -> bool:
        return isinstance(value, str | bytes | os.PathLike) and Path(
            os.fsdecode(value)
        ).resolve().is_relative_to(scratch)

    def audit(event: str, args: tuple[object, ...]) -> None:
        if event.startswith("socket.") or event in {
            "os.system",
            "os.exec",
            "os.posix_spawn",
            "os.posix_spawnp",
        }:
            raise RuntimeError("offline proof prohibits network and shell")
        if event == "subprocess.Popen":
            _executable, argv, _cwd, _environment = args
            if not (
                isinstance(argv, list | tuple)
                and len(argv) == 4  # noqa: PLR2004 - exact read-only debugfs grammar
                and argv[0] == "/usr/sbin/debugfs"
                and argv[1] == "-R"
                and argv[3] == str(image)
                and isinstance(argv[2], str)
                and re.fullmatch(r"(ls -p|stat|cat) /[A-Za-z0-9_./-]*", argv[2])
                and all(part not in {".", ".."} for part in argv[2].split(" ", 2)[-1].split("/"))
            ):
                raise RuntimeError("offline proof permits only exact read-only debugfs")
        if event == "open":
            path, mode, flags = args
            writable = (isinstance(mode, str) and any(char in mode for char in "wax+")) or (
                isinstance(flags, int)
                and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            )
            if writable and not isinstance(path, int) and path != "/dev/null" and not below(path):
                raise RuntimeError("offline proof writes only new scratch")
        if event in {
            "os.mkdir",
            "os.chmod",
            "os.chown",
            "os.truncate",
            "os.utime",
            "os.setxattr",
            "os.removexattr",
        } and not below(args[0]):
            raise RuntimeError("offline proof mutation outside scratch")
        if event in {"os.rename", "os.link", "os.symlink"}:
            raise RuntimeError("offline proof prohibits path substitution")
        if event in {"os.remove", "os.rmdir"} and not (
            below(args[0])
            and Path(os.fsdecode(cast(str, args[0]))).resolve().is_relative_to(scratch / "tmp")
        ):
            raise RuntimeError("offline proof removes only its new temporary data")

    sys.addaudithook(audit)


def main() -> None:
    if len(sys.argv) != 4:  # noqa: PLR2004 - script plus three exact paths
        raise ValueError("offline proof requires exact evidence, selection and new scratch")
    sys.dont_write_bytecode = True
    os.umask(0o077)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts.m3_11_frozen_local import verify_local  # noqa: PLC0415
    from scripts.m3_11_private_inputs import read_private  # noqa: PLC0415
    from scripts.m3_11_retirement_files import directory  # noqa: PLC0415

    evidence_path, selection_path, scratch = (Path(value) for value in sys.argv[1:])
    evidence, selection = read_private(evidence_path), read_private(selection_path)
    directory(scratch.parent)
    if scratch.exists() or scratch.is_symlink() or not scratch.is_absolute():
        raise ValueError("offline proof scratch is not new and absolute")
    readonly(Path(str(evidence["image_path"])), scratch)
    scratch.mkdir(mode=0o700)
    (scratch / "tmp").mkdir(mode=0o700)
    tempfile.tempdir = str(scratch / "tmp")
    print(
        json.dumps(verify_local(evidence, selection, scratch=scratch), sort_keys=True), flush=True
    )


if __name__ == "__main__":
    main()
