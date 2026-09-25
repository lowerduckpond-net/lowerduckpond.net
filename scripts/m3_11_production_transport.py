"""Build immutable remote helpers and the sole guarded command transport."""

from __future__ import annotations

import hashlib
import io
import re
import shlex
import zipfile
from pathlib import Path

from scripts.m3_11_production_remote import ROOT, UNIT


def helper_bundle() -> tuple[bytes, str]:
    directory = Path(__file__).parent
    files = {
        "__main__.py": (
            b"from scripts.m3_11_production_remote import main\nraise SystemExit(main())\n"
        ),
        "scripts/__init__.py": b"",
        **{
            "scripts/" + name: (directory / name).read_bytes()
            for name in (
                "m3_11_production_fence.py",
                "m3_11_production_gate.py",
                "m3_11_production_journal.py",
                "m3_11_production_lease.py",
                "m3_11_production_probe.py",
                "m3_11_production_records.py",
                "m3_11_production_remote.py",
            )
        },
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o100400 << 16
            archive.writestr(info, raw)
    raw = output.getvalue()
    return raw, str(ROOT / (hashlib.sha256(raw).hexdigest() + ".pyz"))


def command(helper: str, token: str, action: str) -> str:
    if (
        re.fullmatch(re.escape(str(ROOT)) + r"/[0-9a-f]{64}\.pyz", helper) is None
        or re.fullmatch(r"[0-9a-f]{64}", token) is None
        or token == "0" * 64
        or not action
        or "\0" in action
    ):
        raise ValueError("production command has invalid transport authority")
    return shlex.join(
        [
            "sudo",
            "--non-interactive",
            "/usr/bin/systemd-run",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--expand-environment=no",
            "--description=Lower Duck Pond M3.11 production action",
            "--service-type=exec",
            "--unit=" + UNIT,
            "--property=ExitType=cgroup",
            "--property=KillMode=control-group",
            "--property=UMask=0077",
            "--property=TimeoutStopSec=15s",
            "/usr/bin/python3",
            "-I",
            "-B",
            helper,
            "action",
            token,
            action,
        ]
    )
