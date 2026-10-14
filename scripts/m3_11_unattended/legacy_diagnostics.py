"""Closed catalog of reviewed historical fixture programs, never a generic waiver.

These are program-content hashes, not container IDs or production inventory.
The four fixture programs invoke the local MinIO harness; the persistence probe
uses ProviderDouble/FileJournal. Unknown programs require investigation.
"""

from __future__ import annotations

import hashlib
import io
import re
import tarfile

from scripts.m3_11_unattended.docker import OWNER, Docker, helper_volume
from scripts.m3_11_unattended.model import LifecycleError, digest

# Exact reviewed historical shell/Python programs, with separate argv checks.
PROGRAMS = {
    "ci-failed-retirement": "50e37ddb0620dc1aba03ee592b8dcb88bfc2df488127985d3bbdd3c22ba934c9",
    "complete": "04d150ebba92108ac2c5eedecd9ed4175d7db79c989cad0c6a8332f0e5b1eb0d",
    "local-restore-negative": "6d8c250427c514367ab347402dd455e1bd8a9d1f8e92c2ad3440c95ded9b23a7",
    "reboot-diagnostic": "3b67a7548111eb3ae87c5d6e296505c2e4a5c63ef701bb40598d85ec1d7a153b",
}
PROBE_SHA256 = "de8fbe7824a280c5fdb695a9d172f493c1fc8268f51eee7992a7aef271b2eb81"
LOCAL_SHA256 = "38114ddc6c7c4e032b0d1b394ed36796a8b2a81bdbdf7b7e054c9d6e7abe5cf6"
SOURCES = {
    "ci-failed-retirement": "cf9aeabcbeec0f93f198a27fa6d97c67ebd3d0fd",
    "complete": "e04c225869dc1fc4a8e1d3c7fefe4feafae856b1",
    "local-restore-negative": "a222c11ed7ab492fa6b0991b0ca1f2b6b1a13ae8",
    "reboot-diagnostic": "0230e45a854a048fc8d24d9d9292df09b3c2a290",
    "agent-exit": "3ad0656c4a16b738754eef583e8a49995fc0afbd",
    "coder-probe-controller": "0230e45a854a048fc8d24d9d9292df09b3c2a290",
}
MAX_SCRIPT = 256 * 1024


def script_digest(docker: Docker, container: str, path: str) -> str:
    raw = docker.command("cp", container + ":" + path, "-")
    if len(raw) > 2 * MAX_SCRIPT:
        raise LifecycleError("legacy diagnostic source exceeds its bound")
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        members = archive.getmembers()
        if len(members) != 1 or not members[0].isfile() or not 0 < members[0].size <= MAX_SCRIPT:
            raise LifecycleError("legacy diagnostic source is not one regular file")
        stream = archive.extractfile(members[0])
        if stream is None:
            raise LifecycleError("legacy diagnostic source is unavailable")
        return hashlib.sha256(stream.read(MAX_SCRIPT + 1)).hexdigest()


def original(docker: Docker, actual: dict[str, object]) -> str:
    config = actual["Config"]
    if not isinstance(config, dict) or config.get("Entrypoint") != [
        "/usr/local/bin/mise",
        "exec",
        "--",
    ]:
        raise LifecycleError("unrecognized retained diagnostic entrypoint")
    labels, command = config.get("Labels"), config.get("Cmd")
    if (
        not isinstance(labels, dict)
        or not isinstance(command, list)
        or not all(isinstance(x, str) for x in command)
    ):
        raise LifecycleError("unrecognized retained diagnostic command")
    source, name = labels.get(OWNER + ".source"), str(actual["Name"])
    role = next(
        (
            key
            for key in (*PROGRAMS, "agent-exit", "coder-probe-controller")
            if re.fullmatch(r"/ldp-m311-" + key + r"-[a-f0-9]{12,32}", name)
        ),
        None,
    )
    if role is None:
        raise LifecycleError("unrecognized retained diagnostic role")
    if source != SOURCES[role]:
        raise LifecycleError("retained diagnostic source revision is unreviewed")
    expected: list[str]
    if role in PROGRAMS:
        if len(command) < 3 or hashlib.sha256(command[2].encode()).hexdigest() != PROGRAMS[role]:  # noqa: PLR2004
            raise LifecycleError("retained diagnostic program changed")
        expected = {
            "ci-failed-retirement": ["bash", "-c", command[2]],
            "complete": ["bash", "-c", command[2], "complete-validation", str(source)],
            "local-restore-negative": [
                "/bin/bash",
                "-c",
                command[2],
                "local-restore-negative",
                str(source),
            ],
            "reboot-diagnostic": [
                "python3",
                "-c",
                command[2],
                "/evidence/diagnostics/reboot-" + name.rsplit("-", 1)[1],
            ],
        }[role]
        program = script_digest(
            docker, str(actual["Id"]), "/work/source/scripts/qualification_local.py"
        )
        if program != LOCAL_SHA256:
            raise LifecycleError("retained fixture local-only guard differs")
    else:
        expected = ["uv", "run", "--no-sync", "--frozen", "python", "/probe/probe.py", str(source)]
        mounts = actual.get("Mounts")
        if not isinstance(mounts, list) or {m.get("Destination") for m in mounts} != {
            "/probe",
            "/opt/lifecycle",
        }:
            raise LifecycleError("retained probe has unexplained access")
        helper = next(m for m in mounts if m["Destination"] == "/opt/lifecycle")
        if helper.get("Name") != helper_volume(str(source)) or helper.get("RW") is not False:
            raise LifecycleError("retained probe helper differs")
        program = script_digest(docker, str(actual["Id"]), "/probe/probe.py")
        if program != PROBE_SHA256:
            raise LifecycleError("retained probe source differs")
    if command != expected:
        raise LifecycleError("retained diagnostic arguments differ")
    return digest(
        {"role": role, "command": command, "source_revision": source, "program_sha256": program}
    )
