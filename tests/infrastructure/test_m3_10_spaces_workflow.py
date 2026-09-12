from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
PHASES = ("create", "prepare", "converge", "idempotence", "verify", "destroy")


def executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o755)


@pytest.mark.parametrize("relative", [False, True])
def test_spaces_workflow_keeps_evidence_paths_stable_across_phase_directories(
    tmp_path: Path, relative: bool
) -> None:
    checkout = tmp_path / "checkout"
    (checkout / "config/ansible").mkdir(parents=True)
    artifact = tmp_path / "artifact.tar"
    artifact.write_bytes(b"disposable artifact")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    wrapper = checkout / "scripts/m3-10-spaces-qualification"
    source = (ROOT / "scripts/m3-10-spaces-qualification").read_text()
    executable(
        wrapper,
        source.replace(
            "/tmp/lowerduckpond-static-host-agent-m3-8.tar",  # noqa: S108 - replace fixed input only
            str(artifact),
        ),
    )
    loader = checkout / "scripts/lib/m3-10-production-state"
    loader.parent.mkdir()
    loader.write_text("# State loading is replaced by disposable environment inputs.\n")
    commands = tmp_path / "commands"
    executable(
        commands / "git",
        "#!/bin/bash\nif [[ $1 == rev-parse ]]; then printf '%040d\\n' 0; fi\n",
    )
    executable(commands / "docker", "#!/bin/bash\nif [[ $1 == inspect ]]; then exit 1; fi\n")
    executable(commands / "tofu", "#!/bin/bash\nexit 0\n")
    executable(
        commands / "uv",
        """#!/usr/bin/python3
import json, os, sys
from pathlib import Path
if 'molecule' in sys.argv:
    phase = sys.argv[sys.argv.index('molecule') + 1]
    destination = Path(os.environ['M3_10_INSTALLED_REPORT'])
    assert destination.is_absolute(), 'installed report path changed meaning after chdir'
    if phase == 'verify':
        destination.write_text(json.dumps({'artifact_sha256': os.environ['TEST_ARTIFACT']}))
if 'scripts.m3_10_qualification_report' in sys.argv:
    directory = Path(sys.argv[-1])
    assert directory.is_absolute(), 'final evidence directory is relative'
    for phase in ('create', 'prepare', 'converge', 'idempotence', 'verify', 'destroy'):
        assert (directory / (phase + '.passed')).read_text() == 'passed\\n'
    assert (directory / 'installed.json').exists()
    (directory / 'qualification.json').write_text('{}')
""",
    )
    evidence = "evidence/runs" if relative else str(tmp_path / "private evidence")
    result = subprocess.run(  # noqa: S603 - copied wrapper with fixed disposable command doubles
        [str(wrapper)],
        env={
            **os.environ,
            "PATH": str(commands) + ":" + os.environ["PATH"],
            "DOCKER_HOST": "unix:///disposable/docker.sock",
            "SPACES_ACCESS_KEY_ID": "disposable-operator",
            "SPACES_SECRET_ACCESS_KEY": "disposable-secret",
            "SPACES_REGION": "nyc3",
            "SPACES_ARCHIVE_BUCKET": "disposable-archive",
            "SPACES_BACKUP_BUCKET": "disposable-backup",
            "M3_10_EVIDENCE_ROOT": evidence,
            "TEST_ARTIFACT": digest,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    expected = checkout / evidence if relative else Path(evidence)
    directories = list(expected.glob("spaces-*"))
    assert len(directories) == 1
    for phase in PHASES:
        assert (directories[0] / f"{phase}.passed").exists()
        assert (directories[0] / f"{phase}.log").exists()
    assert str(directories[0].resolve()) in result.stdout
