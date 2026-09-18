from __future__ import annotations

import hashlib
import json
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
@pytest.mark.parametrize("inputs_available", [False, True])
@pytest.mark.parametrize(
    "docker_selection",
    [
        ("unix:///disposable/docker.sock", "", "", True),
        ("tcp://remote.invalid:2375", "local", "unix:///disposable/docker.sock", True),
        ("unix:///disposable/docker.sock", "remote", "tcp://remote.invalid:2375", False),
        ("", "", "ssh://remote.invalid", False),
        ("", "", "unix:///disposable/docker.sock", True),
        ("", "broken", "", False),
    ],
)
def test_spaces_workflow_keeps_evidence_paths_stable_across_phase_directories(
    tmp_path: Path,
    relative: bool,
    docker_selection: tuple[str, str, str, bool],
    inputs_available: bool,
) -> None:
    docker_host, docker_context, context_endpoint, accepted = docker_selection
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
    loader.write_text('printf loaded >"${TEST_LOADER_MARKER}"\n')
    commands = tmp_path / "commands"
    executable(
        commands / "git",
        "#!/bin/bash\nif [[ $1 == rev-parse ]]; then printf '%040d\\n' 0; fi\n",
    )
    executable(
        commands / "docker",
        """#!/bin/bash
if [[ $1 == context && $2 == inspect ]]; then
    printf '%s\\n' "${TEST_CONTEXT_ENDPOINT}"
elif [[ $1 == info ]]; then
    [[ -z ${DOCKER_CONTEXT:-} && $DOCKER_HOST == unix:///disposable/docker.sock ]] || exit 3
elif [[ $1 == inspect ]]; then
    exit 1
fi
""",
    )
    executable(commands / "tofu", "#!/bin/bash\nexit 0\n")
    executable(
        commands / "uv",
        """#!/usr/bin/python3
import json, os, sys
from pathlib import Path
with Path(os.environ['TEST_UV_CALLS']).open('a') as stream:
    stream.write(json.dumps(sys.argv[1:]) + '\\n')
# A broken optional reporter cannot change the qualification's exit status.
reporters = ('/scripts/qualification_timing.py', '/scripts/qualification_failure.py')
if any(arg.endswith(reporters) for arg in sys.argv):
    sys.exit(57)
marker = Path(os.environ['TEST_INPUT_MARKER'])
if 'scripts.production_qualification_inputs' in sys.argv:
    if os.environ['TEST_INPUTS_AVAILABLE'] != 'true':
        sys.exit(1)
    marker.write_text('captured')
if 'scripts.check_m3_10_provider' in sys.argv or 'molecule' in sys.argv:
    assert marker.exists(), 'provider proof started before input capture'
if 'molecule' in sys.argv:
    assert 'DOCKER_CONTEXT' not in os.environ
    assert os.environ['DOCKER_HOST'] == 'unix:///disposable/docker.sock'
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
            "DOCKER_HOST": docker_host,
            "DOCKER_CONTEXT": docker_context,
            "TEST_CONTEXT_ENDPOINT": context_endpoint,
            "TEST_LOADER_MARKER": str(tmp_path / "loaded"),
            "TEST_INPUT_MARKER": str(tmp_path / "input-captured"),
            "TEST_UV_CALLS": str(tmp_path / "uv-calls.jsonl"),
            "TEST_INPUTS_AVAILABLE": str(inputs_available).lower(),
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
    expected = checkout / evidence if relative else Path(evidence)
    if not accepted:
        assert result.returncode != 0
        assert "requires a local Unix-socket Docker daemon" in result.stderr
        assert not (tmp_path / "loaded").exists()
        assert not expected.exists()
        return
    assert (tmp_path / "loaded").exists()
    calls = [json.loads(line) for line in (tmp_path / "uv-calls.jsonl").read_text().splitlines()]
    assert "start" in calls[0] and "--no-sync" in calls[0]
    assert calls[1] == ["sync", "--all-packages", "--all-groups", "--frozen"]
    assert "finish" in calls[-1] and "--no-sync" in calls[-1]
    directories = list(expected.glob("spaces-*"))
    assert len(directories) == 1
    if not inputs_available:
        assert result.returncode == 1
        assert not (tmp_path / "input-captured").exists()
        assert not list(directories[0].glob("*.passed"))
        assert not (directories[0] / "qualification.json").exists()
        return
    assert result.returncode == 0, result.stdout + result.stderr
    for phase in PHASES:
        assert (directories[0] / f"{phase}.passed").exists()
        assert (directories[0] / f"{phase}.log").exists()
    assert str(directories[0].resolve()) in result.stdout
