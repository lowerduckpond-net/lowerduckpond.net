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
@pytest.mark.parametrize("milestone", ["3.10", "3.11"])
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
    milestone: str,
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
        checkout / "scripts/build-static-host-agent",
        """#!/bin/bash
set -eu
cp -- "$TEST_ARTIFACT_PATH" "$1"
""",
    )
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
if 'scripts.m3_11_combined_inputs' in sys.argv:
    action, directory = sys.argv[-2], Path(sys.argv[-1])
    if action == 'allocate':
        fixture = directory / 'fixture'
        fixture.mkdir()
        run_id = '0198d17f6f4a70008000000000000001'
        values = {
            'LDP_QUALIFICATION_RUN_ID': run_id,
            'LDP_QUALIFICATION_HOST': 'ldp-m3-' + run_id + '-host',
            'LDP_QUALIFICATION_ARCHIVE': 'ldp-m3-' + run_id + '-archive',
            'LDP_QUALIFICATION_IMAGE': 'ldp-m3-' + run_id + ':ubuntu-2604',
            'LDP_QUALIFICATION_SSH_PORT': '0',
            'LDP_QUALIFICATION_ARTIFACT': str(fixture / 'static-host-agent.tar'),
            'MOLECULE_EPHEMERAL_DIRECTORY': str(fixture / 'molecule'),
            'DOCKER_HOST': 'unix:///disposable/docker.sock',
            'M3_10_ARCHIVE_BACKEND': 'spaces', 'M3_11_COMBINED_BACKEND': 'spaces',
            'M3_10_INSTALLED_REPORT': str(directory / 'installed.json'),
        }
        sys.stdout.buffer.write(b''.join(key.encode() + b'\\0' + value.encode() + b'\\0'
                                         for key, value in values.items()))
    elif action == 'capture-public':
        assert (directory / 'create.passed').exists()
        assert not (directory / 'prepare.passed').exists()
        (directory / 'public-inputs.json').write_text('original clean roots')
    elif action == 'prepare-storage':
        assert (directory / 'public-inputs.json').exists()
        assert (directory / 'prepare.passed').exists()
        assert not (directory / 'converge.passed').exists()
        assert Path(os.environ['LDP_QUALIFICATION_ARTIFACT']).read_bytes() == b'disposable artifact'
        (directory / 'live-storage.json').write_text('original owned storage')
    elif action == 'capture':
        assert (directory / 'idempotence.passed').exists()
        assert not (directory / 'verify.passed').exists()
        (directory / 'combined-context.json').write_text('original context')
if 'scripts.check_m3_10_provider' in sys.argv or 'molecule' in sys.argv:
    assert marker.exists(), 'provider proof started before input capture'
if 'molecule' in sys.argv:
    assert 'DOCKER_CONTEXT' not in os.environ
    allowed = {'LDP_QUALIFICATION_TIMING_EVENTS', 'LDP_QUALIFICATION_TIMING_GROUP'}
    if os.environ['TEST_MILESTONE'] == '3.10':
        assert not any(key.startswith('LDP_QUALIFICATION_') and key not in allowed
                       for key in os.environ)
        assert 'MOLECULE_EPHEMERAL_DIRECTORY' not in os.environ
        assert 'M3_11_COMBINED_BACKEND' not in os.environ
    else:
        assert os.environ['M3_11_COMBINED_BACKEND'] == 'spaces'
        assert os.environ['LDP_QUALIFICATION_HOST'].startswith('ldp-m3-')
    assert os.environ['DOCKER_HOST'] == 'unix:///disposable/docker.sock'
    phase = sys.argv[sys.argv.index('molecule') + 1]
    destination = Path(os.environ['M3_10_INSTALLED_REPORT'])
    assert destination.is_absolute(), 'installed report path changed meaning after chdir'
    directory = destination.parent
    if os.environ['TEST_MILESTONE'] == '3.11':
        if phase == 'prepare':
            assert (directory / 'public-inputs.json').exists()
        elif phase == 'converge':
            assert (directory / 'live-storage.json').exists()
        elif phase == 'verify':
            assert (directory / 'combined-context.json').exists()
            (directory / 'combined.json').write_text('original complete live envelope')
        elif phase == 'destroy':
            assert (directory / 'combined.json').exists()
    if phase == 'verify':
        destination.write_text(json.dumps({'artifact_sha256': os.environ['TEST_ARTIFACT']}))
if 'scripts.m3_10_qualification_report' in sys.argv:
    directory = Path(sys.argv[-1])
    assert directory.is_absolute(), 'final evidence directory is relative'
    for phase in ('create', 'prepare', 'converge', 'idempotence', 'verify', 'destroy'):
        assert (directory / (phase + '.passed')).read_text() == 'passed\\n'
    assert (directory / 'installed.json').exists()
    if os.environ['TEST_MILESTONE'] == '3.11':
        assert sys.argv[-3:-1] == ['--milestone', '3.11']
        assert (directory / 'combined.json').exists()
    (directory / 'qualification.json').write_text('{}')
""",
    )
    evidence = "evidence/runs" if relative else str(tmp_path / "private evidence")
    result = subprocess.run(  # noqa: S603 - copied wrapper with fixed disposable command doubles
        [str(wrapper), *(["--milestone", "3.11"] if milestone == "3.11" else [])],
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
            "M3_11_EVIDENCE_ROOT": evidence,
            "M3_11_COMBINED_BACKEND": "foreign-ambient-backend",
            "TEST_MILESTONE": milestone,
            "TEST_ARTIFACT_PATH": str(artifact),
            "TEST_ARTIFACT": digest,
            **dict.fromkeys(
                (
                    "LDP_QUALIFICATION_RUN_ID",
                    "LDP_QUALIFICATION_HOST",
                    "LDP_QUALIFICATION_ARCHIVE",
                    "LDP_QUALIFICATION_IMAGE",
                    "LDP_QUALIFICATION_SSH_PORT",
                    "LDP_QUALIFICATION_ARTIFACT",
                    "MOLECULE_EPHEMERAL_DIRECTORY",
                ),
                "foreign-local-fixture",
            ),
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
    timing_calls = [
        call for call in calls if any(arg.endswith("/qualification_timing.py") for arg in call)
    ]
    start_call, finish_call = timing_calls
    assert start_call == calls[0]
    assert "finish" in finish_call and "--no-sync" in finish_call
    failure_calls = [
        call for call in calls if any(arg.endswith("/qualification_failure.py") for arg in call)
    ]
    assert len(failure_calls) == 1
    assert ("fixture" if inputs_available else "collect") in failure_calls[0]
    assert all("--no-sync" in call for call in failure_calls)
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
