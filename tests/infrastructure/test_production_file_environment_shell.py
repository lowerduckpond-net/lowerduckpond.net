"""The private-file launcher isolates Docker helpers for the complete shell lifetime."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/production-file-environment-shell"
PRIVATE_DIRECTORY = 0o700
PRIVATE_FILE = 0o600
CHILD_FAILURE = 37
REQUIRED = (
    "OPENTOFU_STATE_ACCESS_KEY_ID",
    "OPENTOFU_STATE_SECRET_ACCESS_KEY",
    "OPENTOFU_STATE_BUCKET",
    "OPENTOFU_ENCRYPTION_PASSPHRASE",
    "SPACES_REGION",
    "SPACES_ACCESS_KEY_ID",
    "SPACES_SECRET_ACCESS_KEY",
)


@dataclass
class Launcher:
    script: Path
    private_env: Path
    temporary: Path
    original_config: Path
    environment: dict[str, str]

    def run(self, *arguments: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - reviewed launcher with fake private inputs
            [str(self.script), *arguments],
            input=stdin,
            env=self.environment,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )


@pytest.fixture
def launcher(tmp_path: Path) -> Launcher:
    private = tmp_path / "private"
    private.mkdir(mode=PRIVATE_DIRECTORY)
    installed = private / "production-shell"
    installed.write_bytes(SCRIPT.read_bytes())
    installed.chmod(PRIVATE_DIRECTORY)
    private_env = private / "qualification.env"
    private_env.write_text("".join(f"{name}='private-canary'\n" for name in REQUIRED))
    private_env.chmod(PRIVATE_FILE)
    temporary = tmp_path / "temporary"
    temporary.mkdir(mode=PRIVATE_DIRECTORY)
    tools = tmp_path / "tools"
    tools.mkdir()
    mise = tools / "mise"
    mise.write_text('#!/bin/bash\n[[ $1 == exec && $2 == -- ]] || exit 90\nshift 2\nexec "$@"\n')
    mise.chmod(PRIVATE_DIRECTORY)
    for command in ("docker", "tofu", "docker-credential-desktop.exe"):
        stub = tools / command
        stub.write_text('#!/bin/bash\nprintf "unexpected external request\\n" >&2\nexit 99\n')
        stub.chmod(PRIVATE_DIRECTORY)
    original = tmp_path / "desktop"
    original.mkdir()
    (original / "config.json").write_text(
        json.dumps(
            {
                "credsStore": "desktop.exe",
                "currentContext": "desktop-linux",
                "credHelpers": {"https://index.docker.io/v1/": "desktop.exe"},
            }
        )
    )
    environment = {
        **os.environ,
        "PATH": str(tools) + os.pathsep + os.environ["PATH"],
        "LDP_PRODUCTION_ENV_FILE": str(private_env),
        "LDP_PRODUCTION_REPOSITORY": str(ROOT),
        "DOCKER_CONFIG": str(original),
        "DOCKER_CONTEXT": "desktop-linux",
        "DOCKER_TLS_VERIFY": "1",
        "DOCKER_TLS": "1",
        "DOCKER_CERT_PATH": "/unused/desktop",
        "TMPDIR": str(temporary),
        "SSH_AUTH_SOCK": "/private/original-agent",
    }
    environment.pop("DOCKER_HOST", None)
    return Launcher(installed, private_env, temporary, original, environment)


@pytest.mark.parametrize("status", [0, CHILD_FAILURE])
def test_real_docker_sdk_ignores_desktop_helpers_and_cleans_up_on_exit(
    launcher: Launcher, status: int
) -> None:
    before = launcher.original_config.joinpath("config.json").read_bytes()
    child = """
import json, os, pathlib, stat, sys
from docker.auth import load_config
config = pathlib.Path(os.environ['DOCKER_CONFIG'])
assert config.joinpath('config.json').read_bytes() == b'{}\\n'
assert stat.S_IMODE(config.stat().st_mode) == 0o700
assert stat.S_IMODE(config.joinpath('config.json').stat().st_mode) == 0o600
loaded = load_config()
assert not loaded.creds_store and not loaded.cred_helpers and not loaded.get_all_credentials()
assert loaded.resolve_authconfig('https://index.docker.io/v1/') is None
assert os.environ['DOCKER_HOST'] == 'unix:///var/run/docker.sock'
assert all(name not in os.environ for name in (
    'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'
))
assert os.environ['SSH_AUTH_SOCK'] == '/private/original-agent'
assert os.environ['OPENTOFU_STATE_SECRET_ACCESS_KEY'] == 'private-canary'
assert os.environ['HISTFILE'] == '/dev/null'
print(json.dumps({'config': str(config)}))
sys.exit(int(sys.argv[1]))
"""
    result = launcher.run("--", sys.executable, "-c", child, str(status))
    assert result.returncode == status, result.stderr
    config = Path(json.loads(result.stdout)["config"])
    assert not config.exists()
    assert not list(launcher.temporary.iterdir())
    assert launcher.original_config.joinpath("config.json").read_bytes() == before
    assert "private-canary" not in result.stdout + result.stderr
    assert "unexpected external request" not in result.stderr


def test_interactive_shell_keeps_config_until_exit(launcher: Launcher) -> None:
    command = (
        "import os,pathlib; p=pathlib.Path(os.environ['DOCKER_CONFIG']); "
        "assert p.joinpath('config.json').read_text() == '{}\\n'; print('config:' + str(p))"
    )
    result = launcher.run(stdin=shlex.join([sys.executable, "-c", command]) + "\nexit 0\n")
    assert result.returncode == 0, result.stderr
    (path,) = [
        Path(line.removeprefix("config:"))
        for line in result.stdout.splitlines()
        if line.startswith("config:")
    ]
    assert not path.exists()
    assert not list(launcher.temporary.iterdir())


def test_check_does_not_call_docker_or_mise_or_providers(launcher: Launcher) -> None:
    result = launcher.run("--check")
    assert result.returncode == 0, result.stderr
    assert "without credential helpers" in result.stdout
    assert "private-canary" not in result.stdout + result.stderr
    assert not list(launcher.temporary.iterdir())


def test_each_invocation_gets_a_fresh_config_and_preserves_explicit_socket(
    launcher: Launcher,
) -> None:
    launcher.environment["DOCKER_HOST"] = "unix:///run/user/1000/docker.sock"
    command = "import os; print(os.environ['DOCKER_CONFIG']); print(os.environ['DOCKER_HOST'])"
    first = launcher.run("--", sys.executable, "-c", command)
    second = launcher.run("--", sys.executable, "-c", command)
    assert first.returncode == second.returncode == 0
    assert first.stdout.splitlines()[0] != second.stdout.splitlines()[0]
    assert first.stdout.splitlines()[1] == "unix:///run/user/1000/docker.sock"
    assert not list(launcher.temporary.iterdir())


@pytest.mark.parametrize(
    "fault", ["file-mode", "parent-mode", "symlink", "syntax", "remote", "missing"]
)
def test_invalid_inputs_do_not_start_a_child_or_leak_values(launcher: Launcher, fault: str) -> None:
    if fault == "file-mode":
        launcher.private_env.chmod(0o644)
    elif fault == "parent-mode":
        launcher.private_env.parent.chmod(0o755)
    elif fault == "symlink":
        other = launcher.private_env.with_name("actual.env")
        launcher.private_env.rename(other)
        launcher.private_env.symlink_to(other)
    elif fault == "syntax":
        launcher.private_env.write_text("SECRET='private-canary\n")
    elif fault == "remote":
        launcher.environment["DOCKER_HOST"] = "tcp://example.invalid:2376"
    else:
        launcher.private_env.write_text("SPACES_REGION='private-canary'\n")
        for name in REQUIRED:
            launcher.environment.pop(name, None)
    result = launcher.run("--", sys.executable, "-c", "print('child-ran')")
    assert result.returncode == 2  # noqa: PLR2004 - launcher validation status
    assert "child-ran" not in result.stdout
    assert "private-canary" not in result.stdout + result.stderr
    assert not list(launcher.temporary.iterdir())
