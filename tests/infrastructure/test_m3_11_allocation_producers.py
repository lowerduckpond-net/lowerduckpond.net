"""Actual Bash/Molecule wrapper and allocation producers, with disposable command doubles."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from scripts import qualification_allocation as allocation
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_unattended.inputs import MANAGED_ENV

from .operator_flow_support import DAEMON, SOURCE
from .test_m3_10_spaces_workflow import executable

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("outcome", ["success", "partial", "empty", "lost-inventory"])
def test_actual_shell_records_partial_create_before_errexit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    checkout = tmp_path / "checkout"
    (checkout / "config/ansible").mkdir(parents=True)
    wrapper = checkout / "scripts/m3-10-spaces-qualification"
    executable(wrapper, (ROOT / "scripts/m3-10-spaces-qualification").read_text())
    commands = tmp_path / "commands"
    directory = tmp_path / "attempt"
    directory.mkdir(mode=0o700)
    binding = {
        "managed_run_id": str(uuid.uuid7()),
        "source_revision": SOURCE,
        "helper_revision": SOURCE,
        "artifact_sha256": "a" * 64,
        "qualification_inputs_sha256": "b" * 64,
        "storage_target_sha256": "c" * 64,
    }
    request: dict[str, object] = {"binding": binding, "daemon": DAEMON}
    write_private(directory / "request.json", request)
    write_private(directory / "runtime-inputs.json", {"binding": binding})
    allocation.initialize(directory, request, "unix:///synthetic/docker.sock")
    executable(
        commands / "git",
        '#!/bin/bash\nif [[ $1 == rev-parse ]]; then printf "%s\\n" "' + SOURCE + '"; fi\n',
    )
    executable(commands / "tofu", "#!/bin/bash\nexit 0\n")
    executable(commands / "jq", "#!/bin/bash\nexit 91\n")
    executable(
        commands / "uv",
        f"#!{sys.executable}\n"
        + r"""
import json, os, sys
from pathlib import Path
if 'scripts.qualification_storage_lease' in sys.argv:
    if '--check' in sys.argv:
        sys.exit(0)
    command = sys.argv[sys.argv.index('--') + 1:]
    fd = os.open(os.environ['SYNTHETIC_LOCK'], os.O_RDWR | os.O_CREAT, 0o600)
    os.set_inheritable(fd, True)
    os.execvpe(command[0], command, {**os.environ, 'LDP_QUALIFICATION_STORAGE_LEASE_FD': str(fd)})
if 'scripts.m3_11_combined_inputs' in sys.argv:
    action = sys.argv[-2]
    if action == 'capture-public':
        sys.exit(31)
    assert action in {'allocate', 'create-begin', 'create-command'}
    command = [os.environ['SYNTHETIC_PYTHON'], *sys.argv[sys.argv.index('python') + 1:]]
    os.execv(command[0], command)
if 'molecule' in sys.argv:
    assert sys.argv[sys.argv.index('molecule') + 1] == 'create'
    path = Path(os.environ['SYNTHETIC_ROWS'])
    assert not path.exists(), 'second CREATE crossed the command boundary'
    rows = []
    kinds = {
        'success': ('host', 'archive'), 'empty': (),
        'partial': ('host',), 'lost-inventory': ('host',),
    }[os.environ['SYNTHETIC_OUTCOME']]
    owner = os.environ['LDP_QUALIFICATION_RUN_ID']
    for index, role in enumerate(kinds, 1):
        rows.append({
            'Id': str(index) * 64, 'Name': '/ldp-m3-' + owner + '-' + role,
            'Image': 'sha256:' + '9' * 64,
            'Config': {'Labels': {'lowerduckpond.qualification.run': owner}},
            'State': {'Running': True}, 'HostConfig': {'RestartPolicy': {'Name': 'always'}},
        })
    path.write_text(json.dumps(rows))
    sys.exit(0 if os.environ['SYNTHETIC_OUTCOME'] == 'success' else 17)
# This focused shell test stops immediately after create; earlier independent
# preflights are process doubles. Connected business validation lives separately.
preflights = (
    'scripts.m3_11_unattended.inputs', 'scripts.m3_11_token_preflight',
    'scripts.qualification_minio', 'scripts.production_qualification_inputs',
    'scripts.check_m3_10_provider', 'ldp-m3-archive',
)
assert (
    sys.argv[1] == 'sync' or any(name in sys.argv for name in preflights)
    or any(arg.endswith(('qualification_timing.py', 'qualification_failure.py'))
           for arg in sys.argv)
)
""",
    )
    executable(
        commands / "docker",
        f"#!{sys.executable}\n"
        + r"""
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
path = Path(os.environ['SYNTHETIC_ROWS'])
rows = json.loads(path.read_text()) if path.exists() else []
if args[0] == 'info':
    print(os.environ['SYNTHETIC_DAEMON'])
elif args[0] in ('ps', 'container'):
    if os.environ['SYNTHETIC_OUTCOME'] == 'lost-inventory':
        sys.exit(4)
    names = [arg.removeprefix('name=^/').removesuffix('$')
             for arg in args if arg.startswith('name=')]
    for row in rows:
        if not names or row['Name'].removeprefix('/') in names:
            print(row['Id'])
elif args[0] == 'inspect':
    row = next(row for row in rows if args[-1] in (row['Id'], row['Name'].removeprefix('/')))
    result = {'id': row['Id'],
              'owner': row['Config']['Labels']['lowerduckpond.qualification.run']}
    print(json.dumps(result if '--format' in args else [row]))
else:
    raise AssertionError(args)
""",
    )
    env = {
        **os.environ,
        "PATH": str(commands) + ":" + os.environ["PATH"],
        "PYTHONPATH": str(ROOT),
        "SYNTHETIC_PYTHON": sys.executable,
        "SYNTHETIC_OUTCOME": outcome,
        "SYNTHETIC_ROWS": str(tmp_path / "rows.json"),
        "SYNTHETIC_LOCK": str(tmp_path / "lock"),
        "SYNTHETIC_DAEMON": json.dumps(DAEMON),
        "DOCKER_HOST": "unix:///synthetic/docker.sock",
        MANAGED_ENV: str(directory / "runtime-inputs.json"),
        "M3_11_EVIDENCE_ROOT": str(directory / "qualification"),
        "SPACES_ACCESS_KEY_ID": "SYNTHETIC",
        "SPACES_SECRET_ACCESS_KEY": "SYNTHETIC-SECRET",
        "SPACES_BACKUP_BUCKET": "synthetic-backup",
        "SPACES_ARCHIVE_BUCKET": "synthetic-archive",
        "SPACES_REGION": "nyc3",
    }
    env.pop("DOCKER_CONTEXT", None)
    env.pop("LDP_QUALIFICATION_STORAGE_LEASE_FD", None)
    result = subprocess.run(  # noqa: S603 - fixed local test executable; external services replaced
        [str(wrapper), "--milestone", "3.11"], env=env, capture_output=True, check=False, timeout=30
    )
    assert result.returncode == (31 if outcome == "success" else 17), result.stderr.decode()
    value = read_private(directory / "allocation.json")
    roles = value["roles"]
    assert isinstance(roles, dict)
    expected = {
        "success": ("created", "created"),
        "partial": ("created", "completed-empty"),
        "empty": ("completed-empty", "completed-empty"),
        "lost-inventory": ("begun-uncertain", "begun-uncertain"),
    }[outcome]
    assert (roles["host"]["state"], roles["archive"]["state"]) == expected
    assert roles["destination"]["state"] == roles["acme"]["state"] == "not-attempted"
    fixture = next((directory / "qualification").glob("spaces-*"))
    assert (fixture / "molecule-submission.json").exists()
    # Invoking only the create command again cannot cross the CREATE boundary.
    again = subprocess.run(  # noqa: S603 - fixed local test executable; external services replaced
        [
            str(commands / "uv"),
            "run",
            "python",
            "-m",
            "scripts.m3_11_combined_inputs",
            "create-command",
            str(fixture),
        ],
        env=env,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert again.returncode != 0
    assert read_private(directory / "allocation.json") == value
