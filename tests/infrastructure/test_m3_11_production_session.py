from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from scripts import m3_11_production_session as session

PRIVATE_MODE = 0o600
FAILED_ACTION = 7
SSH_FIXTURE = """
import hashlib,os,shlex,signal,subprocess,sys,time
from pathlib import Path
from scripts import m3_11_production_lease as lease
from scripts import m3_11_production_stage as stage
root=Path(sys.argv[1]);args=shlex.split(sys.argv[2])
def record(value):
    with (root/'trace').open('a') as stream: stream.write(value+'\\n')
if '-c' in args:
    record('stage')
    if (root/'fail-stage').exists():
        print('private staging failure',file=sys.stderr);sys.exit(3)
    raw=sys.stdin.buffer.read()
    assert hashlib.sha256(raw).hexdigest()==args[-1]
    stage.stage(root/'code',raw,args[-1],owner=os.geteuid())
    print('/run/lowerduckpond-m3-11/'+args[-1]+'.pyz')
elif args[-1]=='owner':
    record('owner')
    state=root/'lease';state.mkdir(mode=0o700,exist_ok=True)
    def drain(): record('drained')
    with lease.controller(state,owner=os.geteuid(),drain=drain) as token:
        (root/'owner.pid').write_text(str(os.getpid()))
        if (root/'invalid-token').exists(): print('x'*64,flush=True)
        elif (root/'partial-token').exists(): print('abc',end='',flush=True)
        else: print(token,flush=True)
        sys.stdin.buffer.read(8)
        if (root/'hang-release').exists(): time.sleep(60)
else:
    record('action')
    assert args[-3]=='action' and '--expand-environment=no' in args
    with lease.action(root/'lease',owner=os.geteuid(),token=args[-2]):
        if (root/'lose-owner').exists():
            os.kill(int((root/'owner.pid').read_text()),signal.SIGKILL)
        sys.exit(subprocess.call(['/bin/sh','-c',args[-1]]))
"""


@pytest.fixture
def fixture(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    diagnostics = tmp_path / "attempt"
    diagnostics.mkdir(mode=0o700)
    return tmp_path, diagnostics, [sys.executable, "-c", SSH_FIXTURE, str(tmp_path)]


def test_one_owner_spans_commands_transfers_and_ansible_environment(
    fixture: tuple[Path, Path, list[str]],
) -> None:
    root, diagnostics, ssh = fixture
    payload = b"\0\xff\r\nowned bytes\n"
    original = {"ANSIBLE_SSH_RETRIES": "3", "FAKE_PRIVATE_CREDENTIAL": "private-fixture"}
    with session.controller(ssh, diagnostics) as active:
        result = active.run(
            "binary",
            [sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"],
            data=payload,
        )
        assert result.status == 0 and result.read() == payload
        failed = active.run(
            "failure",
            [
                sys.executable,
                "-c",
                "import sys;print('private failure',file=sys.stderr);sys.exit(7)",
            ],
        )
        assert failed.status == FAILED_ACTION and failed.stderr.read_bytes() == b"private failure\n"
        environment = active.ansible_environment(original)
        assert environment["LDP_M3_11_LEASE_TOKEN"] == active.token
        assert environment["ANSIBLE_SSH_RETRIES"] == "0"
        assert environment["ANSIBLE_HOST_KEY_CHECKING"] == "true"
        assert environment["FAKE_PRIVATE_CREDENTIAL"] == "private-fixture"
        assert original == {
            "ANSIBLE_SSH_RETRIES": "3",
            "FAKE_PRIVATE_CREDENTIAL": "private-fixture",
        }
        assert active.owner.poll() is None
    assert active.owner.returncode == 0
    assert active.owner.stdin is not None and active.owner.stdin.closed
    assert active.owner.stdout is not None and active.owner.stdout.closed
    assert (root / "lease/token").read_bytes() == b"0" * 64 + b"\n"
    assert (root / "trace").read_text().splitlines() == [
        "stage",
        "owner",
        "drained",
        "action",
        "action",
        "drained",
    ]
    for path in diagnostics.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == PRIVATE_MODE
        assert active.token.encode() not in path.read_bytes()
    with pytest.raises(ValueError, match="connection ended"):
        active.run("late", ["true"])


def test_failed_body_releases_owner_without_overwriting_observations(
    fixture: tuple[Path, Path, list[str]],
) -> None:
    root, diagnostics, ssh = fixture
    with pytest.raises(RuntimeError, match="phase failed"), session.controller(ssh, diagnostics):
        raise RuntimeError("phase failed")
    original = {path.name: path.read_bytes() for path in diagnostics.iterdir()}
    with pytest.raises(FileExistsError), session.controller(ssh, diagnostics):
        pytest.fail("reused a previous attempt's observations")
    assert {path.name: path.read_bytes() for path in diagnostics.iterdir()} == original
    assert (root / "trace").read_text().splitlines().count("owner") == 1


def test_staging_failure_never_acquires_an_owner(fixture: tuple[Path, Path, list[str]]) -> None:
    root, diagnostics, ssh = fixture
    (root / "fail-stage").touch()
    with pytest.raises(ValueError, match="staging failed"), session.controller(ssh, diagnostics):
        pytest.fail("failed code staging admitted an owner")
    assert (root / "trace").read_text() == "stage\n"
    assert (
        diagnostics / "0000-stage-controller.stderr"
    ).read_bytes() == b"private staging failure\n"


@pytest.mark.parametrize("fault", ["invalid-token", "partial-token", "hang-release"])
def test_incomplete_owner_protocol_fails_without_claiming_release(
    fixture: tuple[Path, Path, list[str]], fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, diagnostics, ssh = fixture
    (root / fault).touch()
    monkeypatch.setattr(session, "OWNER_READY_SECONDS", 2)
    monkeypatch.setattr(session, "OWNER_RELEASE_SECONDS", 1)
    expected = (
        "invalid authority"
        if fault == "invalid-token"
        else "not ready"
        if fault == "partial-token"
        else "release was not confirmed"
    )
    with pytest.raises(ValueError, match=expected), session.controller(ssh, diagnostics):
        assert fault == "hang-release"
    assert (diagnostics / "0001-owner.stderr").is_file()


def test_owner_loss_rejects_even_an_action_that_returned_success(
    fixture: tuple[Path, Path, list[str]],
) -> None:
    root, diagnostics, ssh = fixture
    with pytest.raises(ValueError), session.controller(ssh, diagnostics) as active:
        (root / "lose-owner").touch()
        with pytest.raises(ValueError, match="connection ended"):
            active.run("lost", ["true"])
    assert (diagnostics / "0002-lost.stdout").read_bytes() == b""
    assert (root / "trace").read_text().splitlines().count("action") == 1


@pytest.mark.parametrize("fault", ["public", "symlink", "replaced", "name"])
def test_diagnostic_paths_require_the_original_private_directory(
    tmp_path: Path, fault: str
) -> None:
    directory = tmp_path / "logs"
    directory.mkdir(mode=0o700)
    if fault == "public":
        directory.chmod(0o755)
    elif fault == "symlink":
        link = tmp_path / "link"
        link.symlink_to(directory)
        directory = link
    if fault in {"public", "symlink"}:
        with pytest.raises(ValueError):
            session.Logs(directory)
        return
    logs = session.Logs(directory)
    if fault == "replaced":
        directory.rename(tmp_path / "old")
        directory.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        logs.paths("../escape" if fault == "name" else "step")


def test_observation_size_bound_retains_original_diagnostic_file(tmp_path: Path) -> None:
    path = tmp_path / "output"
    path.write_bytes(b"original output")
    result = session.Result(0, path, tmp_path / "error")
    with pytest.raises(ValueError, match="exceeds"):
        result.read(3)
    assert path.read_bytes() == b"original output"
