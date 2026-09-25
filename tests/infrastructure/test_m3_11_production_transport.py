from __future__ import annotations

import hashlib
import io
import os
import shlex
import stat
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Protocol, cast

import pytest
from ansible.errors import AnsibleConnectionFailure  # type: ignore[import-untyped]
from ansible.playbook.play_context import PlayContext  # type: ignore[import-untyped]
from ansible.plugins.connection import ssh  # type: ignore[import-untyped]
from ansible.plugins.loader import connection_loader  # type: ignore[import-untyped]

from scripts import m3_11_production_stage as stage
from scripts import m3_11_production_transport as transport
from scripts.m3_11_production_remote import ROOT as REMOTE_ROOT

OWNER = os.geteuid()
TOKEN = "a" * 64
ROOT = Path(__file__).parents[2]
CRASH = 86
PUBLISHED_MODE = 0o400


class Connection(Protocol):
    def set_options(self, *, direct: dict[str, object]) -> None: ...
    def set_option(self, name: str, value: object) -> None: ...
    def exec_command(
        self, cmd: str, in_data: bytes | None = None, sudoable: bool = True
    ) -> tuple[int, bytes, bytes]: ...
    def put_file(self, source: str, destination: str) -> tuple[int, bytes, bytes]: ...
    def fetch_file(self, source: str, destination: str) -> tuple[int, bytes, bytes]: ...
    def _file_transport_command(
        self, source: str, destination: str, action: str
    ) -> tuple[int, bytes, bytes]: ...


def test_helper_bundle_is_deterministic_and_contains_only_qualified_code(tmp_path: Path) -> None:
    raw, helper = transport.helper_bundle()
    assert transport.helper_bundle() == (raw, helper)
    assert Path(helper).stem == hashlib.sha256(raw).hexdigest()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert set(archive.namelist()) == {
            "__main__.py",
            "scripts/__init__.py",
            "scripts/m3_11_production_fence.py",
            "scripts/m3_11_production_gate.py",
            "scripts/m3_11_production_initialize.py",
            "scripts/m3_11_production_journal.py",
            "scripts/m3_11_production_lease.py",
            "scripts/m3_11_production_probe.py",
            "scripts/m3_11_production_records.py",
            "scripts/m3_11_production_remote.py",
        }
        for name in (
            "m3_11_production_fence.py",
            "m3_11_production_gate.py",
            "m3_11_production_initialize.py",
            "m3_11_production_journal.py",
            "m3_11_production_lease.py",
            "m3_11_production_probe.py",
            "m3_11_production_records.py",
            "m3_11_production_remote.py",
        ):
            assert archive.read("scripts/" + name) == (ROOT / "scripts" / name).read_bytes()
    path = stage.stage(tmp_path / "helpers", raw, Path(helper).stem, owner=OWNER)
    result = subprocess.run(  # noqa: S603 - owned isolated helper with invalid arguments
        [sys.executable, "-I", "-B", str(path)], capture_output=True, check=False
    )
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == b"production_action_failed\n"


def test_staging_preserves_exact_published_inode_and_timestamp(tmp_path: Path) -> None:
    raw, helper = transport.helper_bundle()
    directory = tmp_path / "helpers"
    path = stage.stage(directory, raw, Path(helper).stem, owner=OWNER)
    metadata = path.stat()
    assert stat.S_IMODE(metadata.st_mode) == PUBLISHED_MODE
    assert path.read_bytes() == raw
    assert stage.stage(directory, raw, Path(helper).stem, owner=OWNER) == path
    after = path.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_ctime_ns) == (
        metadata.st_ino,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@pytest.mark.parametrize("boundary", ["write", "fchmod", "file-fsync", "rename", "dir-fsync"])
def test_staging_resumes_original_code_after_actual_process_death(
    tmp_path: Path, boundary: str
) -> None:
    raw, helper = transport.helper_bundle()
    source = tmp_path / "code"
    source.write_bytes(raw)
    directory = tmp_path / "helpers"
    program = """
import os,stat,sys
from pathlib import Path
from scripts import m3_11_production_stage as s
boundary=sys.argv[3]
name='fsync' if boundary.endswith('fsync') else boundary
original=getattr(os,name)
def crash(*args,**kwargs):
    if name=='write':
        original(args[0],args[1][:17]);os._exit(86)
    result=original(*args,**kwargs)
    directory=stat.S_ISDIR(os.fstat(args[0]).st_mode) if name=='fsync' else False
    if name!='fsync' or (boundary=='dir-fsync')==directory: os._exit(86)
    return result
setattr(os,name,crash)
raw=Path(sys.argv[2]).read_bytes()
s.stage(Path(sys.argv[1]),raw,sys.argv[4],owner=os.geteuid())
"""
    result = subprocess.run(  # noqa: S603 - fixed crash harness and owned paths
        [sys.executable, "-c", program, str(directory), str(source), boundary, Path(helper).stem],
        check=False,
    )
    assert result.returncode == CRASH
    path = stage.stage(directory, raw, Path(helper).stem, owner=OWNER)
    assert path.read_bytes() == raw
    assert stat.S_IMODE(path.stat().st_mode) == PUBLISHED_MODE
    assert {p.name for p in directory.iterdir()} == {"stage.lock", path.name}


@pytest.mark.parametrize(
    "fault",
    [
        "identity",
        "oversize",
        "directory-link",
        "directory-mode",
        "lock-link",
        "partial",
        "published",
    ],
)
def test_staging_refuses_changed_bytes_and_unsafe_authority(tmp_path: Path, fault: str) -> None:
    raw, helper = transport.helper_bundle()
    digest = Path(helper).stem
    directory = tmp_path / "helpers"
    directory.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    if fault == "identity":
        digest = "f" * 64
    elif fault == "oversize":
        raw += b"x" * stage.MAX_BYTES
        digest = hashlib.sha256(raw).hexdigest()
    elif fault == "directory-link":
        directory.rmdir()
        directory.symlink_to(other, target_is_directory=True)
    elif fault == "directory-mode":
        directory.chmod(0o755)
    elif fault == "lock-link":
        (other / "file").touch(mode=0o600)
        (directory / "stage.lock").symlink_to(other / "file")
    else:
        path = directory / (("." + digest + ".partial") if fault == "partial" else digest + ".pyz")
        path.write_bytes(b"changed")
        path.chmod(0o600 if fault == "partial" else 0o400)
    with pytest.raises((ValueError, OSError)):
        stage.stage(directory, raw, digest, owner=OWNER)


def test_remote_command_preserves_shell_input_as_one_argument() -> None:
    _, helper = transport.helper_bundle()
    action = "printf '%s\\n' '`literal` $VALUE'; cat\n"
    arguments = shlex.split(transport.command(helper, TOKEN, action))
    assert arguments[-4:] == [helper, "action", TOKEN, action]
    assert "--property=ExitType=cgroup" in arguments
    assert "--property=KillMode=control-group" in arguments
    assert "--expand-environment=no" in arguments


@pytest.mark.parametrize(
    ("helper", "token", "action"),
    [
        ("/untrusted/helper.pyz", TOKEN, "true"),
        (str(REMOTE_ROOT / ("a" * 64 + ".pyz")), "0" * 64, "true"),
        (str(REMOTE_ROOT / ("a" * 64 + ".pyz")), TOKEN, ""),
        (str(REMOTE_ROOT / ("a" * 64 + ".pyz")), TOKEN, "bad\0command"),
    ],
)
def test_transport_rejects_missing_or_ambiguous_authority(
    helper: str, token: str, action: str
) -> None:
    with pytest.raises(ValueError):
        transport.command(helper, token, action)


@pytest.fixture
def connection(monkeypatch: pytest.MonkeyPatch) -> Connection:
    connection_loader.add_directory(str(ROOT / "config/ansible/plugins/connection"))
    context = PlayContext()
    context.remote_addr = "192.0.2.1"
    context.remote_user = "ldp-admin"
    result = cast(Connection, connection_loader.get("ldp_m3_11", context, io.BytesIO()))
    assert result is not None
    result.set_options(
        direct={
            "use_tty": False,
            "reconnection_retries": 0,
            "host_key_checking": True,
            "ssh_transfer_method": "piped",
        }
    )
    _, helper = transport.helper_bundle()
    monkeypatch.setenv("LDP_M3_11_ACTION_HELPER", helper)
    monkeypatch.setenv("LDP_M3_11_LEASE_TOKEN", TOKEN)
    return result


def test_actual_ansible_commands_and_both_transfers_use_guarded_streams(
    connection: Connection, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = b"\0\xff\r\nowned binary content\n"
    calls: list[tuple[str, bytes | None, bool]] = []

    def execute(
        _connection: object, cmd: str, in_data: bytes | None = None, sudoable: bool = True
    ) -> tuple[int, bytes, bytes]:
        calls.append((cmd, in_data, sudoable))
        return 0, payload, b""

    monkeypatch.setattr(ssh.Connection, "exec_command", execute)
    connection.exec_command("true", b"pipelined module", sudoable=True)
    source, fetched = tmp_path / "source", tmp_path / "fetched"
    source.write_bytes(payload)
    connection.put_file(str(source), "/root/remote with ' quote")
    connection.fetch_file("/root/remote with ' quote", str(fetched))
    assert fetched.read_bytes() == payload
    assert [data for _, data, _ in calls] == [b"pipelined module", payload, None]
    assert [sudoable for _, _, sudoable in calls] == [True, False, False]
    for command, _, _ in calls:
        arguments = shlex.split(command)
        assert arguments[-3:-1] == ["action", TOKEN]
        assert "--property=ExitType=cgroup" in arguments
    assert shlex.split(calls[1][0])[-1].startswith("dd of=")
    assert shlex.split(calls[2][0])[-1].startswith("dd if=")


@pytest.mark.parametrize("method", ["smart", "sftp", "scp"])
def test_ansible_refuses_unguarded_file_transfer_fallback(
    connection: Connection, method: str
) -> None:
    connection.set_option("ssh_transfer_method", method)
    with pytest.raises(AnsibleConnectionFailure, match="leased pipe"):
        connection._file_transport_command("source", "target", "put")


@pytest.mark.parametrize(
    ("option", "value"),
    [("use_tty", True), ("reconnection_retries", 1), ("host_key_checking", False)],
)
def test_ansible_refuses_unverified_retried_or_tty_transport(
    connection: Connection, option: str, value: object
) -> None:
    connection.set_option(option, value)
    with pytest.raises(AnsibleConnectionFailure, match="verified nonretrying"):
        connection.exec_command("true")
