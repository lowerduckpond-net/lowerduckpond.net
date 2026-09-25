from __future__ import annotations

import gzip
import os
import select
import stat
import sys
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import production_capture
from lowerduckpond_static_host_agent import production_database as database
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.capacity import CapacityRejectedError, FilesystemCapacity
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError, RestoreStore
from lowerduckpond_static_host_agent.production_backup import BackupAuthority

SQL = b"CREATE DATABASE retained_rollout_fixture;\n"
PRIVATE_MODE = 0o600


@dataclass
class Dump:
    directory: Path
    staging: Path
    program: Path
    authority: BackupAuthority

    def run(self, descriptors: tuple[int, ...] = ()) -> Path:
        return database.retain_database(
            self.directory, self.authority, owner=os.geteuid(), descriptors=descriptors
        )


@pytest.fixture
def dump(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dump:
    directory, staging = tmp_path / "evidence", tmp_path / "staging"
    for path in (directory, staging):
        path.mkdir(mode=0o700)
    program = tmp_path / "producer.py"
    program.write_text(f"import sys\nsys.stdout.buffer.write({SQL!r})\n")
    monkeypatch.setattr(database, "DUMP", (sys.executable, str(program)))

    def capacity(fd: int) -> FilesystemCapacity:
        metadata = os.fstat(fd)
        assert stat.S_ISDIR(metadata.st_mode), "capacity must use the pinned directory"
        return FilesystemCapacity(metadata.st_dev, 4096, 8_000_000, 7_000_000, 2_000_000, 1_500_000)

    monkeypatch.setattr(database, "measure_filesystem_capacity_descriptor", capacity)
    authority = BackupAuthority(
        original_sha256="1" * 64,
        phase_sha256="2" * 64,
        report_sha256="3" * 64,
        artifact_sha256="4" * 64,
        repository_binding="5" * 64,
        lineage_sha256="6" * 64,
        namespace={"fixture": "original namespace"},
        launch=None,
    )
    return Dump(directory, staging, program, authority)


def test_retained_original_is_reused_without_redumping_and_can_restage(dump: Dump) -> None:
    original = dump.run()
    assert gzip.decompress(original.read_bytes()) == SQL
    before = (original.stat().st_ino, original.stat().st_mtime_ns, original.read_bytes())
    manifest = (dump.directory / "database-original.json").read_bytes()
    dump.program.write_text("raise RuntimeError('must not run again')\n")
    assert dump.run() == original
    database.stage_database(original, dump.staging, owner=os.geteuid())
    (dump.staging / "mariadb.sql.gz").unlink()
    database.stage_database(original, dump.staging, owner=os.geteuid())
    assert (dump.staging / "mariadb.sql.gz").read_bytes() == before[2]
    assert (original.stat().st_ino, original.stat().st_mtime_ns, original.read_bytes()) == before
    assert (dump.directory / "database-original.json").read_bytes() == manifest
    assert all(
        stat.S_IMODE(path.stat().st_mode) == PRIVATE_MODE for path in dump.directory.iterdir()
    )
    assert not (dump.directory / "journal.json").exists()


@pytest.mark.parametrize("failed", ["producer", "compressor"])
def test_both_pipeline_exits_are_required_and_failed_attempts_are_retained(
    dump: Dump, monkeypatch: pytest.MonkeyPatch, failed: str
) -> None:
    if failed == "producer":
        dump.program.write_text(
            f"import sys\nsys.stdout.buffer.write({SQL!r})\n"
            "sys.stderr.write('dump failed')\nsys.exit(7)\n"
        )
    else:
        monkeypatch.setattr(
            database,
            "GZIP",
            (
                sys.executable,
                "-c",
                "import sys; sys.stdin.buffer.read(); "
                "sys.stdout.buffer.write(b'partial'); sys.exit(7)",
            ),
        )
    with pytest.raises(BackupIdentityError, match="pipeline failed"):
        dump.run()
    assert not (dump.directory / "database-original.json").exists()
    failed_bytes = (dump.directory / "dump-00.sql.gz").read_bytes()
    dump.program.write_text(f"import sys\nsys.stdout.buffer.write({SQL!r})\n")
    monkeypatch.setattr(database, "GZIP", ("/usr/bin/gzip", "--best"))
    assert dump.run().name == "dump-01.sql.gz"
    assert (dump.directory / "dump-00.sql.gz").read_bytes() == failed_bytes


@pytest.mark.parametrize("stream", ["sql", "errors"])
def test_output_and_private_diagnostics_are_bounded(
    dump: Dump, monkeypatch: pytest.MonkeyPatch, stream: str
) -> None:
    maximum = 16
    monkeypatch.setattr(
        database, "MAX_TREE_BYTES" if stream == "sql" else "MAX_DIAGNOSTIC_BYTES", maximum
    )
    if stream == "errors":
        dump.program.write_text("import sys\nsys.stderr.buffer.write(b'x' * 65536)\n")
    with pytest.raises(BackupIdentityError, match="bound"):
        dump.run()
    suffix = "sql.gz" if stream == "sql" else "stderr"
    assert (dump.directory / f"dump-00.{suffix}").stat().st_size <= maximum
    assert not (dump.directory / "database-original.json").exists()


def test_deadline_kills_process_descendants_and_releases_inherited_leases(
    dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    import fcntl  # noqa: PLC0415 - Unix lease proof

    lease = dump.directory / "external-lease"
    child = dump.directory.parent / "descendant.pid"
    with lease.open("wb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        dump.program.write_text(
            "import os, time\nfrom pathlib import Path\n"
            f"os.fstat({held.fileno()})\n"
            "child = os.fork()\n"
            "if child == 0:\n    time.sleep(30)\n"
            f"else:\n    Path({str(child)!r}).write_text(str(child))\n    os._exit(0)\n"
        )
        monkeypatch.setattr(database, "DEADLINE_SECONDS", 0.3)
        with pytest.raises(BackupIdentityError, match="deadline"):
            dump.run((held.fileno(),))
    # killpg delivers SIGKILL asynchronously. Waiting for the already-exited
    # parent does not wait for its orphan. Observe that child's actual exit
    # before checking the lease, as ExitType=cgroup does in the installed action.
    try:
        descriptor = os.pidfd_open(int(child.read_text()))
    except ProcessLookupError:
        pass
    else:
        try:
            assert select.select([descriptor], [], [], 5)[0], "dump descendant survived SIGKILL"
        finally:
            os.close(descriptor)
    # All descendants inherited this same open-file description. If any still
    # hold it, a fresh descriptor cannot acquire the exclusive repository lease.
    with lease.open("rb") as rival:
        fcntl.flock(rival, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert not (dump.directory / "database-original.json").exists()


@pytest.mark.parametrize("changed", ["bytes", "authority", "hardlink", "mode"])
def test_retained_original_cannot_change_on_resume(dump: Dump, changed: str) -> None:
    original = dump.run()
    if changed == "bytes":
        original.write_bytes(b"different")
    elif changed == "authority":
        dump.authority = replace(dump.authority, phase_sha256="f" * 64)
    elif changed == "hardlink":
        (dump.directory / "alias").hardlink_to(original)
    else:
        original.chmod(0o644)
    with pytest.raises((BackupIdentityError, HostRestoreError, StatePathError)):
        dump.run()
    assert not (dump.directory / "dump-01.sql.gz").exists()


def test_original_visible_after_interrupted_publication_is_reused(
    dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    immutable = RestoreStore.immutable

    def interrupted(store: RestoreStore, name: str, raw: bytes) -> None:
        immutable(store, name, raw)
        if name == "database-original.json":
            raise OSError("lost acknowledgement")

    monkeypatch.setattr(RestoreStore, "immutable", interrupted)
    with pytest.raises(OSError, match="lost acknowledgement"):
        dump.run()
    original = (dump.directory / "dump-00.sql.gz").read_bytes()
    dump.program.write_text("raise RuntimeError('must not redump')\n")
    monkeypatch.setattr(RestoreStore, "immutable", immutable)
    assert dump.run().read_bytes() == original


def test_directory_sync_failure_prevents_success_and_retry_keeps_original(
    dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    sync = production_capture._sync

    def interrupted(store: RestoreStore) -> None:
        raise OSError("directory sync interrupted")

    monkeypatch.setattr(database, "_sync", interrupted)
    with pytest.raises(OSError, match="directory sync"):
        dump.run()
    original = (dump.directory / "dump-00.sql.gz").read_bytes()
    dump.program.write_text("raise RuntimeError('must not redump')\n")
    monkeypatch.setattr(database, "_sync", sync)
    assert dump.run().read_bytes() == original


def test_capacity_refusal_does_not_replace_the_prior_staged_dump(
    dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = dump.run()
    target = dump.staging / "mariadb.sql.gz"
    target.write_bytes(b"previous")
    target.chmod(0o600)
    monkeypatch.setattr(
        database,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(os.fstat(fd).st_dev, 4096, 8_000_000, 0, 2_000_000, 0),
    )
    with pytest.raises(CapacityRejectedError):
        database.stage_database(original, dump.staging, owner=os.geteuid())
    assert target.read_bytes() == b"previous"


@pytest.mark.parametrize("unsafe", ["partial", "target"])
def test_staging_refuses_unsafe_existing_names(dump: Dump, unsafe: str) -> None:
    original = dump.run()
    name = "m3-11-database.partial" if unsafe == "partial" else "mariadb.sql.gz"
    (dump.staging / name).symlink_to(original)
    with pytest.raises(OSError):
        database.stage_database(original, dump.staging, owner=os.geteuid())
    assert gzip.decompress(original.read_bytes()) == SQL


def test_capacity_is_checked_before_any_private_metadata_allocation(
    dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        database,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(os.fstat(fd).st_dev, 4096, 8_000_000, 0, 2_000_000, 0),
    )
    with pytest.raises(CapacityRejectedError):
        dump.run()
    assert not list(dump.directory.iterdir())


def test_failed_atomic_stage_keeps_previous_sql_and_resumes_from_retained_bytes(
    dump: Dump, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = dump.run()
    target = dump.staging / "mariadb.sql.gz"
    target.write_bytes(b"previous dump")
    target.chmod(0o600)
    rename = os.rename

    def interrupted(source: str, destination: str, *, src_dir_fd: int, dst_dir_fd: int) -> None:
        raise OSError("replacement interrupted")

    monkeypatch.setattr(os, "rename", interrupted)
    with pytest.raises(OSError, match="replacement interrupted"):
        database.stage_database(original, dump.staging, owner=os.geteuid())
    assert target.read_bytes() == b"previous dump"
    partial = dump.staging / "m3-11-database.partial"
    assert partial.read_bytes() == original.read_bytes()
    monkeypatch.setattr(os, "rename", rename)
    dump.program.write_text("raise RuntimeError('must not redump')\n")
    database.stage_database(original, dump.staging, owner=os.geteuid())
    assert target.read_bytes() == original.read_bytes()
    assert not partial.exists()


def test_attempt_exhaustion_preserves_private_failures_for_inspection(dump: Dump) -> None:
    last = dump.directory / f"dump-{database.MAX_ATTEMPTS - 1:02d}.stderr"
    last.write_bytes(b"original failed attempt")
    last.chmod(0o600)
    with pytest.raises(BackupIdentityError, match="operator inspection"):
        dump.run()
    assert last.read_bytes() == b"original failed attempt"
    assert not (dump.directory / "database-original.json").exists()
    assert not list(dump.directory.glob("*.sql.gz"))
