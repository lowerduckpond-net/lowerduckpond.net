"""Original rollout authority survives interruption without accepting partial success."""

from __future__ import annotations

import copy
import fcntl
import json
import os
from pathlib import Path
from typing import cast

import pytest

from scripts import m3_11_production_journal as journal

CRASH_STATUS = 86
ORIGINAL: dict[str, object] = {
    "format": "lowerduckpond-m3-11-production-transaction-v1",
    "transaction_id": "01997763-4600-7000-8000-000000000001",
    "started_at": "2026-09-25T00:00:00Z",
    "candidate": {
        "source_revision": "a" * 40,
        "artifact_sha256": "b" * 64,
        "input_policy": "lowerduckpond-production-inputs-v1",
        "qualification_inputs_sha256": "c" * 64,
        "storage_target_sha256": "d" * 64,
        "report_sha256": "e" * 64,
    },
    "predecessor": "f" * 64 + " " + "1" * 40 + " " + "d" * 64 + "\n",
    "repository_binding": "2" * 64,
    "namespace": {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "PlatformNamespace",
        "tenantOriginSuffix": "lowerduckpond.com",
        "initializedAt": "2026-09-25T00:00:00Z",
    },
}


def namespace_digest() -> str:
    return journal.digest(journal.canonical(cast(dict[str, object], ORIGINAL["namespace"])))


@pytest.fixture
def records() -> list[tuple[str, bytes]]:
    observations: dict[str, dict[str, object]] = {
        "drained": {
            "services_sha256": "3" * 64,
            "static_state_sha256": "4" * 64,
            "predecessor_sha256": journal.digest(cast(str, ORIGINAL["predecessor"]).encode()),
        },
        "namespace": {"namespace_sha256": namespace_digest(), "artifact_sha256": "b" * 64},
        "lineage": {
            "repository_binding": "2" * 64,
            "lineage_sha256": "5" * 64,
            "genesis_snapshot_id": "6" * 64,
            "audit_head_sha256": "7" * 64,
        },
        "converged": {
            "first_converge_sha256": "8" * 64,
            "second_converge_sha256": "9" * 64,
            "artifact_sha256": "b" * 64,
            "changed": 0,
            "recovery_enabled": True,
            "rotation_enabled": False,
            "publication_enabled": False,
        },
        "backup-verified": {
            "snapshot_id": "0" * 64,
            "descriptor_sha256": "1" * 64,
            "index_sha256": "2" * 64,
            "restored_tree_sha256": "3" * 64,
            "report_sha256": "e" * 64,
        },
        "rotation-enabled": {
            "first_converge_sha256": "4" * 64,
            "second_converge_sha256": "5" * 64,
            "changed": 0,
            "rotation_enabled": True,
            "publication_enabled": False,
        },
        "accepted": {
            "acceptance_sha256": "6" * 64,
            "artifact_sha256": "b" * 64,
            "namespace_sha256": namespace_digest(),
            "lineage_sha256": "5" * 64,
            "snapshot_id": "0" * 64,
            "publication_enabled": False,
        },
    }
    result = [("original", journal.canonical(ORIGINAL))]
    for index, (phase, values) in enumerate(observations.items(), start=1):
        for started in (True, False):
            receipt: dict[str, object] = {
                "format": "lowerduckpond-m3-11-production-phase-v1",
                "original_sha256": journal.digest(result[0][1]),
                "previous_sha256": journal.digest(result[-1][1]),
                "phase": phase,
                "observed_at": f"2026-09-25T00:0{index}:00Z",
            }
            if not started:
                receipt["observations"] = values
            result.append((phase + (".started" if started else ""), journal.canonical(receipt)))
    return result


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    root = tmp_path / "m3-11"
    root.mkdir(mode=0o700)
    return root


def snapshot(root: Path) -> dict[str, tuple[int, int, int, bytes | None]]:
    return {
        path.name: (
            path.lstat().st_ino,
            path.lstat().st_mtime_ns,
            path.lstat().st_mode,
            path.read_bytes() if path.is_file() and not path.is_symlink() else None,
        )
        for path in root.iterdir()
    }


def write_record(root: Path, name: str, raw: bytes) -> Path:
    path = root / name
    path.write_bytes(raw)
    path.chmod(0o400)
    return path


def test_only_final_acceptance_completes_and_retries_preserve_every_original_byte(
    directory: Path, records: list[tuple[str, bytes]]
) -> None:
    assert journal.validate([]) == {"phase": "absent"}
    with journal.locked(directory, owner=os.geteuid(), create=True) as state:
        for index, (name, raw) in enumerate(records):
            assert state.publish(name, raw)
            before = snapshot(directory)
            expected = "complete" if index == len(records) - 1 else name
            status = state.inspect()
            assert status["phase"] == expected
            assert status["original"] == ORIGINAL
            assert status["original_sha256"] == journal.digest(records[0][1])
            assert status["last_sha256"] == journal.digest(raw)
            for previous_name, previous_raw in records[: index + 1]:
                assert not state.publish(previous_name, previous_raw)
            assert snapshot(directory) == before
    original = snapshot(directory)
    with journal.locked(directory, owner=os.geteuid()) as state:
        assert state.inspect()["phase"] == "complete"
    assert snapshot(directory) == original


@pytest.mark.parametrize("missing", range(15))
def test_no_missing_start_or_observation_can_be_treated_as_completed(
    records: list[tuple[str, bytes]], missing: int
) -> None:
    if missing == len(records) - 1:
        assert journal.validate(records[:-1])["phase"] == "accepted.started"
    else:
        with pytest.raises(ValueError):
            journal.validate(records[:missing] + records[missing + 1 :])


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("format",), "other"),
        (("transaction_id",), "01997763-4600-4000-8000-000000000001"),
        (("transaction_id",), "01997763460070008000000000000001"),
        (("started_at",), "2026-09-25T00:00:00+00:00"),
        (("started_at",), "2026-02-30T00:00:00Z"),
        (("candidate", "input_policy"), "other"),
        (("candidate", "source_revision"), "a" * 39),
        (("candidate", "artifact_sha256"), "B" * 64),
        (("candidate", "report_sha256"), True),
        (("candidate", "extra"), "unreviewed"),
        (("predecessor",), "f" * 64 + " " + "1" * 40),
        (("predecessor",), "f" * 64 + " " + "1" * 40 + " " + "e" * 64 + "\n"),
        (("repository_binding",), "2" * 63),
        (("namespace", "tenantOriginSuffix"), "other.example"),
        (("namespace", "initializedAt"), "2026-09-25T00:00:01Z"),
    ],
)
def test_invalid_original_authority_is_rejected(path: tuple[str, ...], value: object) -> None:
    document = copy.deepcopy(ORIGINAL)
    target = document
    for key in path[:-1]:
        target = cast(dict[str, object], target[key])
    target[path[-1]] = value
    with pytest.raises(ValueError):
        journal.validate([("original", journal.canonical(document))])


def test_legacy_predecessor_bytes_are_preserved_without_inventing_a_target() -> None:
    document = copy.deepcopy(ORIGINAL)
    document["predecessor"] = "f" * 64 + " " + "1" * 40 + "\n"
    result = journal.validate([("original", journal.canonical(document))])
    assert result["original"] == document


@pytest.mark.parametrize(
    "raw",
    [b"[]\n", b"{}", b'{"format":1,"format":2}\n', b"null\n", b"x" * (journal.MAX_BYTES + 1)],
)
def test_noncanonical_or_oversized_records_fail_closed(raw: bytes) -> None:
    with pytest.raises(ValueError):
        journal.validate([("original", raw)])


@pytest.mark.parametrize(
    ("name", "key", "value"),
    [
        ("drained.started", "original_sha256", "0" * 64),
        ("drained", "previous_sha256", "0" * 64),
        ("drained", "observed_at", "2026-09-24T23:59:59Z"),
        ("drained", "phase", "accepted"),
        ("drained", "observations.predecessor_sha256", "0" * 64),
        ("namespace", "observations.namespace_sha256", "0" * 64),
        ("namespace", "observations.artifact_sha256", "0" * 64),
        ("lineage", "observations.repository_binding", "0" * 64),
        ("lineage", "observations.genesis_snapshot_id", "a" * 8),
        ("converged", "observations.changed", 1),
        ("converged", "observations.changed", False),
        ("converged", "observations.recovery_enabled", False),
        ("converged", "observations.recovery_enabled", 1),
        ("converged", "observations.rotation_enabled", True),
        ("converged", "observations.publication_enabled", True),
        ("backup-verified", "observations.report_sha256", "0" * 64),
        ("rotation-enabled", "observations.changed", 1),
        ("rotation-enabled", "observations.rotation_enabled", False),
        ("rotation-enabled", "observations.publication_enabled", True),
        ("accepted", "observations.snapshot_id", "f" * 64),
        ("accepted", "observations.lineage_sha256", "f" * 64),
        ("accepted", "observations.publication_enabled", True),
    ],
)
def test_phase_assertions_bind_the_original_and_prior_proofs(
    records: list[tuple[str, bytes]], name: str, key: str, value: object
) -> None:
    index = [record[0] for record in records].index(name)
    document = json.loads(records[index][1])
    if key.startswith("observations."):
        document["observations"][key.removeprefix("observations.")] = value
    else:
        document[key] = value
    # Stop here so rejection must be this phase's authority/assertion, not a later hash.
    changed = [*records[:index], (name, journal.canonical(document))]
    with pytest.raises(ValueError):
        journal.validate(changed)


@pytest.mark.parametrize("boundary", ["write", "file-sync", "rename", "directory-sync"])
@pytest.mark.parametrize("name", ["original", "drained.started", "drained", "accepted"])
def test_actual_process_death_resumes_only_the_original_proposal(
    directory: Path, records: list[tuple[str, bytes]], boundary: str, name: str
) -> None:
    index = [record[0] for record in records].index(name)
    raw = records[index][1]
    with journal.locked(directory, owner=os.geteuid(), create=True) as state:
        for previous_name, previous_raw in records[:index]:
            state.publish(previous_name, previous_raw)
    child = os.fork()
    if child == 0:

        def die(current: str) -> None:
            if current == boundary:
                os._exit(CRASH_STATUS)

        with journal.locked(directory, owner=os.geteuid()) as state:
            state.publish(name, raw, failure_hook=die)
        os._exit(87)
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == CRASH_STATUS
    published = (directory / (name + ".json")).exists()
    before = snapshot(directory)
    with journal.locked(directory, owner=os.geteuid()) as state:
        with pytest.raises(ValueError):
            state.publish(name, raw.replace(b"T00:", b"T01:"))
        assert snapshot(directory) == before
        if not published:
            with pytest.raises(ValueError):
                state.inspect()
            assert snapshot(directory) == before
        assert state.publish(name, raw) is not published
        expected = "complete" if name == "accepted" else name
        assert state.inspect()["phase"] == expected
        after = snapshot(directory)
        assert not state.publish(name, raw)
        assert snapshot(directory) == after
    assert not list(directory.glob(".*.pending"))


@pytest.mark.parametrize("length", [0, 7, 50])
def test_even_a_short_partial_write_retains_full_proposal_identity(
    directory: Path, records: list[tuple[str, bytes]], length: int
) -> None:
    raw = records[0][1]
    with journal.locked(directory, owner=os.geteuid(), create=True) as state:
        temporary = ".original." + journal.digest(raw) + ".pending"
        write_record(directory, temporary, raw[:length])
        original = snapshot(directory)
        with pytest.raises(ValueError):
            state.publish("original", raw.replace(b"T00:", b"T01:"))
        assert snapshot(directory) == original
        assert state.publish("original", raw)
        assert state.inspect()["original"] == ORIGINAL


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "mode", "fifo", "oversized", "bytes"])
@pytest.mark.parametrize("pending", [False, True])
def test_unsafe_record_or_temporary_is_not_repaired(
    directory: Path, records: list[tuple[str, bytes]], fault: str, *, pending: bool
) -> None:
    raw = records[0][1]
    name = ".original." + journal.digest(raw) + ".pending" if pending else "original.json"
    with journal.locked(directory, owner=os.geteuid(), create=True) as state:
        path = write_record(directory, name, raw)
        if fault == "mode":
            path.chmod(0o600)
        elif fault == "hardlink":
            os.link(path, directory.parent / "outside")
        elif fault == "oversized":
            path.chmod(0o600)
            path.write_bytes(b"x" * (journal.MAX_BYTES + 1))
            path.chmod(0o400)
        elif fault == "bytes":
            path.chmod(0o600)
            path.write_bytes(b"foreign original")
            path.chmod(0o400)
        else:
            path.unlink()
            if fault == "fifo":
                os.mkfifo(path, 0o400)
            else:
                outside = write_record(directory.parent, "outside", raw)
                path.symlink_to(outside)
        before = snapshot(directory)
        with pytest.raises((ValueError, OSError)):
            state.publish("original", raw)
        assert snapshot(directory) == before


@pytest.mark.parametrize("extra", ["unknown.json", ".original.unknown.pending", "namespace.json"])
def test_readonly_inspection_rejects_unknown_pending_or_out_of_order_files(
    directory: Path, records: list[tuple[str, bytes]], extra: str
) -> None:
    with journal.locked(directory, owner=os.geteuid(), create=True) as state:
        state.publish(*records[0])
        write_record(directory, extra, b"{}\n")
        before = snapshot(directory)
        with pytest.raises(ValueError):
            state.inspect()
        assert snapshot(directory) == before


def test_inspection_never_creates_a_directory_or_missing_lock(directory: Path) -> None:
    with pytest.raises(FileNotFoundError), journal.locked(directory, owner=os.geteuid()):
        pytest.fail("inspection invented a lock")
    assert not list(directory.iterdir())
    directory.rmdir()
    with pytest.raises(FileNotFoundError), journal.locked(directory, owner=os.geteuid()):
        pytest.fail("inspection invented a directory")
    assert not directory.exists()


def test_missing_lock_in_existing_history_cannot_be_recreated(
    directory: Path, records: list[tuple[str, bytes]]
) -> None:
    write_record(directory, "original.json", records[0][1])
    before = snapshot(directory)
    with (
        pytest.raises(FileNotFoundError),
        journal.locked(directory, owner=os.geteuid(), create=True),
    ):
        pytest.fail("existing history allowed a new lock")
    assert snapshot(directory) == before


@pytest.mark.parametrize("fault", ["owner", "mode", "directory-link", "lock-mode", "lock-content"])
def test_unsafe_journal_storage_is_rejected(directory: Path, fault: str) -> None:
    with journal.locked(directory, owner=os.geteuid(), create=True):
        pass
    owner = os.geteuid()
    if fault == "owner":
        owner += 1
    elif fault == "mode":
        directory.chmod(0o755)
    elif fault == "directory-link":
        moved = directory.with_name("original")
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
    elif fault == "lock-mode":
        (directory / "lock").chmod(0o644)
    else:
        (directory / "lock").write_bytes(b"unexpected")
    with pytest.raises((ValueError, OSError)), journal.locked(directory, owner=owner):
        pytest.fail("unsafe journal accepted")


@pytest.mark.parametrize("during_acquisition", [False, True])
@pytest.mark.parametrize("replace_directory", [False, True])
def test_named_lock_and_directory_must_remain_the_ones_held(
    directory: Path,
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
    *,
    during_acquisition: bool,
    replace_directory: bool,
) -> None:
    def replace() -> None:
        if replace_directory:
            directory.rename(directory.with_name("original"))
            directory.mkdir(mode=0o700)
            (directory / "lock").touch(mode=0o600)
        else:
            (directory / "lock").unlink()
            (directory / "lock").touch(mode=0o600)

    real_flock = fcntl.flock

    def changed_flock(fd: int, operation: int) -> None:
        real_flock(fd, operation)
        replace()

    if during_acquisition:
        monkeypatch.setattr(fcntl, "flock", changed_flock)
    with (
        pytest.raises(ValueError, match=r"replaced|metadata"),
        journal.locked(directory, owner=os.geteuid(), create=True) as state,
    ):
        replace()
        state.publish(*records[0])
    assert not (directory / "original.json").exists()
    assert not (directory.with_name("original") / "original.json").exists()


def test_separate_process_cannot_publish_under_another_rollout_lock(directory: Path) -> None:
    with journal.locked(directory, owner=os.geteuid(), create=True):
        child = os.fork()
        if child == 0:
            try:
                with journal.locked(directory, owner=os.geteuid()):
                    os._exit(87)
            except BlockingIOError:
                os._exit(CRASH_STATUS)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == CRASH_STATUS
    assert set(snapshot(directory)) == {"lock"}
