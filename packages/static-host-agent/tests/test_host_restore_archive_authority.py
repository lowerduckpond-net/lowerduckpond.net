from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archives
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_archive_authority import collect_restore_archives
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from test_archive_commit import _prepared
from test_archive_journal import MemoryRemote
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_delete_commit import _deleting
from test_host_restore_archive import evidence as archive_evidence
from test_host_restore_delete import evidence as delete_evidence
from test_host_restore_deployments import evidence as restore_evidence
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import CA, begin
from test_restore_commit import _restoring


@pytest.mark.parametrize("operation", ["archive", "restore", "delete"])
@pytest.mark.parametrize("choice", ["source", "candidate"])
@pytest.mark.parametrize("absent", [False, True])
def test_archive_requirements_come_from_independent_full_lifecycle_choice_before_any_mutation(  # noqa: PLR0913,PLR0917
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    choice: str,
    absent: bool,
) -> None:
    monkeypatch.setattr(
        archives,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with ExitStack() as contexts:
        if operation == "archive":
            remote, _, _, archive_plan = contexts.enter_context(_prepared(tmp_path, "active"))
            evidence = archive_evidence(remote.repository, archive_plan, choice)
            record = archive_plan.archive_record
        elif operation == "restore":
            remote, _, prepared_restore, _ = contexts.enter_context(
                _restoring(tmp_path, monkeypatch)
            )
            evidence = restore_evidence(remote.repository, prepared_restore.plan, choice)
            record = cast(dict[str, object], prepared_restore.retirement.document["archiveRecord"])
        else:
            remote, _, prepared_delete, _ = contexts.enter_context(
                _deleting(tmp_path, archived=True)
            )
            evidence = delete_evidence(remote.repository, prepared_delete.plan, choice)
            assert prepared_delete.retirement is not None
            record = cast(dict[str, object], prepared_delete.retirement.document["archiveRecord"])
        store = contexts.enter_context(RestoreStore.locked(root, owner=os.geteuid()))
        begin(store, journal)
        client = cast(MemoryRemote, remote.remote.client)
        if absent:
            client.versions.clear()
        client.calls.clear()
        state = tmp_path / "state"
        before = {
            str(path.relative_to(state)): path.read_bytes()
            for path in state.rglob("*")
            if path.is_file()
        }
        authority = collect_restore_archives(store, remote, evidence, CA, remote.remote.inventory())
        assert len(authority) == 1 and authority[0].record == record
        required = choice == ("candidate" if operation == "archive" else "source")
        assert authority[0].required is required
        if absent and required:
            with pytest.raises(HostRestoreError, match="required_archive_unavailable"):
                archives.verify_restore_archives(
                    remote.remote, authority, workspace, owner=os.geteuid()
                )
        else:
            proof = archives.verify_restore_archives(
                remote.remote, authority, workspace, owner=os.geteuid()
            )
            assert proof["versionCount"] == int(not absent)
        after = {
            str(path.relative_to(state)): path.read_bytes()
            for path in state.rglob("*")
            if path.is_file()
        }
        assert before == after
        assert "put" not in client.calls and "delete" not in client.calls
        assert client.calls.count("get") == int(not absent)


def test_unknown_later_version_blocks_before_reconciliation_and_preserves_remote_bytes(
    tmp_path: Path, root: Path, journal: RestoreJournal
) -> None:
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        _prepared(tmp_path, "active") as (remote, _, _, plan),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        begin(store, journal)
        client = cast(MemoryRemote, remote.remote.client)
        client.versions.append({**client.versions[0], "VersionId": "later-version"})
        original = list(client.versions)
        authority = collect_restore_archives(
            store,
            remote,
            archive_evidence(remote.repository, plan, "source"),
            CA,
            remote.remote.inventory(),
        )
        with pytest.raises(HostRestoreError, match="later_remote_timeline"):
            archives.verify_restore_archives(
                remote.remote, authority, workspace, owner=os.geteuid()
            )
        assert client.versions == original
        assert "delete" not in client.calls
