from __future__ import annotations

import os
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archives
from lowerduckpond_static_host_agent.archive_abort import finalize_failed_construction
from lowerduckpond_static_host_agent.archive_commit import finalize_archive_transition
from lowerduckpond_static_host_agent.archive_journal import ArchiveConstructionJournal
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_journal import (
    HostRestoreError,
    RestoreJournal,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_remote import finish_restore_remote
from lowerduckpond_static_host_agent.restore_commit import finalize_restore_transition
from test_archive_commit import _prepared
from test_archive_journal import _NOW, MemoryRemote, prepared_source
from test_archive_journal import capacity as capacity  # noqa: PLC0414
from test_host_restore_journal import journal as journal  # noqa: PLC0414
from test_host_restore_journal import root as root  # noqa: PLC0414
from test_host_restore_routes import begin
from test_restore_commit import _restoring


@pytest.fixture(autouse=True)
def proof_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        archives,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )


class LostDelete(MemoryRemote):
    lose_delete = True

    def delete_object(self, **kwargs: object) -> dict[str, object]:
        response = super().delete_object(**kwargs)
        if self.lose_delete:
            raise TimeoutError("delete response lost")
        return response


@pytest.mark.parametrize("phase", ["prepared", "lost-upload-response", "uploaded"])
def test_failed_construction_cleanup_never_reuploads_or_repeats_a_completed_delete(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    phase: str,
) -> None:
    client = LostDelete()
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        prepared_source(tmp_path, client) as (remote, job_id, source, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        if phase == "prepared":
            ArchiveConstructionJournal(
                remote.repository,
                remote.spool,
                expected_owner=os.geteuid(),
                bucket=remote.remote.bucket,
                require_quarantine_empty=remote.require_quarantine_empty,
            ).prepare(job_id, source, now=_NOW)
        elif phase == "lost-upload-response":
            client.lose_response = True
            with pytest.raises(TimeoutError):
                remote.construct(job_id, source, now=_NOW)
        else:
            remote.construct(job_id, source, now=_NOW)
        finalize_failed_construction(remote.repository, remote.spool, job_id)
        identity = remote.repository.measure_intent_records().records[0].intent_id
        begin(store, journal)
        client.calls.clear()
        if phase != "prepared":
            with pytest.raises(TimeoutError, match="delete response lost"):
                finish_restore_remote(store, remote, identity, workspace)
            assert not client.versions
            assert remote.repository.measure_intent_records().records
        client.lose_delete = False
        receipt = finish_restore_remote(store, remote, identity, workspace)
        client.expected_intent = root  # Completed cleanup retains host-restore authority.
        assert finish_restore_remote(store, remote, identity, workspace) == receipt
        assert not remote.repository.measure_intent_records().records
        assert client.calls.count("delete") == int(phase != "prepared")
        assert "put" not in client.calls


@pytest.mark.parametrize("fault", ["unknown", "marker", "multipart", "before-delete"])
def test_unknown_remote_bytes_are_preserved_even_after_local_failure_is_committed(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    client = MemoryRemote()
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        prepared_source(tmp_path, client) as (remote, job_id, source, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        remote.construct(job_id, source, now=_NOW)
        finalize_failed_construction(remote.repository, remote.spool, job_id)
        identity = remote.repository.measure_intent_records().records[0].intent_id
        begin(store, journal)
        client.calls.clear()
        if fault == "unknown":
            client.versions.append({"Key": "later-timeline", "VersionId": "later", "Size": 1})
        elif fault == "marker":
            client.markers.append({"Key": client.versions[0]["Key"], "VersionId": "marker"})
        elif fault == "multipart":
            client.uploads.append({"Key": client.versions[0]["Key"], "UploadId": "multipart"})
        else:
            original = client.list_object_versions

            def appear(**kwargs: object) -> dict[str, object]:
                if client.calls.count("list") == 4:  # noqa: PLR2004 - last inventory before delete
                    client.versions.append(
                        {"Key": "later-timeline", "VersionId": "later", "Size": 1}
                    )
                return original(**kwargs)

            monkeypatch.setattr(client, "list_object_versions", appear)
        with pytest.raises(HostRestoreError):
            finish_restore_remote(store, remote, identity, workspace)
        assert client.versions and remote.repository.measure_intent_records().records
        assert "delete" not in client.calls and "put" not in client.calls


def test_successful_archive_retains_and_reverifies_its_exact_bound_version(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
) -> None:
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        _prepared(tmp_path) as (remote, releases, job, plan),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        with remote.repository.publication_transaction() as transaction:
            finalize_archive_transition(transaction, remote.spool, releases, job, plan)
        begin(store, journal)
        receipt = finish_restore_remote(store, remote, plan.construction_intent_id, workspace)
        cast(MemoryRemote, remote.remote.client).expected_intent = root
        assert (
            finish_restore_remote(store, remote, plan.construction_intent_id, workspace) == receipt
        )
        assert remote.remote.inventory().versions
        assert not remote.repository.measure_intent_records().records


def test_successful_tenant_restore_retires_only_its_original_archive(
    tmp_path: Path,
    root: Path,
    journal: RestoreJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "proof"
    workspace.mkdir(mode=0o700)
    with (
        _restoring(tmp_path, monkeypatch) as (remote, releases, prepared, _),
        RestoreStore.locked(root, owner=os.geteuid()) as store,
    ):
        with remote.repository.publication_transaction() as transaction:
            finalize_restore_transition(
                transaction,
                remote.spool,
                releases,
                prepared.job,
                prepared.plan,
                prepared.retirement,
            )
        begin(store, journal)
        identity = str(prepared.retirement.document["intentId"])
        receipt = finish_restore_remote(store, remote, identity, workspace)
        assert finish_restore_remote(store, remote, identity, workspace) == receipt
        assert not remote.remote.inventory().versions
        assert not remote.repository.measure_intent_records().records
