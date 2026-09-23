from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as archives
from lowerduckpond_static_host_agent.archive_journal import ArchiveConstructionJournal
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_construction import classify_unbound_construction
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.repository import StateRecordPath
from test_archive_journal import _NOW, MemoryRemote, prepared_source
from test_archive_journal import capacity as capacity  # noqa: PLC0414


@pytest.mark.parametrize("phase", ["prepared", "lost-response", "uploaded", "retired"])
@pytest.mark.parametrize("lifecycle", ["active", "suspended"])
def test_unpublished_construction_proves_exact_version_without_mutating_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, lifecycle: str
) -> None:
    monkeypatch.setattr(
        archives,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    client = MemoryRemote()
    workspace = tmp_path / "verification"
    workspace.mkdir(mode=0o700)
    with prepared_source(tmp_path, client, lifecycle=lifecycle) as (journal, job_id, source, _):
        if phase == "prepared":
            ArchiveConstructionJournal(
                journal.repository,
                journal.spool,
                expected_owner=os.geteuid(),
                bucket=journal.remote.bucket,
                require_quarantine_empty=journal.require_quarantine_empty,
            ).prepare(job_id, source, now=_NOW)
        elif phase == "lost-response":
            client.lose_response = True
            with pytest.raises(TimeoutError):
                journal.construct(job_id, source, now=_NOW)
        else:
            journal.construct(job_id, source, now=_NOW)
            if phase == "retired":
                client.versions.clear()
        identity = journal.repository.measure_intent_records().records[0]
        path = StateRecordPath.archive_construction_intent(identity.intent_id)
        original = journal.repository.read(path).document
        client.calls.clear()
        inventory = journal.remote.inventory()
        with journal.repository.publication_transaction() as transaction:
            obligation = classify_unbound_construction(
                transaction, identity.intent_id, inventory, bucket=journal.remote.bucket
            )
        receipt = archives.verify_restore_archives(
            journal.remote,
            [] if obligation is None else [obligation],
            workspace,
            owner=os.geteuid(),
        )
        assert receipt["versionCount"] == int(phase in {"lost-response", "uploaded"})
        assert journal.repository.read(path).document == original
        assert "put" not in client.calls and "delete" not in client.calls
        assert client.calls.count("get") == int(phase in {"lost-response", "uploaded"})
        if obligation is not None:
            assert obligation.required is False


@pytest.mark.parametrize("fault", ["version", "size", "duplicate", "marker", "multipart"])
def test_construction_never_rebinds_ambiguous_remote_state(tmp_path: Path, fault: str) -> None:
    client = MemoryRemote()
    with prepared_source(tmp_path, client) as (journal, job_id, source, _):
        uploaded = journal.construct(job_id, source, now=_NOW)
        intent_id = str(uploaded.construction.document["intentId"])
        key = uploaded.record["key"]
        if fault == "version":
            client.versions[0]["VersionId"] = "newer-version"
        elif fault == "size":
            client.versions[0]["Size"] = 1
        elif fault == "duplicate":
            client.versions.append({**client.versions[0], "VersionId": "other-version"})
        elif fault == "marker":
            client.markers.append({"Key": key, "VersionId": "marker"})
        else:
            client.uploads.append({"Key": key, "UploadId": "multipart"})
        client.calls.clear()
        inventory = journal.remote.inventory()
        with (
            journal.repository.publication_transaction() as transaction,
            pytest.raises(HostRestoreError),
        ):
            classify_unbound_construction(
                transaction, intent_id, inventory, bucket=journal.remote.bucket
            )
        assert "put" not in client.calls and "delete" not in client.calls
