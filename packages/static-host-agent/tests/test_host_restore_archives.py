from __future__ import annotations

import os
from pathlib import Path

import pytest
from lowerduckpond_static_host_agent import host_restore_archives as recovery
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from test_archive_journal import _NOW, MemoryRemote, prepared_source
from test_archive_journal import capacity as capacity  # noqa: PLC0414 - shared source fixture


@pytest.mark.parametrize(
    "fault", [None, "missing", "current-version", "corrupt", "unknown", "marker", "multipart"]
)
def test_exact_archive_proof_preserves_remote_and_source_on_every_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str | None,
) -> None:
    monkeypatch.setattr(
        recovery,
        "measure_filesystem_capacity_descriptor",
        lambda fd: FilesystemCapacity(
            os.fstat(fd).st_dev, 4096, 8_000_000, 7_000_000, 4_000_000, 3_000_000
        ),
    )
    client = MemoryRemote()
    workspace = tmp_path / "restore-archive-workspace"
    workspace.mkdir(mode=0o700)
    with prepared_source(tmp_path, client) as (journal, job_id, source, _):
        uploaded = journal.construct(job_id, source, now=_NOW)
        original = source.source_manifest
        proof = recovery.RestoreArchive(uploaded.record, source.manifest)
        if fault == "missing":
            client.versions.clear()
        elif fault == "current-version":
            client.versions[0]["VersionId"] = "different-current-version"
        elif fault == "corrupt":
            client.body = b"X" + client.body[1:]
        elif fault == "unknown":
            client.versions.append(
                {"Key": "later-timeline", "VersionId": "later-version", "Size": 12}
            )
        elif fault == "marker":
            client.markers.append(
                {"Key": uploaded.record["key"], "VersionId": "later-delete-marker"}
            )
        elif fault == "multipart":
            client.uploads.append({"Key": "later-timeline", "UploadId": "later-upload"})
        client.calls.clear()
        before = (list(client.versions), list(client.markers), list(client.uploads), client.body)
        if fault is None:
            receipt = recovery.verify_restore_archives(
                journal.remote, [proof], workspace, owner=os.geteuid()
            )
            assert receipt["versionCount"] == 1 and receipt["multipartCount"] == 0
            assert client.calls.count("get") == 1 and client.calls.count("list") == 2  # noqa: PLR2004
        else:
            with pytest.raises((HostRestoreError, ArchiveRemoteError)):
                recovery.verify_restore_archives(
                    journal.remote, [proof], workspace, owner=os.geteuid()
                )
        assert (client.versions, client.markers, client.uploads, client.body) == before
        assert "put" not in client.calls and "delete" not in client.calls
        assert source.source_manifest == original
        assert not tuple(workspace.iterdir())
