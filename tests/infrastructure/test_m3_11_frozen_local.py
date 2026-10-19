"""Native-origin proof clocks, same-byte binding, and locked report publication."""

from __future__ import annotations

import hashlib
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from lowerduckpond_static_contracts import decode_json_object

from scripts import m3_10_qualification_report as report
from scripts import m3_11_frozen_entry as entry
from scripts import m3_11_frozen_local as local
from scripts.m3_11_retirement_files import record
from scripts.m3_11_unattended.model import stamp
from scripts.qualification_disposition import DIRECTORY
from scripts.qualification_mutation import ownership


@pytest.fixture
def selection(tmp_path: Path) -> SimpleNamespace:
    tmp_path.chmod(0o700)
    now = datetime.now(UTC)
    active = {
        "lease_id": "synthetic",
        "manifest_sha256": "a" * 64,
        "status": "active",
        "overdue": False,
        "results": [{"not_due": True} for _ in range(7)],
    }
    contract = {
        "active_lease": active,
        "host_id": "a" * 64,
        "host_started_at": stamp(now - timedelta(hours=1)),
        "host_helper": "b" * 40,
        "native_workflow": "c" * 40,
        "independent_helper": "d" * 40,
        "collector_sha256": "e" * 64,
    }
    common = {
        "overdue": 0,
        "legacy_verified": 50,
        "accepted_uncertainty": 1,
        "cleanup_complete": False,
        "current_lease_closed": False,
    }
    host: dict[str, object] = {
        **common,
        "status": "verified-new-host-cleanup",
        "container_id": contract["host_id"],
        "started_at": contract["host_started_at"],
        "active_obligations": 7,
        "old_cleanup_preserved": True,
        "receipt": {
            "actor": "watchdog",
            "status": "ready",
            "helper_revision": contract["host_helper"],
            "leases": [active],
            "observed_at": stamp(now),
        },
    }
    independent: dict[str, object] = {
        **common,
        "status": "verified-scheduled-cleanup-separate-native-helper-binding",
        "event": "schedule",
        "run_attempt": 1,
        "managed_run_id": active["lease_id"],
        "manifest_sha256": active["manifest_sha256"],
        "active_lease": active,
        "native_workflow_revision": contract["native_workflow"],
        "installed_cleanup_helper_revision": contract["independent_helper"],
        "collector_sha256": contract["collector_sha256"],
        "native_created_at": stamp(now),
    }

    def put(name: str, value: dict[str, object]) -> dict[str, object]:
        path = tmp_path / name
        record(path, value)
        raw = path.read_bytes()
        return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    chosen = {"host": put("host.json", host), "independent": put("independent.json", independent)}
    chosen["collection"] = put(
        "collection.json",
        {
            "status": "passed",
            "verified_sha256": chosen["independent"]["sha256"],
            "provider_calls": 0,
            "new_dispatches": 0,
            "live_mutations": 0,
        },
    )
    evidence = {
        "archive": {},
        "archive_path": str(tmp_path / "archive.zip"),
        "image": {},
        "image_path": str(tmp_path / "state.ext4"),
        "original_result": put("result.json", {"result": "native-bound-result"}),
        "files": [],
        "cleanup_contract": contract,
    }
    return SimpleNamespace(
        chosen=chosen, contract=contract, evidence=evidence, now=now, root=tmp_path
    )


def test_actual_local_proof_result_is_accepted_by_entry(
    selection: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        local, "verify", lambda *a, **kw: {"result": {"result": "native-bound-result"}}
    )
    value = local.verify_local(selection.evidence, selection.chosen, scratch=selection.root)
    emitted: list[dict[str, object]] = []
    monkeypatch.setattr(entry, "emit", emitted.append)
    monkeypatch.setattr(entry, "require_remaining", lambda n: None)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=object()))
    monkeypatch.setattr(entry, "frame", lambda *a, **kw: {**value, "nonce": emitted[-1]["nonce"]})
    proof = entry.LocalProof(str(value["evidence_sha256"]))
    assert proof() == value["evidence_sha256"]


def test_bound_file_parses_only_the_bytes_it_authenticated(
    selection: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = selection.evidence["original_result"]
    path = Path(binding["path"])

    def parse(raw: bytes, **kwargs: Any) -> dict[str, object]:  # noqa: ANN401 - native decoder options
        path.unlink()
        record(path, {"result": "different-native-result"})
        return decode_json_object(raw, **kwargs)

    monkeypatch.setattr(local, "decode_json_object", parse)
    assert local.bound_file(binding) == {"result": "native-bound-result"}


def test_bound_file_rejects_replacement_before_read(selection: SimpleNamespace) -> None:
    binding = selection.evidence["original_result"]
    path = Path(binding["path"])
    path.unlink()
    record(path, {"result": "different-native-result"})
    with pytest.raises(ValueError):
        local.bound_file(binding)


def test_fetch_does_not_renew_cleanup_origin(selection: SimpleNamespace) -> None:
    assert local.cleanup(
        selection.chosen, selection.contract, now=selection.now + timedelta(seconds=5399)
    ) == selection.now + timedelta(seconds=5400)
    with pytest.raises(ValueError):
        local.cleanup(
            selection.chosen, selection.contract, now=selection.now + timedelta(seconds=5400)
        )


def test_long_local_validation_rechecks_original_proof_deadline(
    selection: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [selection.now]
    monkeypatch.setattr(local, "datetime", SimpleNamespace(now=lambda zone: clock[0]))

    def verify(*args: object, **kwargs: object) -> dict[str, object]:
        clock[0] += timedelta(seconds=5400)
        return {"result": {"result": "native-bound-result"}}

    monkeypatch.setattr(local, "verify", verify)
    with pytest.raises(ValueError):
        local.verify_local(selection.evidence, selection.chosen, scratch=selection.root)


def test_changed_original_result_rejected(
    selection: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local, "verify", lambda *a, **kw: {"result": {"result": "different"}})
    with pytest.raises(ValueError):
        local.verify_local(selection.evidence, selection.chosen, scratch=selection.root)


@pytest.mark.parametrize("retired", [False, True])
def test_direct_publication_holds_shared_ownership_until_both_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retired: bool
) -> None:
    tmp_path.chmod(0o700)
    calls: list[str] = []
    monkeypatch.setattr(
        report, "create_report", lambda *a, **kw: {"synthetic": "no acceptance claim"}
    )

    def write(path: Path, raw: bytes, **kwargs: object) -> None:
        with pytest.raises(BlockingIOError), ownership(tmp_path, exclusive=True):
            pytest.fail("retirement crossed publication")
        calls.append(path.name)

    monkeypatch.setattr(report, "write_once", write)
    if retired:
        (tmp_path / DIRECTORY).mkdir(mode=0o700)
        with pytest.raises(ValueError, match="permanently"):
            report.publish_report(
                tmp_path, repository=tmp_path, storage_target="a" * 64, milestone="3.11"
            )
        assert not calls
    else:
        report.publish_report(
            tmp_path, repository=tmp_path, storage_target="a" * 64, milestone="3.11"
        )
        assert calls == ["qualification.json", "qualification.sha256"]


def test_creation_rejects_marker_before_reading_any_original(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    (tmp_path / DIRECTORY).mkdir(mode=0o700)
    with pytest.raises(ValueError, match="permanently"):
        report.create_report(tmp_path)
