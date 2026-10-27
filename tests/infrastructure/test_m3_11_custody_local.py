"""New index bindings separate original bytes from current cleanup authority."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts import m3_11_custody_local as local
from scripts.m3_11_combined_inputs import FORMAT as FIXTURE
from scripts.m3_11_combined_inputs import _environment
from scripts.m3_11_frozen_retirement import FORMAT as OLD_PLAN
from scripts.m3_11_frozen_retirement import RETAINED
from scripts.m3_11_retirement_files import digest, record

from .test_m3_11_custody_retirement import approved_plan
from .test_m3_11_frozen_terminal import closed


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "fixture",
        "archive",
        "manifest",
        "provenance",
        "cleanup-lease",
        "cleanup-helper",
        "expired",
    ],
)
def test_original_native_bindings_are_not_replaced_by_current_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    tmp_path.chmod(0o700)
    approved = approved_plan()
    old, _facts, issuer, created = closed()
    approved.update(historical_lease_id=old.lease_id, historical_manifest_sha256=old.sha256)
    old_run = Path("/evidence/runs") / str(uuid.uuid7()) / "qualification/spaces-synthetic.original"

    def put(name: str, value: dict[str, object]) -> dict[str, object]:
        path = tmp_path / name
        record(path, value)
        raw = path.read_bytes()
        return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    native = {
        "format": FIXTURE,
        "run_id": approved["fixture_id"],
        "environment": _environment(old_run, str(approved["fixture_id"]), "unix:///original.sock"),
    }
    if fault == "fixture":
        native["run_id"] = str(uuid.uuid7())
    original = {
        "format": OLD_PLAN,
        "original_run": str(old_run),
        "producing_attempt": str(uuid.uuid7()),
        "consumer_attempt": str(uuid.uuid7()),
        "lease_id": old.lease_id,
        "manifest_sha256": old.sha256,
        "implementation_revision": old.helper_revision,
        "fixture_sha256": "a" * 64,
        "evidence_sha256": "b" * 64,
        "archive": approved["archive"],
        "retained": RETAINED,
    }
    evidence = {
        "archive": approved["archive"],
        "archive_path": str(tmp_path / "archive.zip"),
        "image": {"size": 8 * 1024**3, "sha256": "a" * 64},
        "image_path": str(tmp_path / "state.ext4"),
        "original_result": {},
        "files": [],
        "cleanup_contract": {"historical": True},
    }
    index = {
        "format": local.FORMAT,
        "source_workspace_id": approved["source_workspace_id"],
        "fixture_id": approved["fixture_id"],
        "historical": {"manifest": old.document(), "issuer": issuer, "created": created},
        "original_fixture": put("fixture.json", native),
        "original_plan": put("old-plan.json", original),
        "migration_records": [
            put("provenance.json", {"activation": False, "originals_preserved": True})
        ],
        "evidence": evidence,
    }
    contract = {
        "active_lease": {
            "lease_id": approved["current_lease_id"],
            "manifest_sha256": approved["current_manifest_sha256"],
            "status": "active",
            "overdue": False,
            "results": [{}] * 7,
        },
        "host_helper": approved["implementation_revision"],
        "independent_helper": approved["implementation_revision"],
    }
    if fault == "archive":
        approved["archive"] = {
            **cast(dict[str, object], approved["archive"]),
            "version": "another-version",
        }
    elif fault == "manifest":
        approved["historical_manifest_sha256"] = "f" * 64
    elif fault == "provenance":
        (tmp_path / "provenance.json").unlink()
    elif fault == "cleanup-lease":
        cast(dict[str, object], contract["active_lease"])["lease_id"] = str(uuid.uuid7())
    elif fault == "cleanup-helper":
        contract["independent_helper"] = "e" * 40
    approved.update(
        custody_sha256=digest(index),
        evidence_sha256=digest(evidence),
        cleanup_contract_sha256=digest(contract),
    )
    calls: list[str] = []

    def cleanup(_selection: object, selected: dict[str, object], *, now: datetime) -> datetime:
        assert selected == contract
        calls.append("cleanup")
        if fault == "expired":
            raise ValueError("synthetic native cleanup proof is stale")
        return now + timedelta(hours=1)

    def preserve(selected: object, *, scratch: Path) -> dict[str, object]:
        assert selected == evidence and scratch == tmp_path
        calls.append("native-preserved-verifier")
        return {"evidence_sha256": digest(evidence)}

    monkeypatch.setattr(local, "cleanup", cleanup)
    # Native preservation is exercised independently, including the actual
    # migrated archive/image. This test isolates new index/authority bindings.
    monkeypatch.setattr(local, "verify_preserved", preserve)
    if fault == "none":
        result = local.verify(
            index, approved, selection={}, cleanup_contract=contract, scratch=tmp_path
        )
        assert result["status"] == "native-custody-and-cleanup-verified"
        assert result["custody_sha256"] == digest(index)
        assert calls == ["cleanup", "native-preserved-verifier", "cleanup"]
        assert evidence["cleanup_contract"] == {"historical": True}
    else:
        with pytest.raises((ValueError, OSError, RuntimeError)):
            local.verify(index, approved, selection={}, cleanup_contract=contract, scratch=tmp_path)
        assert "native-preserved-verifier" not in calls
