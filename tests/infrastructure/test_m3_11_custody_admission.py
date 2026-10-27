"""The fresh native lease supplies its real first runtime use after closeout."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts import m3_11_custody_admission as admission
from scripts import m3_11_custody_registry as registry
from scripts.m3_11_custody_retirement import CustodyRetirement
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended import storage_admission
from scripts.m3_11_unattended.config import LeaseBootstrap
from scripts.m3_11_unattended.model import instant

from .test_m3_11_custody_registry import Client
from .test_m3_11_custody_retirement import Fixture, approval, approved_plan
from .test_m3_11_storage_admission import prepared


@pytest.mark.parametrize(
    "fault",
    ["none", "no-index", "no-external", "changed-result", "wrong-lease", "unclosed-version"],
)
def test_completed_retirement_is_the_only_unused_lease_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    directory, lease, daemon, config, storage = prepared(tmp_path, monkeypatch)
    for path in lease.directory.glob("use-*.json"):
        path.unlink()
    root = directory.parent.parent
    fixture, value = Fixture(root), approved_plan()
    value.update(
        current_lease_id=lease.manifest().lease_id,
        current_manifest_sha256=lease.manifest().sha256,
        implementation_revision=config.helper_revision,
    )
    archive = cast(dict[str, object], value["archive"])
    archive["bucket"] = config.targets.archive_bucket
    fixture.archives.bucket = config.targets.archive_bucket
    transaction = CustodyRetirement(value, fixture)
    result = transaction.execute(approval(value))
    index = {"fixture_id": value["fixture_id"], "retirement_sha256": digest(result)}
    write_private(lease.directory / "custody-retirement.json", index)
    client = Client()
    assert fixture.external is not None
    client.items["x" * 26] = {
        "id": "x" * 26,
        "category": "SECURE_NOTE",
        "tags": [registry.TAG],
        "title": registry.PREFIX + str(value["fixture_id"]),
        "fields": [
            {
                "id": "notesPlain",
                "purpose": "NOTES",
                "value": canonical_bytes(fixture.external).decode(),
            }
        ],
    }
    monkeypatch.setattr(LeaseBootstrap, "reader", lambda _self: client)
    original = registry.Registry
    monkeypatch.setattr(admission, "admission_domain", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(admission, "Registry", lambda *_args: original(client, client.vault))
    if fault == "no-index":
        (lease.directory / "custody-retirement.json").unlink()
    elif fault == "no-external":
        client.items.clear()
    elif fault == "changed-result":
        (transaction.root / "retired.json").write_bytes(b"{}\n")
    elif fault == "wrong-lease":
        raw = read_private(transaction.root / "plan.json")
        raw["current_manifest_sha256"] = "0" * 64
        (transaction.root / "plan.json").write_bytes(canonical_bytes(raw))
    elif fault == "unclosed-version":
        storage.responses["list_objects_v2"] = {
            "IsTruncated": False,
            "Contents": [{"Key": "retained"}],
        }
    args = {
        "lease_id": lease.manifest().lease_id,
        "manifest_sha256": lease.manifest().sha256,
        "evidence_root": root,
        "docker": daemon,
        "clock": lambda: instant(lease.manifest().created_at) + timedelta(minutes=1),
    }
    if fault == "no-index":
        with pytest.raises(RuntimeError, match="original released consumer"):
            storage_admission.observe(config, **args)  # type: ignore[arg-type]
        assert storage.calls == []
    else:
        observed = storage_admission.observe(config, **args)  # type: ignore[arg-type]
        assert observed["whole_bucket_empty"] is (fault == "none")
        assert observed["admitted"] is None
    assert not list(lease.directory.glob("use-*.json"))
    assert daemon.mutations == []
