"""Native stage + real Removal journal and byte copies; synthetic provider only."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

from scripts import m3_11_frozen_remote as remote
from scripts import m3_11_frozen_remote_proof as remote_proof
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_live_storage import FORMAT as STORAGE_FORMAT
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended.model import LeaseManifest

from .test_m3_11_backup_removal import Storage
from .test_m3_11_backup_removal import removal as removal  # noqa: PLC0414
from .test_m3_11_frozen_backups import prepared
from .test_m3_11_frozen_disposal import approval
from .test_m3_11_frozen_disposal import case as case  # noqa: PLC0414


@pytest.mark.parametrize("boundary", ["complete", "lost-data", "lost-owner", "submitted-present"])
def test_remote_stage_preserves_real_journal_and_exact_uncertainty(
    case: SimpleNamespace,
    removal: tuple[Removal, Storage],
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    item, store, expected = prepared(removal)
    item.quiescent = lambda: digest(case.fixture)

    class IsolatedRemote(remote.NativeRemote):
        def __init__(self) -> None:
            # Native authentication/ownership are exercised by owner, transport
            # and fence tests. This keeps the actual state machine, SDK-shaped
            # requests, preservation, Removal and submission ledgers active.
            self.fixture, self.plan, self.run = case.fixture, case.original, case.run
            self.environment = {}
            self.storage = SimpleNamespace(target=item.target)  # type: ignore[assignment]
            self.archives = SimpleNamespace(observed=lambda: [("archives/synthetic.zip", "v1")])  # type: ignore[assignment]
            item.writer = remote._Writer(item.writer, self)

        @contextmanager
        def locked(self, plan: dict[str, object]) -> Iterator[None]:
            yield

        @contextmanager
        def submission(self) -> Iterator[None]:
            yield

        def owner(self) -> None:
            pass

        def frozen_state(self, plan: dict[str, object]) -> None:
            pass

        def fence(self) -> dict[str, object]:
            return {}

        def preserved_evidence(self, plan: dict[str, object]) -> None:
            pass

        def removal(self) -> Removal:
            item.directory = self.stage_root / "backup-removal"
            return item

    native = IsolatedRemote()
    monkeypatch.setattr(remote, "require_supported_closeout", lambda: None)
    monkeypatch.setattr(remote, "dns_absent", lambda *_args: None)
    plan = {
        "format": remote.FORMAT,
        "implementation_revision": "a" * 40,
        "retirement_plan": case.original,
        "retirement_authorization_sha256": "e" * 64,
        "fixture": case.fixture,
        "backup_inventory": expected,
        "maximum_backup_bytes": 1000000,
        "maximum_provider_requests": 1000,
    }
    approved = approval(plan, "remote-cleanup")
    if boundary in {"lost-data", "lost-owner"}:
        store.fail_after = "data-version" if boundary == "lost-data" else "owner-version"
    elif boundary == "submitted-present":
        cast(Mock, item.writer.client.delete_object).side_effect = OSError("unknown effect")  # type: ignore[attr-defined]
    if boundary == "complete":
        receipt = native.execute(plan, approved)
        assert receipt["whole_archive_bucket_empty"] is False
    else:
        with pytest.raises(OSError):
            native.execute(plan, approved)
        before = list(store.operations)
        files = {path: path.read_bytes() for path in native.stage_root.rglob("*") if path.is_file()}
        observed = native.reconcile(plan, approved)
        assert observed["mutation_submissions"] == 0 and store.operations == before
        assert files == {
            path: path.read_bytes() for path in native.stage_root.rglob("*") if path.is_file()
        }
        if boundary == "lost-data":
            receipt = native.continue_unsubmitted(plan, approved)
        else:
            with pytest.raises(ValueError):
                native.continue_unsubmitted(plan, approved)
            assert store.operations == before
            receipt = observed
    assert len(store.operations) == len(set(store.operations))
    if boundary == "submitted-present":
        assert cast(dict[str, object], receipt["observation"])["absent"] is False
        return
    assert set(store.versions) == {("backups/production/untouched", "production-version")}
    storage: dict[str, object] = {
        "format": STORAGE_FORMAT,
        "run_id": item.target.run_id,
        "region": item.target.region,
        "backup_bucket": item.target.backup_bucket,
        "archive_bucket": item.target.archive_bucket,
        "binding": item.binding,
        "owner_version": item.owner_version,
    }
    write_private(case.run / "live-storage.json", storage)
    manifest = cast(
        LeaseManifest,
        SimpleNamespace(
            targets=SimpleNamespace(
                region=item.target.region,
                backup_bucket=item.target.backup_bucket,
                archive_bucket=item.target.archive_bucket,
            )
        ),
    )
    canonical = json.loads(json.dumps(receipt))

    def verify(value: dict[str, object]) -> dict[str, object]:
        return remote_proof.verify(
            case.run,
            case.original,
            case.fixture,
            manifest,
            native.stage_root,
            value,
            guard=lambda: None,
        )

    result = verify(canonical)
    assert result["provider_calls"] == 0 and result["delete_submissions"] == 3  # noqa: PLR2004
    assert result["acknowledged_submissions"] == (
        2 if boundary in {"lost-owner", "lost-data"} else 3
    )
    for changed in (
        {**canonical, "unknown": True},
        {**canonical, "archive_observed_at": "2019-01-01T00:00:00Z"},
        {key: value for key, value in canonical.items() if key != "dns_observed_at"},
    ):
        with pytest.raises(ValueError):
            verify(changed)
