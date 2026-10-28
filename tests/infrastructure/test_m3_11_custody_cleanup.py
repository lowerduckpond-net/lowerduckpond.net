"""Complete scheduled selections reverify original native bytes and proof clocks."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import m3_11_custody_cleanup as cleanup
from scripts import m3_11_custody_github as github
from scripts import m3_11_custody_host as host
from scripts.m3_11_retirement_files import digest, fingerprint, record
from scripts.m3_11_unattended.docker import OWNER, helper_volume
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_custody_github import NOW, current, native_responses
from .test_m3_11_custody_host import EMITTED, ReadDocker, context


def binding(path: Path) -> dict[str, object]:
    return {"path": str(path), **fingerprint(path, github.native.MAX_ZIP)}


@pytest.fixture
def selection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    tmp_path.chmod(0o700)
    manifest, base, value = current()
    ctx, actor = context()
    ctx["host_helper"] = manifest.helper_revision
    ctx["runtime"]["workspace_id"] = "3301d911-61fe-4a27-aaa7-6a1da9c03c63"
    actor["Name"] = "/ldp-m311-watchdog-" + manifest.helper_revision[:12]
    actor["Config"]["Labels"][OWNER + ".helper"] = manifest.helper_revision
    actor["Mounts"][0].update(
        Name=helper_volume(manifest.helper_revision),
        Source="/volumes/" + helper_volume(manifest.helper_revision),
    )

    class Docker(ReadDocker):
        def cleanup_logs(self, container_id: str) -> bytes:
            receipt = deepcopy(value["documents"]["cleanup"])
            receipt.update(format="lowerduckpond-m3-11-lease-cleanup-v1", actor="watchdog")
            return (EMITTED + " " + json.dumps(receipt) + "\n").encode()

    monkeypatch.setattr(host, "datetime", SimpleNamespace(now=lambda zone: NOW))
    host.capture(Docker(ctx, actor), ctx, tmp_path / "host.json")
    value["run"].update(event="schedule", display_title="M3.11 reconcile")
    responses = native_responses(value)
    github.capture_scheduled(
        responses.__getitem__, 456, tmp_path / "github", base, manifest, clock=lambda: NOW
    )
    contract = {
        **ctx,
        "format": cleanup.FORMAT,
        "current_manifest": manifest.document(),
        "active_lease": value["documents"]["cleanup"]["leases"][1],
        "independent_helper": manifest.helper_revision,
        "native_workflow": manifest.helper_revision,
        "collector_sha256": "e" * 64,
        "github": base,
    }
    files = {
        name: fingerprint(tmp_path / "github" / name, github.native.MAX_ZIP)
        for name in cleanup.FILES
    }
    github_files = {"directory": str(tmp_path / "github"), "files": files}
    host_binding = binding(tmp_path / "host.json")
    record(
        tmp_path / "collection.json",
        {
            "format": "lowerduckpond-m3-11-custody-read-collection-v1",
            "status": "passed",
            "collector_sha256": contract["collector_sha256"],
            "host_sha256": host_binding["sha256"],
            "github_files_sha256": digest(files),
            "provider_calls": 0,
            "new_dispatches": 0,
            "live_mutations": 0,
        },
    )
    chosen = {
        "format": cleanup.SELECTION,
        "host": host_binding,
        "github": github_files,
        "collection": binding(tmp_path / "collection.json"),
    }
    return SimpleNamespace(
        root=tmp_path, chosen=chosen, contract=contract, manifest=manifest, native_value=value
    )


def test_complete_selection_reuses_no_projected_status_as_native_proof(
    selection: SimpleNamespace,
) -> None:
    result = cleanup.verify_scheduled(
        selection.chosen, selection.contract, now=NOW, scratch=selection.root / "scratch"
    )
    assert result == datetime(2026, 10, 10, 1, 30, tzinfo=UTC)
    assert sorted(p.name for p in (selection.root / "scratch" / "github").iterdir()) == sorted(
        cleanup.FILES
    )


@pytest.mark.parametrize(
    "change",
    [
        "github-bytes",
        "host-bytes",
        "collection-bytes",
        "helper",
        "manifest",
        "active-row",
        "host-start",
        "configuration",
        "collector",
        "protocol",
        "stale",
        "future",
    ],
)
def test_full_selection_fails_closed_on_binding_or_original_clock_change(
    selection: SimpleNamespace, change: str
) -> None:
    chosen, contract = deepcopy(selection.chosen), deepcopy(selection.contract)
    now = NOW
    if change == "github-bytes":
        (selection.root / "github" / "run.json").write_bytes(b"{}")
    elif change == "host-bytes":
        (selection.root / "host.json").write_bytes(b"{}")
    elif change == "collection-bytes":
        (selection.root / "collection.json").write_bytes(b"{}")
    elif change == "helper":
        contract["host_helper"] = "f" * 40
    elif change == "manifest":
        contract["current_manifest"]["lease_id"] = "01a145f3-87cc-74a2-b6cb-45a50b30414b"
    elif change == "active-row":
        contract["active_lease"]["results"][0]["status"] = "verified"
    elif change == "host-start":
        contract["host_started_at"] = "2026-10-10T00:00:01Z"
    elif change == "configuration":
        contract["cleanup_configuration_sha256"] = "f" * 64
    elif change == "collector":
        contract["collector_sha256"] = "f" * 64
    elif change == "protocol":
        chosen["format"] = "scheduled-label-instead-of-manual-proof"
    elif change == "stale":
        now += timedelta(seconds=5400)
    elif change == "future":
        now -= timedelta(minutes=5)
    with pytest.raises((ValueError, LifecycleError)):
        cleanup.verify_scheduled(chosen, contract, now=now, scratch=selection.root / "scratch")


def test_genuine_schedule_remains_required_for_enabled_custody_protocol(
    selection: SimpleNamespace,
) -> None:
    contract, chosen = deepcopy(selection.contract), deepcopy(selection.chosen)
    assert cleanup.verify_scheduled(
        chosen, contract, now=NOW, scratch=selection.root / "scheduled-accepted"
    ) == datetime(2026, 10, 10, 1, 30, tzinfo=UTC)
    value = deepcopy(selection.native_value)
    value["run"].update(event="workflow_dispatch", display_title="M3.11 confirm")
    responses = native_responses(value)
    github.capture(
        responses.__getitem__,
        456,
        selection.root / "manual",
        contract["github"],
        selection.manifest,
        clock=lambda: NOW,
    )
    files = {
        name: fingerprint(selection.root / "manual" / name, github.native.MAX_ZIP)
        for name in cleanup.FILES
    }
    chosen["github"] = {"directory": str(selection.root / "manual"), "files": files}
    record(
        selection.root / "manual-collection.json",
        {
            "format": "lowerduckpond-m3-11-custody-read-collection-v1",
            "status": "passed",
            "collector_sha256": contract["collector_sha256"],
            "host_sha256": chosen["host"]["sha256"],
            "github_files_sha256": digest(files),
            "provider_calls": 0,
            "new_dispatches": 0,
            "live_mutations": 0,
        },
    )
    chosen["collection"] = binding(selection.root / "manual-collection.json")
    with pytest.raises(ValueError, match="scheduled run"):
        cleanup.verify_scheduled(
            chosen, contract, now=NOW, scratch=selection.root / "manual-rejected"
        )
    contract["format"] = cleanup.MANUAL_PROPOSAL_FORMAT
    with pytest.raises(ValueError, match="unknown custody cleanup protocol"):
        cleanup.contract(contract)


def test_valid_large_native_metadata_is_copied_with_bounded_chunks(
    selection: SimpleNamespace,
) -> None:
    from scripts.m3_11_retirement_files import CHUNK  # noqa: PLC0415 - explicit copy boundary

    value = deepcopy(selection.native_value)
    value["run"]["additional_native_metadata"] = "x" * (CHUNK + 1)
    responses = native_responses(value)
    github.capture_scheduled(
        responses.__getitem__,
        456,
        selection.root / "large",
        selection.contract["github"],
        selection.manifest,
        clock=lambda: NOW,
    )
    chosen = deepcopy(selection.chosen)
    files = {
        name: fingerprint(selection.root / "large" / name, github.native.MAX_ZIP)
        for name in cleanup.FILES
    }
    chosen["github"] = {"directory": str(selection.root / "large"), "files": files}
    record(
        selection.root / "large-collection.json",
        {
            "format": "lowerduckpond-m3-11-custody-read-collection-v1",
            "status": "passed",
            "collector_sha256": selection.contract["collector_sha256"],
            "host_sha256": chosen["host"]["sha256"],
            "github_files_sha256": digest(files),
            "provider_calls": 0,
            "new_dispatches": 0,
            "live_mutations": 0,
        },
    )
    chosen["collection"] = binding(selection.root / "large-collection.json")
    assert cleanup.verify_scheduled(
        chosen, selection.contract, now=NOW, scratch=selection.root / "large-accepted"
    ) == datetime(2026, 10, 10, 1, 30, tzinfo=UTC)
    assert (selection.root / "large-accepted" / "github" / "run.json").stat().st_size > CHUNK
