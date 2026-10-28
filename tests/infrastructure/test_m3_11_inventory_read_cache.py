"""Fresh authenticated listings, immutable version reuse and late CREATE fences."""

from __future__ import annotations

from copy import deepcopy
from http import HTTPStatus
from pathlib import Path
from typing import override

import pytest

from scripts.m3_11_unattended.connect_api import Response
from scripts.m3_11_unattended.inventory import ConnectInventory, fact
from scripts.m3_11_unattended.model import LeaseManifest, LifecycleError, instant

from .test_m3_11_lease_inventory import NOW, ConnectDouble, LeaseCase, manifest


class VersionedConnect(ConnectDouble):
    def __init__(self) -> None:
        super().__init__()
        self.list_reads = self.body_reads = 0
        self.racing_version = False

    @override
    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        response = super().request(method, path, body)
        if method == "GET":
            self.list_reads += 1
            if response.status == HTTPStatus.OK:
                assert isinstance(response.body, list)
                return Response(
                    HTTPStatus.OK,
                    [
                        {k: deepcopy(v) for k, v in row.items() if k != "fields"}
                        for row in response.body
                    ],
                )
        return response

    @override
    def item(self, vault: str, item: str) -> dict[str, object]:
        self.body_reads += 1
        value = super().item(vault, item)
        if self.racing_version:
            value["version"] = 2
        return value


def populated(tmp_path: Path) -> tuple[VersionedConnect, ConnectInventory, dict[str, object]]:
    client = VersionedConnect()
    inventory = ConnectInventory(client, client.vault, spool=tmp_path / "pending")
    selected = manifest()
    record = fact(selected, "manifest", selected.document())
    inventory.publish(record)
    for value in client.items.values():
        value["version"] = 1
    client.list_reads = client.body_reads = 0
    return client, inventory, record


def test_every_scan_lists_fresh_and_returns_independent_validated_objects(tmp_path: Path) -> None:
    client, inventory, record = populated(tmp_path)
    first = inventory.records()
    first[0]["payload"]["lease_id"] = "mutated-caller-copy"  # type: ignore[index]
    assert inventory.records() == [record]
    assert client.list_reads == 2  # noqa: PLR2004 - two explicit scans/publications
    assert client.body_reads == 1


def test_new_close_fact_is_not_hidden_by_cached_manifest(tmp_path: Path) -> None:
    client, inventory, record = populated(tmp_path)
    inventory.records()
    closing = fact(LeaseManifest.parse(record["payload"]), "close-cancel", {})
    inventory.publish(closing)
    assert closing in inventory.records()
    assert client.posts == 2  # noqa: PLR2004 - two explicit scans/publications


@pytest.mark.parametrize("change", ["version", "metadata", "reader", "error", "disappearance"])
def test_change_or_failed_listing_invalidates_validated_body(tmp_path: Path, change: str) -> None:
    client, inventory, record = populated(tmp_path)
    inventory.records()
    item = next(iter(client.items.values()))
    if change == "version":
        item["version"] = 2
    elif change == "metadata":
        item["updatedAt"] = "2026-10-28T00:00:00Z"
    elif change == "reader":
        client.credential_sha256 = "changed-reader"
    elif change == "error":
        client.fail_list = True
        with pytest.raises(LifecycleError):
            inventory.records()
        client.fail_list = False
    else:
        client.hidden = True
        assert inventory.records() == []
        client.hidden = False
    assert inventory.records() == [record]
    assert client.body_reads == 2  # noqa: PLR2004 - two explicit scans/publications


@pytest.mark.parametrize("version", [None, True, 0, -1, "1"])
def test_unversioned_metadata_never_authorizes_body_reuse(tmp_path: Path, version: object) -> None:
    client, inventory, record = populated(tmp_path)
    next(iter(client.items.values()))["version"] = version
    assert inventory.records() == inventory.records() == [record]
    assert client.body_reads == 2  # noqa: PLR2004 - two explicit scans/publications


def test_racing_list_and_full_versions_never_enter_cache(tmp_path: Path) -> None:
    client, inventory, record = populated(tmp_path)
    client.racing_version = True
    assert inventory.records() == inventory.records() == [record]
    assert client.body_reads == 2  # noqa: PLR2004 - two explicit scans/publications


def test_publication_readback_always_performs_exact_fresh_get(tmp_path: Path) -> None:
    client, inventory, record = populated(tmp_path)
    inventory.records()
    selected = next(iter(client.items))
    assert inventory._read(selected, published=True) == record
    assert client.body_reads == 2  # noqa: PLR2004 - two explicit scans/publications


def test_cache_memory_limit_retains_full_get_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, inventory, record = populated(tmp_path)
    monkeypatch.setattr("scripts.m3_11_unattended.inventory.MAX_READ_CACHE_BYTES", 0)
    assert inventory.records() == inventory.records() == [record]
    assert client.body_reads == 2  # noqa: PLR2004 - two explicit scans/publications


def test_cutoff_crossed_during_inventory_forbids_subsequent_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    clock = [NOW]
    original = case.lifecycle.records

    def slow_records() -> dict[str, dict[str, object]]:
        value = original()
        clock[0] = instant(case.manifest.policy.issuance_before)
        return value

    monkeypatch.setattr(case.lifecycle, "records", slow_records)
    case.lifecycle.clock = lambda: clock[0]
    with pytest.raises(LifecycleError, match="outside its approved bounds"):
        case.issue()
    assert sum(v.creates for v in case.providers.values()) == 0


def test_cancel_arriving_during_inventory_forbids_subsequent_create(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = LeaseCase(tmp_path)
    case.confirm()
    cancelled = [False]
    original = case.lifecycle.records

    def slow_records() -> dict[str, dict[str, object]]:
        value = original()
        cancelled[0] = True
        return value

    def check() -> None:
        if cancelled[0]:
            raise LifecycleError("synthetic cancellation")

    monkeypatch.setattr(case.lifecycle, "records", slow_records)
    with pytest.raises(LifecycleError, match="synthetic cancellation"):
        case.lifecycle.issue(
            writer_sha256="a" * 64,
            approved_policy_sha256=case.manifest.policy.sha256,
            independent_server_id="s" * 26,
            check_cancelled=check,
        )
    assert sum(v.creates for v in case.providers.values()) == 0


@pytest.mark.parametrize("failed", [False, True])
def test_exact_readback_invalidates_prior_cached_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    client, inventory, record = populated(tmp_path)
    inventory.records()
    selected = next(iter(client.items))
    original = client.item

    def read(vault: str, item: str) -> dict[str, object]:
        if failed:
            raise LifecycleError("synthetic failed exact read")
        value = original(vault, item)
        value["version"] = 2
        return value

    with monkeypatch.context() as context:
        context.setattr(client, "item", read)
        if failed:
            with pytest.raises(LifecycleError):
                inventory._read(selected, published=True)
        else:
            assert inventory._read(selected, published=True) == record
    reads_before = client.body_reads
    assert inventory.records() == [record]
    assert client.body_reads == reads_before + 1
