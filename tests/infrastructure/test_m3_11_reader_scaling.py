"""Synthetic transport regressions, not live readiness or CREATE evidence."""

from __future__ import annotations

import json
import subprocess
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

import pytest

from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import journal as implementation
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.journal import ConnectObligations, event, record_title
from scripts.m3_11_unattended.model import LifecycleError, digest

from .test_m3_11_lease_migration import imported
from .test_m3_11_unattended_lifecycle import Case


class Transport:
    """Only the external exchange process is controlled; all readers run unchanged."""

    def __init__(
        self, monkeypatch: pytest.MonkeyPatch, items: dict[str, dict[str, object]]
    ) -> None:
        self.items = deepcopy(items)
        self.calls: Counter[tuple[str, str, str]] = Counter()
        self.list_status = 200
        self.body_status = 200
        self.duplicate = False
        self.body_overrides: dict[str, object] = {}
        for row in self.items.values():
            row["version"] = 1
        monkeypatch.setattr(subprocess, "run", self.run)

    def run(self, argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert argv[1:] == ["-m", "scripts.m3_11_unattended.connect_api", "--exchange"]
        request = json.loads(cast(bytes, kwargs["input"]))
        assert request["method"] == "GET"
        url = urlsplit(request["url"])
        path = url.path
        self.calls[url.netloc, request["token"], path] += 1
        if path.endswith("/items"):
            status = self.list_status
            body: object = [
                {key: deepcopy(value) for key, value in item.items() if key != "fields"}
                for item in self.items.values()
            ]
            if self.duplicate:
                cast(list[object], body).append(deepcopy(cast(list[object], body)[0]))
        else:
            status = self.body_status
            body = {**deepcopy(self.items[path.rsplit("/", 1)[1]]), **self.body_overrides}
        return subprocess.CompletedProcess(
            argv, 0, canonical_bytes({"status": status, "body": body}), b""
        )

    @property
    def reads(self) -> int:
        return sum(count for (_, _, path), count in self.calls.items() if "/items/" in path)


def setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Case, Transport, ConnectObligations, dict[str, object]]:
    case, old, mapping, _ = imported(tmp_path)
    transport = Transport(monkeypatch, old.items)
    client = Connect("https://synthetic.example.test", "SYNTHETIC-ORIGINAL-IDENTITY")
    reader = ConnectObligations(
        client, old.vault, spool=tmp_path / "reader", expected=digest(mapping)
    )
    return case, transport, reader, mapping


def test_fresh_list_each_scan_and_private_return_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, transport, reader, _ = setup(tmp_path, monkeypatch)
    first = reader.records()
    first[0]["payload"] = {"caller_mutation": True}
    assert reader.records() == case.journal.records()
    assert transport.reads == len(transport.items)
    assert (
        sum(count for (_, _, path), count in transport.calls.items() if path.endswith("/items"))
        == 2  # noqa: PLR2004 - exactly two fresh authenticated scans
    )


@pytest.mark.parametrize("fault", ["removed", "version", "title", "tags", "state", "duplicate"])
def test_changed_or_unavailable_inventory_never_passes_from_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    _, transport, reader, _ = setup(tmp_path, monkeypatch)
    reader.records()
    selected = next(iter(transport.items))
    if fault == "removed":
        del transport.items[selected]
    elif fault == "version":
        transport.items[selected]["version"] = 2
        cast(list[dict[str, object]], transport.items[selected]["fields"])[0]["value"] = "{}"
    elif fault == "title":
        transport.items[selected]["title"] = "changed"
    elif fault == "tags":
        transport.items[selected]["tags"] = ["changed"]
    elif fault == "state":
        transport.items[selected]["state"] = "ARCHIVED"
    else:
        transport.duplicate = True
    with pytest.raises((LifecycleError, ValueError)):
        reader.records()
    assert not reader._read_cache


@pytest.mark.parametrize("change", ["client", "server", "identity", "vault", "new-reader"])
def test_body_cache_cannot_cross_server_identity_vault_or_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    _, transport, reader, mapping = setup(tmp_path, monkeypatch)
    reader.records()
    before = transport.reads
    if change == "client":
        reader.client = Connect(reader.client.url, "SYNTHETIC-ORIGINAL-IDENTITY")
    elif change == "server":
        reader.client.url = "https://independent.example.test"
    elif change == "identity":
        reader.client = Connect(reader.client.url, "SYNTHETIC-INDEPENDENT-IDENTITY")
    elif change == "vault":
        reader.vault = "w" * 26
        for item in transport.items.values():
            item["vault"] = {"id": reader.vault}
    else:
        reader = ConnectObligations(
            reader.client, reader.vault, spool=tmp_path / "separate", expected=digest(mapping)
        )
    reader.records()
    assert transport.reads == before + len(transport.items)


@pytest.mark.parametrize("version", [None, True, False, 0, -1, "1", 1.0])
def test_missing_or_invalid_versions_use_full_gets_after_a_warm_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, version: object
) -> None:
    _, transport, reader, _ = setup(tmp_path, monkeypatch)
    reader.records()
    for item in transport.items.values():
        if version is None:
            item.pop("version")
        else:
            item["version"] = version
    reader.records()
    reader.records()
    assert transport.reads == 3 * len(transport.items)
    assert not reader._read_cache


@pytest.mark.parametrize("full_version", [2, True, None, 0, -1, "1"])
def test_list_body_version_mismatch_is_never_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, full_version: object
) -> None:
    _, transport, reader, _ = setup(tmp_path, monkeypatch)
    transport.body_overrides = {"version": full_version}
    reader.records()
    reader.records()
    assert transport.reads == 2 * len(transport.items)
    assert not reader._read_cache


def test_cache_memory_bound_keeps_uncached_full_get_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, transport, reader, _ = setup(tmp_path, monkeypatch)
    monkeypatch.setattr(implementation, "MAX_READ_CACHE_BYTES", 1)
    reader.records()
    reader.records()
    assert transport.reads == 2 * len(transport.items)
    assert not reader._read_cache


def test_partial_cache_budget_counts_admitted_bytes_and_refetches_the_rest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, transport, reader, _ = setup(tmp_path, monkeypatch)
    imported_note = next(
        item for item in transport.items.values() if str(item["title"]).startswith("m3-11-import-")
    )
    listed = {key: value for key, value in imported_note.items() if key != "fields"}
    budget = len(canonical_bytes(listed)) + len(canonical_bytes(imported_note))
    monkeypatch.setattr(implementation, "MAX_READ_CACHE_BYTES", budget)
    reader.records()
    assert set(reader._read_cache) == {imported_note["id"]}
    assert reader._read_cache_bytes == budget
    reader.records()
    assert transport.reads == 2 * len(transport.items) - 1
    assert reader._read_cache_bytes == budget


@pytest.mark.parametrize("status", [401, 403, 404])
@pytest.mark.parametrize("boundary", ["list", "changed-body", "new-body"])
def test_permission_or_absence_failure_cannot_return_partial_or_cached_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int, boundary: str
) -> None:
    case, transport, reader, _ = setup(tmp_path, monkeypatch)
    reader.records()
    original = deepcopy(transport.items)
    if boundary == "list":
        transport.list_status = status
    else:
        if boundary == "changed-body":
            next(iter(transport.items.values()))["version"] = 2
        else:
            add_observation(transport, case)
        transport.body_status = status
    with pytest.raises(LifecycleError):
        reader.records()
    assert not reader._read_cache
    transport.list_status = transport.body_status = 200
    transport.items = original
    before = transport.reads
    reader.records()
    assert transport.reads == before + len(transport.items)


def add_observation(transport: Transport, case: Case) -> dict[str, object]:
    value = event("heartbeat", case.run_id, {"synthetic": True})
    item = deepcopy(next(iter(transport.items.values())))
    item.update(id="z" * 26, title=record_title(value))
    cast(list[dict[str, object]], item["fields"])[0]["value"] = canonical_bytes(value).decode()
    transport.items[str(item["id"])] = item
    return value


def test_new_list_membership_is_read_and_removed_optional_members_are_not_reused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, transport, reader, _ = setup(tmp_path, monkeypatch)
    reader.records()
    before = transport.reads
    value = add_observation(transport, case)
    assert value in reader.records()
    assert transport.reads == before + 1
    del transport.items["z" * 26]
    assert value not in reader.records()
    assert "z" * 26 not in reader._read_cache


def test_changed_version_refetches_valid_observation_and_rejects_new_issuance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, transport, reader, _ = setup(tmp_path, monkeypatch)
    value = add_observation(transport, case)
    reader.records()
    before = transport.reads
    item = transport.items["z" * 26]
    item["version"] = 2
    assert value in reader.records()
    assert transport.reads == before + 1
    value = event("intent", case.run_id, {})
    item.update(version=3, title=record_title(value))
    cast(list[dict[str, object]], item["fields"])[0]["value"] = canonical_bytes(value).decode()
    with pytest.raises(LifecycleError, match="obsolete issuance"):
        reader.records()


@pytest.mark.parametrize("fault", ["id", "vault", "title", "category", "tags", "state", "fields"])
def test_malformed_full_response_cannot_become_a_cache_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    _, transport, reader, _ = setup(tmp_path, monkeypatch)
    replacement: object = {"id": "w" * 26} if fault == "vault" else "invalid"
    transport.body_overrides = {fault: replacement}
    with pytest.raises((LifecycleError, ValueError)):
        reader.records()
    assert not reader._read_cache
