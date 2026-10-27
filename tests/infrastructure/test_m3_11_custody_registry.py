"""Native journal publication, mixed inventories and lost replies without replay."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import override

import pytest

from scripts import m3_11_custody_registry as registry
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.connect_api import Response
from scripts.m3_11_unattended.inventory import ConnectInventoryReader
from scripts.m3_11_unattended.model import stamp

from .test_m3_11_custody_retirement import approval, approved_plan
from .test_m3_11_lease_inventory import ConnectDouble


def exclusion() -> dict[str, object]:
    value = approved_plan()
    return {
        "format": registry.FORMAT,
        "fixture_id": value["fixture_id"],
        "plan": value,
        "authorization": approval(value),
        "reserved_at": stamp(datetime.now(UTC)),
    }


class Client(ConnectDouble):
    def __init__(self) -> None:
        super().__init__()
        self.posts = 0
        self.fail_before = self.fail_after = False

    @override
    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        assert path == f"/v1/vaults/{self.vault}/items"
        if method == "GET":
            return Response(200, [deepcopy(row) for row in self.items.values()])
        assert method == "POST" and body is not None
        self.posts += 1
        if self.fail_before:
            raise ConnectionError("synthetic no response")
        self.items["x" * 26] = {**deepcopy(body), "id": "x" * 26}
        if self.fail_after:
            raise ConnectionError("synthetic lost acknowledgment")
        return Response(201, self.items["x" * 26])

    @override
    def published_item(self, vault: str, item: str) -> dict[str, object]:
        return self.item(vault, item)


def test_once_publication_is_visible_to_separate_reader_and_ignored_by_native_leases(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    client, value = Client(), exclusion()
    first = registry.Registry(client, client.vault)
    first.publish_once(value, spool=tmp_path)
    assert first.records() == [value]
    assert ConnectInventoryReader(client, client.vault).records() == []
    second = registry.Registry(client, client.vault)
    assert second.selected(str(value["fixture_id"])) == value
    with pytest.raises(ValueError, match="no replay"):
        first.publish_once(value, spool=tmp_path)
    assert client.posts == 1


@pytest.mark.parametrize("phase", ["before", "after"])
def test_lost_post_is_consumed_before_and_after_commit(tmp_path: Path, phase: str) -> None:
    tmp_path.chmod(0o700)
    client, value = Client(), exclusion()
    setattr(client, "fail_" + phase, True)
    reader = registry.Registry(client, client.vault)
    with pytest.raises(ConnectionError):
        reader.publish_once(value, spool=tmp_path)
    setattr(client, "fail_" + phase, False)
    with pytest.raises((ValueError, FileExistsError)):
        reader.publish_once(value, spool=tmp_path)
    assert client.posts == 1 and len(list(tmp_path.glob("*.json"))) == 1


@pytest.mark.parametrize(
    "fault", ["duplicate", "payload", "tag", "title", "canonical", "truncated"]
)
def test_malformed_or_conflicting_external_evidence_fails_closed(
    tmp_path: Path, fault: str
) -> None:
    tmp_path.chmod(0o700)
    client, value = Client(), exclusion()
    reader = registry.Registry(client, client.vault)
    reader.publish_once(value, spool=tmp_path)
    item = client.items["x" * 26]
    if fault == "duplicate":
        client.items["y" * 26] = {**deepcopy(item), "id": "y" * 26}
    elif fault == "tag":
        item["tags"] = []
    elif fault == "title":
        item["title"] = registry.PREFIX + "wrong"
    elif fault == "truncated":
        item["state"] = "ARCHIVED"
    else:
        fields = item["fields"]
        assert isinstance(fields, list)
        if fault == "canonical":
            fields[0]["value"] = json.dumps(value, indent=2)
        else:
            fields[0]["value"] = canonical_bytes({**value, "fixture_id": "wrong"}).decode()
    with pytest.raises((ValueError, RuntimeError)):
        reader.records()


def test_unrelated_old_notes_do_not_become_retirement_authority() -> None:
    client = Client()
    client.items["a" * 26] = {"id": "a" * 26, "title": "old-legacy-event", "tags": ["old"]}
    assert registry.Registry(client, client.vault).records() == []
