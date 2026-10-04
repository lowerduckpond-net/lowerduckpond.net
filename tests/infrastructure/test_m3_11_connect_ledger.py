"""Independent-cache journal boundaries, including ambiguous mutation outcomes."""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path
from typing import override

import pytest

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended.connect_api import Connect, Response
from scripts.m3_11_unattended.connect_ledger import ACK_FORMAT, ConnectLedger
from scripts.m3_11_unattended.journal import TAG, OpJournal, event
from scripts.m3_11_unattended.model import LifecycleError, digest

VAULT = "v" * 26
ANCHOR = "a" * 26
LOCAL_AUTHOR, REMOTE_AUTHOR, REMOTE_SERVER = "L" * 26, "R" * 26, "S" * 26
CANARY = "connect-ledger-private-canary"
BINDING: dict[str, object] = {"source_revision": "a" * 40, "managed_run_id": str(uuid.uuid7())}


def note(
    record: dict[str, object], item_id: str, *, author: str = LOCAL_AUTHOR
) -> dict[str, object]:
    return {
        "id": item_id,
        "title": OpJournal._title(record),
        "category": "SECURE_NOTE",
        "tags": [TAG],
        "vault": {"id": VAULT},
        "version": 1,
        "lastEditedBy": author,
        "createdAt": "2026-10-04T00:00:00Z",
        "updatedAt": "2026-10-04T00:00:00Z",
        "fields": [{"id": "notesPlain", "value": canonical_bytes(record).decode()}],
    }


class Replica(Connect):
    """A server cache; writes do not propagate until the test explicitly copies them."""

    def __init__(self, anchor: dict[str, object]) -> None:
        super().__init__("https://connect.example", CANARY)
        self.items = {ANCHOR: note(anchor, ANCHOR)}
        self.version = 1
        self.posts = 0
        self.reads = 0
        self.omit = False
        self.duplicate = False
        self.fail = ""
        self.move_during_read = False
        self.corrupt_after_post = False
        self.late: tuple[str, dict[str, object]] | None = None

    @override
    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> Response:
        if method == "POST":
            assert body is not None
            self.posts += 1
            selected = str(self.posts).zfill(26)
            created = {
                **copy.deepcopy(body),
                "id": selected,
                "version": 1,
                "lastEditedBy": LOCAL_AUTHOR,
                "createdAt": "2026-10-04T00:00:00Z",
                "updatedAt": "2026-10-04T00:00:00Z",
            }
            if self.fail == "before":
                self.late = selected, created
                raise LifecycleError("operation uncertain")
            self.items[selected] = created
            self.version += 1
            if self.corrupt_after_post:
                self.items[selected]["version"] = 0
            if self.fail == "after":
                raise LifecycleError("operation uncertain")
            return Response(201, copy.deepcopy(created))
        if path == f"/v1/vaults/{VAULT}":
            return Response(
                200, {"id": VAULT, "items": len(self.items), "contentVersion": self.version}
            )
        assert path == f"/v1/vaults/{VAULT}/items"
        values = [
            {key: copy.deepcopy(value) for key, value in item.items() if key != "fields"}
            for item in self.items.values()
        ]
        if self.move_during_read:
            self.version += 1
        if self.duplicate:
            values[-1] = values[0]
        return Response(200, values[:-1] if self.omit else values)

    @override
    def item(self, vault: str, item: str) -> dict[str, object]:
        assert vault == VAULT
        self.reads += 1
        return copy.deepcopy(self.items[item])


@pytest.fixture
def record() -> dict[str, object]:
    return event("run", str(uuid.uuid7()), {"binding": BINDING})


def ledger(client: Replica, tmp_path: Path, anchor: dict[str, object]) -> ConnectLedger:
    return ConnectLedger(
        client,
        VAULT,
        spool=tmp_path / "spool",
        anchor=ANCHOR,
        anchor_sha256=digest(anchor),
        minimum={str(anchor["event_id"]): digest(anchor)},
    )


def ack(record: dict[str, object]) -> dict[str, object]:
    return event(
        "heartbeat",
        str(record["run_id"]),
        {
            "format": ACK_FORMAT,
            "event_id": record["event_id"],
            "event_sha256": digest(record),
            "binding": BINDING,
            "github_run_id": 100,
            "github_run_attempt": 1,
            "independent_server_id": REMOTE_SERVER,
        },
    )


def confirmed(selected: ConnectLedger, record: dict[str, object]) -> bool:
    return selected.confirmed(
        record,
        independent_server=REMOTE_SERVER,
        independent_author=REMOTE_AUTHOR,
        binding=BINDING,
    )


def test_cache_readback_is_not_independent_persistence(
    tmp_path: Path, record: dict[str, object]
) -> None:
    cache = Replica(record)
    selected = ledger(cache, tmp_path, record)
    addition = event("intent", str(record["run_id"]), {"scope": "bounded-double"})
    selected.stage(addition)
    assert addition in selected.records()
    assert not confirmed(selected, addition)
    # A locally authored imitation cannot establish independence.
    cache.items["b" * 26] = note(ack(addition), "b" * 26)
    cache.version += 1
    assert not confirmed(selected, addition)
    cache.items["c" * 26] = note(ack(addition), "c" * 26, author=REMOTE_AUTHOR)
    cache.version += 1
    assert confirmed(selected, addition)


@pytest.mark.parametrize("failure", ["before", "after"])
def test_lost_response_is_reconciled_without_another_post(
    tmp_path: Path, record: dict[str, object], failure: str
) -> None:
    cache = Replica(record)
    selected = ledger(cache, tmp_path, record)
    addition = event("intent", str(record["run_id"]), {"scope": "bounded-double"})
    cache.fail = failure
    if failure == "before":
        with pytest.raises(LifecycleError, match="readback"):
            selected.stage(addition)
        selected = ledger(cache, tmp_path, record)  # Real on-disk intent survives process restart.
        with pytest.raises(LifecycleError, match="no duplicate"):
            selected.stage(addition)
        assert cache.late is not None
        cache.items[cache.late[0]] = cache.late[1]
        cache.version += 1
    else:
        selected.stage(addition)
    selected.stage(addition)
    assert cache.posts == 1
    assert read_private(tmp_path / "spool" / (str(addition["event_id"]) + ".json")) == addition
    assert not confirmed(selected, addition)


def test_returned_identity_is_retained_before_failed_inspection(
    tmp_path: Path, record: dict[str, object]
) -> None:
    cache = Replica(record)
    selected = ledger(cache, tmp_path, record)
    addition = event("intent", str(record["run_id"]), {"scope": "bounded-double"})
    cache.corrupt_after_post = True
    with pytest.raises(LifecycleError, match="metadata"):
        selected.stage(addition)
    saved = read_private(tmp_path / "spool" / (str(addition["event_id"]) + ".returned.json"))
    assert saved == {"item_id": str(1).zfill(26)}


@pytest.mark.parametrize(
    "fault", ["empty", "partial", "anchor", "checkpoint", "duplicate", "moving"]
)
def test_incomplete_or_unstable_cache_never_means_clear(
    tmp_path: Path, record: dict[str, object], fault: str
) -> None:
    cache = Replica(record)
    selected = ledger(cache, tmp_path, record)
    addition = event("result", str(record["run_id"]), {"test": "other"})
    cache.items["b" * 26] = note(addition, "b" * 26)
    selected.records()
    if fault == "empty":
        cache.items.clear()
    elif fault == "partial":
        cache.omit = True
    elif fault == "anchor":
        del cache.items[ANCHOR]
    elif fault == "checkpoint":
        del cache.items["b" * 26]
    elif fault == "duplicate":
        cache.duplicate = True
    else:
        cache.move_during_read = True
    with pytest.raises(LifecycleError):
        selected.records()


@pytest.mark.parametrize(
    "fault", ["version", "author", "time", "binding", "hash", "server", "run", "execution"]
)
def test_mismatched_or_edited_ack_never_confirms(
    tmp_path: Path, record: dict[str, object], fault: str
) -> None:
    cache = Replica(record)
    proof = ack(record)
    payload = proof["payload"]
    assert isinstance(payload, dict)
    item = note(proof, "b" * 26, author=REMOTE_AUTHOR)
    if fault == "version":
        item["version"] = 2
    elif fault == "author":
        item["lastEditedBy"] = LOCAL_AUTHOR
    elif fault == "time":
        item["updatedAt"] = "2026-10-04T00:01:00Z"
    else:
        if fault == "binding":
            payload["binding"] = {"source_revision": "b" * 40}
        elif fault == "hash":
            payload["event_sha256"] = "0" * 64
        elif fault == "server":
            payload["independent_server_id"] = LOCAL_AUTHOR
        elif fault == "run":
            proof["run_id"] = str(uuid.uuid7())
        else:
            payload["github_run_id"] = True
        item = note(proof, "b" * 26, author=REMOTE_AUTHOR)
    cache.items["b" * 26] = item
    assert not confirmed(ledger(cache, tmp_path, record), record)


def test_cached_immutable_reads_still_require_fresh_metadata(
    tmp_path: Path, record: dict[str, object]
) -> None:
    cache = Replica(record)
    selected = ledger(cache, tmp_path, record)
    assert selected.records() == [record]
    assert selected.records() == [record]
    assert cache.reads == 1
    cache.items[ANCHOR]["version"] = 2
    with pytest.raises(LifecycleError, match="changed"):
        selected.records()


def test_server_content_and_secret_canaries_never_escape_errors(
    tmp_path: Path, record: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    cache = Replica(record)
    cache.items[ANCHOR]["title"] = CANARY
    with pytest.raises(LifecycleError) as error:
        ledger(cache, tmp_path, record).records()
    assert CANARY not in str(error.value)
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err


def test_immutable_content_change_after_restart_is_rejected(
    tmp_path: Path, record: dict[str, object]
) -> None:
    cache = Replica(record)
    changed = copy.deepcopy(record)
    changed["payload"] = {"unexpected": CANARY}
    cache.items[ANCHOR] = note(changed, ANCHOR)
    with pytest.raises(LifecycleError, match=r"immutable|anchor"):
        ledger(cache, tmp_path, record).records()


@pytest.mark.parametrize("duplicate", [False, True])
def test_journal_rejects_noncanonical_or_duplicate_record_fields(
    tmp_path: Path, record: dict[str, object], duplicate: bool
) -> None:
    cache = Replica(record)
    fields = cache.items[ANCHOR]["fields"]
    assert isinstance(fields, list)
    fields[0]["value"] = (
        '{"kind":"ignored",' + canonical_bytes(record).decode()[1:]
        if duplicate
        else json.dumps(record, indent=2)
    )
    with pytest.raises(LifecycleError, match="content changed"):
        ledger(cache, tmp_path, record).records()
