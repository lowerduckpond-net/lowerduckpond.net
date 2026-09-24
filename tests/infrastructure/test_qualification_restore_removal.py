from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from scripts import qualification_restore as restore
from scripts import qualification_restore_removal as removal
from scripts.qualification_case import private_document
from scripts.qualification_context import ARTIFACT_ENV, RUN_ENV, resource_names


@pytest.fixture
def fixture(  # noqa: PLR0915 - one owned Docker failure model
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    (tmp_path / "fixture").mkdir()
    environment = {
        **resource_names(uuid.uuid7().hex),
        ARTIFACT_ENV: str(tmp_path / "fixture/agent.tar"),
    }
    Path(environment[ARTIFACT_ENV]).write_bytes(b"owned artifact")
    root = restore.directory(environment)
    root.mkdir(mode=0o700)
    pair = {"destination": "a" * 64, "acme": "b" * 64}
    states = {}
    receipts = {}
    for kind, identity in pair.items():
        receipt = {
            "id": identity,
            "name": f"/ldp-m3-{environment[RUN_ENV]}-{kind}",
            "owner": environment[RUN_ENV],
            "image": "sha256:" + "c" * 64,
        }
        receipts[kind] = receipt
        (root / f"{kind}.json").write_text(json.dumps(receipt))
        states[identity] = {"running": True, "started_at": "original", "restarts": 0}
    (root / "completed.json").write_text(json.dumps({"identities": pair, "status": "passed"}))
    value: dict[str, Any] = {
        "environment": environment,
        "root": root,
        "pair": pair,
        "states": states,
        "events": [],
        "fault": None,
        "receipts": receipts,
    }

    def fail(event: str) -> None:
        if value["fault"] == event:
            value["fault"] = None
            raise ValueError("transient Docker/controller failure")

    def command(_: dict[str, str], *args: str, **kwargs: object) -> bytes:
        if args[:3] == ("docker", "container", "ls"):
            kind = next(kind for kind in pair if f"name=^{receipts[kind]['name']}$" in args)
            return pair[kind].encode() if pair[kind] in states else b""
        action, identity = args[1], args[-1]
        kind = next(kind for kind, item in pair.items() if item == identity)
        event = action + "-" + kind
        fail("before-" + event)
        value["events"].append(event)
        if action == "stop":
            states[identity]["running"] = False
        elif action == "rm":
            assert not any(state["running"] for state in states.values())
            del states[identity]
        else:
            pytest.fail("unexpected Docker mutation")
        fail("after-" + event)
        return b""

    def proof(_: dict[str, str]) -> dict[str, str]:
        fail("proof")
        assert set(states) == set(pair.values())
        assert all(state["running"] for state in states.values())
        return pair

    def write(directory: Path, name: str, payload: object) -> None:
        assert isinstance(payload, dict)
        event = f"write-{payload['step']}" if name == "removal.json" else "write-removed"
        fail("before-" + event)
        original_write(directory, name, payload)
        fail("after-" + event)

    original_write = private_document
    monkeypatch.setattr(removal, "private_document", write)
    monkeypatch.setattr(removal, "snapshot", lambda _, identity: dict(states[identity]))
    monkeypatch.setattr(restore, "command", command)
    monkeypatch.setattr(restore, "paired_proof", proof)
    monkeypatch.setattr(restore, "source_fenced", lambda _: fail("source"))
    monkeypatch.setattr(restore, "acme_accounting", lambda *a, **kw: fail("acme"))
    monkeypatch.setattr(
        restore,
        "inspect",
        lambda _, identity: next(receipts[kind] for kind in pair if pair[kind] == identity),
    )
    return value


@pytest.mark.parametrize(
    "fault",
    ["proof", "source", "acme"]
    + [
        prefix + event
        for prefix in ("before-", "after-")
        for event in (
            "stop-destination",
            "stop-acme",
            "rm-destination",
            "rm-acme",
            *("write-" + step for step in removal.STEPS),
            "write-removed",
        )
    ],
)
def test_interrupted_paired_teardown_resumes_without_requiring_deleted_destination(
    fixture: dict[str, Any],
    fault: str,
) -> None:
    fixture["fault"] = fault
    with pytest.raises(ValueError, match="transient"):
        restore.remove_pair(fixture["environment"], fixture["pair"])
    restore.remove_pair(fixture["environment"], fixture["pair"])
    assert not fixture["states"]
    assert json.loads((fixture["root"] / "removed.json").read_text()) == {
        "identities": fixture["pair"]
    }
    events = list(fixture["events"])
    restore.remove_pair(fixture["environment"], fixture["pair"])
    assert fixture["events"] == events
    assert events.count("rm-destination") == events.count("rm-acme") == 1


@pytest.mark.parametrize("fault", ["restarted", "receipt", "artifact", "early-absence", "owner"])
def test_partial_retirement_refuses_changed_remaining_resource_or_authority(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    fixture["fault"] = "after-stop-destination"
    with pytest.raises(ValueError, match="transient"):
        restore.remove_pair(fixture["environment"], fixture["pair"])
    identity = fixture["pair"]["acme"]
    if fault == "restarted":
        fixture["states"][identity]["started_at"] = "restarted"
    elif fault == "receipt":
        (fixture["root"] / "acme.json").write_text("{}")
    elif fault == "artifact":
        Path(fixture["environment"][ARTIFACT_ENV]).write_bytes(b"changed")
    elif fault == "early-absence":
        del fixture["states"][identity]
    else:
        original = restore.inspect
        monkeypatch.setattr(restore, "inspect", lambda *a: {**original(*a), "owner": "changed"})
    with pytest.raises(ValueError):
        restore.remove_pair(fixture["environment"], fixture["pair"])
    assert not any(event.startswith("rm-") for event in fixture["events"])


def test_explicit_resume_uses_existing_authorization_under_the_run_lease(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = fixture["root"].parent
    (directory / "run.lock").touch(mode=0o600)
    monkeypatch.setattr(removal, "environment_for", lambda _: fixture["environment"])
    with pytest.raises(ValueError, match="no prior authorization"):
        removal.resume(directory)
    assert not fixture["events"]
    fixture["fault"] = "after-rm-destination"
    with pytest.raises(ValueError, match="transient"):
        restore.remove_pair(fixture["environment"], fixture["pair"])
    assert set(fixture["states"]) == {fixture["pair"]["acme"]}
    assert removal.resume(directory) == fixture["root"] / "removed.json"
    assert not fixture["states"]
