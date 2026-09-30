"""Read original helper failures without journals or live service unit retention."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import qualification_archive_failure as archive
from scripts import qualification_failure as failure
from scripts import qualification_restore as owned
from scripts.qualification_probe import diagnostic, document, sanitize

JOB = "0198d17f-6f4a-7000-8000-000000000001"
CORRELATION = "0198d17f-6f4a-7000-8000-000000000002"


def event() -> dict[str, object]:
    return {
        "helper": "construction",
        "invocation": "a" * 32,
        "artifact_sha256": "b" * 64,
        "job_id": JOB,
        "correlation_id": CORRELATION,
        "chain": [
            {"exception": "OSError", "locations": [{"file": "archive_service.py", "line": 123}]}
        ],
        "diagnostic": diagnostic("category=local_io"),
    }


def test_failure_identity_does_not_depend_on_journal_or_current_invocation() -> None:
    raw = json.dumps({"construction": [event()]}).encode()
    assert archive.sanitize(raw, CORRELATION) == {
        "collection": "observed",
        "failures": [{**event(), "matches_last_submission": True}],
    }
    assert archive.sanitize(raw, JOB)["failures"] == [{**event(), "matches_last_submission": False}]


@pytest.mark.parametrize("damage", ["message", "path", "identity", "chain", "overflow", "helper"])
def test_private_or_malformed_values_cannot_enter_shareable_report(damage: str) -> None:
    value = event()
    if damage == "message":
        value["message"] = "private provider token"
    elif damage == "path":
        value["chain"] = [
            {"exception": "OSError", "locations": [{"file": "/private/token", "line": 123}]}
        ]
    elif damage == "identity":
        value["job_id"] = "private token"
    elif damage == "chain":
        value["chain"] = [{"exception": "token with spaces", "locations": []}]
    elif damage == "helper":
        value["helper"] = "export"
    records = [value] * (archive.MAX_EVENTS + 1 if damage == "overflow" else 1)
    with pytest.raises(ValueError):
        archive.sanitize(json.dumps({"construction": records}).encode(), CORRELATION)


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    identities = {
        "source": {"id": "c" * 64, "name": "/source", "owner": "owned", "image": "d" * 64},
        "destination": {
            "id": "e" * 64,
            "name": "/destination",
            "owner": "owned",
            "image": "f" * 64,
        },
    }
    monkeypatch.setattr(owned, "environment_for", lambda _run: {"DOCKER_HOST": "unix:///test"})
    monkeypatch.setattr(archive, "host_name", lambda _env: "source")
    monkeypatch.setattr(owned, "directory", lambda _env: tmp_path)
    monkeypatch.setattr(
        archive,
        "document",
        lambda path: (
            {"container_id": "c" * 64}
            if path.name == "failure-fixture.json"
            else identities["destination"]
        ),
    )
    monkeypatch.setattr(
        owned,
        "inspect",
        lambda _env, identity: identities["source" if identity == "c" * 64 else "destination"],
    )
    return tmp_path


def test_source_and_destination_failures_are_collected_independently(
    fixture: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def command(arguments: list[str], **kwargs: object) -> bytes:
        assert kwargs["environment"] == {"DOCKER_HOST": "unix:///test"}
        assert "journalctl" not in arguments
        assert kwargs["stdin"] == archive.PROBE
        value = event()
        if arguments[3] == "c" * 64:
            value.update(job_id="unknown", correlation_id="unknown")
        return json.dumps({"construction": [value]}).encode()

    monkeypatch.setattr(archive, "bounded_command", command)
    result = archive.collect(fixture, CORRELATION)
    assert result["destination"] == {
        "collection": "observed",
        "failures": [{**event(), "matches_last_submission": True}],
    }
    assert result["source"] != result["destination"]


def test_changed_destination_is_not_probed(fixture: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        archive,
        "document",
        lambda path: (
            {"container_id": "c" * 64}
            if path.name == "failure-fixture.json"
            else {"id": "e" * 64, "name": "/changed"}
        ),
    )
    probed = []

    def command(arguments: list[str], **_kwargs: object) -> bytes:
        probed.append(arguments[3])
        return b"{}"

    monkeypatch.setattr(archive, "bounded_command", command)
    result = archive.collect(fixture, CORRELATION)
    assert result["destination"] == {"collection": "unavailable"}
    assert probed == ["c" * 64]


def test_original_report_keeps_first_observation_after_later_cleanup(
    fixture: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(failure, "_observe", lambda *_args: ("unavailable", sanitize({})))
    first = {
        "destination": archive.sanitize(
            json.dumps({"construction": [event()]}).encode(), CORRELATION
        )
    }
    monkeypatch.setattr(archive, "collect", lambda *_args: first)
    original = failure.collect(fixture, 2, "verify")
    saved = original.read_bytes()
    assert json.loads(saved)["archive_failures"] == first
    monkeypatch.setattr(
        archive, "collect", lambda *_args: {"destination": {"collection": "unavailable"}}
    )
    later = failure.collect(fixture)
    assert later != original
    assert original.read_bytes() == saved


def test_first_failure_snapshot_survives_teardown_and_rechecks_identity(
    fixture: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(failure, "_directory", lambda: fixture)
    monkeypatch.setattr(failure, "_last_submission", lambda _root: ("archive", {}, CORRELATION))
    monkeypatch.setattr(failure, "_observe", lambda *_args: ("unavailable", sanitize({})))
    first = {
        "destination": archive.sanitize(
            json.dumps({"construction": [event()]}).encode(), CORRELATION
        )
    }
    monkeypatch.setattr(archive, "collect", lambda *_args: first)
    # Use the real file reader for the controller snapshot, not the fixture receipt stub.
    monkeypatch.setattr(archive, "document", document)
    failure.capture_failure_observation()
    original = (fixture / "failure-snapshot.json").read_bytes()
    monkeypatch.setattr(archive, "collect", lambda *_args: {"collection": "unavailable"})
    failure.capture_failure_observation()
    assert (fixture / "failure-snapshot.json").read_bytes() == original
    result = archive.before_teardown(fixture, CORRELATION)
    assert result["hosts"] == first
    assert result["observation_origin"] == "captured-before-teardown"
    assert archive.before_teardown(fixture, JOB) == {"collection": "unavailable"}
    snapshot = json.loads(original)
    snapshot["archive_failures"]["destination"]["failures"][0]["chain"][0]["message"] = (
        "private-token"
    )
    (fixture / "failure-snapshot.json").write_text(json.dumps(snapshot))
    assert archive.before_teardown(fixture, CORRELATION) == {"collection": "unavailable"}
