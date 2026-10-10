"""Legacy import keeps every obligation and cannot restart obsolete issuance."""

from __future__ import annotations

import hashlib
import uuid
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import audit_policy_recovery, cleanup_expiry
from scripts.m3_11_unattended.cleanup import retained_legacy
from scripts.m3_11_unattended.connect_activate import publish_import
from scripts.m3_11_unattended.creation_outcome import FORMAT, RETAINED_FORMAT, original_abort
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.journal import (
    MIGRATION_FORMAT,
    MIGRATION_TAG,
    TAG,
    ConnectObligations,
    event,
    migration,
    record_title,
)
from scripts.m3_11_unattended.lifecycle import Lifecycle, intents
from scripts.m3_11_unattended.model import LifecycleError, digest, stamp

from .test_m3_11_lease_inventory import ConnectDouble
from .test_m3_11_unattended_lifecycle import Case


def note(client: ConnectDouble, value: dict[str, object], *, tag: str, title: str) -> None:
    client.request(
        "POST",
        "/v1/vaults/" + client.vault + "/items",
        {
            "title": title,
            "category": "SECURE_NOTE",
            "tags": [tag],
            "vault": {"id": client.vault},
            "fields": [
                {
                    "id": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "label": "notesPlain",
                    "value": canonical_bytes(value).decode(),
                }
            ],
        },
    )


def imported(tmp_path: Path) -> tuple[Case, ConnectDouble, dict[str, object], ConnectObligations]:
    case = Case(tmp_path / "original")
    intent, credential = case.create()
    records = case.journal.records()
    mapping: dict[str, object] = {
        "format": MIGRATION_FORMAT,
        "records": {str(row["event_id"]): digest(row) for row in records},
        "obligations": {
            intent.sha256: {
                "generation_id": str(uuid.uuid7()),
                "provider_id": credential.identifier,
                "original_status": "unresolved",
            }
        },
        "retained_files": {"/synthetic-private/old-credential.json": "a" * 64},
        "expiry_updates": [],
        "issuers": [
            {
                "container_id": "b" * 64,
                "daemon_sha256": "c" * 64,
                "stopped_at": stamp(case.now),
                "running": False,
                "restart_policy": "no",
                "issuance_disabled": True,
            }
        ],
        "approved_at": stamp(case.now),
        "approval_reference": "SYNTHETIC-IMPORT-ONLY",
    }
    client = ConnectDouble()
    for row in records:
        note(client, row, tag=TAG, title=record_title(row))
    note(client, mapping, tag=MIGRATION_TAG, title="m3-11-import-" + digest(mapping))
    journal = ConnectObligations(
        client, "v" * 26, spool=tmp_path / "pending", expected=digest(mapping)
    )
    return case, client, mapping, journal


def test_imported_status_does_not_substitute_for_fresh_cleanup(tmp_path: Path) -> None:
    case, client, mapping, journal = imported(tmp_path)
    assert journal.records() == case.journal.records()
    before = deepcopy(mapping)
    lifecycle = Lifecycle(journal, {"spaces": case.provider}, clock=lambda: case.now)
    lifecycle.request_revocation(case.run_id)
    assert all(result.status == "verified" for result in lifecycle.sweep())
    assert case.provider.deletes == ["credential00000001"]
    count = client.posts
    assert all(result.status == "verified" for result in lifecycle.sweep())
    assert client.posts == count
    assert mapping == before
    assert journal.mapping == before


@pytest.mark.parametrize("fault", ["missing", "changed", "new-legacy-intent", "wrong-mapping"])
def test_migration_rejects_lost_changed_or_unaccounted_originals(
    tmp_path: Path, fault: str
) -> None:
    case, client, mapping, journal = imported(tmp_path)
    if fault == "missing":
        del client.items[next(iter(client.items))]
    elif fault == "changed":
        client.items[next(iter(client.items))]["title"] = "changed"
    elif fault == "new-legacy-intent":
        old = next(row for row in case.journal.records() if row["kind"] == "intent")
        additional = event("intent", case.run_id, cast(dict[str, object], old["payload"]))
        note(client, additional, tag=TAG, title=record_title(additional))
    else:
        mapping["obligations"] = {}
        note(client, mapping, tag=MIGRATION_TAG, title="m3-11-import-" + digest(mapping))
        journal = ConnectObligations(
            client, "v" * 26, spool=tmp_path / "other", expected=digest(mapping)
        )
    with pytest.raises(LifecycleError):
        journal.records()


def test_cleanup_only_rollback_refuses_new_old_format_issuance(tmp_path: Path) -> None:
    case, _client, _mapping, journal = imported(tmp_path)
    with pytest.raises(LifecycleError, match="permanently disabled"):
        journal.persist(event("intent", case.run_id, {}))
    with pytest.raises(LifecycleError, match="permanently disabled"):
        audit_policy_recovery.grant(cast(object, None), {})  # type: ignore[arg-type] # must reject before transport
    with pytest.raises(LifecycleError, match="permanently disabled"):
        cleanup_expiry.apply(cast(object, None), {}, directory=tmp_path, expected="a" * 64)


def test_lost_cleanup_note_reply_is_not_reposted_with_a_new_event_id(tmp_path: Path) -> None:
    case, client, _mapping, journal = imported(tmp_path)
    original = event("revoke", case.run_id, {"reason": "terminal-path"})
    client.lose_reply = True
    with pytest.raises(LifecycleError):
        journal.persist(original)
    count = client.posts
    client.lose_reply = False
    repeated = event("revoke", case.run_id, {"reason": "terminal-path"})
    assert journal.persist(repeated) == original
    assert client.posts == count


def test_missing_issuer_fencing_or_retained_expiry_evidence_cannot_be_imported(
    tmp_path: Path,
) -> None:
    _case, _client, mapping, _journal = imported(tmp_path)
    mapping["issuers"] = []
    with pytest.raises(LifecycleError, match="stopped issuer"):
        migration(mapping)


class ImportDocker:
    """Only original issuer inspection is permitted during migration."""

    def __init__(self) -> None:
        self.daemon = {"ID": "SYNTHETIC-ORIGINAL-DAEMON"}
        self.running = False
        self.restart = "no"

    def info(self) -> dict[str, str]:
        return self.daemon

    def command(self, *arguments: str) -> bytes:
        assert arguments[0] == "ps"
        return ("b" * 64 + "\n").encode()

    def owned(self, selected: str) -> dict[str, object]:
        assert selected == "b" * 64
        return {
            "Id": selected,
            "State": {"Running": self.running},
            "HostConfig": {"RestartPolicy": {"Name": self.restart, "MaximumRetryCount": 0}},
        }


def local_import(tmp_path: Path) -> tuple[Case, ConnectDouble, dict[str, object], ImportDocker]:

    case = Case(tmp_path / "original")
    intent, credential = case.create()
    run = tmp_path / "retained" / case.run_id
    for kind in ("credential-created", "credential-cleanup"):
        (run / kind).mkdir(mode=0o700, parents=True)
    created = next(row for row in case.journal.records() if row["kind"] == "created")
    write_private(run / "credential-created" / (intent.sha256 + ".json"), created)
    write_private(
        run / "credential-cleanup" / (intent.sha256 + ".json"),
        {
            "intent_sha256": intent.sha256,
            "identifier": credential.identifier,
            "secret": credential.secret,
        },
    )
    files = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in run.glob("*/*.json")
    }
    docker = ImportDocker()
    mapping: dict[str, object] = {
        "format": MIGRATION_FORMAT,
        "records": {str(row["event_id"]): digest(row) for row in case.journal.records()},
        "obligations": {
            intent.sha256: {
                "generation_id": str(uuid.uuid7()),
                "provider_id": credential.identifier,
                "original_status": "unresolved",
            }
        },
        "retained_files": files,
        "expiry_updates": [],
        "issuers": [
            {
                "container_id": "b" * 64,
                "daemon_sha256": digest(docker.info()),
                "stopped_at": stamp(case.now),
                "running": False,
                "restart_policy": "no",
                "issuance_disabled": True,
            }
        ],
        "approved_at": stamp(case.now),
        "approval_reference": "SYNTHETIC-LOCAL-RECOVERY",
    }
    client = ConnectDouble()
    for row in case.journal.records():
        if row != created:
            note(client, row, tag=TAG, title=record_title(row))
    return case, client, mapping, docker


def test_import_recovers_only_local_returned_id_and_negative_probe_secret(tmp_path: Path) -> None:

    case, client, mapping, docker = local_import(tmp_path)
    expected = publish_import(
        client,
        vault=client.vault,
        approved=mapping,
        spool=tmp_path / "pending",
        docker=cast(Docker, docker),
    )
    journal = ConnectObligations(
        client, client.vault, spool=tmp_path / "cleanup", expected=expected
    )
    assert journal.records() == case.journal.records()
    secrets, complete = retained_legacy(journal)
    assert complete
    intent = intents(journal)[0]
    # A returned ID remains an obligation even if its provider policy is wrong.
    case.provider.items[secrets[intent.sha256].identifier]["scope"] = {"wrong": "scope"}
    lifecycle = Lifecycle(journal, {"spaces": case.provider}, clock=lambda: case.now)
    lifecycle.request_revocation(case.run_id)
    result = lifecycle.reconcile(intent, secrets[intent.sha256])
    assert result.status == "verified" and result.negative_authentication == "denied"
    assert case.provider.deletes == [secrets[intent.sha256].identifier]
    assert case.provider.creates == 1
    assert all(Path(path).exists() for path in cast(dict[str, str], mapping["retained_files"]))


@pytest.mark.parametrize("fault", ["changed-local", "running", "restart", "missing-file"])
def test_import_rejects_changed_evidence_or_unfenced_issuer_before_post(
    tmp_path: Path, fault: str
) -> None:

    _case, client, mapping, docker = local_import(tmp_path)
    path = Path(next(iter(cast(dict[str, str], mapping["retained_files"]))))
    if fault == "changed-local":
        path.write_bytes(path.read_bytes() + b" ")
    elif fault == "missing-file":
        path.unlink()
    elif fault == "running":
        docker.running = True
    else:
        docker.restart = "always"
    count = client.posts
    with pytest.raises((LifecycleError, OSError, ValueError)):
        publish_import(
            client,
            vault=client.vault,
            approved=mapping,
            spool=tmp_path / "pending",
            docker=cast(Docker, docker),
        )
    assert client.posts == count


def test_import_recovers_original_abort_when_intent_never_reached_connect(tmp_path: Path) -> None:

    case, _client, mapping, docker = local_import(tmp_path)
    intent = intents(case.journal)[0]
    original = next(row for row in case.journal.records() if row["kind"] == "intent")
    run = event(
        "run",
        case.run_id,
        {
            "binding": {
                "managed_run_id": case.run_id,
                "source_revision": intent.source_revision,
                "helper_revision": intent.helper_revision,
                "storage_target_sha256": intent.targets.storage_digest,
                "artifact_sha256": "a" * 64,
                "qualification_inputs_sha256": "b" * 64,
            },
            "mode": "qualification",
            "approval_sha256": "c" * 64,
            "creation_protocol": FORMAT,
        },
    )
    abort = original_abort(intent, original, run)
    path = tmp_path / "aborted" / case.run_id / "credential-aborted" / (intent.sha256 + ".json")
    path.parent.mkdir(mode=0o700, parents=True)
    write_private(path, {"format": RETAINED_FORMAT, "intent": original, "abort": abort})
    mapping["retained_files"] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}
    mapping["records"] = {str(row["event_id"]): digest(row) for row in (run, original, abort)}
    cast(dict[str, dict[str, object]], mapping["obligations"])[intent.sha256]["provider_id"] = None
    client = ConnectDouble()
    note(client, run, tag=TAG, title=record_title(run))
    expected = publish_import(
        client,
        vault=client.vault,
        approved=mapping,
        spool=tmp_path / "pending",
        docker=cast(Docker, docker),
    )
    journal = ConnectObligations(
        client, client.vault, spool=tmp_path / "cleanup", expected=expected
    )
    assert {row["event_id"] for row in journal.records()} == {
        row["event_id"] for row in (run, original, abort)
    }
    case.provider.items.clear()
    lifecycle = Lifecycle(journal, {"spaces": case.provider}, clock=lambda: case.now)
    lifecycle.request_revocation(case.run_id)
    result = lifecycle.reconcile(intent)
    assert result.status == "verified"
    assert case.provider.deletes == []
