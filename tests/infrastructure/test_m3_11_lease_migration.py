"""Legacy import keeps every obligation and cannot restart obsolete issuance."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from copy import deepcopy
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import audit_policy_recovery, cleanup_expiry, historical_absence
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
from scripts.m3_11_unattended.legacy_terminal import restored, terminal, validate_claims
from scripts.m3_11_unattended.lifecycle import Lifecycle, _authentication_marker, intents
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
        if arguments[-1] == "{{.ID}} {{.Names}}":
            return ("b" * 64 + " ldp-m311-controller-synthetic\n").encode()
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
    preserved = terminal(intent, journal.records())
    assert preserved is not None and preserved.negative_authentication == "not-tested"
    assert terminal(intent, [run, original, abort]) == preserved
    with pytest.raises(LifecycleError, match="conflicts"):
        terminal(intent, [run, original, abort, _authentication_marker(intent)])


@pytest.mark.parametrize("negative", ["denied", "unavailable"])
def test_terminal_removal_preserves_original_proof_and_authentication_requirement(
    tmp_path: Path, negative: str
) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    assert (
        case.lifecycle.reconcile(intent, credential if negative == "denied" else None).status
        == "verified"
    )
    records = case.journal.records()
    before = deepcopy(records)
    result = terminal(intent, records)
    assert result is not None and result.status == "verified"
    assert result.negative_authentication == negative
    assert records == before
    if negative == "unavailable":
        assert terminal(intent, records, credential) is None
    else:
        assert terminal(intent, records, credential) == result
    assert terminal(intent, [*records, _authentication_marker(intent)]) is None


@pytest.mark.parametrize("retained", [False, True])
def test_terminal_rejects_denied_proof_with_empty_explicit_binding(
    tmp_path: Path, retained: bool
) -> None:
    case = Case(tmp_path)
    intent, credential = case.create()
    case.lifecycle.request_revocation(case.run_id)
    assert case.lifecycle.reconcile(intent).status == "verified"
    records = case.journal.records()
    resolved = next(row for row in records if row["kind"] == "resolved")
    cast(dict[str, object], resolved["payload"]).update(
        negative_authentication="denied", negative_authentication_markers=[]
    )
    with pytest.raises(LifecycleError, match="invalid marker bindings"):
        terminal(intent, records, credential if retained else None)


@pytest.mark.parametrize(
    "fault",
    [
        "label-only",
        "missing-created",
        "wrong-id",
        "wrong-run",
        "pending-probe",
        "unknown-marker",
        "empty-markers",
    ],
)
def test_import_rejects_unsupported_terminal_claims_before_writing(
    tmp_path: Path, fault: str
) -> None:
    case, _client, mapping, docker = local_import(tmp_path)
    intent = intents(case.journal)[0]
    case.lifecycle.request_revocation(case.run_id)
    case.lifecycle.reconcile(intent)
    records = case.journal.records()
    resolved = next(row for row in records if row["kind"] == "resolved")
    value = cast(dict[str, object], resolved["payload"])
    if fault == "label-only":
        records.remove(resolved)
    elif fault == "missing-created":
        records = [row for row in records if row["kind"] != "created"]
        cast(dict[str, dict[str, object]], mapping["obligations"])[intent.sha256]["provider_id"] = (
            None
        )
    elif fault == "wrong-id":
        value["credential_id"] = "another-credential"
    elif fault == "wrong-run":
        resolved["run_id"] = str(uuid.uuid7())
    elif fault == "pending-probe":
        records.append(_authentication_marker(intent))
    else:
        value.update(
            negative_authentication="denied",
            negative_authentication_markers=[] if fault == "empty-markers" else [str(uuid.uuid7())],
        )
    mapping["retained_files"] = {}
    mapping["records"] = {str(row["event_id"]): digest(row) for row in records}
    cast(dict[str, dict[str, object]], mapping["obligations"])[intent.sha256]["original_status"] = (
        "verified"
    )
    client = ConnectDouble()
    for row in records:
        note(client, row, tag=TAG, title=record_title(row))
    before = client.posts
    with pytest.raises((LifecycleError, ValueError)):
        publish_import(
            client,
            vault=client.vault,
            approved=mapping,
            spool=tmp_path / "bad-import",
            docker=cast(Docker, docker),
        )
    assert client.posts == before
    note(client, mapping, tag=MIGRATION_TAG, title="m3-11-import-" + digest(mapping))
    with pytest.raises((LifecycleError, ValueError)):
        ConnectObligations(
            client, client.vault, spool=tmp_path / "bad-read", expected=digest(mapping)
        ).records()


def test_sole_accepted_uncertainty_stays_uncertain_and_conflicts_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = Case(tmp_path)
    intent, _credential = case.create()
    records = [row for row in case.journal.records() if row["kind"] == "intent"]
    # Bind the unchanged exception logic to one synthetic test intent only.
    monkeypatch.setattr(historical_absence, "INTENT", intent.sha256)
    monkeypatch.setattr(historical_absence, "RUN", intent.run_id)
    payload = {**historical_absence.PAYLOAD, "intent_sha256": intent.sha256}
    monkeypatch.setattr(historical_absence, "PAYLOAD", deepcopy(payload))
    receipt = event("heartbeat", intent.run_id, payload)
    records.append(receipt)
    result = terminal(intent, records)
    assert result is not None and result.status == historical_absence.STATUS
    assert result.negative_authentication == "unavailable"
    mapping: dict[str, object] = {
        "obligations": {intent.sha256: {"original_status": historical_absence.STATUS}}
    }
    validate_claims(mapping, records)
    with pytest.raises(LifecycleError, match="conflicts"):
        terminal(intent, [*records, _authentication_marker(intent)])
    cast(dict[str, object], receipt["payload"])["operator_approval_recorded_at"] = stamp(case.now)
    with pytest.raises(LifecycleError, match="authorization"):
        terminal(intent, records)


def expiry_update(tmp_path: Path) -> dict[str, object]:
    """Original nonsecret update/results; no provider calls or regenerated proof."""
    case = Case(tmp_path / "expiry-original")
    intent, _credential = case.create()
    expiry = "2026-10-17T00:00:00Z"
    before = {
        "name": "synthetic",
        "status": "active",
        "expires_on": "2026-10-10T00:00:00Z",
        "policies": [
            {
                "effect": "allow",
                "resources": {"synthetic": "*"},
                "permission_groups": [{"id": "group"}],
            }
        ],
    }
    providers = {
        kind: {
            "id": "credential" + str(index),
            "authority_sha256": digest(kind),
            "before": before,
            "after": {**before, "expires_on": expiry},
        }
        for index, kind in enumerate(("cloudflare-account", "cloudflare-user"))
    }
    plan: dict[str, object] = {
        "format": cleanup_expiry.FORMAT,
        "targets_sha256": digest(dataclasses.asdict(intent.targets)),
        "expires_at": expiry,
        "observed_at": "2026-10-09T00:00:00Z",
        "providers": providers,
    }
    contents = {
        str(tmp_path / (kind + ".json")): json.dumps(
            {
                "plan_sha256": digest(plan),
                "identity_sha256": row["authority_sha256"],
                "expires_at": expiry,
                "status": "verified",
                "observed_at": "2026-10-09T00:01:00Z",
            }
        )
        + "\n"
        for kind, row in providers.items()
    }
    return {
        "plan": plan,
        "plan_sha256": digest(plan),
        "generation_id": str(uuid.uuid7()),
        "result_files": {
            key: hashlib.sha256(value.encode()).hexdigest() for key, value in contents.items()
        },
        "result_contents": contents,
    }


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "missing",
        "changed-bytes",
        "wrong-plan",
        "wrong-identity",
        "unresolved",
        "wrong-target",
    ],
)
def test_expiry_retirement_requires_original_bound_results(
    tmp_path: Path, fault: str | None
) -> None:
    from .test_m3_11_unattended_lifecycle import TARGETS  # noqa: PLC0415

    update = expiry_update(tmp_path)
    contents = cast(dict[str, str], update["result_contents"])
    path = next(iter(contents))
    if fault == "missing":
        del update["result_contents"]
        assert not cleanup_expiry.terminal_update(update, targets=TARGETS)
        return
    if fault == "changed-bytes":
        contents[path] += " "
    elif fault in {"wrong-plan", "wrong-identity", "unresolved"}:
        value = json.loads(contents[path])
        value[
            {
                "wrong-plan": "plan_sha256",
                "wrong-identity": "identity_sha256",
                "unresolved": "status",
            }[fault]
        ] = "f" * 64
        contents[path] = json.dumps(value)
        cast(dict[str, str], update["result_files"])[path] = hashlib.sha256(
            contents[path].encode()
        ).hexdigest()
    targets = (
        dataclasses.replace(TARGETS, account_id="f" * 32) if fault == "wrong-target" else TARGETS
    )
    if fault is None:
        assert cleanup_expiry.terminal_update(update, targets=targets)
    else:
        with pytest.raises(LifecycleError):
            cleanup_expiry.terminal_update(update, targets=targets)


@pytest.mark.parametrize("interruption", ["early-success", "later-failure"])
def test_audit_restoration_retry_persists_new_terminal_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interruption: str
) -> None:
    case = Case(tmp_path)
    original, _credential = case.create()
    intent = dataclasses.replace(
        original,
        role="audit",
        provider="cloudflare-account",
        name=f"ldp-m311-{uuid.UUID(case.run_id).hex}-audit",
    )
    case.journal.persist(event("intent", intent.run_id, intent.document()))
    trigger = dataclasses.replace(
        original,
        role="page-rules",
        provider="cloudflare-user",
        name=f"ldp-m311-{uuid.UUID(case.run_id).hex}-page-rules",
    )
    case.journal.persist(event("intent", trigger.run_id, trigger.document()))
    monkeypatch.setattr(audit_policy_recovery, "RUN_ID", case.run_id)
    candidate: dict[str, object] = {
        "account_id": intent.targets.account_id,
        "authorized": False,
        "before": {},
        "candidate_after": {},
        "credential_id": "audit-credential",
        "credential_sha256": "b" * 64,
        "observed_at": stamp(case.now),
        "provider": "cloudflare-account",
        "scope": {},
    }
    monkeypatch.setattr(audit_policy_recovery, "CANDIDATE_SHA256", digest(candidate))
    monkeypatch.setattr(audit_policy_recovery, "INTENT_SHA256", trigger.sha256)
    plan = event(
        "heartbeat",
        intent.run_id,
        {
            "format": audit_policy_recovery.FORMAT,
            "candidate": candidate,
            "helper_revision": intent.helper_revision,
            "intent_sha256": trigger.sha256,
            "grant_before": stamp(case.now + audit_policy_recovery.GRANT_WINDOW),
            "restore_after": stamp(case.now + audit_policy_recovery.RESTORE_WINDOW),
        },
    )
    plan["recorded_at"] = stamp(case.now)
    case.journal.persist(plan)
    audit_policy_recovery.observation(
        case.journal,
        status="original-policy-verified",
        actor="legacy-cleanup",
        helper=intent.helper_revision,
        now=case.now + timedelta(minutes=1 if interruption == "early-success" else 20),
    )
    if interruption == "later-failure":
        assert restored(case.journal.records())
        audit_policy_recovery.observation(
            case.journal,
            status="restoration-unresolved",
            actor="watchdog",
            helper=intent.helper_revision,
            now=case.now + timedelta(minutes=21),
        )
    assert not restored(case.journal.records())
    audit_policy_recovery.observation(
        case.journal,
        status="original-policy-verified",
        actor="legacy-cleanup",
        helper=intent.helper_revision,
        now=case.now + timedelta(minutes=22),
    )
    assert restored(case.journal.records())
    # Conflicting same-time observations cannot be hidden by record ordering.
    assert not restored(case.journal.records(), fenced_after=case.now + timedelta(minutes=22))
    assert restored(case.journal.records(), fenced_after=case.now + timedelta(minutes=21))
    with pytest.raises(LifecycleError, match="original plan"):
        restored(case.journal.records(), now=case.now + timedelta(minutes=21))
    audit_policy_recovery.observation(
        case.journal,
        status="restoration-unresolved",
        actor="github",
        helper=intent.helper_revision,
        now=case.now + timedelta(minutes=22),
    )
    assert not restored(case.journal.records())
    broken = event(
        "heartbeat",
        str(uuid.uuid7()),
        {
            "format": audit_policy_recovery.PROOF_FORMAT,
            "plan_sha256": digest(plan),
            "cleanup_actor": "legacy-cleanup",
            "status": "original-policy-verified",
            "observed_at": stamp(case.now + timedelta(minutes=23)),
            "helper_revision": intent.helper_revision,
        },
    )
    with pytest.raises(LifecycleError, match="original plan"):
        restored([*case.journal.records(), broken])
