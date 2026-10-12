"""Actual collection, approval, assembly, host import and read-only admission boundaries."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import audit_policy_recovery, historical_absence
from scripts.m3_11_unattended import connect_activate as activation
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.creation_outcome import FORMAT, RETAINED_FORMAT, original_abort
from scripts.m3_11_unattended.docker import SOCKET, Docker, controller_name, prepare, utility
from scripts.m3_11_unattended.journal import TAG, event, record_title
from scripts.m3_11_unattended.legacy_terminal import terminal
from scripts.m3_11_unattended.model import (
    CREATION_SETTLE,
    LIFETIME,
    Intent,
    LifecycleError,
    ProviderKind,
    Targets,
    digest,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import RunState, replace_private

from .operator_flow_support import DAEMON, SOURCE, Services
from .operator_host_support import IMAGE, Host
from .test_m3_11_lease_configuration import mapping, reader_document
from .test_m3_11_lease_migration import expiry_update
from .test_m3_11_operator_records import command


class MigrationCase:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.services = Services(monkeypatch)
        self.host = Host(tmp_path / "daemon", self.services, monkeypatch)
        self.studio = tmp_path / "studio"
        self.studio.mkdir(mode=0o700)
        self.docker = Docker()
        self.prepared = prepare(self.docker, SOURCE)
        self.run_id = str(uuid.uuid7())
        self.directory = self.host.evidence / "runs" / self.run_id
        self.directory.mkdir(parents=True, mode=0o700)
        self.directory.parent.chmod(0o700)
        targets = Targets.parse(self.services.manifest["targets"])
        before = datetime.now(UTC) - timedelta(days=2)
        secret_ref = mapping(
            mapping(mapping(self.services.manifest["providers"])["cleanup"])["references"]
        )["digitalocean"]
        self.intent = Intent(
            run_id=self.run_id,
            role="archive",
            source_revision="6" * 40,
            helper_revision="6" * 40,
            provider="spaces",
            cleanup_authority_sha256=hashlib.sha256(
                self.services.operator.secrets[str(secret_ref)].encode()
            ).hexdigest(),
            name="ldp-m311-" + uuid.UUID(self.run_id).hex + "-archive",
            requested_at=stamp(before),
            create_before=stamp(before + CREATION_SETTLE),
            deadline=stamp(before + LIFETIME),
            scope={"grants": [{"bucket": targets.archive_bucket, "permission": "readwrite"}]},
            baseline_ids=(),
            targets=targets,
        )
        binding: dict[str, object] = {
            "managed_run_id": self.run_id,
            "source_revision": self.intent.source_revision,
            "helper_revision": self.intent.helper_revision,
            "artifact_sha256": "a" * 64,
            "qualification_inputs_sha256": "d" * 64,
            "storage_target_sha256": targets.storage_digest,
        }
        self.request: dict[str, object] = {
            "format": "lowerduckpond-m3-11-unattended-request-v1",
            "binding": binding,
            "mode": "qualification",
            "approval_sha256": "c" * 64,
            "controller_image": IMAGE,
            "daemon": DAEMON,
        }
        write_private(self.directory / "request.json", self.request)
        state = RunState(self.directory)
        state.begin(binding)
        # There is deliberately no journey result. Original intent and terminal
        # evidence, independently bound to a fenced issuer, must suffice.
        state.update("finished", cleanup="unresolved")
        for kind in ("credential-intents", "credential-created", "credential-cleanup"):
            (self.directory / kind).mkdir(mode=0o700)
        write_private(
            self.directory / "credential-intents" / (self.intent.sha256 + ".json"),
            self.intent.document(),
        )
        self.originals = [
            event(
                "run",
                self.run_id,
                {"binding": binding, "mode": "qualification", "approval_sha256": "c" * 64},
            ),
            event("intent", self.run_id, self.intent.document()),
            event(
                "created",
                self.run_id,
                {"intent_sha256": self.intent.sha256, "credential_id": "SYNTHETIC-OLD-KEY"},
            ),
            event(
                "resolved",
                self.run_id,
                {
                    "intent_sha256": self.intent.sha256,
                    "credential_id": "SYNTHETIC-OLD-KEY",
                    "provider_readback": "absent",
                    "negative_authentication": "denied",
                },
            ),
        ]
        write_private(
            self.directory / "credential-created" / (self.intent.sha256 + ".json"),
            self.originals[2],
        )
        write_private(
            self.directory / "credential-cleanup" / (self.intent.sha256 + ".json"),
            {
                "intent_sha256": self.intent.sha256,
                "identifier": "SYNTHETIC-OLD-KEY",
                "secret": "SYNTHETIC-RETIRED-SECRET",
            },
        )
        vault = str(mapping(self.services.manifest["vaults"])["journal"])
        for index, original in enumerate(self.originals):
            identifier = chr(107 + index) * 26
            self.services.items[vault, identifier] = {
                "id": identifier,
                "version": 1,
                "title": record_title(original),
                "vault": {"id": vault},
                "category": "SECURE_NOTE",
                "tags": [TAG],
                "fields": [
                    {
                        "id": "notesPlain",
                        "label": "notesPlain",
                        "type": "STRING",
                        "purpose": "NOTES",
                        "value": canonical_bytes(original).decode(),
                    }
                ],
            }
        self.container = self.host.add(
            controller_name(self.run_id), source=self.intent.helper_revision
        )
        historical = reader_document(
            "cleanup", now=datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=1)
        )
        self.services.operator.secrets["synthetic-existing-historical-reader"] = str(
            mapping(historical["entry"])["token"]
        )
        self.historical = historical
        self.declarations: dict[str, object] = {
            "format": activation.DECLARATIONS_FORMAT,
            "retained_files": sorted(str(path) for path in self.directory.rglob("*.json")),
            "obligations": {
                self.intent.sha256: {
                    "generation_id": self.services.manifest["generation_id"],
                    "original_status": "unresolved",
                }
            },
            "expiry_updates": [],
            "issuers": [
                {
                    "container_id": self.container["Id"],
                    "stopped_at": stamp(before + timedelta(hours=1)),
                    "issuance_disabled": True,
                }
            ],
        }
        self.baseline = self.host.original_files()

    def collect(self) -> dict[str, object]:
        return utility(
            self.docker,
            prepared=self.prepared,
            operation="inspect-import",
            daemon_socket=SOCKET,
            payload={
                "historical_reader": self.historical,
                "journal_vault": mapping(self.services.manifest["vaults"])["journal"],
                "declarations": self.declarations,
            },
        )

    def approve_and_stage(self, monkeypatch: pytest.MonkeyPatch) -> LeaseConfiguration:
        collected = self.collect()
        index = self.studio / "migration-evidence.json"
        write_private(index, collected)
        draft = self.studio / "policy-draft.json"
        write_private(draft, self.services.manifest)
        for kind, source_flag, source in (
            ("policy", "--inputs", draft),
            ("migration", "--evidence-index", index),
        ):
            proposed = self.studio / (kind + "-proposal.json")
            command(
                monkeypatch, kind + "-proposal", source_flag, str(source), "--output", str(proposed)
            )
            command(
                monkeypatch,
                "record-" + kind,
                "--proposal",
                str(proposed),
                "--expected-proposal-sha256",
                digest(read_private(proposed)),
                "--approved-at",
                stamp(datetime.now(UTC) - timedelta(seconds=1)),
                "--approval-reference",
                "SYNTHETIC external consent only",
                "--output",
                str(self.studio / kind),
            )
        draft_inputs = self.studio / "draft-inputs.json"
        write_private(
            draft_inputs,
            {
                **self.services.manifest,
                "policy": None,
                "approved_policy_sha256": None,
                "migration_sha256": None,
            },
        )
        bound = self.studio / "bound-inputs.json"
        command(
            monkeypatch,
            "bind-inputs",
            "--draft",
            str(draft_inputs),
            "--policy",
            str(self.studio / "policy/policy.json"),
            "--migration",
            str(self.studio / "migration/legacy-import.json"),
            "--runtime-revision",
            SOURCE,
            "--output",
            str(bound),
        )
        self.services.manifest = read_private(bound)
        self.services.stage(self.studio)
        return LeaseConfiguration.load(self.studio / "staged/controller-connect.json")

    def imported(self, config: LeaseConfiguration) -> None:
        utility(
            self.docker,
            prepared=self.prepared,
            operation="import",
            daemon_socket=SOCKET,
            payload={
                "configuration": config.document(cleanup_only=True),
                "mapping": read_private(self.studio / "migration/legacy-import.json"),
            },
        )

    def project(self, config: LeaseConfiguration) -> dict[str, object]:
        return utility(
            self.docker,
            prepared=self.prepared,
            operation="admission",
            daemon_socket=SOCKET,
            payload={
                "configuration": config.document(cleanup_only=True),
                "run_id": self.run_id,
                "container_id": self.container["Id"],
            },
        )


def test_actual_collect_approve_bind_import_and_read_only_projection_preserve_originals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    config = case.approve_and_stage(monkeypatch)
    case.imported(config)
    count = len(case.services.exchanges)
    projected = case.project(config)
    assert projected["binding_sha256"] == digest(case.request["binding"])
    assert all(value["method"] == "GET" for value in case.services.exchanges[count:])
    assert case.host.original_files() == case.baseline
    assert read_private(case.directory / "status.json")["credential_cleanup"] == "unresolved"
    assert not (case.directory / "journey-result.json").exists()
    # A fresh process uses the same host mapping-bound spool and reads back the import.
    prior = {str(path): path.read_bytes() for path in case.host.spool.rglob("*") if path.is_file()}
    case.imported(config)
    assert {
        str(path): path.read_bytes() for path in case.host.spool.rglob("*") if path.is_file()
    } == prior


@pytest.mark.parametrize(
    "fault",
    [
        "running",
        "restart",
        "source",
        "image",
        "daemon",
        "request",
        "intent",
        "unreviewed-secret",
        "negative-proof",
        "missing-import",
        "wrong-mapping",
        "unrelated-uncertainty",
    ],
)
def test_projection_cannot_convert_labels_or_missing_evidence_into_permission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    config = case.approve_and_stage(monkeypatch)
    case.imported(config)
    if fault == "running":
        mapping(case.container["State"])["Running"] = True
    elif fault == "restart":
        mapping(mapping(case.container["HostConfig"])["RestartPolicy"])["Name"] = "always"
    elif fault == "source":
        mapping(mapping(case.container["Config"])["Labels"])[
            "lowerduckpond.m3-11.unattended.source"
        ] = SOURCE
    elif fault == "image":
        case.container["Image"] = "sha256:" + "a" * 64
    elif fault == "daemon":
        altered = dict(case.request)
        altered["daemon"] = {**DAEMON, "ID": "other"}
        replace_private(case.directory / "request.json", altered)
    elif fault in {"request", "intent"}:
        path = case.directory / (
            "request.json"
            if fault == "request"
            else "credential-intents/" + case.intent.sha256 + ".json"
        )
        path.unlink()
    elif fault == "unreviewed-secret":
        write_private(
            case.directory / "credential-cleanup" / ("a" * 64 + ".json"), {"unreviewed": True}
        )
    elif fault in {"negative-proof", "missing-import", "unrelated-uncertainty"}:
        for key, item in list(case.services.items.items()):
            if (str(item["title"]).startswith("m3-11-import-") and fault == "missing-import") or (
                item["title"] == record_title(case.originals[-1]) and fault != "missing-import"
            ):
                del case.services.items[key]
        if fault == "unrelated-uncertainty":
            forged = event(
                "heartbeat",
                case.run_id,
                {**historical_absence.PAYLOAD, "intent_sha256": case.intent.sha256},
            )
            item = case.services.items[
                next(key for key in case.services.items if key[0] == config.journal_vault)
            ]
            item.update(
                title=record_title(forged),
                fields=[
                    {
                        "id": "notesPlain",
                        "label": "notesPlain",
                        "type": "STRING",
                        "purpose": "NOTES",
                        "value": canonical_bytes(forged).decode(),
                    }
                ],
            )
    elif fault == "wrong-mapping":
        config = dataclasses.replace(config, migration_sha256="0" * 64)
    count = len(case.services.exchanges)
    with pytest.raises((LifecycleError, OSError, ValueError)):
        case.project(config)
    assert all(value["method"] == "GET" for value in case.services.exchanges[count:])


@pytest.mark.parametrize("fault", ["running", "restart", "file"])
def test_visible_import_still_rechecks_original_files_and_current_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    config = case.approve_and_stage(monkeypatch)
    case.imported(config)
    if fault == "file":
        replace_private(
            case.directory / "request.json", {**case.request, "approval_sha256": "0" * 64}
        )
    elif fault == "running":
        mapping(case.container["State"])["Running"] = True
    else:
        mapping(mapping(case.container["HostConfig"])["RestartPolicy"])["Name"] = "always"
    count = len(case.services.exchanges)
    with pytest.raises((LifecycleError, ValueError)):
        case.imported(config)
    assert all(row["method"] == "GET" for row in case.services.exchanges[count:])


@pytest.mark.parametrize("fault", ["malformed", "contradictory", "unindexed"])
def test_existing_legacy_journey_must_be_valid_and_hash_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    RunState(case.directory).finish_journey("failed", 1)
    result = case.directory / "journey-result.json"
    if fault != "unindexed":
        case.declarations["retained_files"] = [
            *cast(list[str], case.declarations["retained_files"]),
            str(result),
        ]
        replace_private(
            result,
            {"format": "wrong"} if fault == "malformed" else {**read_private(result), "status": 0},
        )
    with pytest.raises((LifecycleError, ValueError)):
        case.collect()


def complete_history(case: MigrationCase, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: PLR0915 - one connected producer-to-consumer scenario
    """Modeled 43 known IDs, seven original aborts and one fixed synthetic exception.

    This is not the real historical 738-event journal. Only fixed-identity
    historical exception pins are rebound; every serializer/validator stays real.
    """

    roles = ("archive", "backup", "operator", "caddy", "observer", "page-rules", "audit")
    generation = case.services.manifest["generation_id"]
    refs = mapping(mapping(mapping(case.services.manifest["providers"])["cleanup"])["references"])
    selected_run, run_record = case.run_id, case.originals[0]
    directory = case.directory
    originals = list(case.originals)
    for index in range(1, 51):
        if index % len(roles) == 0:
            selected_run = str(uuid.uuid7())
            directory = case.host.evidence / "runs" / selected_run
            directory.mkdir(mode=0o700)
            binding = {**mapping(case.request["binding"]), "managed_run_id": selected_run}
            request = {**case.request, "binding": binding}
            write_private(directory / "request.json", request)
            state = RunState(directory)
            state.begin(binding)
            state.update("finished", cleanup="unresolved")
            run_record = event(
                "run",
                selected_run,
                {
                    "binding": binding,
                    "mode": "qualification",
                    "approval_sha256": case.request["approval_sha256"],
                    "creation_protocol": FORMAT,
                },
            )
            originals.append(run_record)
            row = case.host.add(controller_name(selected_run), source=case.intent.helper_revision)
            cast(list[dict[str, object]], case.declarations["issuers"]).append(
                {
                    "container_id": row["Id"],
                    "stopped_at": stamp(instant(case.intent.requested_at) + timedelta(hours=1)),
                    "issuance_disabled": True,
                }
            )
        role = (
            "page-rules" if index == 50 else "audit" if index == 49 else roles[index % len(roles)]  # noqa: PLR2004 - concrete synthetic contract cardinality or protocol value
        )
        provider = (
            "spaces"
            if role in {"archive", "backup", "operator"}
            else "cloudflare-user"
            if role == "page-rules"
            else "cloudflare-account"
        )
        ref = refs[
            {
                "spaces": "digitalocean",
                "cloudflare-account": "cloudflare_account",
                "cloudflare-user": "cloudflare_user",
            }[provider]
        ]
        intent = dataclasses.replace(
            case.intent,
            run_id=selected_run,
            role=role,
            provider=cast(ProviderKind, provider),
            name=f"ldp-m311-{uuid.UUID(selected_run).hex}-{role}",
            cleanup_authority_sha256=hashlib.sha256(
                case.services.operator.secrets[str(ref)].encode()
            ).hexdigest(),
        )
        root = directory / "credential-intents"
        root.mkdir(mode=0o700, exist_ok=True)
        write_private(root / (intent.sha256 + ".json"), intent.document())
        original = event("intent", selected_run, intent.document())
        originals.append(original)
        claim = "verified"
        if index < 42 or index == 49:  # noqa: PLR2004 - 43 known IDs including original audit child
            identifier = f"SYNTHETIC-RETIRED-{index:04d}"
            originals.extend(
                [
                    event(
                        "created",
                        selected_run,
                        {"intent_sha256": intent.sha256, "credential_id": identifier},
                    ),
                    event(
                        "resolved",
                        selected_run,
                        {
                            "intent_sha256": intent.sha256,
                            "credential_id": identifier,
                            "provider_readback": "absent",
                            "negative_authentication": "denied",
                        },
                    ),
                ]
            )
        elif index < 49:  # noqa: PLR2004 - seven original pre-creation aborts
            abort = original_abort(intent, original, run_record)
            originals.append(abort)
            aborted = directory / "credential-aborted"
            aborted.mkdir(mode=0o700, exist_ok=True)
            write_private(
                aborted / (intent.sha256 + ".json"),
                {"format": RETAINED_FORMAT, "intent": original, "abort": abort},
            )
            claim = "not-submitted"
        else:
            # Exact exception logic remains non-configurable in production.
            monkeypatch.setattr(historical_absence, "INTENT", intent.sha256)
            monkeypatch.setattr(historical_absence, "RUN", intent.run_id)
            monkeypatch.setattr(
                historical_absence,
                "PAYLOAD",
                {**historical_absence.PAYLOAD, "intent_sha256": intent.sha256},
            )
            originals.append(event("heartbeat", selected_run, dict(historical_absence.PAYLOAD)))
            claim = historical_absence.STATUS
            before = instant(case.intent.requested_at)
            candidate = {
                "account_id": intent.targets.account_id,
                "authorized": False,
                "before": {},
                "candidate_after": {},
                "credential_id": "SYNTHETIC-RETIRED-0049",
                "credential_sha256": "b" * 64,
                "observed_at": stamp(before),
                "provider": "cloudflare-account",
                "scope": {},
            }
            monkeypatch.setattr(audit_policy_recovery, "RUN_ID", selected_run)
            monkeypatch.setattr(audit_policy_recovery, "CANDIDATE_SHA256", digest(candidate))
            monkeypatch.setattr(audit_policy_recovery, "INTENT_SHA256", intent.sha256)
            plan = event(
                "heartbeat",
                selected_run,
                {
                    "format": audit_policy_recovery.FORMAT,
                    "candidate": candidate,
                    "helper_revision": intent.helper_revision,
                    "intent_sha256": intent.sha256,
                    "grant_before": stamp(before + audit_policy_recovery.GRANT_WINDOW),
                    "restore_after": stamp(before + audit_policy_recovery.RESTORE_WINDOW),
                },
            )
            plan["recorded_at"] = stamp(before)
            originals.extend(
                [
                    plan,
                    event(
                        "heartbeat",
                        selected_run,
                        {
                            "format": audit_policy_recovery.PROOF_FORMAT,
                            "plan_sha256": digest(plan),
                            "status": "original-policy-verified",
                            "cleanup_actor": "legacy-cleanup",
                            "observed_at": stamp(before + timedelta(hours=2)),
                            "helper_revision": intent.helper_revision,
                        },
                    ),
                ]
            )
        mapping(case.declarations["obligations"])[intent.sha256] = {
            "generation_id": generation,
            "original_status": claim,
        }
    vault = str(mapping(case.services.manifest["vaults"])["journal"])
    for original in originals[len(case.originals) :]:
        identifier = digest(original)[:26].translate(str.maketrans("0123456789", "ghijklmnop"))
        case.services.items[vault, identifier] = {
            "id": identifier,
            "version": 1,
            "title": record_title(original),
            "vault": {"id": vault},
            "category": "SECURE_NOTE",
            "tags": [TAG],
            "fields": [
                {
                    "id": "notesPlain",
                    "label": "notesPlain",
                    "type": "STRING",
                    "purpose": "NOTES",
                    "value": canonical_bytes(original).decode(),
                }
            ],
        }
    update = expiry_update(case.host.evidence)
    plan = mapping(update["plan"])
    plan["targets_sha256"] = digest(dataclasses.asdict(case.intent.targets))
    update["plan_sha256"] = digest(plan)
    contents = mapping(update["result_contents"])

    for filename, content in contents.items():
        value = json.loads(str(content))
        value["plan_sha256"] = digest(plan)
        payload = canonical_bytes(value)
        contents[filename] = payload.decode()
        mapping(update["result_files"])[filename] = hashlib.sha256(payload).hexdigest()
        write_private(Path(filename), value)
    case.declarations["expiry_updates"] = [update]
    case.declarations["retained_files"] = sorted(
        str(path) for path in case.host.evidence.rglob("*.json")
    )
    case.originals = originals
    case.baseline = case.host.original_files()


@pytest.mark.parametrize("conflict_first", [False, True])
def test_import_refuses_conflicting_duplicate_original_before_any_post(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conflict_first: bool
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    config = case.approve_and_stage(monkeypatch)
    original = case.originals[-1]
    altered = {
        **original,
        "payload": {**mapping(original["payload"]), "negative_authentication": "unavailable"},
    }
    value = {
        "id": "z" * 26,
        "version": 1,
        "title": record_title(altered),
        "vault": {"id": config.journal_vault},
        "category": "SECURE_NOTE",
        "tags": [TAG],
        "fields": [
            {
                "id": "notesPlain",
                "label": "notesPlain",
                "type": "STRING",
                "purpose": "NOTES",
                "value": canonical_bytes(altered).decode(),
            }
        ],
    }
    key = config.journal_vault, "z" * 26
    case.services.items = (
        {key: value, **case.services.items}
        if conflict_first
        else {**case.services.items, key: value}
    )
    count = len(case.services.exchanges)
    with pytest.raises(LifecycleError):
        case.imported(config)
    assert all(row["method"] == "GET" for row in case.services.exchanges[count:])


def test_production_uncertainty_pin_cannot_accept_another_original_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        historical_absence.INTENT
        == audit_policy_recovery.INTENT_SHA256
        == "ccdc7926243530cf6dd6615745f8520440d29531f28869a226f432b31a64b574"
    )
    assert (
        historical_absence.RUN
        == audit_policy_recovery.RUN_ID
        == "01a11021-76d1-775a-adb1-fe00b6fd6152"
    )
    case = MigrationCase(tmp_path, monkeypatch)
    original = case.originals[1]
    forged = event(
        "heartbeat",
        case.run_id,
        {**historical_absence.PAYLOAD, "intent_sha256": case.intent.sha256},
    )
    with pytest.raises(LifecycleError, match="conflicts"):
        terminal(case.intent, [original, forged])
    assert not historical_absence.admits(case.intent.sha256, historical_absence.STATUS)


@pytest.mark.parametrize(
    "fault", ["target", "missing-result", "unrestored", "wrong-trigger", "missing-authority"]
)
def test_auxiliary_originals_cannot_be_omitted_or_rebound_for_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    complete_history(case, monkeypatch)
    if fault == "target":
        update = mapping(cast(list[object], case.declarations["expiry_updates"])[0])
        plan = mapping(update["plan"])
        plan["targets_sha256"] = "0" * 64
        update["plan_sha256"] = digest(plan)
        for filename, raw in mapping(update["result_contents"]).items():
            value = json.loads(str(raw))
            value["plan_sha256"] = digest(plan)
            payload = canonical_bytes(value)
            mapping(update["result_contents"])[filename] = payload.decode()
            mapping(update["result_files"])[filename] = hashlib.sha256(payload).hexdigest()
            replace_private(Path(filename), value)
    elif fault == "missing-result":
        filename = next(
            iter(
                mapping(
                    cast(list[dict[str, object]], case.declarations["expiry_updates"])[0][
                        "result_files"
                    ]
                )
            )
        )
        Path(filename).unlink()
        with pytest.raises((OSError, LifecycleError)):
            case.collect()
        return
    config = case.approve_and_stage(monkeypatch)
    case.imported(config)
    if fault in {"unrestored", "wrong-trigger", "missing-authority"}:
        for key, row in list(case.services.items.items()):
            if row["category"] != "SECURE_NOTE" or str(row["title"]).startswith("m3-11-import-"):
                continue
            record = json.loads(str(cast(list[dict[str, object]], row["fields"])[0]["value"]))
            original_payload = mapping(record["payload"])
            if (
                (
                    fault == "unrestored"
                    and original_payload.get("format") == audit_policy_recovery.PROOF_FORMAT
                )
                or (
                    fault == "wrong-trigger"
                    and record["kind"] == "intent"
                    and original_payload.get("role") == "page-rules"
                    and record["run_id"] == historical_absence.RUN
                )
                or (
                    fault == "missing-authority"
                    and record["kind"] == "intent"
                    and original_payload.get("role") == "audit"
                    and record["run_id"] == historical_absence.RUN
                )
            ):
                del case.services.items[key]
    count = len(case.services.exchanges)
    with pytest.raises((LifecycleError, ValueError)):
        case.project(config)
    assert all(row["method"] == "GET" for row in case.services.exchanges[count:])
