"""Pre-generation estate shapes; no production inventory or credentials in fixtures."""

# ruff: noqa: PLC0415 - independent entry points under test

from __future__ import annotations

import dataclasses
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import legacy_actors
from scripts.m3_11_unattended import legacy_discovery as discovery
from scripts.m3_11_unattended.connect_configuration import reader
from scripts.m3_11_unattended.creation_outcome import FORMAT
from scripts.m3_11_unattended.docker import EVIDENCE_VOLUME, OWNER, controller_name, helper_volume
from scripts.m3_11_unattended.journal import TAG, event, migration, record_title
from scripts.m3_11_unattended.legacy_terminal import require_terminal_run
from scripts.m3_11_unattended.model import LifecycleError, digest, stamp
from scripts.m3_11_unattended.operator_records import migration_body
from scripts.m3_11_unattended.state import RunState

from .test_m3_11_lease_configuration import mapping
from .test_m3_11_operator_migration import MigrationCase


class DiscoveryCase(MigrationCase):
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        super().__init__(tmp_path, monkeypatch)
        self.actors = [self.actor(self.container, self.directory, "controller")]
        self.binding = mapping(self.request["binding"])
        self.empty = self.host.evidence / "runs" / str(uuid.uuid7())
        self.empty.mkdir(mode=0o700)
        binding = {**self.binding, "managed_run_id": self.empty.name}
        write_private(self.empty / "request.json", {**self.request, "binding": binding})
        state = RunState(self.empty)
        state.begin(binding)
        state.finish_journey("failed", 1)
        self.actors.append(
            self.actor(
                self.host.add(controller_name(self.empty.name), source=self.intent.helper_revision),
                self.empty,
                "controller",
            )
        )
        self.manual = self.host.evidence / "manual-page-rules" / str(uuid.uuid7())
        self.manual.mkdir(parents=True, mode=0o700)
        self.manual.parent.chmod(0o700)
        run_id = self.manual.name
        manual = dataclasses.replace(
            self.intent,
            run_id=run_id,
            role="page-rules",
            provider="cloudflare-user",
            name="ldp-m311-" + uuid.UUID(run_id).hex + "-page-rules",
        )
        self.manual_intent = manual
        run = event(
            "run",
            run_id,
            {
                "binding": {**self.binding, "managed_run_id": run_id},
                "mode": "rehearsal",
                "approval_sha256": "c" * 64,
                "creation_protocol": FORMAT,
            },
        )
        intent = event("intent", run_id, manual.document())
        created = event(
            "created",
            run_id,
            {"intent_sha256": manual.sha256, "credential_id": "MANUAL-ORIGINAL-ID"},
        )
        resolved = event(
            "resolved",
            run_id,
            {
                "intent_sha256": manual.sha256,
                "credential_id": "MANUAL-ORIGINAL-ID",
                "provider_readback": "absent",
                "negative_authentication": "denied",
            },
        )
        for name, value in {
            "worker-started.json": {"run_id": run_id, "started_at": manual.requested_at},
            "run-event.json": run,
            "intent.json": manual.document(),
            "intent-event.json": intent,
            "created-event.json": created,
            "credential.json": {
                "identifier": "MANUAL-ORIGINAL-ID",
                "secret": "SYNTHETIC-RETIRED-MANUAL",
            },
        }.items():
            write_private(self.manual / name, mapping(value))
        self.originals.extend([run, intent, created, resolved])
        container = self.host.add(
            "ldp-m311-page-rules-probe-" + uuid.UUID(run_id).hex,
            source=manual.helper_revision,
            running=True,
        )
        mapping(mapping(container["Config"])["Labels"])[OWNER + ".purpose"] = (
            "single-page-rules-diagnostic"
        )
        self.actors.append(self.actor(container, self.manual, "manual-page-rules"))
        self.declarations = {
            "format": discovery.DECLARATIONS,
            "retained_files": sorted(str(p) for p in self.host.evidence.rglob("*.json")),
            "expiry_updates": [],
            "actors": self.actors,
            "obligations": {
                item.sha256: {
                    "generation_id": None,
                    "cleanup_authority_sha256": item.cleanup_authority_sha256,
                    "original_status": "verified",
                }
                for item in (self.intent, manual)
            },
        }
        self.sync()

    def actor(self, row: dict[str, object], directory: Path, kind: str) -> dict[str, str]:
        mounts = cast(list[dict[str, object]], row["Mounts"])
        for destination, name, writable in [
            ("/evidence", EVIDENCE_VOLUME, True),
            ("/opt/lifecycle", helper_volume(self.intent.helper_revision), False),
            *(
                ([("/probe", "ldp-m311-manual-page-rules-" + uuid.UUID(directory.name).hex, False)])
                if kind == "manual-page-rules"
                else []
            ),
        ]:
            mounts.append(
                {
                    "Type": "volume",
                    "Destination": destination,
                    "Name": name,
                    "Source": "/synthetic/" + name,
                    "RW": writable,
                }
            )
        mapping(row["State"]).update(
            StartedAt=self.intent.requested_at, FinishedAt=self.intent.deadline
        )
        return {
            "container_id": str(row["Id"]),
            "kind": kind,
            "directory": str(directory),
            "run_id": directory.name,
        }

    def sync(self) -> None:
        vault = str(mapping(self.services.manifest["vaults"])["journal"])
        for original in self.originals:
            key = digest(original)[:26].translate(str.maketrans("0123456789", "ghijklmnop"))
            self.services.items[vault, key] = {
                "id": key,
                "vault": {"id": vault},
                "category": "SECURE_NOTE",
                "tags": [TAG],
                "title": record_title(original),
                "fields": [
                    {
                        "id": "notesPlain",
                        "purpose": "NOTES",
                        "value": canonical_bytes(original).decode(),
                    }
                ],
            }

    def discover(self) -> dict[str, object]:
        return discovery.collect(
            reader(self.historical),
            vault=str(mapping(self.services.manifest["vaults"])["journal"]),
            declarations=self.declarations,
            docker=self.docker,
        )

    def finalize(self, discovered: dict[str, object]) -> dict[str, object]:
        return discovery.finalize(
            reader(self.historical),
            vault=str(mapping(self.services.manifest["vaults"])["journal"]),
            declarations={
                "format": "lowerduckpond-m3-11-migration-fences-v2",
                "discovery": discovered,
                "fences": [
                    {
                        "container_id": a["container_id"],
                        "stopped_at": self.intent.deadline,
                        "issuance_disabled": True,
                    }
                    for a in self.actors
                ],
            },
            docker=self.docker,
        )

    def stop(self) -> None:
        for row in self.host.rows.values():
            mapping(row["State"])["Running"] = False

    def collect(self) -> dict[str, object]:
        discovered = self.discover()
        self.stop()
        return self.finalize(discovered)


def test_discovery_precedes_fence_and_empty_manual_admission_preserves_originals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    baseline = case.host.original_files()
    discovered = case.discover()
    with pytest.raises((LifecycleError, ValueError)):
        migration_body(discovered)
    with pytest.raises(LifecycleError, match="fence"):
        case.finalize(discovered)
    case.originals.append(event("heartbeat", case.run_id, {"cleanup": "still available"}))
    case.sync()
    case.stop()
    before = datetime.now(UTC)
    collected = case.finalize(discovered)
    approved = migration(
        {
            **migration_body(collected),
            "approved_at": stamp(datetime.now(UTC)),
            "approval_reference": "synthetic consent",
        }
    )
    assert all(
        mapping(row)["generation_id"] is None for row in mapping(approved["obligations"]).values()
    )
    for issuer in cast(list[dict[str, object]], approved["issuers"]):
        assert str(issuer["stopped_at"]) >= stamp(before)
    for directory in (case.directory, case.empty):
        require_terminal_run(directory, approved, case.originals, targets=case.intent.targets)
    assert case.host.original_files() == baseline
    assert all(row["method"] == "GET" for row in case.services.exchanges)


@pytest.mark.parametrize(
    "fault",
    [
        "omitted-key",
        "omitted-actor",
        "unknown-actor",
        "manual-conflict",
        "empty-issued",
        "authority",
    ],
)
def test_bad_inventory_fails_before_fencing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    if fault == "omitted-key":
        cast(list[str], case.declarations["retained_files"]).remove(
            str(case.directory / "credential-cleanup" / (case.intent.sha256 + ".json"))
        )
    elif fault == "omitted-actor":
        case.actors.pop()
    elif fault == "unknown-actor":
        case.host.add("ldp-m311-admission-unreviewed-issuer")
    elif fault == "manual-conflict":
        old = read_private(case.manual / "run-event.json")
        case.originals.append(
            event("run", case.manual.name, {**mapping(old["payload"]), "approval_sha256": "f" * 64})
        )
        case.sync()
    elif fault == "empty-issued":
        (case.empty / "credential-cleanup").mkdir(mode=0o700)
        write_private(
            case.empty / "credential-cleanup" / ("f" * 64 + ".json"), {"original": "unreviewed"}
        )
    else:
        mapping(mapping(case.declarations["obligations"])[case.intent.sha256])[
            "cleanup_authority_sha256"
        ] = "f" * 64
    with pytest.raises((LifecycleError, ValueError)):
        case.discover()


@pytest.mark.parametrize(
    "fault",
    ["new-intent", "new-created", "image", "source", "mount", "restart", "changed-original"],
)
def test_post_fence_check_rejects_changed_originals_or_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    discovered = case.discover()
    case.stop()
    if fault.startswith("new-"):
        original = case.originals[1 if fault == "new-intent" else 2]
        case.originals.append(
            event(str(original["kind"]), case.run_id, mapping(original["payload"]))
        )
        case.sync()
    elif fault == "image":
        case.container["Image"] = "sha256:" + "a" * 64
    elif fault == "source":
        mapping(mapping(case.container["Config"])["Labels"])[OWNER + ".source"] = "b" * 40
    elif fault == "mount":
        cast(list[dict[str, object]], case.container["Mounts"])[-1]["RW"] = True
    elif fault == "restart":
        mapping(case.container["HostConfig"])["RestartPolicy"] = {
            "Name": "always",
            "MaximumRetryCount": 0,
        }
    else:
        (case.directory / "request.json").unlink()
    with pytest.raises((LifecycleError, ValueError, OSError)):
        case.finalize(discovered)


def test_fence_recheck_detects_restart_after_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.m3_11_unattended.connect_activate import recheck_import

    case = DiscoveryCase(tmp_path, monkeypatch)
    discovered = case.discover()
    case.stop()
    approved = {
        **migration_body(case.finalize(discovered)),
        "approved_at": stamp(datetime.now(UTC)),
        "approval_reference": "synthetic consent",
    }
    recheck_import(approved, case.docker)
    mapping(case.container["State"])["StartedAt"] = stamp(datetime.now(UTC) - timedelta(seconds=1))
    with pytest.raises(LifecycleError, match="restarted"):
        recheck_import(approved, case.docker)


@pytest.mark.parametrize("missing_proof", [False, True])
def test_independent_cleanup_never_substitutes_new_authority_for_pre_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_proof: bool
) -> None:
    from scripts.m3_11_unattended.cleanup import sweep_legacy

    from .test_m3_11_legacy_import_reader import attach_bridge

    case = DiscoveryCase(tmp_path, monkeypatch)
    if missing_proof:
        # An explicitly unresolved declaration remains unresolved without old
        # authority. It cannot use the otherwise configured replacement clients.
        removed = next(
            row
            for row in case.originals
            if row["kind"] == "resolved" and row["run_id"] == case.manual.name
        )
        case.originals.remove(removed)
        for key, item in list(case.services.items.items()):
            if item.get("title") == record_title(removed):
                del case.services.items[key]
        mapping(mapping(case.declarations["obligations"])[case.manual_intent.sha256])[
            "original_status"
        ] = "unresolved"
    config = case.approve_and_stage(monkeypatch)
    attach_bridge(case, monkeypatch)
    case.imported(config)
    case.host.isolated = True
    before = len(case.services.exchanges)
    result = sweep_legacy(
        config,
        config.generations[config.active_generation]["cleanup"].reader(),
        root=tmp_path / "independent",
    )
    assert result["status"] == ("unresolved" if missing_proof else "ready")
    assert all(row["method"] == "GET" for row in case.services.exchanges[before:])
    if missing_proof:
        # Import did not require a fabricated terminal fact. Only subsequent
        # genuine recovery with the ORIGINAL authority can close this intent.
        from scripts.m3_11_unattended.journal import ConnectObligations
        from scripts.m3_11_unattended.lifecycle import Lifecycle
        from scripts.m3_11_unattended.model import Credential

        from .test_m3_11_unattended_lifecycle import ProviderDouble

        case.host.isolated = False
        provider = ProviderDouble()
        provider.kind = case.manual_intent.provider
        provider.authority_sha256 = case.manual_intent.cleanup_authority_sha256
        journal = ConnectObligations(
            config.generations[config.active_generation]["cleanup"].reader(),
            config.journal_vault,
            spool=tmp_path / "original-recovery",
            expected=config.migration_sha256,
        )
        recovery = Lifecycle(journal, {provider.kind: provider})
        credential = Credential("MANUAL-ORIGINAL-ID", "SYNTHETIC-RETIRED-MANUAL", {})
        assert recovery.reconcile(case.manual_intent, credential).status == "verified"
        before = len(case.services.exchanges)
        assert recovery.reconcile(case.manual_intent, credential).status == "verified"
        assert all(row["method"] == "GET" for row in case.services.exchanges[before:])
        result = sweep_legacy(
            config,
            config.generations[config.active_generation]["cleanup"].reader(),
            root=tmp_path / "after-original-recovery",
        )
        assert result["status"] == "ready"


def test_detached_expiry_originals_use_exact_embedded_bytes_without_host_path(
    tmp_path: Path,
) -> None:
    from scripts.m3_11_unattended.legacy_terminal import retained_bytes

    from .test_m3_11_lease_migration import expiry_update

    update = expiry_update(tmp_path)
    update["generation_id"] = None
    mapping_document: dict[str, object] = {"expiry_updates": [update]}
    for filename, content in mapping(update["result_contents"]).items():
        path = Path(filename)
        if path.exists():
            path.unlink()
        assert retained_bytes(mapping_document, path) == str(content).encode()
        write_private(path, {"changed": "original"})
        assert retained_bytes(mapping_document, path) != str(content).encode()
        path.unlink()
        path.symlink_to(path.parent / "missing")
        with pytest.raises(OSError):
            retained_bytes(mapping_document, path)


def test_v1_cannot_silently_accept_a_null_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = MigrationCase(tmp_path, monkeypatch)
    value = {
        **migration_body(case.collect()),
        "approved_at": stamp(datetime.now(UTC)),
        "approval_reference": "synthetic consent",
    }
    mapping(mapping(value["obligations"])[case.intent.sha256])["generation_id"] = None
    with pytest.raises((LifecycleError, ValueError)):
        migration(value)


def test_local_manual_marker_cannot_reuse_an_older_denial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    marker = event(
        "cleanup",
        case.manual.name,
        {
            "intent_sha256": case.manual_intent.sha256,
            "negative_authentication": "required",
            "proof_binding": "event-id",
        },
    )
    path = case.manual / "retained-record-unresolved-event.json"
    write_private(path, marker)
    cast(list[str], case.declarations["retained_files"]).append(str(path))
    with pytest.raises(LifecycleError, match="terminal status"):
        case.discover()
    mapping(mapping(case.declarations["obligations"])[case.manual_intent.sha256])[
        "original_status"
    ] = "unresolved"
    collected = case.collect()
    assert marker in cast(list[dict[str, object]], collected["records"])
    approved = {
        **migration_body(collected),
        "approved_at": stamp(datetime.now(UTC)),
        "approval_reference": "synthetic consent",
    }
    with pytest.raises(LifecycleError, match="terminal removal"):
        require_terminal_run(
            case.directory,
            approved,
            cast(list[dict[str, object]], collected["records"]),
            targets=case.intent.targets,
        )


def test_named_diagnostic_is_not_permission_to_skip_originals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    extra = case.host.add("ldp-m311-agent-exit-" + "a" * 32)
    with pytest.raises(LifecycleError):
        legacy_actors.observe(
            case.docker,
            {
                "container_id": extra["Id"],
                "kind": "retained-diagnostic",
                "run_id": None,
                "directory": None,
            },
            case.originals,
            {},
        )


def test_coherent_new_probe_revision_is_not_a_reviewed_historical_program(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = DiscoveryCase(tmp_path, monkeypatch)
    extra = case.host.add("ldp-m311-agent-exit-" + "a" * 32, source="f" * 40)
    mapping(extra["Config"]).update(
        Entrypoint=["/usr/local/bin/mise", "exec", "--"],
        Cmd=["uv", "run", "--no-sync", "--frozen", "python", "/probe/probe.py", "f" * 40],
    )
    extra["Mounts"] = [
        {
            "Destination": "/opt/lifecycle",
            "Type": "volume",
            "Name": helper_volume("f" * 40),
            "RW": False,
        },
        {"Destination": "/probe", "Type": "volume", "Name": "synthetic-probe", "RW": True},
    ]
    with pytest.raises(LifecycleError, match="source revision is unreviewed"):
        legacy_actors.observe(
            case.docker,
            {
                "container_id": extra["Id"],
                "kind": "retained-diagnostic",
                "run_id": None,
                "directory": None,
            },
            case.originals,
            {},
        )


def test_retained_probe_script_is_rechecked_after_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.m3_11_unattended import legacy_diagnostics

    case = DiscoveryCase(tmp_path, monkeypatch)
    source = legacy_diagnostics.SOURCES["agent-exit"]
    extra = case.host.add("ldp-m311-agent-exit-" + "a" * 32, source=source)
    mapping(extra["Config"]).update(
        Entrypoint=["/usr/local/bin/mise", "exec", "--"],
        Cmd=["uv", "run", "--no-sync", "--frozen", "python", "/probe/probe.py", source],
    )
    extra["Mounts"] = [
        {
            "Destination": "/opt/lifecycle",
            "Type": "volume",
            "Name": helper_volume(source),
            "RW": False,
        },
        {"Destination": "/probe", "Type": "volume", "Name": "synthetic-probe", "RW": True},
    ]
    mapping(extra["State"]).update(
        StartedAt=case.intent.requested_at, FinishedAt=case.intent.deadline
    )
    observed = [legacy_diagnostics.PROBE_SHA256]
    monkeypatch.setattr(legacy_diagnostics, "script_digest", lambda *args: observed[0])
    actor = legacy_actors.observe(
        case.docker,
        {
            "container_id": extra["Id"],
            "kind": "retained-diagnostic",
            "run_id": None,
            "directory": None,
        },
        case.originals,
        {},
    )
    legacy_actors.fenced(case.docker, actor)
    observed[0] = "f" * 64
    with pytest.raises(LifecycleError, match="probe source differs"):
        legacy_actors.fenced(case.docker, actor)
    with pytest.raises(LifecycleError):
        legacy_actors.observe(
            case.docker,
            {**case.actors[0], "kind": "retained-diagnostic", "run_id": None, "directory": None},
            case.originals,
            {},
        )
