"""Retirement cannot adopt another run or manufacture missing historical evidence."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from lowerduckpond_m3_archive.report import ArchiveQualificationReport
from lowerduckpond_m3_archive.storage import AcceptanceEvidence
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.repository import StateRecordError, StateRecordPath

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_combined_inputs import FORMAT as FIXTURE_FORMAT
from scripts.m3_11_combined_inputs import _environment
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_phase_receipts import FORMAT as PHASE_FORMAT
from scripts.m3_11_private_inputs import write_private
from scripts.m3_11_retirement_context import FILES, Context
from scripts.m3_11_retirement_files import digest, preserve
from scripts.m3_11_retirement_live import SpacesFixture
from scripts.m3_11_retirement_state import inventory

from .test_m3_11_live_storage import storage as storage  # noqa: PLC0414

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def context(storage: LiveStorage, monkeypatch: pytest.MonkeyPatch) -> Context:
    run = Path(storage.environment["M3_10_INSTALLED_REPORT"]).parent
    saved = _environment(run, storage.target.run_id, storage.environment["DOCKER_HOST"])
    storage = replace(storage, environment={**storage.environment, **saved})
    write_private(
        run / "fixture.json",
        {"format": FIXTURE_FORMAT, "run_id": storage.target.run_id, "environment": saved},
    )
    report = ArchiveQualificationReport.create(
        AcceptanceEvidence(True, True, True, True, True, True, True), source_revision="a" * 40
    )
    report.write(run / "storage.json")
    storage = replace(
        storage,
        binding={
            **storage.binding,
            "storage_run_id": report.run_id,
            "storage_report_sha256": hashlib.sha256(
                (run / "storage.json").read_bytes()
            ).hexdigest(),
        },
    )
    monkeypatch.setattr(LiveStorage, "require_owner", Mock())
    storage.save()
    nonce = str(uuid.uuid7())
    original: dict[str, object] = {
        "format": evidence.CONTEXT_FORMAT,
        "run_id": storage.target.run_id,
        "captured_at": (datetime.now(UTC) - timedelta(days=3)).isoformat(),
        **storage.binding,
        **dict.fromkeys(evidence.IDENTITY_FIELDS, "c" * 64),
        "subject_set_sha256": evidence.subject_digest(nonce),
        "backup_repository_sha256": hashlib.sha256(storage.target.repository.encode()).hexdigest(),
    }
    write_private(run / "combined-context.json", original)
    write_private(
        run / "combined-names.json",
        {
            "format": evidence.NAMES_FORMAT,
            "run_id": storage.target.run_id,
            "nonce": nonce,
            "subjects": list(evidence.subjects(nonce)),
        },
    )
    write_private(run / "installed.json", {"original": "legacy evidence"})
    write_private(
        run / "combined.started.json",
        {
            "context_sha256": digest(original),
            "installed_sha256": hashlib.sha256((run / "installed.json").read_bytes()).hexdigest(),
        },
    )
    for name in FILES:
        path = run / name
        if path.exists():
            continue
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if name == "source-revision":
            preserve(path, iter([b"a" * 40 + b"\n"]), 41)
        elif name == "qualification-inputs.json":
            # The real legacy writer adds a newline; preserve and accept that format.
            value = {
                key: original[key]
                for key in (
                    "source_revision",
                    "input_policy",
                    "qualification_inputs_sha256",
                    "storage_target_sha256",
                )
            }
            raw = json.dumps(value).encode() + b"\n"
            preserve(path, iter([raw]), len(raw))
        elif name == "failure-exit.json":
            write_private(path, {"exit_status": 2, "phase": "verify"})
        elif name.startswith("combined-phases/"):
            value = {
                "format": PHASE_FORMAT,
                "context_sha256": digest(original),
                "phase": path.name.removesuffix(".json").removesuffix(".started"),
                "started_at": original["captured_at"],
            }
            if not name.endswith(".started.json"):
                value.update(completed_at=original["captured_at"], observations={"original": True})
            write_private(path, value)
        else:
            write_private(path, {"original": name})
    return Context(run, storage.environment)


def test_original_failure_needs_no_public_dns_history_or_new_timestamps(context: Context) -> None:
    before = context.original()
    assert before["original_exit_status"] == 2  # noqa: PLR2004 - original failed exit status
    assert not (context.run / "public-dns").exists()
    assert context.original() == before


@pytest.mark.parametrize(
    "path",
    [
        "combined.json",
        "combined-assertions.json",
        "qualification.json",
        "owned-teardown",
        "public-dns",
        "combined-phases/reboot.started.json",
        "combined-phases/public-ca-cold-recovery.started.json",
    ],
)
def test_success_or_public_phase_progress_is_ineligible(context: Context, path: str) -> None:
    write_private(context.run / path, {"private": "must not be adopted"})
    with pytest.raises(ValueError):
        context.original()


@pytest.mark.parametrize(
    "damage",
    [
        "artifact",
        "source",
        "input",
        "storage",
        "start",
        "zero-status",
        "phase",
        "endpoint",
        "production-host",
    ],
)
def test_foreign_or_changed_bindings_fail_before_provider_use(
    context: Context, damage: str
) -> None:
    if damage == "endpoint":
        with pytest.raises(ValueError):
            Context(context.run, {**context.environment, "DOCKER_HOST": "ssh://production"})
        return
    if damage == "production-host":
        with pytest.raises(ValueError):
            Context(
                context.run, {**context.environment, "LDP_QUALIFICATION_HOST": "production-host"}
            )
        return
    if damage == "artifact":
        Path(context.environment["LDP_QUALIFICATION_ARTIFACT"]).write_bytes(b"replacement")
        with pytest.raises(ValueError):
            Context(context.run, context.environment)
        return
    path, changed = {
        "source": ("source-revision", b"b" * 40),
        "input": ("qualification-inputs.json", b'{"wrong":"target"}'),
        "storage": ("storage.json", b'{"wrong":"original report"}'),
        "start": ("combined.started.json", b'{"wrong":"attempt"}'),
        "zero-status": (
            "failure-exit.json",
            evidence.canonical_bytes({"exit_status": 0, "phase": "verify"}),
        ),
        "phase": ("combined-phases/reconstruction.started.json", b'{"wrong":"context"}'),
    }[damage]
    (context.run / path).write_bytes(changed)
    with pytest.raises(ValueError):
        context.original()


def test_dns_is_a_new_read_only_absence_proof(
    context: Context, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts import m3_11_retirement_live as live  # noqa: PLC0415

    client = Mock()
    client.get_collection.return_value = []
    monkeypatch.setattr(live, "CloudflareClient", Mock(return_value=client))
    monkeypatch.setattr(live, "_require_zone_identity", Mock(return_value="one-account"))
    fixture = object.__new__(SpacesFixture)
    fixture.context = context
    fixture.environment = {
        **context.environment,
        "CLOUDFLARE_API_TOKEN": "fixture-secret",
        "CLOUDFLARE_ZONE_ID": "1" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "2" * 32,
    }
    assert fixture.dns()["records"] == 0
    assert client.get_collection.call_count == 6  # noqa: PLR2004 - three exact names in each zone
    assert not (context.run / "public-dns").exists()
    client.get_collection.side_effect = RuntimeError("private-provider-message")
    with pytest.raises(RuntimeError):
        fixture.dns()
    client.post.assert_not_called()
    client.delete.assert_not_called()


class Records:
    def __init__(self) -> None:
        base = ROOT / "tests/static-publication/fixtures/accepted"
        site = json.loads((base / "site.json").read_bytes())
        site["spec"]["desiredState"] = "archived"
        self.tenant = site["metadata"]["id"]
        self.deployment = site["spec"]["desiredDeployment"]["id"]
        self.values = {
            "/" + "/".join(path.components): value
            for path, value in (
                (StateRecordPath.tenant_desired(self.tenant), site),
                (
                    StateRecordPath.tenant_archive(self.tenant, self.deployment),
                    json.loads((base / "archive-record.json").read_bytes()),
                ),
                (
                    StateRecordPath.tenant_deployment(self.tenant, self.deployment),
                    json.loads((base / "deployment-record.json").read_bytes()),
                ),
            )
        }

    def read(self, path: str) -> bytes:
        return canonical_json_bytes(self.values[path])

    def names(self, path: str) -> dict[str, str]:
        return (
            {self.tenant: "directory"}
            if path == "/tenants"
            else {self.deployment + ".json": "regular"}
        )


@pytest.mark.parametrize("damage", [None, "tenant", "deployment", "tree", "desired", "digest"])
def test_archive_requires_exact_canonical_tenant_deployment_ownership(damage: str | None) -> None:
    reader = Records()
    archive = reader.values[
        "/" + "/".join(StateRecordPath.tenant_archive(reader.tenant, reader.deployment).components)
    ]
    if damage == "tenant":
        archive["tenantId"] = str(uuid.uuid7())
    elif damage == "deployment":
        archive["deploymentId"] = str(uuid.uuid7())
    elif damage == "tree":
        archive["releaseTreeDigest"]["value"] = "a" * 64
    elif damage == "digest":
        archive["bundleDigest"]["value"] = "invalid"
    elif damage == "desired":
        reader.values["/" + "/".join(StateRecordPath.tenant_desired(reader.tenant).components)][
            "spec"
        ]["desiredState"] = "active"
    if damage is None:
        assert inventory(reader, "")[0]["archive"] == archive
    else:
        with pytest.raises((ValueError, StateRecordError)):
            inventory(reader, "")


@pytest.mark.parametrize(
    "damage", ["dns-record", "zone-identity", "changed-names", "duplicate-zone"]
)
def test_dns_absence_rejects_foreign_subjects_and_zone_bindings(
    context: Context, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    from scripts import m3_11_retirement_live as live  # noqa: PLC0415

    client = Mock()
    client.get_collection.return_value = []
    monkeypatch.setattr(live, "CloudflareClient", Mock(return_value=client))
    identity = Mock(return_value="original-account")
    monkeypatch.setattr(live, "_require_zone_identity", identity)
    fixture = object.__new__(SpacesFixture)
    fixture.context = context
    fixture.environment = {
        **context.environment,
        "CLOUDFLARE_API_TOKEN": "fixture-secret",
        "CLOUDFLARE_ZONE_ID": "1" * 32,
        "CLOUDFLARE_TENANT_ZONE_ID": "2" * 32,
    }
    original = fixture.dns()
    if damage == "dns-record":
        client.get_collection.return_value = [{"type": "TXT", "content": "foreign-value"}]
    elif damage == "zone-identity":
        identity.side_effect = ["original-account", "other-account"]
    elif damage == "duplicate-zone":
        fixture.environment["CLOUDFLARE_TENANT_ZONE_ID"] = fixture.environment["CLOUDFLARE_ZONE_ID"]
    else:
        (context.run / "combined-names.json").write_text('{"nonce":"replacement"}')
    with pytest.raises(ValueError):
        fixture.dns()
    assert original["records"] == 0
    assert not (context.run / "public-dns").exists()
    client.post.assert_not_called()
    client.delete.assert_not_called()


def test_context_cannot_bind_another_backup_prefix_even_with_valid_digest(
    context: Context,
) -> None:
    path = context.run / "combined-context.json"
    value = dict(context.context)
    value["backup_repository_sha256"] = hashlib.sha256(
        b"s3:https://example.invalid/foreign"
    ).hexdigest()
    path.write_bytes(evidence.canonical_bytes(value))
    altered = Context(context.run, context.environment)
    with pytest.raises(ValueError, match="context differs from original inputs"):
        altered.original()
