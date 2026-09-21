from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import (
    ContractError,
    canonical_json_bytes,
    platform_state_digest,
)
from lowerduckpond_static_host_agent.archive_remote import ArchiveRemoteError
from lowerduckpond_static_host_agent.audit import AuditError
from lowerduckpond_static_host_agent.backup_identity import (
    LINEAGE_SCHEMA,
    BackupIdentityError,
    RepositoryIdentity,
)
from lowerduckpond_static_host_agent.backup_inventory import BackupState, capture_state_inventory
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName, LockOrderError
from lowerduckpond_static_host_agent.repository import StateRecordError

FIXTURES = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
DEPLOYMENT = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
INTENT = "0198d17f-6f4a-7000-8000-000000000003"
JOB = "0198d17f-6f4a-7000-8000-000000000002"
CORRELATION = "0198d17f-6f4a-7000-8000-000000000001"


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((FIXTURES / (name + ".json")).read_bytes())
    assert type(value) is dict
    return value


@dataclass
class Fixture:
    root: Path
    lineage: dict[str, object]

    def write(self, path: str, document: dict[str, object]) -> None:
        destination = self.root / path
        destination.write_bytes(canonical_json_bytes(document))
        destination.chmod(0o600)

    def capture(self) -> BackupState:
        with (
            LockManager(self.root / "locks", expected_owner=os.geteuid()) as locks,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED),
        ):
            return capture_state_inventory(
                self.root,
                locks=locks,
                expected_owner=os.geteuid(),
                repository_genesis=self.lineage,
            )

    def tenant(self) -> None:
        root = self.root / "tenants" / TENANT
        root.mkdir(mode=0o700)
        for name in ("deployments", "archives"):
            (root / name).mkdir(mode=0o700)
        self.write(f"tenants/{TENANT}/desired.json", _fixture("site"))
        self.write(f"tenants/{TENANT}/observed.json", _fixture("tenant-observed-state"))
        self.write(f"tenants/{TENANT}/deployments/{DEPLOYMENT}.json", _fixture("deployment-record"))
        self.write(f"tenants/{TENANT}/archives/{DEPLOYMENT}.json", _fixture("archive-record"))


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    for name in (
        "platform",
        "locks",
        "tenants",
        "intents",
        "authorization",
        "audit",
        "intake",
        "exports",
    ):
        (root / name).mkdir(mode=0o700)
    for name in ("jobs", "correlations", "results"):
        (root / "authorization" / name).mkdir(mode=0o700)
    with LockManager.initialize(root / "locks", expected_owner=os.geteuid()):
        pass
    identity = RepositoryIdentity("a" * 64, "source-node", "/private/backup")
    lineage: dict[str, object] = {
        "schema": LINEAGE_SCHEMA,
        "lineageId": INTENT,
        "initializedAt": "2026-09-21T05:00:00Z",
        "repository": identity.document(),
        "repositoryBinding": identity.binding(),
        "namespaceDigest": platform_state_digest(_fixture("platform-namespace")).to_dict(),
        "initialEntryCount": 0,
        "initialTerminalEntryDigest": None,
    }
    fixture = Fixture(root, lineage)
    fixture.write("platform/namespace.json", _fixture("platform-namespace"))
    fixture.write("platform/audit-lineage.json", lineage)
    fixture.write("locks/audit-lineage-genesis.json", lineage)
    return fixture


def test_inventory_captures_all_records_without_mutation_or_credentials(fixture: Fixture) -> None:
    fixture.tenant()
    fixture.write("platform/launch.json", _fixture("launch-record"))
    fixture.write(f"authorization/jobs/{JOB}.json", _fixture("authorization-job"))
    fixture.write(f"authorization/correlations/{CORRELATION}.json", _fixture("authorization-job"))
    fixture.write(f"authorization/results/{JOB}.json", _fixture("operation-result"))
    fixture.write(f"intents/{INTENT}.json", _fixture("transaction-intent"))
    fixture.write(
        "platform/archive-quarantine.json",
        {
            "format": "lowerduckpond-archive-quarantine-v2",
            "bucket": "fake-archive-bucket",
            "discoveryIncomplete": True,
            "versions": [],
            "multipartUploads": [],
        },
    )
    cursor = fixture.root / "locks/authorization-recovery.cursor"
    cursor.write_text(JOB)
    cursor.chmod(0o600)
    temporary = fixture.root / "authorization/jobs" / (".ldp-state-" + "a" * 32)
    temporary.write_bytes(b"unfinished write")
    temporary.chmod(0o600)
    before = {
        str(path): (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in fixture.root.rglob("*")
        if path.is_file()
    }
    state = fixture.capture()
    assert state.lineage == fixture.lineage
    assert state.launch == _fixture("launch-record")
    assert state.audit.entry_count == 0
    assert len(state.tenants) == 1
    assert state.tenants[0].desired == _fixture("site")
    assert state.tenants[0].observed == _fixture("tenant-observed-state")
    assert state.tenants[0].deployments == (_fixture("deployment-record"),)
    assert state.tenants[0].archives == (_fixture("archive-record"),)
    assert state.intents == (_fixture("transaction-intent"),)
    assert before == {
        str(path): (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
        for path in fixture.root.rglob("*")
        if path.is_file()
    }


def test_launch_and_all_tenants_may_be_explicitly_absent(fixture: Fixture) -> None:
    state = fixture.capture()
    assert state.launch is None
    assert state.tenants == ()
    assert state.intents == ()


@pytest.mark.parametrize("missing", ["desired.json", "observed.json", "deployments", "archives"])
def test_interrupted_namespace_is_preserved_only_with_tenant_intent(
    fixture: Fixture,
    missing: str,
) -> None:
    root = fixture.root / "tenants" / TENANT
    root.mkdir(mode=0o700)
    for name in ("deployments", "archives"):
        if name != missing:
            (root / name).mkdir(mode=0o700)
    for name, source in (("desired.json", "site"), ("observed.json", "tenant-observed-state")):
        if name != missing:
            fixture.write(f"tenants/{TENANT}/{name}", _fixture(source))
    with pytest.raises(BackupIdentityError):
        fixture.capture()
    fixture.write(f"intents/{INTENT}.json", _fixture("transaction-intent"))
    captured = fixture.capture()
    assert captured.intents
    if missing == "desired.json":
        assert captured.tenants[0].desired is None
    if missing == "observed.json":
        assert captured.tenants[0].observed is None


@pytest.mark.parametrize(
    "damage",
    [
        "unknown-root",
        "unknown-platform",
        "missing-store",
        "unknown-tenant",
        "record-path",
        "noncanonical",
        "bad-audit",
        "bad-cursor",
        "genesis",
        "repository",
        "unknown-intent",
        "wrong-result",
        "extra-record",
        "malformed-temporary",
        "quarantine",
    ],
)
def test_unclassified_or_conflicting_authority_fails_without_repair(  # noqa: PLR0912 - corruption matrix
    fixture: Fixture,
    damage: str,
) -> None:
    fixture.tenant()
    if damage == "unknown-root":
        (fixture.root / "unknown").mkdir(mode=0o700)
    elif damage == "unknown-platform":
        fixture.write("platform/unknown.json", {})
    elif damage == "missing-store":
        (fixture.root / "intents").rmdir()
    elif damage == "unknown-tenant":
        fixture.write(f"tenants/{TENANT}/unknown.json", {})
    elif damage == "record-path":
        original = fixture.root / "tenants" / TENANT / "deployments" / (DEPLOYMENT + ".json")
        original.rename(original.with_name(INTENT + ".json"))
    elif damage == "noncanonical":
        (fixture.root / "platform/namespace.json").write_text(
            json.dumps(_fixture("platform-namespace"))
        )
    elif damage == "bad-audit":
        fixture.write("audit/segment-00000000000000000000.jsonl", {})
    elif damage == "bad-cursor":
        fixture.write("locks/authorization-recovery.cursor", {})
    elif damage == "genesis":
        (fixture.root / "locks/audit-lineage-genesis.json").unlink()
    elif damage == "repository":
        fixture.lineage = {**fixture.lineage, "lineageId": JOB}
    elif damage == "unknown-intent":
        fixture.write(f"intents/{INTENT}.json", _fixture("site"))
    elif damage == "wrong-result":
        fixture.write(f"authorization/results/{INTENT}.json", _fixture("operation-result"))
    elif damage == "extra-record":
        for number in range(5):
            identifier = f"0198d17f-6f4a-7000-8000-{number:012x}"
            fixture.write(f"tenants/{TENANT}/deployments/{identifier}.json", {})
    elif damage == "malformed-temporary":
        fixture.write("intents/.ldp-state-invalid", {})
    else:
        fixture.write("platform/archive-quarantine.json", {})
    with pytest.raises(
        (
            BackupIdentityError,
            StatePathError,
            ContractError,
            StateRecordError,
            AuditError,
            ArchiveRemoteError,
            FileNotFoundError,
        )
    ):
        fixture.capture()


def test_backup_inventory_requires_both_shared_leases(fixture: Fixture) -> None:
    with (
        LockManager(fixture.root / "locks", expected_owner=os.geteuid()) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
        pytest.raises(LockOrderError),
    ):
        capture_state_inventory(
            fixture.root,
            locks=locks,
            expected_owner=os.geteuid(),
            repository_genesis=fixture.lineage,
        )
