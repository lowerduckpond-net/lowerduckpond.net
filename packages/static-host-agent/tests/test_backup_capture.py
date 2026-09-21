from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_capture import build_capture_descriptor
from lowerduckpond_static_host_agent.backup_descriptor import decode_backup_descriptor
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.capacity import FilesystemCapacity
from lowerduckpond_static_host_agent.durable import StatePathError
from lowerduckpond_static_host_agent.locks import LockManager, LockMode, LockName
from lowerduckpond_static_host_agent.release_store import ReleaseStoreError
from lowerduckpond_static_host_agent.release_tree import measure_release_tree
from test_backup_caddy import Fixture as CaddyFixture
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - shared pytest fixture
from test_backup_inventory import DEPLOYMENT, INTENT, TENANT
from test_backup_inventory import Fixture as StateFixture
from test_backup_inventory import fixture as fixture  # noqa: PLC0414 - shared pytest fixture


@dataclass
class Capture:
    state: StateFixture
    caddy: CaddyFixture
    roots: dict[str, Path]
    workspace: Path

    def descriptor(self) -> dict[str, object]:
        with (
            LockManager(self.state.root / "locks", expected_owner=os.geteuid()) as locks,
            locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
            locks.acquire(LockName.TENANT_STATE, mode=LockMode.SHARED),
        ):
            return decode_backup_descriptor(
                build_capture_descriptor(
                    self.roots,
                    self.workspace,
                    self.caddy.root,
                    locks=locks,
                    expected_owner=os.geteuid(),
                    content_group=os.getegid(),
                    artifact_sha256="b" * 64,
                    repository_genesis=self.state.lineage,
                    capture_id=INTENT,
                    captured_at="2026-09-21T05:00:01Z",
                )
            )


@pytest.fixture
def capture(
    fixture: StateFixture,
    caddy_fixture: CaddyFixture,  # noqa: F811 - imported pytest fixture
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Capture:
    def capacity(descriptor: int) -> FilesystemCapacity:
        return FilesystemCapacity(
            os.fstat(descriptor).st_dev, 4096, 32_000_000, 25_000_000, 2_000_000, 1_000_000
        )

    monkeypatch.setattr(
        "lowerduckpond_static_host_agent.backup_sources.measure_filesystem_capacity_descriptor",
        capacity,
    )
    roots = {
        "state": fixture.root,
        "content": tmp_path / "content",
        "recovery": tmp_path / "recovery",
    }
    roots["content"].mkdir(mode=0o711)
    roots["recovery"].mkdir(mode=0o700)
    for name, mode in (("fixture", 0o750), ("sites", 0o710), ("sites/.staging", 0o700)):
        (roots["content"] / name).mkdir(mode=mode)
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    fixture.tenant()
    for name in (TENANT, TENANT + "/releases", TENANT + "/releases/" + DEPLOYMENT):
        (roots["content"] / "sites" / name).mkdir(mode=0o755)
    release = roots["content"] / "sites" / TENANT / "releases" / DEPLOYMENT
    (release / "index.html").write_bytes(b"complete release")
    (release / "index.html").chmod(0o644)
    with (
        LockManager(fixture.root / "locks", expected_owner=os.geteuid()) as locks,
        locks.acquire(LockName.PUBLICATION, mode=LockMode.SHARED),
    ):
        digest = measure_release_tree(
            release,
            lock_manager=locks,
            expected_owner=os.geteuid(),
        ).digest.to_dict()
    record_path = f"tenants/{TENANT}/deployments/{DEPLOYMENT}.json"
    record = json.loads((fixture.root / record_path).read_bytes())
    record["releaseTreeDigest"] = digest
    fixture.write(record_path, record)
    return Capture(fixture, caddy_fixture, roots, workspace)


def test_capture_binds_actual_releases_contracts_tree_and_runtime(capture: Capture) -> None:
    document = capture.descriptor()
    tenants = document["tenants"]
    assert type(tenants) is list
    tenant = tenants[0]
    assert tenant["tenantId"] == TENANT
    assert tenant["releases"][0]["deploymentId"] == DEPLOYMENT
    assert document["lineage"] == capture.state.lineage
    assert document["launchDigest"] is None
    assert document["caddy"] == capture.caddy.capture().to_dict()
    raw = canonical_json_bytes(document, maximum_bytes=256 * 1024)
    assert b"secret-environment-canary" not in raw
    assert b"secret-configuration-canary" not in raw
    assert not list(capture.workspace.iterdir())
    assert capture.descriptor() == document


def test_excluded_delivery_and_intake_changes_do_not_change_captured_authority(
    capture: Capture,
) -> None:
    original = capture.descriptor()
    for name in ("intake", "exports"):
        (capture.state.root / name / "secret-canary").write_bytes(b"excluded transient bytes")
    assert capture.descriptor() == original
    release = capture.roots["content"] / "sites" / TENANT / "releases" / DEPLOYMENT
    (release / "index.html").write_bytes(b"unrecorded release change")
    with pytest.raises(BackupIdentityError, match="release digest"):
        capture.descriptor()


def test_capture_preserves_and_excludes_safe_recovery_publication_temporary(
    capture: Capture,
) -> None:
    original = capture.descriptor()
    path = capture.roots["recovery"] / (".ldp-state-" + "a" * 32)
    path.write_bytes(b"uncommitted recovery evidence")
    path.chmod(0o600)
    assert capture.descriptor() == original
    assert path.read_bytes() == b"uncommitted recovery evidence"
    path.chmod(0o644)
    with pytest.raises(StatePathError, match="unsafe inode"):
        capture.descriptor()


@pytest.mark.parametrize(
    "damage", ["unknown-content", "recovery-record", "unknown-tenant", "unbound-release", "staging"]
)
def test_capture_refuses_unclassified_source_or_partial_release(
    capture: Capture, damage: str
) -> None:
    content = capture.roots["content"]
    if damage == "unknown-content":
        (content / "unknown").mkdir()
    elif damage == "recovery-record":
        (capture.roots["recovery"] / "unknown.json").write_bytes(b"{}")
    elif damage == "unknown-tenant":
        (content / "sites" / TENANT).rename(content / "sites" / INTENT)
    elif damage == "unbound-release":
        release = content / "sites" / TENANT / "releases" / DEPLOYMENT
        release.rename(release.with_name(INTENT))
    else:
        (content / "sites/.staging/pending").write_bytes(b"partial release")
    with pytest.raises((BackupIdentityError, ReleaseStoreError)):
        capture.descriptor()


def test_record_digest_changes_when_durable_history_changes(capture: Capture) -> None:
    original = capture.descriptor()
    path = f"tenants/{TENANT}/deployments/{DEPLOYMENT}.json"
    record = json.loads((capture.state.root / path).read_bytes())
    record["createdAt"] = "2026-09-21T05:00:00Z"
    capture.state.write(path, record)
    updated = capture.descriptor()
    assert updated["tenants"] != original["tenants"]
    assert updated["authority"] != original["authority"]
