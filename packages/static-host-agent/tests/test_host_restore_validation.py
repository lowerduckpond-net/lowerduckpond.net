from __future__ import annotations

import os

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.host_restore_journal import HostRestoreError
from lowerduckpond_static_host_agent.host_restore_validation import validate_restored_authority
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401 - pytest fixture
from test_backup_capture import Capture
from test_backup_capture import capture as capture  # noqa: PLC0414 - shared real authority fixture
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_backup_inventory import _fixture


def verify(capture: Capture, raw: bytes, *, artifact: str = "b" * 64) -> dict[str, object]:
    return validate_restored_authority(
        raw,
        capture.roots,
        capture.workspace,
        owner=os.geteuid(),
        content_group=os.getegid(),
        repository_genesis=capture.state.lineage,
        artifact_sha256=artifact,
        namespace=_fixture("platform-namespace"),
        launch=None,
    )


def test_reconstruction_checks_capture_without_requiring_excluded_caddy_payloads(
    capture: Capture,
) -> None:
    descriptor = capture.descriptor()
    raw = canonical_json_bytes(descriptor, maximum_bytes=256 * 1024)
    # None of the Caddy generation paths are supplied to recovery validation.
    original = {
        path: path.read_bytes()
        for root in capture.roots.values()
        for path in root.rglob("*")
        if path.is_file()
    }
    measured = verify(capture, raw)
    assert measured == {name: descriptor[name] for name in measured}
    assert original == {
        path: path.read_bytes()
        for root in capture.roots.values()
        for path in root.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("damage", ["artifact", "authority", "namespace", "audit", "release"])
def test_mixed_or_changed_restored_authority_never_becomes_a_new_capture(
    capture: Capture,
    damage: str,
) -> None:
    descriptor = capture.descriptor()
    raw = canonical_json_bytes(descriptor, maximum_bytes=256 * 1024)
    if damage == "artifact":
        with pytest.raises(HostRestoreError, match="trusted_input"):
            verify(capture, raw, artifact="c" * 64)
        return
    if damage == "authority":
        path = capture.roots["content"] / "fixture" / "index.html"
        path.write_bytes(b"uncaptured content")
        path.chmod(0o644)
    elif damage == "namespace":
        path = capture.state.root / "platform/namespace.json"
        path.write_bytes(b"{}\n")
    elif damage == "audit":
        path = capture.state.root / "audit/segment-00000000000000000000.jsonl"
        path.write_bytes(b"{}\n")
        path.chmod(0o600)
    else:
        path = next((capture.roots["content"] / "sites").rglob("index.html"))
        path.write_bytes(b"corrupt release")
    before = path.read_bytes()
    with pytest.raises((HostRestoreError, BackupIdentityError, ValueError, RuntimeError)):
        verify(capture, raw)
    assert path.read_bytes() == before
