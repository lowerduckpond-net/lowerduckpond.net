from __future__ import annotations

import hashlib
import os
import ssl
import sys
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import host_restore_bootstrap as bootstrap
from lowerduckpond_static_host_agent import host_restore_fence as fence
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.host_restore_journal import RestoreStore
from lowerduckpond_static_host_agent.host_restore_services import (
    ORDINARY_ACTIVATORS,
    ORDINARY_SERVICES,
    TEMPLATES,
)
from lowerduckpond_static_host_agent.host_restore_snapshot import RestoreSnapshot
from test_backup_caddy import fixture as caddy_fixture  # noqa: F401
from test_backup_capture import capture as capture  # noqa: PLC0414
from test_backup_capture import fixture as fixture  # noqa: PLC0414
from test_host_restore_inputs import configuration as configuration  # noqa: PLC0414
from test_host_restore_snapshot import restic as restic  # noqa: PLC0414


@pytest.mark.parametrize("fault", ["none", "destination", "receipt", "public-ca", "unsafe-input"])
def test_workstation_preflight_is_readonly_and_requires_bound_source_fence(  # noqa: PLR0913,PLR0917
    restic: tuple[RestoreSnapshot, dict[str, dict[str, object]]],
    configuration: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fault: str,
) -> None:
    source = tmp_path / "source-fence"
    source.mkdir(mode=0o700)
    monkeypatch.setattr(fence, "close_public_ingress", lambda: None)
    monkeypatch.setattr(
        fence,
        "quiesce_host",
        lambda: tuple(
            sorted((*ORDINARY_ACTIVATORS, *ORDINARY_SERVICES, *TEMPLATES, "caddy.service"))
        ),
    )
    monkeypatch.setattr(fence, "require_quiescent", lambda: None)
    with RestoreStore.locked(source, owner=os.geteuid()) as store:
        receipt = fence.source_fence_receipt(
            store,
            restic[0],
            str(configuration["restoreId"]),
            "a" * 32,
            "b" * 64,
        )
    root = tmp_path / "private-inputs"
    root.mkdir(mode=0o700)
    configuration["repositoryBinding"] = restic[0].identity.binding()
    configuration["sourceFenceDigest"] = framed_digest(fence.FENCE_SCHEMA, receipt)
    public = b"test-only original public trust bytes"
    cast(dict[str, object], configuration["caddy"])["originalOriginPullCaSha256"] = [
        hashlib.sha256(public).hexdigest()
    ]
    files = {
        "target.json": canonical_json_bytes(configuration),
        f"source-fence-{configuration['restoreId']}.json": receipt,
        "original-origin-pull-ca-0.pem": ssl.DER_cert_to_PEM_cert(public).encode(),
    }
    for name, raw in files.items():
        path = root / name
        path.write_bytes(raw)
        path.chmod(0o600)
    if fault == "receipt":
        (root / f"source-fence-{configuration['restoreId']}.json").write_bytes(b"{}\n")
    elif fault == "public-ca":
        (root / "original-origin-pull-ca-0.pem").unlink()
    elif fault == "unsafe-input":
        (root / "target.json").chmod(0o644)
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in root.iterdir()}
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "host_restore_bootstrap",
            "--directory",
            str(root),
            "--restore-id",
            str(configuration["restoreId"]),
            "--destination",
            ("c" if fault == "destination" else "b") * 32,
        ],
    )
    assert bootstrap.main() == int(fault != "none")
    assert before == {
        path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in root.iterdir()
    }
    output = capsys.readouterr()
    assert str(root) not in output.err and public.decode() not in output.out
