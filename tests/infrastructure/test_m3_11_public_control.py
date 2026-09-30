"""The public issuer can cancel work through only its private Unix socket."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import socketserver
import tempfile
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import m3_11_public_caddy as policy
from scripts import m3_11_public_probe as probe


@pytest.fixture
def control(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, object]]:
    # Unix socket paths have a short kernel limit; pytest node names can exceed it.
    with tempfile.TemporaryDirectory(prefix="ldp-public-control-") as directory:
        root = Path(directory)
        monkeypatch.setattr(policy, "STORAGE", root)
        monkeypatch.setattr(pwd, "getpwnam", Mock(return_value=pwd.getpwuid(os.getuid())))
        calls: list[tuple[str, str]] = []
        state: dict[str, object] = {"calls": calls, "config": {"apps": {"tls": {}}}}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:  # noqa: A002
                pass

            def reply(self, body: bytes) -> None:
                self.send_response(int(str(state.get("status", 200))))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                state["config"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                calls.append(("POST", self.path))
                self.reply(b"")

            def do_GET(self) -> None:
                calls.append(("GET", self.path))
                self.reply(json.dumps(state["config"]).encode())

        with socketserver.UnixStreamServer(str(root / "admin.sock"), Handler) as server:
            (root / "admin.sock").chmod(0o600)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield state
            finally:
                server.shutdown()
                thread.join(timeout=5)


def test_control_cancels_apps_and_confirms_live_configuration(control: dict[str, object]) -> None:
    probe._admin("POST", "/load", policy.suspended_configuration())
    probe._require_suspended()
    assert control["config"] == json.loads(policy.suspended_configuration())
    assert control["calls"] == [("POST", "/load"), ("GET", "/config/")]


def test_stopped_inventory_excludes_only_the_validated_control_socket(
    control: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    inactive = Mock()
    monkeypatch.setattr(probe, "_inactive", inactive)
    key = policy.STORAGE / "account.key"
    key.write_bytes(b"retained account bytes")
    key.chmod(0o600)
    assert probe._inventory() == {"account.key": hashlib.sha256(key.read_bytes()).hexdigest()}
    inactive.assert_called_once_with(policy.UNIT)
    (policy.STORAGE / "admin.sock").unlink()
    (policy.STORAGE / "admin.sock").write_bytes(b"a regular file cannot be silently omitted")
    with pytest.raises(ValueError, match="unsafe admin socket"):
        probe._inventory()


@pytest.mark.parametrize(
    "fault", ["active-apps", "error-status", "oversized", "socket-mode", "parent-mode", "symlink"]
)
def test_control_refuses_unverified_or_nonprivate_endpoint(
    control: dict[str, object], fault: str
) -> None:
    if fault == "error-status":
        control["status"] = 500
    elif fault == "oversized":
        control["config"] = "a" * policy.MAXIMUM_BYTES
    elif fault == "socket-mode":
        (policy.STORAGE / "admin.sock").chmod(0o660)
    elif fault == "parent-mode":
        policy.STORAGE.chmod(0o750)
    elif fault == "symlink":
        (policy.STORAGE / "admin.sock").rename(policy.STORAGE / "other.sock")
        (policy.STORAGE / "admin.sock").symlink_to("other.sock")
    with pytest.raises(ValueError):
        probe._require_suspended()
    if fault in {"socket-mode", "parent-mode", "symlink"}:
        assert control["calls"] == []


def test_suspension_rejects_legacy_or_changed_configuration_before_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        probe, "_guard", Mock(return_value={"nonce": "0198d17f-6f4a-7000-8000-000000000001"})
    )
    monkeypatch.setattr(probe, "_closed", Mock())
    monkeypatch.setattr(probe, "_read", Mock(return_value=b'{"admin":{"disabled":true}}'))
    admin = Mock()
    monkeypatch.setattr(probe, "_admin", admin)
    with pytest.raises(ValueError, match="predates controlled"):
        probe._suspend("a" * 64)
    admin.assert_not_called()
