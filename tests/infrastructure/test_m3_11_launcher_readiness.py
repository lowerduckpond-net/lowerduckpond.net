"""Launcher reuse admission preserves exact lease, policy and prior outcome gates."""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from scripts.m3_11_unattended import __main__ as cli
from scripts.m3_11_unattended import approval
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import SOCKET, Docker, controller_name
from scripts.m3_11_unattended.model import LifecycleError, digest, stamp
from scripts.m3_11_unattended.reuse_admission import AdmissionUncertainError

from .test_m3_11_unattended_admission import Daemon
from .test_m3_11_unattended_controller import DAEMON, configuration


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "lease",
        "policy",
        "unreleased",
        "running",
        "successful",
        "lost-launch",
        "lost-admission",
    ],
)
def test_only_released_failed_same_lease_can_pass_launcher_admission(  # noqa: PLR0915 - full native launcher boundary
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    config = configuration()
    lease_id, old_run = str(uuid.uuid7()), str(uuid.uuid7())
    daemon = Daemon()
    daemon.controllers.append(controller_name(old_run))
    now = datetime.now(UTC)
    approved: dict[str, object] = {
        "format": approval.FORMAT,
        "prepared": {
            "source_revision": "e" * 40,
            "helper_revision": "e" * 40,
            "controller_image": "sha256:" + "b" * 64,
            "artifact_sha256": "c" * 64,
            "daemon": DAEMON,
        },
        "targets": dataclasses.asdict(config.targets),
        "qualification_inputs_sha256": "d" * 64,
        "modes": ["rehearsal"],
        "approved_at": stamp(now - timedelta(seconds=1)),
        "expires_at": stamp(now + timedelta(hours=1)),
        "policy_sha256": config.approved_policy_sha256,
        "lease_id": lease_id,
        "approval_reference": "SYNTHETIC-REUSE-ONLY",
    }
    lease: dict[str, object] = {
        "lease_id": lease_id,
        "policy_sha256": config.approved_policy_sha256,
        "use_released": True,
        "manifest_sha256": "a" * 64,
    }
    status = {"phase": "finished", "qualification": "failed", "credential_cleanup": "unresolved"}
    if fault == "lease":
        lease["lease_id"] = str(uuid.uuid7())
    elif fault == "policy":
        lease["policy_sha256"] = "0" * 64
    elif fault == "unreleased":
        lease["use_released"] = False
    elif fault == "running":
        status["phase"] = "running"
    elif fault == "successful":
        status["qualification"] = "passed"
    monkeypatch.setattr(cli, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(cli, "fingerprint", lambda *_args: "d" * 64)
    monkeypatch.setattr(LeaseConfiguration, "load", lambda _path: config)
    monkeypatch.setattr(
        cli, "operate", lambda *_args: json.dumps({"status": status, "lease": lease}).encode()
    )
    monkeypatch.setattr(cli, "require_current_watchdogs", lambda *_args, **_kwargs: None)
    requests = []

    def admitted(*_args: object, **kwargs: object) -> dict[str, object]:
        assert kwargs["operation"] == "reuse-admission"
        payload = cast(dict[str, object], kwargs["payload"])
        request = cast(dict[str, object], payload["request"])
        requests.append(request)
        if fault == "lost-admission":
            raise OSError("synthetic lost response after durable admission")
        return {
            "format": "lowerduckpond-m3-11-storage-admission-v1",
            "lease_id": lease_id,
            "manifest_sha256": "a" * 64,
            "policy_sha256": config.approved_policy_sha256,
            "storage_target_sha256": config.targets.storage_digest,
            "helper_revision": config.helper_revision,
            "whole_bucket_empty": True,
            "failure": None,
            "admitted": {
                "attempt_id": cast(dict[str, object], request["binding"])["managed_run_id"],
                "request_sha256": digest(request),
                "binding_sha256": digest(request["binding"]),
                "admission_sha256": "b" * 64,
            },
        }

    monkeypatch.setattr(cli, "utility", admitted)
    monkeypatch.setattr(
        cli,
        "initialize_run",
        lambda *_args, **_kwargs: pytest.fail(
            "reuse allocation must remain inside the daemon's ownership locks"
        ),
    )

    def launch(*_args: object, **_kwargs: object) -> None:
        if fault == "lost-launch":
            raise OSError("synthetic lost launch reply")

    monkeypatch.setattr(cli, "launch", launch)
    arguments = {
        "approved": approved,
        "config": tmp_path / "unused",
        "source": "e" * 40,
        "mode": "rehearsal",
        "daemon_socket": SOCKET,
    }
    if fault in {"lost-launch", "lost-admission"}:
        with pytest.raises(AdmissionUncertainError) as rejected:
            cli.start(cast(Docker, daemon), **arguments)  # type: ignore[arg-type]
        assert len(requests) == 1
        assert (
            rejected.value.attempt_id
            == cast(dict[str, object], requests[0]["binding"])["managed_run_id"]
        )
    elif fault == "none":
        result = cli.start(cast(Docker, daemon), **arguments)  # type: ignore[arg-type] # heterogeneous CLI inputs
        assert result != old_run
        assert requests[0]["lease_id"] == lease_id
    else:
        with pytest.raises(LifecycleError, match="unresolved revocation"):
            cli.start(cast(Docker, daemon), **arguments)  # type: ignore[arg-type]
        assert requests == []
