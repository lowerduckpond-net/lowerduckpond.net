"""Standard start preserves all gates for the explicit fresh-lease first use."""

from __future__ import annotations

import dataclasses
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts.m3_11_unattended import __main__ as cli
from scripts.m3_11_unattended import approval, docker, storage_admission
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.model import LifecycleError, digest, instant, stamp
from scripts.m3_11_unattended.reuse_admission import AdmissionUncertainError

from .test_m3_11_unattended_admission import Daemon
from .test_m3_11_unattended_controller import DAEMON, configuration


@pytest.mark.parametrize(
    "fault", ["none", "no-selection", "prior-consumer", "unverified", "uncertain"]
)
def test_start_reaches_only_explicit_native_first_use(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    config, daemon = configuration(), Daemon()
    source, lease_id = config.helper_revision, "019b8e10-4ef0-7000-8000-000000000001"
    now = instant(config.policy.approved_at) + timedelta(minutes=1)
    allowed = {
        "format": approval.FORMAT,
        "prepared": {
            "source_revision": source,
            "helper_revision": source,
            "controller_image": "sha256:" + "b" * 64,
            "artifact_sha256": "c" * 64,
            "daemon": DAEMON,
        },
        "targets": dataclasses.asdict(config.targets),
        "qualification_inputs_sha256": "d" * 64,
        "modes": ["qualification"],
        "approved_at": stamp(now - timedelta(seconds=1)),
        "expires_at": stamp(now + timedelta(hours=1)),
        "policy_sha256": config.policy.sha256,
        "lease_id": lease_id,
        "approval_reference": "SYNTHETIC custody first-use test",
    }
    monkeypatch.setattr(cli, "datetime", SimpleNamespace(now=lambda _zone: now))
    monkeypatch.setattr(cli, "current_candidate", lambda *_args: None)
    monkeypatch.setattr(cli, "fingerprint", lambda *_args: "d" * 64)
    monkeypatch.setattr(LeaseConfiguration, "load", lambda _path: config)
    gates: list[str] = []
    monkeypatch.setattr(
        cli, "require_current_watchdogs", lambda *_args, **_kwargs: gates.append("watchdogs")
    )
    if fault == "prior-consumer":
        daemon.controllers.append(docker.controller_name(lease_id))
        monkeypatch.setattr(
            cli,
            "operate",
            lambda *_args: json.dumps(
                {
                    "status": {"phase": "finished", "qualification": "failed"},
                    "lease": {
                        "lease_id": lease_id,
                        "policy_sha256": config.policy.sha256,
                        "use_released": True,
                        "manifest_sha256": "a" * 64,
                    },
                }
            ).encode(),
        )

    def utility(*_args: object, **kwargs: object) -> dict[str, object]:
        assert daemon.reserved and gates == ["watchdogs"]
        assert kwargs["operation"] == "reuse-admission"
        payload = cast(dict[str, object], kwargs["payload"])
        assert payload["custody_first_use"] is True and payload["manifest_sha256"] == "a" * 64
        assert payload["approved"] == allowed
        request = cast(dict[str, object], payload["request"])
        run_id = cast(dict[str, object], request["binding"])["managed_run_id"]
        gates.append("native-first-use")
        if fault == "uncertain":
            raise RuntimeError("synthetic lost native admission reply")
        if fault == "unverified":
            return {}
        return {
            "format": storage_admission.FORMAT,
            "lease_id": lease_id,
            "manifest_sha256": "a" * 64,
            "policy_sha256": config.policy.sha256,
            "storage_target_sha256": config.targets.storage_digest,
            "helper_revision": source,
            "whole_bucket_empty": True,
            "failure": None,
            "admitted": {
                "attempt_id": run_id,
                "request_sha256": digest(request),
                "binding_sha256": digest(request["binding"]),
                "admission_sha256": "e" * 64,
            },
        }

    monkeypatch.setattr(cli, "utility", utility)
    monkeypatch.setattr(
        cli,
        "initialize_run",
        lambda *_args, **_kwargs: pytest.fail("must not allocate a fresh issuance"),
    )
    monkeypatch.setattr(cli, "launch", lambda *_args, **_kwargs: gates.append("launch"))
    arguments = {
        "approved": allowed,
        "config": Path("unused"),
        "source": source,
        "mode": "qualification",
        "daemon_socket": "/socket",
        "custody_manifest_sha256": None if fault == "no-selection" else "a" * 64,
    }
    if fault == "none":
        assert cli.start(daemon, **arguments)  # type: ignore[arg-type]
        assert gates == ["watchdogs", "native-first-use", "launch"]
    else:
        with pytest.raises((LifecycleError, AdmissionUncertainError)):
            cli.start(daemon, **arguments)  # type: ignore[arg-type]
        assert "launch" not in gates
    assert not daemon.reserved
