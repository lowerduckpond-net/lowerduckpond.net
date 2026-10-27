"""Actual mount identities and daemon admission, never copied path equality."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from scripts import m3_11_custody_domain as domain
from scripts.m3_11_unattended.docker import (
    ADMISSION,
    CONFIG_VOLUME,
    EVIDENCE_VOLUME,
    LEASE_DIRECTORY,
    LEASE_VOLUME,
    helper_volume,
)
from scripts.m3_11_unattended.docker import (
    Docker as NativeDocker,
)

from .test_m3_11_custody_retirement import approved_plan


class Docker:
    def __init__(self, runtime: dict[str, Any]) -> None:
        self.runtime = runtime
        self.actor = {
            "Id": "a" * 64,
            "Image": runtime["image"],
            "State": {"Running": True},
            "Mounts": [
                {
                    "Destination": path,
                    "Name": name,
                    "Type": "volume",
                    "RW": writable,
                    "Source": "/volumes/" + name,
                }
                for path, name, writable in (
                    ("/evidence", EVIDENCE_VOLUME, True),
                    (LEASE_DIRECTORY, LEASE_VOLUME, True),
                    ("/configuration", CONFIG_VOLUME, False),
                    ("/opt/lifecycle", helper_volume("f" * 40), False),
                )
            ],
        }
        self.reservation = {
            "Id": "b" * 64,
            "Image": runtime["image"],
            "State": {"Status": "created"},
        }

    def info(self) -> dict[str, object]:
        return {"ID": self.runtime["daemon_id"]}

    def owned(self, identity: str) -> dict[str, object]:
        return self.reservation if identity == ADMISSION else self.actor

    def native_volume(self, name: str) -> dict[str, object]:
        return {
            "Name": name,
            "Mountpoint": "/volumes/" + name,
            "CreatedAt": self.runtime["evidence_volume_created_at"],
        }

    def command(self, *arguments: str) -> bytes:
        assert arguments == ("volume", "inspect", EVIDENCE_VOLUME)
        return json.dumps([self.native_volume(EVIDENCE_VOLUME)]).encode()


@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "container",
        "short",
        "daemon",
        "admission",
        "image",
        "copied-root",
        "shadow",
        "helper",
        "replaced-volume",
        "readonly",
    ],
)
def test_only_one_actual_native_lock_domain_is_admitted(fault: str) -> None:
    value = approved_plan()
    runtime = cast(dict[str, Any], value["runtime"])
    docker = Docker(deepcopy(runtime))
    invocation = {
        "container_id": "a" * 64,
        "admission_id": "b" * 64,
        "workspace_id": runtime["workspace_id"],
        "image": runtime["image"],
    }
    if fault == "container":
        docker.actor["Id"] = "c" * 64
    elif fault == "short":
        invocation["container_id"] = "a" * 12
    elif fault == "daemon":
        docker.runtime["daemon_id"] = "other-daemon"
    elif fault == "admission":
        docker.reservation["State"] = {"Status": "running"}
    elif fault == "image":
        docker.actor["Image"] = "sha256:" + "2" * 64
    elif fault == "replaced-volume":
        docker.runtime["evidence_volume_created_at"] = "2026-10-27T00:00:00Z"
    elif fault == "copied-root":
        docker.actor["Mounts"][0]["Type"] = "bind"
    elif fault == "readonly":
        docker.actor["Mounts"][0]["RW"] = False
    elif fault == "helper":
        docker.actor["Mounts"][-1]["Name"] = helper_volume("e" * 40)
    elif fault == "shadow":
        docker.actor["Mounts"].append({"Destination": "/evidence/leases", "Type": "bind"})
    if fault == "none":
        domain.verify(cast(domain.DomainDocker, docker), runtime, invocation, helper="f" * 40)
    else:
        with pytest.raises(ValueError):
            domain.verify(cast(domain.DomainDocker, docker), runtime, invocation, helper="f" * 40)


@pytest.mark.parametrize("fault", ["none", "daemon", "volume", "image", "copied", "root", "shadow"])
def test_first_runtime_use_cannot_move_to_a_copied_retirement_domain(fault: str) -> None:
    runtime = cast(dict[str, Any], approved_plan()["runtime"])
    docker = Docker(deepcopy(runtime))
    root = Path("/evidence")
    if fault == "daemon":
        docker.runtime["daemon_id"] = "other-daemon"
    elif fault == "volume":
        docker.runtime["evidence_volume_created_at"] = "2026-10-27T00:00:00Z"
    elif fault == "image":
        docker.actor["Image"] = "sha256:" + "2" * 64
    elif fault == "copied":
        docker.actor["Mounts"][0]["Type"] = "bind"
    elif fault == "root":
        root = Path("/copied/evidence")
    elif fault == "shadow":
        docker.actor["Mounts"].append({"Destination": "/evidence/leases", "Type": "bind"})
    if fault == "none":
        domain.admission_domain(cast(NativeDocker, docker), runtime, evidence_root=root)
    else:
        with pytest.raises(ValueError):
            domain.admission_domain(cast(NativeDocker, docker), runtime, evidence_root=root)
