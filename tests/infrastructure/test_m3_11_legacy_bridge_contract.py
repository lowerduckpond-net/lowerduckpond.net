"""Reject executable-looking bridges with unavailable or substituted cleanup inputs."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, cast

import pytest

from scripts.m3_11_unattended import legacy_actors, legacy_diagnostics
from scripts.m3_11_unattended import legacy_bridge_contract as contract
from scripts.m3_11_unattended import legacy_import_reader as bridge
from scripts.m3_11_unattended.connect_activate import reader_images
from scripts.m3_11_unattended.docker import Docker
from scripts.m3_11_unattended.model import LifecycleError

from .operator_host_support import IMAGE
from .test_m3_11_legacy_import_reader import VAULT, Host


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> Host:
    host = Host()
    hashes = {
        bridge.PROGRAM: host.bridge_sha256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_ledger.py": bridge.LEDGER_SHA256,
        "/opt/lifecycle/scripts/m3_11_unattended/connect_auth.py": bridge.INSPECTOR_SHA256,
    }
    # Only Docker file transport is controlled. The acceptance predicates run normally.
    monkeypatch.setattr(legacy_diagnostics, "script_digest", lambda _host, _id, path: hashes[path])
    return host


def rejected(host: Host, images: set[str] | None = None) -> None:
    expected = {IMAGE} if images is None else images
    with pytest.raises(LifecycleError):
        legacy_actors.require_import_readers(
            cast(Docker, host), vault=VAULT, expected="a" * 64, images=expected
        )
    # It must not receive the inventory exemption either.
    assert host.bridged["Id"] in legacy_actors.inventory(cast(Docker, host), reader_images=expected)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("Type", "volume"),
        ("Source", "/var/run/docker.sock"),
        ("Source", "/some/other/docker.sock"),
        ("Destination", "/unused/docker.sock"),
        ("RW", False),
        ("RW", "true"),
        ("Propagation", "rshared"),
        ("Propagation", None),
    ],
)
def test_socket_binding_must_reach_the_retained_daemon(host: Host, key: str, value: object) -> None:
    socket = host.bridged["Mounts"][-1]
    assert socket["Destination"] == "/var/run/docker.sock"
    socket[key] = value
    rejected(host)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "extra-tool-overlay", "ancestor"])
def test_socket_and_tool_mount_topology_is_closed(host: Host, fault: str) -> None:
    mounts = host.bridged["Mounts"]
    if fault == "missing":
        mounts.pop()
    elif fault == "duplicate":
        mounts.append(deepcopy(mounts[-1]))
    else:
        mounts.append(
            {
                "Type": "bind",
                "Source": "/wrong",
                "RW": False,
                "Destination": "/usr/local/bin" if fault == "extra-tool-overlay" else "/opt",
            }
        )
    rejected(host)


@pytest.mark.parametrize(
    "extra",
    [
        "DOCKER_HOST=unix:///missing.sock",
        "DOCKER_CONTEXT=other",
        "DOCKER_CONTEXT=",
        "DOCKER_CONFIG=/other",
        "PYTHONPATH=/other",
        "UV_PROJECT=/other",
        "MISE_CONFIG_DIR=/other",
        "HTTP_PROXY=http://other:80",
        "PATH=/other",
        "not-an-assignment",
    ],
)
def test_environment_cannot_override_endpoint_or_startup(host: Host, extra: str) -> None:
    host.bridged["Config"]["Env"].append(extra)
    rejected(host)


@pytest.mark.parametrize("fault", ["absent", "missing-host", "wrong-host", "duplicate-host"])
def test_docker_host_is_exact_and_unambiguous(host: Host, fault: str) -> None:
    config = host.bridged["Config"]
    env = config["Env"]
    if fault == "absent":
        del config["Env"]
    elif fault == "duplicate-host":
        env.append("DOCKER_HOST=unix:///var/run/docker.sock")
    else:
        env.remove("DOCKER_HOST=unix:///var/run/docker.sock")
        if fault == "wrong-host":
            env.append("DOCKER_HOST=tcp://other:2375")
    rejected(host)


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("Config", "WorkingDir", "/other"),
        ("Config", "User", "1000"),
        ("Config", "Entrypoint", []),
        ("HostConfig", "NetworkMode", "none"),
        ("HostConfig", "Runtime", "other-runtime"),
        ("HostConfig", "Runtime", None),
        ("HostConfig", "ReadonlyRootfs", True),
        ("HostConfig", "Privileged", True),
        ("HostConfig", "AutoRemove", True),
        ("HostConfig", "Tmpfs", {"/cleanup": "ro"}),
        ("HostConfig", "VolumesFrom", ["other"]),
        ("HostConfig", "Dns", ["192.0.2.1"]),
        ("HostConfig", "ExtraHosts", ["api.cloudflare.com:192.0.2.1"]),
        ("HostConfig", "CapDrop", ["ALL"]),
        ("HostConfig", "SecurityOpt", ["no-new-privileges"]),
        ("HostConfig", "MaskedPaths", ["/cleanup"]),
        ("HostConfig", "MaskedPaths", ["/usr/bin"]),
        ("HostConfig", "ReadonlyPaths", ["/evidence"]),
        ("HostConfig", "ReadonlyPaths", {}),
        ("HostConfig", "Memory", 1),
        ("HostConfig", "NanoCpus", 1),
        ("HostConfig", "CpusetCpus", "999"),
        ("HostConfig", "PidsLimit", 1),
        ("HostConfig", "Ulimits", [{"Name": "nofile", "Soft": 1, "Hard": 1}]),
    ],
)
def test_launch_overrides_cannot_hide_or_disable_cleanup(
    host: Host, section: str, key: str, value: object
) -> None:
    host.bridged[section][key] = value
    rejected(host)


def test_normal_kernel_masks_and_environment_order_do_not_change_contract(host: Host) -> None:
    host.bridged["HostConfig"].update(
        MaskedPaths=[
            *sorted(contract.MASKED_PATHS),
            "/sys/devices/system/cpu/cpu0/thermal_throttle",
        ],
        ReadonlyPaths=sorted(contract.READONLY_PATHS),
    )
    host.bridged["Config"]["Env"].reverse()
    legacy_actors.require_import_readers(
        cast(Docker, host), vault=VAULT, expected="a" * 64, images={IMAGE}
    )


@pytest.mark.parametrize("fault", ["wrong-head", "modified-source", "untracked-module"])
def test_whole_helper_checkout_is_pinned_and_clean(host: Host, fault: str) -> None:
    if fault == "wrong-head":
        host.source_head = "f" * 40
    else:
        host.source_status = (
            b" M scripts/m3_11_unattended/cleanup.py\n"
            if fault == "modified-source"
            else b"?? scripts/m3_11_unattended/json.py\n"
        )
    rejected(host)


@pytest.mark.parametrize("images", [set(), {"sha256:" + "f" * 64}, {IMAGE, "sha256:" + "f" * 64}])
def test_bridge_cannot_self_authorize_its_image(host: Host, images: set[str]) -> None:
    rejected(host, images)


@pytest.mark.parametrize("fault", [None, "other-revision", "diagnostic", "invalid-image", "v1"])
def test_image_authority_comes_from_original_controller_in_v2_import(fault: str | None) -> None:
    actor: dict[str, Any] = {
        "kind": "controller",
        "identity": {"source_revision": bridge.LEGACY_REVISION, "image": IMAGE},
    }
    if fault == "other-revision":
        actor["identity"]["source_revision"] = "f" * 40
    elif fault == "diagnostic":
        actor["kind"] = "retained-diagnostic"
    elif fault == "invalid-image":
        actor["identity"]["image"] = "mutable:latest"
    mapping: dict[str, object] = {
        "format": "lowerduckpond-m3-11-legacy-import-" + ("v1" if fault == "v1" else "v2"),
        "issuers": [{"actor": actor}],
    }
    assert reader_images(mapping) == ({IMAGE} if fault is None else set())
