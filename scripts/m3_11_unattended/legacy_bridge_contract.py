"""Closed structural contract for the retained host cleanup bridge.

Expected image identities come from reviewed original controller bindings, never
from a mutable tag or the bridge's own declaration. This is not a cleanup receipt.
"""

from __future__ import annotations

import re

from scripts.m3_11_unattended import legacy_import_reader as bridge
from scripts.m3_11_unattended.docker import (
    CLEANUP_VOLUME,
    EVIDENCE_VOLUME,
    SOCKET,
    Docker,
    helper_volume,
)

# Pinned qualification Dockerfile/launch defaults; source socket from the retained
# Coder daemon mount, not the import utility's container-local Docker endpoint.
DAEMON_SOCKET = "/docker-sock/docker.sock"
ENVIRONMENT = {
    "MISE_DATA_DIR": "/opt/mise-data",
    "MISE_CONFIG_DIR": "/opt/mise-config",
    "MISE_YES": "1",
    "MISE_TRUSTED_CONFIG_PATHS": "/opt/qualification-tools:/opt/lifecycle:/work/source",
    "PATH": "/opt/mise-data/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "DOCKER_HOST": "unix://" + SOCKET,
}
ENTRYPOINT = ["/usr/local/bin/mise", "exec", "--"]
# Moby v28.5.1 oci/defaults.go; retain normal kernel masks without allowing a
# custom mask/readonly path to hide config, tools, socket or writable evidence.
MASKED_PATHS = {
    "/proc/asound",
    "/proc/acpi",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
}
READONLY_PATHS = {"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"}


def path_restrictions(host: dict[str, object]) -> bool:
    for key, allowed in (("MaskedPaths", MASKED_PATHS), ("ReadonlyPaths", READONLY_PATHS)):
        values = host.get(key, [])
        if values is None:
            values = []
        if not isinstance(values, list) or any(
            not isinstance(path, str)
            or not (
                path in allowed
                or (
                    key == "MaskedPaths"
                    and re.fullmatch(r"/sys/devices/system/cpu/cpu[0-9]+/thermal_throttle", path)
                )
            )
            for path in values
        ):
            return False
    return True


def source(docker: Docker, container: str) -> bool:
    command = (
        "exec",
        container,
        "/usr/bin/git",
        "--no-optional-locks",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-C",
        "/opt/lifecycle",
    )
    return docker.command(
        *command, "rev-parse", "HEAD"
    ).decode().strip() == bridge.LEGACY_REVISION and not docker.command(
        *command, "status", "--porcelain=v1", "--untracked-files=all"
    )


def images(actors: list[dict[str, object]]) -> set[str]:
    result = set()
    for actor in actors:
        identity = actor.get("identity")
        if actor.get("kind") != "controller" or not isinstance(identity, dict):
            continue
        selected = identity.get("image")
        if (
            identity.get("source_revision") == bridge.LEGACY_REVISION
            and isinstance(selected, str)
            and re.fullmatch(r"sha256:[a-f0-9]{64}", selected)
        ):
            result.add(selected)
    return result


def environment(value: object) -> bool:
    if not isinstance(value, list):
        return False
    observed: dict[str, str] = {}
    for entry in value:
        if not isinstance(entry, str) or "=" not in entry:
            return False
        key, content = entry.split("=", 1)
        if key in observed:
            return False
        observed[key] = content
    # This excludes DOCKER_CONTEXT precedence and Python/uv/mise/proxy overrides.
    return observed == ENVIRONMENT


def configuration(actual: dict[str, object], expected_images: set[str]) -> bool:
    config, host = actual.get("Config"), actual.get("HostConfig")
    if not isinstance(config, dict) or not isinstance(host, dict):
        return False
    return (
        len(expected_images) == 1
        and isinstance(actual.get("Image"), str)
        and actual["Image"] in expected_images
        and config.get("WorkingDir") == "/opt/lifecycle"
        and config.get("User") == ""
        and config.get("Entrypoint") == ENTRYPOINT
        and environment(config.get("Env"))
        and host.get("NetworkMode") == "host"
        and host.get("Runtime") == "runc"
        and all(host.get(key) is False for key in ("ReadonlyRootfs", "Privileged", "AutoRemove"))
        and host.get("Tmpfs") in (None, {})
        and path_restrictions(host)
        and all(
            host.get(key, 0) == 0
            for key in (
                "Memory",
                "MemoryReservation",
                "MemorySwap",
                "NanoCpus",
                "CpuPeriod",
                "CpuQuota",
                "CpuShares",
                "OomScoreAdj",
            )
        )
        and all(host.get(key, "") == "" for key in ("CpusetCpus", "CpusetMems", "UsernsMode"))
        and host.get("PidsLimit") in (None, 0)
        and all(
            host.get(key) in (None, [])
            for key in (
                "VolumesFrom",
                "Dns",
                "DnsOptions",
                "DnsSearch",
                "ExtraHosts",
                "CapAdd",
                "CapDrop",
                "Devices",
                "DeviceRequests",
                "SecurityOpt",
                "Ulimits",
            )
        )
    )


def _whole_volume_mounts(actual: dict[str, object], destinations: set[str]) -> bool:
    # Docker may retain a volume subpath only in the requested mount options.
    # It must not select a different cleanup configuration/evidence subtree.
    host = actual.get("HostConfig")
    if not isinstance(host, dict):
        return False
    requested = host.get("Mounts", [])
    if not isinstance(requested, list):
        return False
    for mount in requested:
        if not isinstance(mount, dict) or not isinstance(mount.get("Target"), str):
            return False
        if mount["Target"] in destinations:
            options = mount.get("VolumeOptions", {})
            if not isinstance(options, dict) or options.get("Subpath") not in (None, ""):
                return False
    return True


def mounts(actual: dict[str, object], bridge_sha256: str) -> bool:
    volumes = {
        "/cleanup": (CLEANUP_VOLUME, False),
        "/evidence": (EVIDENCE_VOLUME, True),
        "/opt/lifecycle": (helper_volume(bridge.LEGACY_REVISION), False),
        "/opt/import-bridge": ("ldp-m311-import-bridge-" + bridge_sha256, False),
    }
    expected = {
        path: {"Type": "volume", "Name": name, "RW": writable}
        for path, (name, writable) in volumes.items()
    }
    expected[SOCKET] = {
        "Type": "bind",
        "Source": DAEMON_SOCKET,
        "RW": True,
        "Propagation": "rprivate",
    }
    observed = actual.get("Mounts")
    if (
        not isinstance(observed, list)
        or len(observed) != len(expected)
        or not _whole_volume_mounts(actual, set(expected))
    ):
        return False
    seen = set()
    for mount in observed:
        if not isinstance(mount, dict) or not isinstance(mount.get("Destination"), str):
            return False
        destination = mount["Destination"]
        # Closed topology also rejects ancestor/descendant overlays of the five
        # roots and extra mounts hiding image tools or startup modules elsewhere.
        if destination not in expected or destination in seen:
            return False
        if (
            not isinstance(mount.get("RW"), bool)
            or any(mount.get(key) != value for key, value in expected[destination].items())
            or mount.get("SubPath") not in (None, "")
        ):
            return False
        seen.add(destination)
    return seen == set(expected)
