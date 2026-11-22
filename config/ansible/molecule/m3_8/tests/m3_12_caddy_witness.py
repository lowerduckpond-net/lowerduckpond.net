"""Supply a distinct, equivalent platform-only selector for the installed rollback."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from uuid import uuid7

from lowerduckpond_static_contracts import decode_json_object
from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_CONFIGURATION_NAME,
    CADDY_ROUTE_METADATA_NAME,
    MAX_CADDY_CONFIGURATION_BYTES,
    MAX_CADDY_ROUTE_METADATA_BYTES,
    CaddyDerivedGenerationPayload,
    PinnedCaddyGeneration,
)
from lowerduckpond_static_host_agent.caddy_runtime import CaddyRuntime
from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore
from lowerduckpond_static_host_agent.entrypoints import _open_caddy_control_runtime
from lowerduckpond_static_host_agent.successor_rollback import PhysicalRollback, _generation

from scripts.m3_12_contracts import Document, require
from scripts.m3_12_installed_root import (
    PUBLICATION,
    ROOT,
    SELECTION,
    STATIC,
    canonical,
    enrollment,
    lease_check,
    predecessor_digest,
    private,
)


def _payload_record(source: PinnedCaddyGeneration, name: str, maximum: int) -> Document:
    descriptor = source.duplicate_payload_descriptor(name)
    try:
        return decode_json_object(os.pread(descriptor, maximum + 1, 0), maximum_bytes=maximum)
    finally:
        os.close(descriptor)


def select_peer(runtime: CaddyRuntime, predecessor: Document, candidate: str) -> bool:
    """Publish through the immutable store under the caller's publication lock."""
    with runtime.open_verified_generation(predecessor["generation"]) as original:
        require(_generation(original, preceding=True) == predecessor, "installed-predecessor-drift")
    with runtime.open_active_verified().generation as source:
        if _generation(source, preceding=True) != predecessor:
            return False  # Ordinary dark staging already gave us a distinct generation.
        payload = CaddyDerivedGenerationPayload(
            source,
            _payload_record(source, CADDY_CONFIGURATION_NAME, MAX_CADDY_CONFIGURATION_BYTES),
            _payload_record(source, CADDY_ROUTE_METADATA_NAME, MAX_CADDY_ROUTE_METADATA_BYTES),
        )
        with runtime._open_generation_store() as store:
            store.admit_candidate(payload, store.list_verified())
            manifest = store.publish(candidate, payload)
            require(manifest.files == source.manifest.files, "installed-peer-payload-changed")
            runtime.select_active(candidate)
            store.prune_unreferenced((predecessor["generation"], candidate))
    return True


def _restart() -> None:
    subprocess.run(
        ["/usr/bin/systemctl", "restart", "caddy.service"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def stage(token: str) -> None:
    lease_check(token)
    local = enrollment()
    require(
        local["predecessor"] == predecessor_digest()
        and SELECTION.resolve(strict=True) == SELECTION.parent / local["artifact"]
        and private(ROOT / "dark-staging.started")
        == canonical({"lease": sha256(token.encode()).hexdigest(), "stage": "dark-staging"})
        and json.loads(private(ROOT / "dark-staging.complete"))["stage"] == "dark-staging"
        and not os.path.lexists(ROOT / "dark-repeat.started")
        and not os.path.lexists(ROOT / "durable-launch.started")
        and not os.path.lexists(STATIC / "platform/launch.json"),
        "installed-peer-requires-dark-staging",
    )
    with (
        _open_caddy_control_runtime() as runtime,
        CaddyStartupStore.open(Path("/etc/caddy/intents"), expected_owner=0) as startup,
    ):
        engine = PhysicalRollback(
            STATIC,
            ROOT,
            PUBLICATION,
            runtime,
            require_lease=lambda: lease_check(token),
            restart=_restart,
            startup=startup,
        )
        with engine.locked():
            require(not engine.gate(), "installed-peer-requires-closed-publication")
            changed = select_peer(
                runtime, json.loads(private(ROOT / "preceding-generation.json")), str(uuid7())
            )
        if changed:
            lease_check(token)
            _restart()


if __name__ == "__main__":
    stage(sys.argv[1])
