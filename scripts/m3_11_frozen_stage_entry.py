"""Exact staged operations; observation can never choose a continuation mode."""

from __future__ import annotations

import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from scripts import production_qualification_inputs as source
from scripts.m3_11_frozen_budget import (
    LOCAL_SECONDS,
    REFRESH_SECONDS,
    REMOTE_SECONDS,
    SNAPSHOT_SECONDS,
)
from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_disposal import LocalDocker, NativeLocal
from scripts.m3_11_frozen_entry import ACK_SECONDS, LocalProof, emit
from scripts.m3_11_frozen_frames import frame
from scripts.m3_11_frozen_remote import NativeRemote
from scripts.m3_11_frozen_retirement import require_supported_closeout
from scripts.m3_11_frozen_terminal import snapshot
from scripts.m3_11_frozen_transport import STAGED_MUTATIONS, STAGED_OBSERVATIONS
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import digest
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import OWNER, controller_name
from scripts.m3_11_unattended.model import identity, instant
from scripts.m3_11_unattended.state import LeaseState
from scripts.m3_11_unattended.storage_admission import (
    ReadOnlyDocker,
    bounded_helper,
    existing_lock,
    require_remaining,
)


class CopyProof:
    def __init__(self, expected: str) -> None:
        self.expected = expected

    def __call__(self) -> str:
        require_remaining(ACK_SECONDS)
        nonce = str(uuid.uuid7())
        emit(
            {
                "operation": "revalidate-preserved-files",
                "nonce": nonce,
                "evidence_sha256": self.expected,
            }
        )
        value = fields(
            frame(sys.stdin.buffer, deadline=time.monotonic() + ACK_SECONDS),
            {"nonce", "status", "evidence_sha256", "observed_at"},
        )
        now = datetime.now(UTC)
        require(
            value["nonce"] == nonce
            and value["evidence_sha256"] == self.expected
            and value["status"] == "native-preserved-files-verified"
            and now - timedelta(seconds=ACK_SECONDS) <= instant(value["observed_at"]) <= now,
            "local disposal native preserved-copy verification differs",
        )
        return self.expected


def terminal_provenance(
    selected: dict[str, object], root: Path, docker: ReadOnlyDocker
) -> dict[str, object]:
    """Reinspect the exact original controller inside the locked native call."""
    attempt = root / "runs" / identity(selected["consumer_attempt"])
    request = read_private(attempt / "request.json")
    binding = fields(request["binding"], set(cast(dict[str, object], request["binding"])))
    lease = LeaseState(root / "leases" / identity(selected["lease_id"]))
    retained = fields(selected["controller_identity"], {"id", "image", "name", "daemon_sha256"})
    native = docker.owned(controller_name(attempt.name))
    config = cast(dict[str, object], native.get("Config", {}))
    labels = cast(dict[str, object], config.get("Labels", {}))
    state = cast(dict[str, object], native.get("State", {}))
    require(
        digest(request) == selected["request_sha256"]
        and digest(binding) == selected["consumer_binding"]
        and request["lease_id"] == selected["lease_id"]
        and request["mode"] == "qualification"
        and binding["managed_run_id"] == attempt.name
        and binding["source_revision"] == selected["runtime_revision"]
        and binding["helper_revision"] == selected["helper_revision"]
        and read_private(attempt / "controller-identity.json") == retained
        and read_private(attempt / "attempt.json")["binding"] == binding
        and read_private(attempt / "attempt-started.json")
        == {
            "binding_sha256": selected["consumer_binding"],
            "manifest_sha256": selected["manifest_sha256"],
        }
        and read_private(lease.directory / ("use-" + attempt.name + ".json"))
        == {
            "attempt_id": attempt.name,
            "binding_sha256": selected["consumer_binding"],
            "kind": "attempt",
        }
        and docker.info() == request["daemon"]
        and digest(request["daemon"]) == retained["daemon_sha256"]
        and native.get("Id") == retained["id"]
        and native.get("Image") == retained["image"] == request["controller_image"]
        and native.get("Name") == retained["name"] == "/" + controller_name(attempt.name)
        and labels.get(OWNER) == "true"
        and labels.get(OWNER + ".source") == selected["helper_revision"]
        and state.get("Running") is True,
        "terminal reader original controller, daemon, request or use binding differs",
    )
    return {
        "controller_identity": retained,
        "request_sha256": digest(request),
        "consumer_binding": digest(binding),
    }


def terminal_snapshot(payload: object) -> None:
    value = fields(
        payload,
        {"plan", "authorization", "fixture", "runtime_revision", "operation", "bundle_sha256"},
    )
    selected = fields(
        value["plan"],
        {
            "format",
            "implementation_revision",
            "lease_id",
            "manifest_sha256",
            "consumer_attempt",
            "controller_identity",
            "request_sha256",
            "consumer_binding",
            "runtime_revision",
            "helper_revision",
        },
    )
    require(
        value["operation"] == "terminal-snapshot"
        and selected["format"] == "lowerduckpond-m3-11-terminal-snapshot-plan-v1"
        and value["authorization"] == {}
        and value["fixture"] == {},
        "terminal snapshot operation differs",
    )
    with bounded_helper(seconds=SNAPSHOT_SECONDS):
        require(
            value["runtime_revision"] == selected["runtime_revision"],
            "terminal runtime source differs",
        )
        source.current_candidate(Path("/work/source"), str(value["runtime_revision"]))
        root = Path("/evidence")
        lease = LeaseState(root / "leases" / identity(selected["lease_id"]))
        with (
            existing_lock(
                root / "runs" / identity(selected["consumer_attempt"]) / "controller.lock"
            ),
            existing_lock(lease.directory / "runtime-use.lock"),
        ):
            require(
                lease.manifest().sha256 == selected["manifest_sha256"],
                "terminal snapshot manifest differs",
            )
            provenance = terminal_provenance(selected, root, ReadOnlyDocker())
            result = snapshot(
                LeaseConfiguration.load(Path("/configuration/controller.json")), lease
            )
            emit(
                {
                    "status": "observed-terminal-facts",
                    "snapshot": result,
                    "plan_sha256": digest(selected),
                    "bundle_sha256": value["bundle_sha256"],
                    "provenance": provenance,
                }
            )


def run(value: dict[str, object]) -> None:
    operation = str(value["operation"])
    require(operation in STAGED_MUTATIONS | STAGED_OBSERVATIONS, "staged operation is unknown")
    if operation in STAGED_MUTATIONS:
        require_supported_closeout()
    plan = cast(dict[str, object], value["plan"])
    retired = cast(dict[str, object], plan["retirement_plan"])
    require(value["fixture"] == plan["fixture"], "staged outer fixture binding differs")
    started = time.monotonic()
    seconds = REMOTE_SECONDS if operation.startswith("remote-") else LOCAL_SECONDS
    with bounded_helper(seconds=seconds):
        source.current_candidate(Path("/work/source"), str(value["runtime_revision"]))
        if operation.startswith("remote-"):
            proof = LocalProof(str(retired["evidence_sha256"]), ack_seconds=REFRESH_SECONDS)
            proof()
            remote = NativeRemote(
                configuration=LeaseConfiguration.load(Path("/configuration/controller.json")),
                fixture=cast(dict[str, object], value["fixture"]),
                evidence_root=Path("/evidence"),
                revalidate_copies_and_cleanup=proof,
                docker=ReadOnlyDocker(),
                require_cleanup_current=proof.current,
                refresh_cleanup=proof.refresh_if_needed,
                observation_only=operation == "remote-observe",
            )
            handler = {
                "remote-cleanup": remote.execute,
                "remote-continue": remote.continue_unsubmitted,
                "remote-observe": remote.reconcile,
            }[operation]
            result = handler(plan, value["authorization"])
            deletes, reads = remote.deletes, remote.reads
        else:
            local = NativeLocal(
                evidence_root=Path("/evidence"),
                docker=LocalDocker(),
                revalidate_copies=CopyProof(str(retired["evidence_sha256"])),
            )
            result = (
                local.execute(plan, value["authorization"])
                if operation == "local-disposal"
                else local.reconcile(
                    plan, value["authorization"], continue_unsubmitted=operation == "local-continue"
                )
            )
            deletes = reads = 0
        emit(
            {
                "status": "observed" if operation in STAGED_OBSERVATIONS else "verified",
                "operation": operation,
                "result": result,
                "elapsed_seconds": time.monotonic() - started,
                "provider_delete_submissions": deletes,
                "provider_inventory_owner_reads": reads,
            }
        )
