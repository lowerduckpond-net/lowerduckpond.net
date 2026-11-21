"""Root-side admission and stage checks for the installed qualification adapter."""

from __future__ import annotations

import json
import os
import re
import socket
import stat
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

ROOT = Path("/var/lib/lowerduckpond/convergence/m3-12")
STATIC = Path("/var/lib/lowerduckpond/static")
SELECTION = Path("/opt/lowerduckpond/static-host-agent/current")
PUBLICATION = Path("/etc/lowerduckpond/static-publication.json")
M3_11 = ROOT.parent / "m3-11"
ENROLLMENT = ROOT / "installed-enrollment.json"
MAXIMUM = 256 * 1024
RECORD_MODE = 0o600
STAGES = ("dark-staging", "dark-repeat", "durable-launch", "enabled-convergence", "enabled-repeat")
SHA = re.compile(r"[0-9a-f]{64}", re.ASCII)


def private(path: Path, mode: int = RECORD_MODE) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != mode
            or not 0 < metadata.st_size <= MAXIMUM
        ):
            raise ValueError("installed successor authority is unsafe")
        raw = source.read(MAXIMUM + 1)
    if len(raw) != metadata.st_size:
        raise ValueError("installed successor authority changed")
    return raw


def canonical(document: object) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def enrollment() -> dict[str, Any]:
    metadata = ROOT.lstat()
    marker = Path("/.dockerenv").lstat()
    if (
        os.geteuid() != 0
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700  # noqa: PLR2004 - protected root
        or marker.st_uid != 0
        or not stat.S_ISREG(marker.st_mode)
    ):
        raise ValueError("installed successor requires its owned Docker guest")
    raw = private(ENROLLMENT)
    value = json.loads(raw)
    if (
        type(value) is not dict
        or canonical(value) != raw
        or set(value)
        != {
            "format",
            "hostname",
            "artifact",
            "predecessor",
            "allocation",
            "invocation",
            "candidate",
            "platform",
        }
        or value["format"] != "lowerduckpond-m3-12-installed-enrollment-v1"
        or not all(
            type(value[name]) is str and SHA.fullmatch(value[name])
            for name in ("artifact", "predecessor", "allocation", "candidate", "platform")
        )
        or value["hostname"] != socket.gethostname()
    ):
        raise ValueError("installed successor enrollment changed")
    return dict(value)


def predecessor_digest() -> str:
    """Compare actual root-owned M3.11 records through the historical reader."""
    from scripts import m3_11_production_journal as journal  # noqa: PLC0415
    from scripts import m3_11_production_records as records  # noqa: PLC0415

    raw = records.operate(M3_11, ["read"], b"", owner=0)
    if journal.validate(records.decode(raw))["phase"] != "complete":
        raise ValueError("installed successor requires an accepted M3.11 predecessor")
    return sha256(raw).hexdigest()


def lease_check(token: str) -> None:
    from scripts.m3_11_production_lease import require_action  # noqa: PLC0415

    require_action(Path("/run/lowerduckpond-m3-11/lease"), owner=0, token=token)


def require_stage(raw: bytes, token: str) -> str:
    lease_check(token)
    bound = enrollment()
    if predecessor_digest() != bound["predecessor"]:
        raise ValueError("installed successor predecessor changed")
    request = json.loads(raw)
    phase = None
    for stage in STAGES:
        try:
            claimed = private(ROOT / (stage + ".started"))
        except FileNotFoundError:
            break
        try:
            completed = json.loads(private(ROOT / (stage + ".complete")))
        except FileNotFoundError:
            # Earlier committed work may use its original invocation's lease.
            if claimed != canonical({"lease": sha256(token.encode()).hexdigest(), "stage": stage}):
                raise ValueError("installed successor action lease changed") from None
            phase = stage
            break
        if (
            set(completed) != {"stage", "observationSha256"}
            or completed["stage"] != stage
            or not SHA.fullmatch(completed["observationSha256"])
        ):
            raise ValueError("installed successor completion is invalid")
    if phase is None or phase == "durable-launch":
        raise ValueError("installed successor has no pending converge")
    enabled = phase.startswith("enabled-")
    if canonical(request) != canonical(
        {
            "stage": "converge",
            "artifact_sha256": bound["artifact"],
            "archive_enabled": True,
            "generation_enabled": True,
            "publication_enabled": enabled,
            "reconstruction_enabled": False,
            "recovery_enabled": True,
            "rotation_enabled": True,
        }
    ):
        raise ValueError("installed successor requested a different stage")
    if enabled:
        checked = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import sys;from pathlib import Path;"
                "sys.path.insert(0,'/opt/lowerduckpond/static-host-agent/current/site-packages');"
                "from lowerduckpond_static_host_agent.platform_launch import verify_launch;"
                "receipt=verify_launch(Path('/var/lib/lowerduckpond/static'),"
                "Path('/var/lib/lowerduckpond/convergence/m3-12'));"
                "assert receipt['binding']['targetKind']=='installed-fixture'",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if checked.returncode:
            raise ValueError("installed successor launch scope changed")
    return phase


def launch(token: str, raw: bytes) -> bytes:
    """Check the leased installed enrollment again before the common initializer."""
    from datetime import UTC, datetime  # noqa: PLC0415

    from lowerduckpond_static_host_agent.platform_launch import initialize_launch  # noqa: PLC0415

    from scripts.m3_12_contracts import (  # noqa: PLC0415
        INSTALLED,
        AdmissionContext,
        Evidence,
        digest,
        encode,
        require,
    )

    lease_check(token)
    local = enrollment()
    lease_sha256 = sha256(token.encode()).hexdigest()
    require(
        local["predecessor"] == predecessor_digest()
        and private(ROOT / "durable-launch.started")
        == canonical({"lease": lease_sha256, "stage": "durable-launch"})
        and not json.loads(private(PUBLICATION, 0o400))["static_publication_enabled"],
        "installed-launch-is-not-dark-or-leased",
    )
    for stage in STAGES[:2]:
        receipt = json.loads(private(ROOT / (stage + ".complete")))
        require(
            set(receipt) == {"stage", "observationSha256"}
            and receipt["stage"] == stage
            and SHA.fullmatch(receipt["observationSha256"]) is not None,
            "installed-dark-prerequisites-missing",
        )
    admission = json.loads(raw)
    target = json.loads(private(ROOT / "installed-target.json"))
    allocation = json.loads(private(ROOT / "installed-allocation.json"))
    require(
        target["targetKind"] == INSTALLED
        and target["purpose"] == "installed-test"
        and target["enrollmentSha256"] == digest(local)
        and target["allocationSha256"] == digest(allocation) == local["allocation"]
        and target["docker"] == allocation["docker"]
        and SELECTION.is_symlink()
        and SELECTION.resolve(strict=True) == SELECTION.parent / local["artifact"]
        and not os.path.lexists(ROOT / "revoked"),
        "installed-launch-enrollment-changed",
    )
    records = {}
    for slot, key in admission["prerequisites"].items():
        require(SHA.fullmatch(key) is not None, "invalid-installed-receipt")
        receipt = private(ROOT / ("prerequisite-" + key + ".json"))
        require(sha256(receipt).hexdigest() == key, "invalid-installed-receipt")
        if slot in {"darkStage", "darkRepeat"}:
            stage = STAGES[0 if slot == "darkStage" else 1]
            observation = json.loads(private(ROOT / (stage + ".complete")))
            require(
                json.loads(receipt)["observationSha256"] == observation["observationSha256"],
                "installed-stage-observation-changed",
            )
        records[key] = receipt
    health = subprocess.run(
        ["/usr/local/libexec/lowerduckpond/check-caddy-publication-open"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    require(
        health.returncode == 0 and health.stdout == b"current\n", "installed-generation-invalid"
    )

    def observe() -> AdmissionContext:
        lease_check(token)
        require(enrollment() == local, "installed-launch-enrollment-changed")
        return AdmissionContext(
            now=datetime.now(UTC),
            invocation_id=local["invocation"],
            enrolled_target=target,
            candidate_sha256=local["candidate"],
            platform_sha256=local["platform"],
            authority_sha256=digest(local),
            lease_sha256=lease_sha256,
            run_id=allocation["runId"],
            active_authority=True,
            revoked=os.path.lexists(ROOT / "revoked"),
            tenant_history=False,
            tenant_generation=False,
            unfinished_lifecycle=False,
            production_identifiers=frozenset({"lowerduckpond_production_01"}),
            observed_disposable_identifiers=frozenset({socket.gethostname()}),
        )

    return encode(
        initialize_launch(
            STATIC,
            ROOT,
            encode(admission),
            Evidence(records),
            observe,
        )
    )


def physical(token: str, action: str, *, stop_after_selection: bool = False) -> bytes:
    """Exercise the same physical primitive on the original owned installed guest."""
    from lowerduckpond_static_host_agent.caddy_startup import CaddyStartupStore  # noqa: PLC0415
    from lowerduckpond_static_host_agent.durable import DurableDirectory  # noqa: PLC0415
    from lowerduckpond_static_host_agent.entrypoints import (  # noqa: PLC0415
        _open_caddy_control_runtime,
    )
    from lowerduckpond_static_host_agent.platform_launch import verify_launch  # noqa: PLC0415
    from lowerduckpond_static_host_agent.successor_rollback import PhysicalRollback  # noqa: PLC0415

    from scripts.m3_12_contracts import digest, encode, require  # noqa: PLC0415

    lease_check(token)
    local = enrollment()
    require(
        local["predecessor"] == predecessor_digest()
        and SELECTION.resolve(strict=True) == SELECTION.parent / local["artifact"]
        and os.path.lexists(ROOT / "enabled-repeat.complete")
        and action in {"restore-platform-only", "reactivate-same-policy"}
        and (not stop_after_selection or action == "restore-platform-only"),
        "installed-rollback-enrollment-changed",
    )
    receipt = verify_launch(STATIC, ROOT)
    require(receipt["binding"]["targetKind"] == "installed-fixture", "installed-rollback-purpose")
    predecessor = json.loads(private(ROOT / "preceding-generation.json"))
    decision = {
        "format": "lowerduckpond-m3-12-installed-physical-decision-v1",
        "action": action,
        "authorizationSha256": digest(local),
        "precedingGenerationSha256": predecessor["manifestSha256"],
        "retainedLaunchSha256": receipt["launchRecordSha256"],
        "retainedIntentSha256": receipt["intentSha256"],
    }

    def restart() -> None:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "caddy.service"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )

    with (
        DurableDirectory.open(ROOT, expected_owner=0, expected_directory_mode=0o700) as root,
        _open_caddy_control_runtime() as runtime,
        CaddyStartupStore.open(Path("/etc/caddy/intents"), expected_owner=0) as startup,
    ):
        engine = PhysicalRollback(
            STATIC,
            ROOT,
            PUBLICATION,
            runtime,
            require_lease=lambda: lease_check(token),
            restart=restart,
            startup=startup,
        )
        raw = encode(
            engine.reconcile(
                decision, after_selection=interrupt_installed if stop_after_selection else None
            )
        )
        key = ("installed-" + action + "-effect.json",)
        if not os.path.lexists(ROOT.joinpath(*key)):
            root.create_immutable(key, raw)
        else:
            require(private(ROOT.joinpath(*key)) == raw, "installed-rollback-effect-changed")
        return raw


def interrupt_installed() -> None:
    """Leave the owned test action after the durable selector handoff."""
    raise SystemExit(75)
