"""One existing-controller exec with bounded frames and retained uncertainty.

The reviewed private caller supplies the exact program, explicit later approval,
controller binding and full native copy/cleanup verifier. Re-entry into the same
output directory never submits an exec again. Reconciliation requires a separate
program whose sealed operation is read-only; there is no automatic callback.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

from scripts import m3_11_frozen_budget as stage_budget
from scripts import m3_11_frozen_stage_receipt as receipts
from scripts.m3_11_frozen_context import MAX_READS
from scripts.m3_11_frozen_entry import ACK_SECONDS
from scripts.m3_11_frozen_frames import frame, send
from scripts.m3_11_frozen_retirement import (
    FORMAT,
    OBSERVATION,
    RETAINED,
    fingerprint,
    reserve,
)
from scripts.m3_11_frozen_transport import (
    STAGED_MUTATIONS,
    STAGED_OBSERVATIONS,
    STARTUP_SECONDS,
    require_operation,
)
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_retirement_files import RetirementError, digest, directory, record, sync
from scripts.m3_11_unattended.storage_admission import HELPER_SECONDS

MAX_FRAMES = 16
CALLER_SECONDS = 6000  # Preserve the reviewed full local-evidence transaction allowance.


def terminal(
    value: dict[str, object], authorization: dict[str, object], *, observation_only: bool = False
) -> None:
    """An exit-zero/status word is not evidence of the exact approved outcome."""
    outer = fields(
        value,
        {
            "status",
            "retirement",
            "elapsed_seconds",
            "provider_delete_submissions",
            "provider_inventory_owner_reads",
        },
    )
    if observation_only:
        observation(outer, authorization)
        return
    receipt = fields(
        outer["retirement"],
        {
            "format",
            "outcome",
            "plan_sha256",
            "authorization_sha256",
            "absence_sha256",
            "versions_retired",
            "qualification_authority",
            "fixture_execution",
            "fixture_disposal",
            "original_tenant_job_audit_unchanged",
            "retained",
            "lease_released",
            "credential_cleanup_complete",
        },
    )
    fingerprint(receipt["absence_sha256"])
    expected = {
        "format": FORMAT,
        "outcome": "exact-version-retired-frozen-fixture-retained",
        "plan_sha256": authorization["plan_sha256"],
        "authorization_sha256": digest(authorization),
        "absence_sha256": receipt["absence_sha256"],
        "versions_retired": 1,
        "qualification_authority": "none",
        "fixture_execution": "permanently-excluded",
        "fixture_disposal": "separately-authorized-closeout-required",
        "original_tenant_job_audit_unchanged": True,
        "retained": RETAINED,
        "lease_released": False,
        "credential_cleanup_complete": False,
    }
    if (
        outer["status"] != "verified"
        or digest(receipt) != digest(expected)
        or type(outer["elapsed_seconds"]) not in (float, int)
        or not math.isfinite(float(cast(float, outer["elapsed_seconds"])))
        or not 0 <= float(cast(float, outer["elapsed_seconds"])) < HELPER_SECONDS
        or type(outer["provider_delete_submissions"]) is not int
        or outer["provider_delete_submissions"] != 1
        or type(outer["provider_inventory_owner_reads"]) is not int
        or not 0 < outer["provider_inventory_owner_reads"] <= MAX_READS
    ):
        raise RetirementError("retirement terminal receipt differs from exact authorization")


def observation(outer: dict[str, object], authorization: dict[str, object]) -> None:
    """Absence is observation, never a newly manufactured completion receipt."""
    receipt = fields(
        outer["retirement"],
        {
            "format",
            "plan_sha256",
            "authorization_sha256",
            "observed_at",
            "version_state",
            "recorded_retirement",
            "qualification_authority",
            "lease_released",
            "credential_cleanup_complete",
        },
    )
    observed = datetime.fromisoformat(str(receipt["observed_at"]))
    approved = datetime.fromisoformat(str(authorization["approved_at"]))
    if (
        outer["status"] != "observed"
        or receipt["format"] != OBSERVATION
        or receipt["plan_sha256"] != authorization["plan_sha256"]
        or receipt["authorization_sha256"] != digest(authorization)
        or observed.tzinfo is None
        or approved.tzinfo is None
        or not approved <= observed <= datetime.now(UTC)
        or receipt["version_state"] not in {"absent", "present"}
        or type(receipt["recorded_retirement"]) is not bool
        or (receipt["recorded_retirement"] and receipt["version_state"] != "absent")
        or receipt["qualification_authority"] != "none"
        or receipt["lease_released"] is not False
        or receipt["credential_cleanup_complete"] is not False
        or type(outer["elapsed_seconds"]) not in (float, int)
        or not math.isfinite(float(cast(float, outer["elapsed_seconds"])))
        or not 0 <= float(cast(float, outer["elapsed_seconds"])) < HELPER_SECONDS
        or type(outer["provider_delete_submissions"]) is not int
        or outer["provider_delete_submissions"] != 0
        or type(outer["provider_inventory_owner_reads"]) is not int
        or not 0 < outer["provider_inventory_owner_reads"] <= MAX_READS
    ):
        raise RetirementError("retirement observation differs from its read-only contract")


def stage_terminal(
    value: dict[str, object],
    approved: dict[str, object],
    *,
    operation: str,
    plan: dict[str, object],
) -> None:
    outer = fields(
        value,
        {
            "status",
            "operation",
            "result",
            "elapsed_seconds",
            "provider_delete_submissions",
            "provider_inventory_owner_reads",
        },
    )
    observing = operation in STAGED_OBSERVATIONS
    local = operation.startswith("local-")
    seconds = stage_budget.LOCAL_SECONDS if local else stage_budget.REMOTE_SECONDS
    result = outer["result"]
    if (
        not isinstance(result, dict)
        or outer["operation"] != operation
        or outer["status"] != ("observed" if observing else "verified")
        or result.get("plan_sha256") != approved.get("plan_sha256")
        or result.get("authorization_sha256") != digest(approved)
        or type(outer["elapsed_seconds"]) not in (float, int)
        or not math.isfinite(float(cast(float, outer["elapsed_seconds"])))
        or not 0 <= float(cast(float, outer["elapsed_seconds"])) < seconds
        or type(outer["provider_delete_submissions"]) is not int
        or type(outer["provider_inventory_owner_reads"]) is not int
    ):
        raise RetirementError("staged result differs from exact operation/authority/budget")
    if local:
        receipts.local(result, plan, observing=observing)
        if (
            outer["provider_delete_submissions"] != 0
            or outer["provider_inventory_owner_reads"] != 0
            or result.get("provider_calls") != 0
        ):
            raise RetirementError("local staged result performed provider operations")
        if not observing and (
            result.get("original_directory") != "absent"
            or result.get("qualification_changed") is not False
            or result.get("lease_changed") is not False
        ):
            raise RetirementError(
                "local staged disposal is incomplete or changed original semantics"
            )
    elif (
        result.get("archive_delete_submissions") != 0
        or result.get("credential_mutations") != 0
        or result.get("actors_retained") is not True
        or result.get("lease_released") is not False
        or not 0 < outer["provider_inventory_owner_reads"] <= stage_budget.MAX_PROVIDER_REQUESTS
        or not (
            outer["provider_delete_submissions"] == 0
            if observing
            else (0 if operation == "remote-continue" else 1)
            <= outer["provider_delete_submissions"]
            <= stage_budget.MAX_PROVIDER_REQUESTS
        )
    ):
        raise RetirementError("remote staged result exceeded its exact mutation scope")
    if not local:
        receipts.remote(result, plan, observing=observing)
    if observing and (
        result.get("mutation_submissions") != 0 or result.get("no_replay") is not True
    ):
        raise RetirementError("staged observation attempted effects or replay")


def execute(  # noqa: PLR0912,PLR0913,PLR0915 - one bounded submission and protocol transaction
    *,
    program: str,
    bundle: str,
    authorization: dict[str, object],
    controller: str,
    environment: dict[str, str],
    output: Path,
    verify: Callable[[], dict[str, object]],
    caller_started: float | None = None,
    observation_only: bool = False,
    stage_operation: str | None = None,
) -> dict[str, object]:
    now = time.monotonic()
    started = now if caller_started is None else caller_started
    if not math.isfinite(started) or not 0 <= started <= now:
        raise RetirementError("retirement caller clock is invalid")
    staged = stage_operation is not None
    if staged and (
        stage_operation not in STAGED_MUTATIONS | STAGED_OBSERVATIONS or observation_only
    ):
        raise RetirementError("staged operation must be explicit without a competing mode")
    operation = stage_operation or ("reconcile" if observation_only else "execute")
    observing = operation in STAGED_OBSERVATIONS or observation_only
    helper_seconds = (
        (
            stage_budget.REMOTE_SECONDS
            if operation.startswith("remote-")
            else stage_budget.LOCAL_SECONDS
        )
        if staged
        else HELPER_SECONDS
    )
    deadline = started + (stage_budget.CALLER_SECONDS if staged else CALLER_SECONDS)
    if now >= deadline:
        raise TimeoutError("retirement enclosing caller allowance already ended")
    if type(observation_only) is not bool:
        raise RetirementError("retirement observation mode must be explicit")
    bound = require_operation(
        program,
        bundle,
        operation=operation,
        plan_sha256=authorization.get("plan_sha256"),
    )
    if re.fullmatch(r"[0-9a-f]{64}", controller) is None:
        raise RetirementError("retirement controller identity is invalid")
    if not environment.get("DOCKER_HOST", "").startswith("unix:///") or environment.get(
        "DOCKER_CONTEXT"
    ):
        raise RetirementError("retirement requires its bound local daemon endpoint")
    directory(output.parent)
    output.mkdir(mode=0o700)  # A lost parent never silently adopts an old submission.
    sync(output.parent)
    verify()  # No exec and no reservation if local prerequisites already fail.
    if deadline - time.monotonic() < helper_seconds + STARTUP_SECONDS + 120:
        raise TimeoutError("retirement lacks the whole child and reporting allowance")
    reserve(
        output / "exec-submitted.json",
        {
            "controller": controller,
            "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
            "bundle_sha256": hashlib.sha256(bundle.encode()).hexdigest(),
            "authorization_sha256": hashlib.sha256(
                json.dumps(authorization, sort_keys=True).encode()
            ).hexdigest(),
            "maximum_submissions": 1,
        },
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        descriptor = os.open(
            output / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as stderr:
            if deadline - time.monotonic() < helper_seconds + STARTUP_SECONDS + 120:
                raise TimeoutError("retirement pre-exec reserve ended; do not replay")
            process = subprocess.Popen(  # noqa: S603 - fixed executable, reviewed program, no shell
                [  # noqa: S607 - existing supported Docker CLI, no shell
                    "docker",
                    "exec",
                    "-i",
                    "-w",
                    "/work/source",
                    controller,
                    "uv",
                    "run",
                    "--no-sync",
                    "--frozen",
                    "python",
                    "-I",
                    "-B",
                    "-c",
                    program,
                ],
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr,
                bufsize=0,
            )
            incoming, outgoing = cast(BinaryIO, process.stdout), cast(BinaryIO, process.stdin)
            send(outgoing, {"bundle": bundle, "authorization": authorization}, deadline=deadline)
            for sequence in range(64 if staged else MAX_FRAMES):
                value = frame(incoming, deadline=deadline)
                record(output / f"remote-{sequence:02d}.json", value)
                if value.get("operation") in {
                    "revalidate-preserved-files-and-cleanup",
                    "revalidate-preserved-files",
                }:
                    exchange = (
                        stage_budget.REFRESH_SECONDS
                        if operation.startswith("remote-")
                        else ACK_SECONDS
                    )
                    if deadline - time.monotonic() < exchange + 120:
                        raise TimeoutError("retirement lacks full native verification reserve")
                    proof = verify()
                    if proof.get("evidence_sha256") != value.get("evidence_sha256"):
                        raise RetirementError("retirement local evidence binding differs")
                    send(outgoing, {**proof, "nonce": value["nonce"]}, deadline=deadline)
                    continue
                outgoing.close()
                status = process.wait(timeout=max(0.1, min(120, deadline - time.monotonic())))
                expected_status = "observed" if observing else "verified"
                if value.get("status") != expected_status or status != 0:
                    raise RetirementError("retirement child has an unresolved outcome")
                if staged:
                    stage_terminal(
                        value,
                        authorization,
                        operation=operation,
                        plan=cast(dict[str, object], bound["plan"]),
                    )
                else:
                    terminal(value, authorization, observation_only=observation_only)
                record(
                    output / "verified.json",
                    {
                        "result": value,
                        "caller_wall_seconds": time.monotonic() - started,
                        "exec_submissions": 1,
                        "automatic_retry": False,
                    },
                )
                return value
            raise RetirementError("retirement child exceeded its exchange bound")
    except BaseException:
        record(
            output / "unresolved.json",
            {
                "status": "unresolved",
                "caller_wall_seconds": time.monotonic() - started,
                "exec_submissions": 1,
                "no_replay": True,
            },
        )
        raise
    finally:
        if process is not None:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            # This ends only the local observation process, never the daemon
            # helper. The helper's own nonrenewing deadline remains in force.
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            if process.stdout is not None:
                process.stdout.close()
