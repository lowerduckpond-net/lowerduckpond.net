"""Read whole-bucket readiness before allocating an attempt with a retained lease."""

from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration

from scripts import production_qualification_inputs
from scripts.check_m3_10_provider import PolicyClient, check_storage
from scripts.m3_10_policy_client import make_policy_client
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import canonical_bytes
from scripts.m3_11_unattended import readiness_credentials, reuse_admission
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.docker import EVIDENCE_VOLUME, LEASE_DIRECTORY, Docker
from scripts.m3_11_unattended.model import (
    Credential,
    LifecycleError,
    digest,
    identity,
    instant,
    stamp,
)
from scripts.m3_11_unattended.state import LeaseState, RunState, private_directory
from scripts.m3_11_unattended.watchdog import require_released_consumers
from scripts.provider_preflight_diagnostics import document as failure_document
from scripts.qualification_budget import MINIMUM_TOKEN_REMAINING

FORMAT = "lowerduckpond-m3-11-storage-admission-v1"
# New composed readiness path: retain existing 1200-second daemon read budgets.
# Admit each read only with its whole allowance plus reporting reserve remaining.
# These provisional outer bounds are not renewed and do not extend any approval.
HELPER_SECONDS = 3600
CALLER_SECONDS = HELPER_SECONDS + 120
REPORT_SECONDS = 60
GIT_SECONDS = 60
PROVIDER_SECONDS = 40  # Existing 10-second connect + 30-second read, no retries.
MAX_REQUESTS = 35
_deadline: float | None = None


def require_remaining(seconds: int) -> None:
    if _deadline is None or _deadline - time.monotonic() < seconds + REPORT_SECONDS:
        raise LifecycleError("storage admission lacks time for the next complete read")


class ReadOnlyDocker(Docker):
    def command(self, *arguments: str, stdin: bytes | None = None, timeout: int = 1200) -> bytes:
        if (
            not arguments
            or (
                arguments[0] not in {"info", "inspect", "ps", "context"}
                and arguments != ("volume", "inspect", EVIDENCE_VOLUME)
            )
            or (arguments[0] == "context" and arguments[1:2] != ("inspect",))
            or stdin is not None
        ):
            raise LifecycleError("storage admission attempted a non-read daemon operation")
        require_remaining(timeout)
        return super().command(*arguments, timeout=timeout)


def bounded_git(repository: Path, *arguments: str) -> bytes:
    if not arguments or arguments[0] not in {"rev-parse", "status", "show"}:
        raise LifecycleError("storage admission attempted a non-read source operation")
    require_remaining(GIT_SECONDS)
    executable = shutil.which("git")
    if executable is None:
        raise LifecycleError("storage admission source reader is unavailable")
    try:
        result = subprocess.run(  # noqa: S603 - source-owned read-only Git arguments
            [
                executable,
                "--no-optional-locks",
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(repository),
                *arguments,
            ],
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"},
            capture_output=True,
            timeout=GIT_SECONDS,
            check=False,
        )
    except OSError, subprocess.SubprocessError:
        raise LifecycleError("storage admission source read failed") from None
    if result.returncode:
        raise LifecycleError("storage admission source read failed")
    return result.stdout


@contextmanager
def bounded_helper(*, seconds: int = HELPER_SECONDS) -> Iterator[None]:
    global _deadline  # noqa: PLW0603 - single-use process, restored on exit

    def expired(_signum: int, _frame: object) -> None:
        # A lower layer may catch ordinary exceptions. Exit cannot be retried by
        # an SDK; the parent receives nonzero and never allocates the attempt.
        os._exit(124)

    if (
        type(seconds) is not int
        or not HELPER_SECONDS <= seconds <= 36000  # noqa: PLR2004 - existing job ceiling
        or _deadline is not None
        or signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
        or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
        or signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, [])
    ):
        raise LifecycleError("storage admission cannot establish its nonrenewing bound")
    signal.signal(signal.SIGALRM, expired)
    _deadline = time.monotonic() + seconds
    signal.setitimer(signal.ITIMER_REAL, seconds)
    original_git = production_qualification_inputs.git
    production_qualification_inputs.git = bounded_git
    try:
        yield
    finally:
        production_qualification_inputs.git = original_git
        _deadline = None
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)


@contextmanager
def existing_lock(path: Path) -> Iterator[None]:
    """Lock an original file through a read-only mount, without creating a lease."""
    private_directory(path.parent)
    if path.resolve(strict=True) != path:
        raise LifecycleError("storage admission lock is not canonical")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
            or stat.S_IMODE(value.st_mode) != 0o600  # noqa: PLR2004 - private lock
        ):
            raise LifecycleError("storage admission lock metadata differs")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def observe(  # noqa: PLR0913, PLR0915 - locked validation through allocation
    config: LeaseConfiguration,
    *,
    lease_id: str,
    manifest_sha256: str,
    evidence_root: Path,
    docker: Docker,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    allocate: Callable[[LeaseState, Callable[[], None]], dict[str, object]] | None = None,
    require_unused_custody: bool = False,
) -> dict[str, object]:
    started = time.monotonic()
    lease = LeaseState(evidence_root / "leases" / identity(lease_id))
    with existing_lock(lease.directory / "runtime-use.lock"):
        reuse_admission.require_prior_reservations_released(lease)
        manifest = lease.manifest()
        if (
            manifest.lease_id != lease_id
            or manifest.sha256 != manifest_sha256
            or manifest.targets != config.targets
            or manifest.policy.sha256 != config.approved_policy_sha256
            or not manifest.policy.retain_after_failure
        ):
            raise LifecycleError("storage readiness differs from the approved retained lease")
        operator = next(intent for intent in manifest.intents if intent.role == "operator")
        original_uses = sorted(lease.directory.glob("use-*.json"))
        custody_first_use = (
            not original_uses and (lease.directory / "custody-retirement.json").exists()
        )
        if require_unused_custody and not custody_first_use:
            raise LifecycleError("custody first use requires an unused completed retirement lease")
        if not original_uses and not custody_first_use:
            raise LifecycleError("storage readiness lacks an original released consumer")
        use_digest = digest([read_private(path) for path in original_uses])
        deliveries = {intent.role: lease.credential(intent) for intent in manifest.intents}
        if any(value is None for value in deliveries.values()):
            raise LifecycleError("a retained credential delivery is unavailable")
        credential = cast(Credential, deliveries[operator.role])

        def unchanged() -> None:
            now = clock()
            stopped = lease.issuer_stop()
            if (
                manifest.policy.deadline(instant(manifest.created_at)) - now
                < MINIMUM_TOKEN_REMAINING
                or lease.manifest().sha256 != manifest.sha256
                or any(lease.directory.glob("close-*.json"))
                or stopped is None
                or stopped["retained_roles"] != sorted(intent.role for intent in manifest.intents)
                or instant(stopped["stopped_at"]) > now
                or sorted(lease.directory.glob("use-*.json")) != original_uses
                or digest([read_private(path) for path in original_uses]) != use_digest
                or any(
                    lease.credential(intent) != deliveries[intent.role]
                    or lease.created(intent)
                    != {
                        "intent_sha256": intent.sha256,
                        "credential_id": cast(Credential, deliveries[intent.role]).identifier,
                    }
                    for intent in manifest.intents
                )
            ):
                raise LifecycleError(
                    "retained lease is closing, changed or lacks remaining validity"
                )
            for path in original_uses:
                use = read_private(path)
                attempt = identity(use["attempt_id"])
                state = RunState(evidence_root / "runs" / attempt)
                progress = state.status()
                if (
                    path.name != "use-" + attempt + ".json"
                    or state.cancelled
                    or progress["phase"] != "finished"
                    or progress["qualification"] not in {"failed", "interrupted"}
                    or not lease.released_use(
                        attempt_id=attempt, binding_sha256=str(use["binding_sha256"])
                    )
                ):
                    raise LifecycleError("storage readiness requires every original use released")

        unchanged()
        require_released_consumers(lease, docker)
        target = {
            "region": manifest.targets.region,
            "archive_bucket": manifest.targets.archive_bucket,
        }
        lock_name = hashlib.sha256(canonical_bytes(target)).hexdigest() + ".lock"
        with existing_lock(Path(LEASE_DIRECTORY) / lock_name):
            configuration = ArchiveConfiguration(
                manifest.targets.region,
                manifest.targets.archive_bucket,
                credential.identifier,
                credential.secret,
            )
            client = make_policy_client(configuration)
            requests = 0

            def before_read(_request: object = None, **kwargs: object) -> None:
                nonlocal requests
                if requests >= MAX_REQUESTS:
                    raise LifecycleError("storage readiness exceeded its read bound")
                unchanged()
                require_remaining(PROVIDER_SECONDS)
                requests += 1

            client.meta.events.register("request-created.s3", before_read)  # type: ignore[attr-defined]
            failure = None
            admitted = None
            with readiness_credentials.read_only_requests(unchanged) as credential_reads:
                try:
                    if custody_first_use:
                        from scripts import m3_11_custody_admission as custody  # noqa: PLC0415

                        custody.require_completed(
                            config, lease, evidence_root=evidence_root, docker=docker
                        )
                    final_roles = readiness_credentials.validate_all_roles(
                        config, manifest, lease, clock=clock, guard=unchanged
                    )
                    check_storage(
                        cast(PolicyClient, client), bucket=manifest.targets.archive_bucket
                    )
                    final_roles()
                    unchanged()
                    require_released_consumers(lease, docker)
                except Exception as error:
                    failure = failure_document(error, phase="storage", started=started)
                if failure is None and allocate is not None:
                    # Only the final local commit excludes cleanup. Network reads
                    # cannot hold up unrelated lease reconciliation for an hour.
                    with existing_lock(evidence_root / ".credential-cleanup.lock"):
                        unchanged()
                        require_remaining(REPORT_SECONDS)
                        admitted = allocate(lease, unchanged)
            return {
                "format": FORMAT,
                "lease_id": lease_id,
                "manifest_sha256": manifest.sha256,
                "policy_sha256": manifest.policy.sha256,
                "storage_target_sha256": manifest.targets.storage_digest,
                "helper_revision": config.helper_revision,
                "whole_bucket_empty": failure is None,
                "failure": failure,
                "admitted": admitted,
                "observed_at": stamp(clock()),
                "provider_read_count": requests,
                **credential_reads,
                "elapsed_seconds": time.monotonic() - started,
            }
