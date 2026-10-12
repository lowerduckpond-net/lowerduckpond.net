"""Detached, single-attempt execution of the existing M3.11 command."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import qualification_allocation, qualification_deadline
from scripts.m3_10_qualification_report import verify_report
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import cleanup, inputs, production
from scripts.m3_11_unattended.config import LeaseConfiguration
from scripts.m3_11_unattended.connect_diagnostics import retain_failure
from scripts.m3_11_unattended.creation_outcome import (
    restore_aborted,
)
from scripts.m3_11_unattended.docker import OWNER, SOCKET, Docker, controller_name
from scripts.m3_11_unattended.inventory import (
    ConnectInventory,
    fact,
    require_clear,
    require_confirmation,
)
from scripts.m3_11_unattended.journal import event, validate
from scripts.m3_11_unattended.lifecycle import (
    LeaseLifecycle,
    Lifecycle,
    fixture_scopes,
    identifier,
    intents,
    known_id,
    lease_manifest,
)
from scripts.m3_11_unattended.model import (
    Credential,
    Intent,
    LifecycleError,
    digest,
    identity,
    instant,
    stamp,
    strings,
)
from scripts.m3_11_unattended.state import (
    LeaseState,
    RunState,
    cleanup_lock,
    private_directory,
)
from scripts.production_qualification_inputs import current_candidate, fingerprint, revision

SECRETS = {
    "archive": ("SPACES_ARCHIVE_ACCESS_KEY_ID", "SPACES_ARCHIVE_SECRET_ACCESS_KEY"),
    "backup": ("SPACES_BACKUP_ACCESS_KEY_ID", "SPACES_BACKUP_SECRET_ACCESS_KEY"),
    "operator": ("SPACES_ACCESS_KEY_ID", "SPACES_SECRET_ACCESS_KEY"),
    "caddy": (None, "CADDY_CLOUDFLARE_API_TOKEN"),
    "observer": (None, "CLOUDFLARE_API_TOKEN"),
    "audit": (None, "M3_10_TOKEN_AUDIT_TOKEN"),
    "page-rules": (None, "M3_10_PAGE_RULES_TOKEN"),
}


def executing_group(group: int) -> bool:
    """Observe the owned Linux group, including a supervisor orphaned by just/uv."""
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            # comm may contain spaces or parentheses; fields after its final
            # delimiter begin with state, parent PID, process group.
            fields = (process / "stat").read_bytes().rsplit(b") ", 1)[1].split()
        except FileNotFoundError, ProcessLookupError:
            continue
        if int(fields[2]) == group and fields[0] not in {b"Z", b"X"}:
            return True
    return False


def safe_environment() -> dict[str, str]:
    return {
        key: os.environ[key]
        for key in (
            "PATH",
            "HOME",
            "TMPDIR",
            "SSL_CERT_FILE",
            "MISE_DATA_DIR",
            "MISE_CONFIG_DIR",
            "MISE_TRUSTED_CONFIG_PATHS",
        )
        if key in os.environ
    }


def retained_credentials(directory: Path) -> dict[str, Credential]:
    values: dict[str, Credential] = {}
    for path in sorted((directory / "credential-cleanup").glob("*.json")):
        value = fields(read_private(path), {"intent_sha256", "identifier", "secret"})
        record = strings(value)
        if path.stem != record["intent_sha256"]:
            raise LifecycleError("retained credential identity changed")
        values[record["intent_sha256"]] = Credential(record["identifier"], record["secret"], {})
    return values


def restore_created(lifecycle: Lifecycle, directory: Path, *, run_id: str) -> None:
    """Recover exact private creation receipts before cleanup evaluates ownership."""
    owned = {
        intent.sha256: intent for intent in intents(lifecycle.journal) if intent.run_id == run_id
    }
    for path in sorted((directory / "credential-created").glob("*.json")):
        record = validate(read_private(path))
        payload = fields(record["payload"], {"intent_sha256", "credential_id"})
        if (
            record["kind"] != "created"
            or record["run_id"] != run_id
            or payload["intent_sha256"] != path.stem
            or path.stem not in owned
        ):
            raise LifecycleError("retained creation record has no matching obligation")
        selected = identifier(payload["credential_id"])
        if known_id(lifecycle.journal, owned[path.stem]) not in (None, selected):
            raise LifecycleError("retained creation identity conflicts with its obligation")
        lifecycle.journal.persist(record)
    # Never synthesize an outcome during recovery. Only transport an original
    # execution's immutable attestation, after all retained IDs are restored.
    restore_aborted(lifecycle.journal, directory, run_id=run_id)


def persist_terminal_result(lifecycle: Lifecycle, directory: Path) -> None:
    """Do not publish closure until the exact terminal event is independently durable."""
    state = RunState(directory)
    request = read_private(directory / "request.json")
    binding = fields(request["binding"], inputs.BINDING)
    if read_private(directory / "attempt.json")["binding"] != binding:
        raise LifecycleError("terminal result differs from the original attempt binding")
    run_id = identity(binding["managed_run_id"])
    status = state.status()
    expected = {
        **status,
        "binding": binding,
        "approval_sha256": request["approval_sha256"],
        "phase": "finished",
        "credential_cleanup": "verified",
        "closure": "complete" if status["qualification"] == "passed" else "unresolved",
    }
    records = [
        record
        for record in lifecycle.journal.records()
        if record["kind"] == "result" and record["run_id"] == run_id
    ]
    path = directory / "terminal-journal-event.json"
    original = (
        read_private(path)
        if path.exists()
        else (records[0] if len(records) == 1 else event("result", run_id, expected))
    )
    payload = original.get("payload")
    if (
        len(records) > 1
        or (records and records != [original])
        or original.get("kind") != "result"
        or original.get("run_id") != run_id
        or not isinstance(payload, dict)
        or {key: value for key, value in payload.items() if key != "observed_at"}
        != {key: value for key, value in expected.items() if key != "observed_at"}
    ):
        raise LifecycleError("terminal journal event changed or is ambiguous")
    if not path.exists():
        write_private(path, original)
    lifecycle.journal.persist(original)


class Worker:
    def __init__(self, directory: Path, config: LeaseConfiguration, source: Path) -> None:
        self.state, self.config, self.source = RunState(directory), config, source
        self.request = fields(
            read_private(directory / "request.json"),
            {
                "format",
                "binding",
                "mode",
                "approval_sha256",
                "controller_image",
                "daemon",
                "lease_id",
            },
        )
        self.binding = fields(self.request["binding"], inputs.BINDING)
        self.run_id = identity(self.binding["managed_run_id"])
        self.helper = revision(self.binding["helper_revision"])
        self.revision = revision(self.binding["source_revision"])
        self.directory = directory
        self.pending = qualification_deadline.Interruption()
        self.ends_at = time.monotonic() + qualification_deadline.LIVE_SECONDS
        if config.mode != "controller":
            raise LifecycleError("cleanup-only configuration cannot launch qualification")
        self.lease_id = identity(self.request["lease_id"])
        self.lease_state = LeaseState(directory.parent.parent / "leases" / self.lease_id)
        self.lifecycle: LeaseLifecycle | None = None
        self.inventory: ConnectInventory | None = None
        self.attempt_started = False

    @property
    def owns_lease(self) -> bool:
        """Issuance ancestry does not restore released runtime ownership."""
        directory = self.lease_state.directory
        if (directory / ("released-" + self.run_id + ".json")).exists():
            return False
        uses = list(directory.glob("use-*.json"))
        own = directory / ("use-" + self.run_id + ".json")
        if own in uses:
            return read_private(own) == {
                "attempt_id": self.run_id,
                "binding_sha256": digest(self.binding),
                "kind": "attempt",
            } and not any(
                path != own
                and not (
                    directory / ("released-" + path.stem.removeprefix("use-") + ".json")
                ).exists()
                for path in uses
            )
        # The original issuer owns preparation failures until a runtime consumer
        # has acquired the lease. It cannot inherit another consumer's authority.
        return self.lease_id == self.run_id and not uses

    def check_cancelled(self) -> None:
        if self.state.cancelled or self.state.stopped or self.pending.signum is not None:
            raise LifecycleError("qualification was cancelled")
        if time.monotonic() >= self.ends_at:
            raise LifecycleError("qualification exceeded its original 600-minute ceiling")

    def remember(self, intent: Intent, credential: Credential) -> None:
        write_private(
            self.directory / "credential-cleanup" / (intent.sha256 + ".json"),
            {
                "intent_sha256": intent.sha256,
                "identifier": credential.identifier,
                "secret": credential.secret,
            },
        )

    def _failure(self, error: Exception, *, cleanup_failed: bool = False) -> None:
        try:
            retain_failure(
                self.directory
                / ("cleanup-failure.json" if cleanup_failed else "worker-failure.json"),
                binding=self.binding,
                stage=str(self.state.status()["phase"]),
                error=error,
            )
        except Exception:
            return  # Diagnostics never change the terminal cleanup path.

    def remember_intent(self, intent: Intent) -> None:
        write_private(
            self.directory / "credential-intents" / (intent.sha256 + ".json"), intent.document()
        )

    def remember_created(self, intent: Intent, record: dict[str, object]) -> None:
        directory = self.directory / "credential-created"
        directory.mkdir(mode=0o700, exist_ok=True)
        private_directory(directory)
        path = directory / (intent.sha256 + ".json")
        if not path.exists():
            write_private(path, record)
        if read_private(path) != record:
            raise LifecycleError("retained creation identity changed")

    def _verify_source(self) -> None:
        helper_root = Path(__file__).resolve().parents[2]
        current_candidate(helper_root, self.helper)
        current_candidate(self.source, self.revision)
        if (
            fingerprint(self.source, self.revision) != self.binding["qualification_inputs_sha256"]
            or self.config.targets.storage_digest != self.binding["storage_target_sha256"]
        ):
            raise LifecycleError("controller source or storage target changed")
        if self.request["format"] != "lowerduckpond-m3-11-unattended-request-v2" or self.request[
            "mode"
        ] not in {"rehearsal", "qualification"}:
            raise LifecycleError("controller request is invalid")
        artifact = (
            self.directory.parent.parent / "prepared" / self.revision / "static-host-agent.tar"
        )
        with artifact.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != self.binding["artifact_sha256"]:
                raise LifecycleError("prepared artifact differs from live approval")

    def _verify_daemon(self) -> None:
        docker = Docker()
        if docker.endpoint != "unix://" + SOCKET or docker.info() != self.request["daemon"]:
            raise LifecycleError("controller socket does not reach the approved Docker host")
        selected = docker.owned(controller_name(self.run_id))
        labels = selected.get("Config", {})
        if (
            selected.get("Name") != "/" + controller_name(self.run_id)
            or selected.get("Image") != self.request["controller_image"]
            or not isinstance(labels, dict)
            or not isinstance(labels.get("Labels"), dict)
            or labels["Labels"].get(OWNER + ".source") != self.helper
        ):
            raise LifecycleError("controller identity differs from the approved attempt")
        proof = {
            "id": selected["Id"],
            "image": selected["Image"],
            "name": selected["Name"],
            "daemon_sha256": digest(self.request["daemon"]),
        }
        path = self.directory / "controller-identity.json"
        if not path.exists():
            write_private(path, proof)
        if read_private(path) != proof:
            raise LifecycleError("restored attempt cannot adopt another controller")

    def _command(
        self,
        command: list[str],
        *,
        log: str,
        stdin: bytes | None = None,
        environment: dict[str, str] | None = None,
        seconds: int = 1500,
    ) -> None:
        self.check_cancelled()
        with (self.directory / log).open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            child = subprocess.Popen(  # noqa: S603 - fixed, pinned qualification helper commands
                command,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                cwd=self.source,
                env=environment or safe_environment(),
                stdout=stream,
                stderr=stream,
                start_new_session=True,
            )
            deadline = min(time.monotonic() + seconds, self.ends_at)
            first = True
            try:
                while True:
                    self.check_cancelled()
                    if time.monotonic() >= deadline:
                        raise LifecycleError("bounded preparation exceeded its deadline")
                    try:
                        child.communicate(input=stdin if first else None, timeout=1)
                        break
                    except subprocess.TimeoutExpired:
                        first = False
            finally:
                qualification_deadline._kill_group(child, signal.SIGTERM)
                try:
                    child.wait(timeout=qualification_deadline.GRACE_SECONDS)
                except subprocess.TimeoutExpired:
                    qualification_deadline._kill_group(child, signal.SIGKILL)
                    child.wait(timeout=qualification_deadline.GRACE_SECONDS)
        if child.returncode:
            raise LifecycleError(
                "bounded qualification preparation failed; private evidence retained"
            )
        self.check_cancelled()

    def _inventory(self) -> ConnectInventory:
        if self.inventory is None:
            bootstrap = self.config.generations[self.config.active_generation]["cleanup"]
            self.inventory = ConnectInventory(
                bootstrap.reader(),
                self.config.journal_vault,
                spool=self.directory.parent.parent / "inventory-pending" / "controller",
            )
        return self.inventory

    def _provision(self) -> tuple[dict[str, Credential], dict[str, object]]:
        """One complete manifest confirmation; no creation ACK choreography."""
        inventory = self._inventory()
        legacy = cleanup.sweep_legacy(
            self.config, inventory.client, root=self.directory.parent.parent
        )
        if legacy["status"] != "ready":
            raise LifecycleError("legacy credential obligations remain unresolved")
        require_clear(inventory, current_lease=self.lease_id)
        now = datetime.now(UTC)
        if self.lease_id == self.run_id:
            self.config.require_issuance(now=now)
            roles = self.config.generations[self.config.active_generation]
            creator = roles["provision"].providers(targets=self.config.targets, now=now)
            cleanup_providers = roles["cleanup"].providers(targets=self.config.targets, now=now)
            manifest = lease_manifest(
                lease_id=self.lease_id,
                source=self.revision,
                helper=self.helper,
                targets=self.config.targets,
                policy=self.config.policy,
                approved_policy_sha256=self.config.approved_policy_sha256,
                creator=roles["provision"].generation,
                cleanup=roles["cleanup"].generation,
                providers=creator,
                cleanup_providers=cleanup_providers,
                scopes=fixture_scopes(self.config.targets, creator),
                now=now,
            )
            if (self.lease_state.directory / "manifest.json").exists():
                raise LifecycleError("existing issuance cannot be replayed")
            self.lifecycle = LeaseLifecycle(
                manifest, inventory, self.lease_state, providers=creator
            )
            writer = digest({"attempt": self.run_id, "pid": os.getpid(), "started": stamp(now)})
            self.lifecycle.prepare(writer_sha256=writer)
            while True:
                self.check_cancelled()
                if datetime.now(UTC) >= instant(manifest.policy.start_before):
                    raise LifecycleError(
                        "independent manifest confirmation missed the approved cutoff"
                    )
                try:
                    require_confirmation(
                        inventory, manifest, independent_server_id=self.config.independent_server_id
                    )
                    break
                except LifecycleError:
                    time.sleep(5)
            # Confirmation may take time; reject locally known reader expiry
            # immediately before the first credential CREATE as well.
            self.config.require_issuance(now=datetime.now(UTC))
            self.lifecycle.issue(
                writer_sha256=writer,
                approved_policy_sha256=self.config.approved_policy_sha256,
                independent_server_id=self.config.independent_server_id,
                check_cancelled=self.check_cancelled,
            )
        else:
            manifest = self.lease_state.manifest()
            if (
                manifest.targets != self.config.targets
                or manifest.policy.sha256 != self.config.approved_policy_sha256
            ):
                raise LifecycleError("reused lease target or approved policy changed")
            bootstrap = self.config.generations[self.config.active_generation]["cleanup"]
            providers = bootstrap.providers(targets=self.config.targets, now=now)
            self.lifecycle = LeaseLifecycle(
                manifest, inventory, self.lease_state, providers=providers
            )
        from scripts.m3_11_unattended.watchdog import require_released_consumers  # noqa: PLC0415

        with self.lease_state.use_lock():
            require_released_consumers(self.lease_state, Docker())
            self.lease_state.acquire_use(
                attempt_id=self.run_id, binding_sha256=digest(self.binding), kind="attempt"
            )
        return self.lifecycle.credentials(binding=self.binding)

    def _production(
        self, credentials: dict[str, Credential], fixture: dict[str, object]
    ) -> dict[str, object]:
        if self.config.production is None:
            raise LifecycleError("isolated production reader is unavailable")
        lease = {"receipt": fixture, "approved_policy_sha256": self.config.approved_policy_sha256}
        production.audit_lease(lease, binding=self.binding, now=datetime.now(UTC))
        request = {
            **self.config.production,
            "targets": dataclasses.asdict(self.config.targets),
            "binding": self.binding,
            "lease": lease,
            "output": str(self.directory / "production-check.json"),
            "fixture": {
                "audit": credentials["audit"].secret,
                "observer": credentials["observer"].secret,
                **{
                    role + "_id": credentials[role].identifier
                    for role in ("archive", "backup", "caddy")
                },
            },
        }
        self._command(
            [sys.executable, "-m", "scripts.m3_11_unattended.production", "bootstrap"],
            log="production-check.log",
            stdin=canonical_bytes(request),
        )
        return read_private(self.directory / "production-check.json")

    def _deliver(
        self, credentials: dict[str, Credential], receipts: dict[str, object]
    ) -> dict[str, str]:
        fixture = receipts["fixture"]
        if not isinstance(fixture, dict) or instant(fixture["deadline"]) < datetime.now(
            UTC
        ) + timedelta(hours=12):
            raise LifecycleError("managed credential deadline needs at least 12 hours remaining")
        values: dict[str, str] = {}
        for role, (identifier_name, secret_name) in SECRETS.items():
            if identifier_name is not None:
                values[identifier_name] = credentials[role].identifier
            values[secret_name] = credentials[role].secret
        if self.lifecycle is None:
            raise LifecycleError("lease validation is unavailable")
        path = self.directory / "runtime-inputs.json"
        write_private(
            path,
            {
                "format": inputs.FORMAT,
                "binding": self.binding,
                "targets": dataclasses.asdict(self.config.targets),
                "credentials": values,
                "receipts": receipts,
            },
        )
        environment, _ = inputs.load(path, repository=self.source, now=datetime.now(UTC))
        environment = {
            **safe_environment(),
            **environment,
            "DOCKER_HOST": "unix:///var/run/docker.sock",
            "DOCKER_CONFIG": str(self.directory / "docker-config"),
            "M3_11_EVIDENCE_ROOT": str(self.directory / "qualification"),
            "LDP_QUALIFICATION_CONTEXT_DIRECTORY": str(self.directory / "supervisor"),
        }
        inputs.require_environment(
            environment,
            {**self.config.targets.environment(), **values, inputs.MANAGED_ENV: str(path)},
        )
        return environment

    def _journey(self, environment: dict[str, str]) -> int:
        just = shutil.which("just")
        if just is None:
            raise LifecycleError("qualification command is unavailable")
        if self.lifecycle is None:
            raise LifecycleError("attempt has no validated lease")
        qualification_allocation.initialize(
            self.directory, self.request, environment["DOCKER_HOST"]
        )
        with (self.directory / "controller.log").open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            child = subprocess.Popen(  # noqa: S603 - existing command in exact clean checkout
                [just, "m3-11-spaces-qualification"],
                cwd=self.source,
                env=environment,
                stdout=stream,
                stderr=stream,
                start_new_session=True,
            )
            try:
                self.journey_shutdown_at: float | None = None
                self.attempt_started = True
                write_private(
                    self.directory / "attempt-started.json",
                    {
                        "binding_sha256": digest(self.binding),
                        "manifest_sha256": self.lifecycle.manifest.sha256,
                    },
                )
                return self._monitor_journey(child)
            finally:
                # Bookkeeping errors must drain the journey before the outer
                # finally revokes credentials. The supervisor needs its existing
                # allowance to drain its separately grouped payload and report.
                try:
                    drained = self._drain_journey(child)
                except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
                    self._failure(error)
                    drained = False
                if not drained and sys.exception() is None:
                    raise LifecycleError("qualification process shutdown was not verified")
                if drained:
                    write_private(
                        self.directory / "host-drained.json",
                        {"binding_sha256": digest(self.binding), "drained": True},
                    )

    def _drain_journey(self, child: subprocess.Popen[bytes]) -> bool:
        stop_at = self.journey_shutdown_at or (
            time.monotonic()
            + qualification_deadline.REPORT_SECONDS
            + 4 * qualification_deadline.GRACE_SECONDS
        )
        qualification_deadline._kill_group(child, signal.SIGTERM)
        while executing_group(child.pid):
            child.poll()
            if time.monotonic() >= stop_at:
                break
            time.sleep(qualification_deadline.INTERRUPT_POLL_SECONDS)
        # A launcher exiting is not proof its supervisor stopped. Only kill the
        # remaining group after cooperative shutdown's existing bounded window.
        qualification_deadline._kill_group(child, signal.SIGKILL)
        try:
            child.wait(timeout=qualification_deadline.GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            self._failure(error)
            return False
        return not executing_group(child.pid)

    def _monitor_journey(self, child: subprocess.Popen[bytes]) -> int:
        interrupted = False
        interrupted_status = 143
        while child.poll() is None:
            expired = time.monotonic() >= self.ends_at
            if (
                self.state.cancelled
                or self.state.stopped
                or self.pending.signum is not None
                or expired
            ) and not interrupted:
                interrupted_status = 124 if expired else 143
                qualification_deadline._kill_group(child, signal.SIGTERM)
                interrupted, self.journey_shutdown_at = (
                    True,
                    time.monotonic()
                    + qualification_deadline.REPORT_SECONDS
                    + 4 * qualification_deadline.GRACE_SECONDS,
                )
            if (
                self.journey_shutdown_at is not None
                and time.monotonic() >= self.journey_shutdown_at
            ):
                break
            self.state.update("running", cleanup="pending")
            time.sleep(1)
        return (
            interrupted_status
            if interrupted
            else (128 - child.returncode if child.returncode < 0 else child.returncode)
        )

    def revoke(self) -> bool:
        """Publish before the local provider lock; failed publication cannot skip deletion."""
        if self.lifecycle is None:
            if not (self.lease_state.directory / "manifest.json").exists():
                return False
            self.lifecycle = LeaseLifecycle(
                self.lease_state.manifest(), self._inventory(), self.lease_state, providers={}
            )
        published = True
        try:
            # Serialize the fresh ownership decision and close request with
            # release/acquisition. Explicit lease cancellation and expiry remain
            # global cleanup obligations even after this attempt released use.
            with self.lease_state.use_lock():
                if (
                    not self.state.cancelled
                    and datetime.now(UTC)
                    < self.lifecycle.manifest.policy.deadline(
                        instant(self.lifecycle.manifest.created_at)
                    )
                    and not self.owns_lease
                ):
                    return False
                try:
                    self.lifecycle.abandon_prepared()
                except (RuntimeError, OSError, ValueError) as error:
                    published = False
                    self._failure(error, cleanup_failed=True)
                try:
                    self.lifecycle.request_close("cancel" if self.state.cancelled else "finish")
                except (RuntimeError, OSError, ValueError) as error:
                    published = False
                    self._failure(error, cleanup_failed=True)
        except (RuntimeError, OSError, ValueError) as error:
            self._failure(error, cleanup_failed=True)
            return False
        try:
            (self.directory / "runtime-inputs.json").unlink(missing_ok=True)
            with cleanup_lock(self.directory.parent, blocking=False):
                self._cleanup_progress("revoking", "pending")
                manifest = self.lifecycle.manifest
                bootstrap = self.config.generations[self.config.active_generation]["cleanup"]
                providers = bootstrap.providers(
                    targets=self.config.targets, now=datetime.now(UTC), tolerate_unavailable=True
                )
                generations = {
                    key: roles["cleanup"].providers(
                        targets=self.config.targets,
                        now=datetime.now(UTC),
                        tolerate_unavailable=True,
                    )
                    for key, roles in self.config.generations.items()
                }
                results = self.lifecycle.reconcile(providers, generations=generations)
                verified = published and all(result.status == "verified" for result in results)
                receipt: dict[str, object] = {
                    "actor": "controller",
                    "helper_revision": self.helper,
                    "observed_at": stamp(datetime.now(UTC)),
                    "status": "verified" if verified else "unresolved",
                    "overdue": datetime.now(UTC)
                    > manifest.policy.deadline(instant(manifest.created_at)),
                    "results": [dataclasses.asdict(result) for result in results],
                }
                if verified:
                    self._inventory().publish(
                        fact(manifest, "closed", {"results": receipt["results"]})
                    )
                    if not (self.directory / "revocation.json").exists():
                        write_private(self.directory / "revocation.json", receipt)
                    for path in self.lease_state.directory.glob("credential-*.json"):
                        path.unlink()
                self._cleanup_progress("finished", "verified" if verified else "unresolved")
                return verified
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            self._failure(error, cleanup_failed=True)
            self._cleanup_progress("finished", "unresolved")
            return False

    def _terminal(self) -> None:
        retain = False
        try:
            if self.lifecycle is not None and (self.directory / "journey-result.json").exists():
                result = read_private(self.directory / "journey-result.json")
                retain = (
                    self.request["mode"] == "qualification"
                    and self.lifecycle.manifest.policy.retain_after_failure
                    and not self.state.cancelled
                    and self.attempt_started
                    and (self.directory / "attempt-started.json").exists()
                    and (not self.pending.signum or (self.directory / "stop-attempt.json").exists())
                    and result["outcome"] in {"failed", "interrupted"}
                    and (self.directory / "runtime-inputs.json").exists()
                    and not any(slot.startswith("close-") for slot in self.lifecycle.records())
                )
            if retain:
                # Retention is not release: the durable runtime-use owner stays
                # held until exact host/guest quiescence is verified separately.
                (self.directory / "runtime-inputs.json").unlink(missing_ok=True)
                self._cleanup_progress("finished", "pending")
            else:
                self.revoke()
        except (RuntimeError, OSError, ValueError) as error:
            self._failure(error, cleanup_failed=True)
            self.revoke()

    def _cleanup_progress(self, phase: str, status: str) -> bool:
        try:
            self.state.update(phase, cleanup=status, preserve_verified=True)
            return True
        except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
            # Progress storage failure is not permission to skip revocation.
            # Keep closure unresolved until its evidence can be persisted.
            self._failure(error, cleanup_failed=True)
            return False

    def run(self) -> int:
        private_directory(self.directory)
        with self.state.lock(), qualification_deadline.interrupts() as pending:
            self.pending = pending
            fresh = self.state.begin(self.binding)
            try:
                self._verify_daemon()
                self._verify_source()
                if not fresh:
                    self.state.interrupted()
                    return 1
                for name in (
                    "credential-intents",
                    "credential-cleanup",
                    "qualification",
                    "docker-config",
                    "supervisor",
                ):
                    (self.directory / name).mkdir(mode=0o700)
                (self.directory / "docker-config/config.json").write_text("{}\n")
                self.state.update("provisioning", cleanup="pending")
                credentials, fixture = self._provision()
                self.state.update("production-check", cleanup="pending")
                production = self._production(credentials, fixture)
                environment = self._deliver(
                    credentials, {"production": production, "fixture": fixture}
                )
                if self.request["mode"] == "rehearsal":
                    # Bounded actual fixture capability probes, then a recorded
                    # interruption. This never claims installed qualification.
                    uv = shutil.which("uv")
                    if uv is None:
                        raise LifecycleError("qualification runtime is unavailable")
                    self._command(
                        [
                            uv,
                            "run",
                            "--frozen",
                            "ldp-m3-archive",
                            "credential-check",
                            "--region",
                            self.config.targets.region,
                            "--archive-bucket",
                            self.config.targets.archive_bucket,
                            "--backup-bucket",
                            self.config.targets.backup_bucket,
                            "--probe-record",
                            str(self.directory / "fixture-storage-ownership.json"),
                            "--source-revision",
                            self.revision,
                            "--run-id",
                            self.run_id,
                        ],
                        log="rehearsal-probes.log",
                        environment=environment,
                    )
                    # Exercise the same real controller signal handler used by
                    # cancellation; the finally path must revoke all children.
                    signal.raise_signal(signal.SIGTERM)
                    if self.pending.signum != signal.SIGTERM:
                        raise LifecycleError("rehearsal interruption was not observed")
                    self.state.finish_journey("rehearsal-interrupted", 143)
                    return 0
                status = self._journey(environment)
                if status == 0:
                    paths = list((self.directory / "qualification").glob("*/qualification.json"))
                    if len(paths) != 1:
                        raise LifecycleError(
                            "qualification completion report is missing or ambiguous"
                        )
                    verify_report(
                        paths[0],
                        source=self.revision,
                        artifact=str(self.binding["artifact_sha256"]),
                        repository=self.source,
                        storage_target=self.config.targets.storage_digest,
                        milestone="3.11",
                        managed_binding=self.binding,
                    )
                self.state.finish_journey("passed" if status == 0 else "failed", status)
                return status
            except (
                RuntimeError,
                ValueError,
                OSError,
                KeyError,
                TypeError,
                subprocess.SubprocessError,
            ) as error:
                self._failure(error)
                if not (self.directory / "journey-result.json").exists():
                    expired = time.monotonic() >= self.ends_at
                    self.state.finish_journey(
                        "failed"
                        if expired
                        else "interrupted"
                        if self.state.cancelled or pending.signum
                        else "failed",
                        124 if expired else 143 if self.state.cancelled or pending.signum else 1,
                    )
                return 1
            finally:
                self._terminal()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        worker = Worker(args.directory, LeaseConfiguration.load(args.config), args.source)
        # One daemon-wide admission lock, shared across all pinned helper revisions.
        with RunState(args.directory.parent.parent).lock():
            worker.run()
        # Keep the detached container available for status and restart recovery.
        # Its restart policy never turns a completed/failed attempt into a retry.
        retry_seconds = cleanup.RETRY_SECONDS
        while True:
            # run() already attempted terminal cleanup immediately. Bound later
            # failures to an hourly cadence without consuming the shared quota.
            time.sleep(retry_seconds)
            if worker.state.status()["credential_cleanup"] != "verified":
                if worker.lifecycle is not None and not worker.state.cancelled:
                    manifest = worker.lifecycle.manifest
                    if datetime.now(UTC) < manifest.policy.deadline(
                        instant(manifest.created_at)
                    ) and not any(slot.startswith("close-") for slot in worker.lifecycle.records()):
                        continue
                verified = worker.revoke()
                retry_seconds = (
                    cleanup.REMOTE_SECONDS
                    if verified
                    else min(2 * retry_seconds, cleanup.REMOTE_SECONDS)
                )
            else:
                retry_seconds = cleanup.REMOTE_SECONDS
    except RuntimeError, OSError, ValueError, TypeError, KeyError:
        print(
            "Detached qualification requires reconciliation; private evidence is retained.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
