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

from scripts import qualification_deadline
from scripts.m3_10_qualification_report import verify_report
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended import cleanup, inputs, quota
from scripts.m3_11_unattended.cloudflare import Cloudflare
from scripts.m3_11_unattended.config import Configuration, connect
from scripts.m3_11_unattended.docker import SOCKET, Docker
from scripts.m3_11_unattended.journal import OpJournal, event
from scripts.m3_11_unattended.lifecycle import Lifecycle, intents
from scripts.m3_11_unattended.model import (
    ROLES,
    Credential,
    Intent,
    LifecycleError,
    ProviderKind,
    identity,
    instant,
    stamp,
    strings,
)
from scripts.m3_11_unattended.state import RunState, private_directory
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


class Worker:
    def __init__(self, directory: Path, config: Configuration, source: Path) -> None:
        self.state, self.config, self.source = RunState(directory), config, source
        self.request = fields(
            read_private(directory / "request.json"),
            {"format", "binding", "mode", "approval_sha256", "controller_image", "daemon"},
        )
        self.binding = fields(self.request["binding"], inputs.BINDING)
        self.run_id = identity(self.binding["managed_run_id"])
        self.helper = revision(self.binding["helper_revision"])
        self.revision = revision(self.binding["source_revision"])
        self.directory = directory
        self.pending = qualification_deadline.Interruption()
        self.ends_at = time.monotonic() + qualification_deadline.LIVE_SECONDS
        self.cleanup_journal: OpJournal | None = None
        self.cleanup_cache = directory.parent.parent / "cleanup-journal-cache.json"

    def check_cancelled(self) -> None:
        if self.state.cancelled or self.pending.signum is not None:
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

    def remember_intent(self, intent: Intent) -> None:
        write_private(
            self.directory / "credential-intents" / (intent.sha256 + ".json"), intent.document()
        )

    def _verify_source(self) -> None:
        helper_root = Path(__file__).resolve().parents[2]
        current_candidate(helper_root, self.helper)
        current_candidate(self.source, self.revision)
        if (
            fingerprint(self.source, self.revision) != self.binding["qualification_inputs_sha256"]
            or self.config.targets.storage_digest != self.binding["storage_target_sha256"]
        ):
            raise LifecycleError("controller source or storage target changed")
        if self.request["format"] != "lowerduckpond-m3-11-unattended-request-v1" or self.request[
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

    def _provision(self) -> tuple[dict[str, Credential], dict[str, object]]:  # noqa: PLR0912 - independent admission and credential roles
        for sibling in self.directory.parent.iterdir():
            if sibling != self.directory and (sibling / "status.json").exists():
                progress = RunState(sibling).status()
                if progress["credential_cleanup"] != "verified" or progress["phase"] != "finished":
                    raise LifecycleError(
                        "another attempt or unresolved cleanup blocks provisioning"
                    )
        now = datetime.now(UTC).replace(microsecond=0)
        separate = connect(
            self.config.cleanup,
            targets=self.config.targets,
            vault=self.config.journal_vault,
            now=now,
        )
        if isinstance(separate.journal, OpJournal):
            separate.journal.use_cache(self.cleanup_cache)
            self.cleanup_journal = separate.journal
        separate.authority.require(now + timedelta(hours=14))
        cleanup.require_independent_ready(separate.journal, helper=self.helper, now=now)
        Lifecycle(separate.journal, separate.providers).require_clear()
        creator = connect(
            self.config.provision,
            targets=self.config.targets,
            vault=self.config.journal_vault,
            now=now,
            provisioning=True,
        )
        if self.request["mode"] == "qualification":
            self._require_rehearsal(creator.journal.records())
        for kind in separate.providers:
            # Establish the same provider inventory/owner through independent
            # authorities before allocating any child credential.
            before = {item["id"] for item in separate.providers[kind].inventory()}
            if not before or before != {item["id"] for item in creator.providers[kind].inventory()}:
                raise LifecycleError("provisioning and cleanup provider identities differ")
        records = creator.journal.records()
        quota.require_capacity(creator.journal.op, separate.journal.op, records=len(records))
        for record in records:
            payload = record["payload"]
            if (
                record["kind"] == "run"
                and isinstance(payload, dict)
                and payload.get("approval_sha256") == self.request["approval_sha256"]
                and payload.get("mode") == self.request["mode"]
            ):
                raise LifecycleError("this approved attempt has already been consumed")
        creator.journal.append(
            event(
                "run",
                self.run_id,
                {
                    "binding": self.binding,
                    "mode": self.request["mode"],
                    "approval_sha256": self.request["approval_sha256"],
                },
            )
        )
        lifecycle = Lifecycle(
            creator.journal,
            creator.providers,
            remember=self.remember,
            remember_intent=self.remember_intent,
        )
        credentials: dict[str, Credential] = {}
        deadlines: list[datetime] = []
        for role in ("archive", "backup", "operator", "audit", "caddy", "observer", "page-rules"):
            self.check_cancelled()
            if role in {"archive", "backup", "operator"}:
                provider: ProviderKind = "spaces"
                bucket = (
                    "" if role == "operator" else getattr(self.config.targets, role + "_bucket")
                )
                scope: dict[str, object] = {
                    "grants": [
                        {
                            "bucket": bucket,
                            "permission": "fullaccess" if role == "operator" else "readwrite",
                        }
                    ]
                }
            else:
                provider = "cloudflare-user" if role == "page-rules" else "cloudflare-account"
                client = creator.providers[provider]
                if not isinstance(client, Cloudflare):
                    raise LifecycleError("fixture token provisioning authority is invalid")
                scope = client.scope(role, self.config.targets)
            intent, credential = lifecycle.provision(
                run_id=self.run_id,
                role=role,
                source=self.revision,
                helper=self.helper,
                targets=self.config.targets,
                provider=provider,
                scope=scope,
                authority=separate.authority,
            )
            if separate.providers[provider].inspect(credential.identifier) is None:
                raise LifecycleError("independent cleanup cannot observe the created credential")
            credentials[role] = credential
            deadlines.append(instant(intent.deadline))
        if len({credential.secret for credential in credentials.values()}) != len(ROLES) or len(
            {credential.identifier for credential in credentials.values()}
        ) != len(ROLES):
            raise LifecycleError("provider issued duplicate fixture credential identities")
        receipt = {
            "format": inputs.FIXTURE_FORMAT,
            **self.binding,
            "started_at": stamp(min(deadlines) - timedelta(hours=14)),
            "completed_at": stamp(datetime.now(UTC)),
            "deadline": stamp(min(deadlines)),
            "checks": inputs.FIXTURE_RESULT,
            "identities_sha256": {
                role: hashlib.sha256(value.identifier.encode()).hexdigest()
                for role, value in credentials.items()
            },
        }
        return credentials, receipt

    def _require_rehearsal(self, records: list[dict[str, object]]) -> None:
        completed = [
            record
            for record in records
            if record["kind"] == "result"
            and isinstance(record["payload"], dict)
            and record["payload"].get("approval_sha256") == self.request["approval_sha256"]
            and record["payload"].get("qualification") == "rehearsal-interrupted"
            and record["payload"].get("credential_cleanup") == "verified"
        ]
        if len(completed) != 1:
            raise LifecycleError(
                "qualification requires its completed credential lifecycle rehearsal"
            )
        rehearsal = completed[0]
        owned = {
            Intent.parse(record["payload"]).sha256
            for record in records
            if record["kind"] == "intent" and record["run_id"] == rehearsal["run_id"]
        }
        for record in records:
            payload = record["payload"]
            if (
                record["kind"] == "heartbeat"
                and isinstance(payload, dict)
                and payload.get("actor") == "github"
                and payload.get("helper_revision") == self.helper
                and instant(record["recorded_at"]) >= instant(rehearsal["recorded_at"])
                and isinstance(payload.get("results"), list)
            ):
                verified = {
                    value.get("intent_sha256")
                    for value in payload["results"]
                    if isinstance(value, dict) and value.get("status") == "verified"
                }
                if len(owned) == len(ROLES) and owned <= verified:
                    return
        raise LifecycleError("GitHub has not independently verified the rehearsal revocations")

    def _production(self, credentials: dict[str, Credential]) -> dict[str, object]:
        request = {
            **self.config.production,
            "targets": dataclasses.asdict(self.config.targets),
            "binding": self.binding,
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
        # The bootstrap checker consumes a service account, not its expiry field.
        if instant(request.pop("service_account_expires_at")) <= datetime.now(UTC):
            raise LifecycleError("production reader authority has expired")
        request["service_account"] = request.pop("service_account_token")
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
            interrupted = False
            interrupted_status = 143
            stop_at: float | None = None
            while child.poll() is None:
                expired = time.monotonic() >= self.ends_at
                if (
                    self.state.cancelled or self.pending.signum is not None or expired
                ) and not interrupted:
                    interrupted_status = 124 if expired else 143
                    os.killpg(child.pid, signal.SIGTERM)
                    interrupted, stop_at = (
                        True,
                        time.monotonic()
                        + qualification_deadline.REPORT_SECONDS
                        + 4 * qualification_deadline.GRACE_SECONDS,
                    )
                if stop_at is not None and time.monotonic() >= stop_at:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=qualification_deadline.GRACE_SECONDS)
                    break
                self.state.update("running", cleanup="pending")
                time.sleep(1)
            return (
                interrupted_status
                if interrupted
                else (128 - child.returncode if child.returncode < 0 else child.returncode)
            )

    def revoke(self) -> bool:
        self.state.update("revoking", cleanup="pending")
        try:
            lifecycle = cleanup.connect_cleanup(
                self.config.cleanup, self.config.targets, self.config.journal_vault
            )
            if self.cleanup_journal is None:
                if isinstance(lifecycle.journal, OpJournal):
                    lifecycle.journal.use_cache(self.cleanup_cache)
                    self.cleanup_journal = lifecycle.journal
            else:
                self.cleanup_journal.refresh()
                lifecycle.journal = self.cleanup_journal
            lifecycle.request_revocation(self.run_id)
            available = retained_credentials(self.directory)
            receipt = cleanup.sweep(
                lifecycle, actor="controller", helper=self.helper, secrets=available
            )
            own = {
                intent.sha256
                for intent in intents(lifecycle.journal)
                if intent.run_id == self.run_id
            }
            local = {path.stem for path in (self.directory / "credential-intents").glob("*.json")}
            if not local <= own or not set(available) <= own:
                raise LifecycleError("independent credential obligations are missing")
            results = receipt["results"]
            verified = isinstance(results, list) and all(
                isinstance(value, dict)
                and (value.get("intent_sha256") not in own or value.get("status") == "verified")
                for value in results
            )
            if verified:
                for path in (self.directory / "credential-cleanup").glob("*.json"):
                    path.unlink()
                if not (self.directory / "revocation.json").exists():
                    write_private(self.directory / "revocation.json", receipt)
            self.state.update("finished", cleanup="verified" if verified else "unresolved")
            if (
                verified
                and (self.directory / "journey-result.json").exists()
                and not any(
                    record["kind"] == "result" and record["run_id"] == self.run_id
                    for record in lifecycle.journal.records()
                )
            ):
                lifecycle.journal.append(
                    event(
                        "result",
                        self.run_id,
                        {
                            "binding": self.binding,
                            "approval_sha256": self.request["approval_sha256"],
                            **self.state.status(),
                        },
                    )
                )
            return verified
        except RuntimeError, OSError, ValueError, KeyError, TypeError:
            self.state.update("finished", cleanup="unresolved")
            return False
        finally:
            (self.directory / "runtime-inputs.json").unlink(missing_ok=True)

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
                production = self._production(credentials)
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
            ):
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
                self.revoke()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        worker = Worker(args.directory, Configuration.load(args.config), args.source)
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
