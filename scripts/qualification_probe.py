"""Read-only, bounded disposable-host observations; never recovery authority.

The controller sends this standalone file to the owned fixture's Python stdin.
Only selected fields pass through ``sanitize``; raw records stay on that host.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

UNKNOWN = "unknown"
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 10000
MIN_HTTP_STATUS = 100
MAX_HTTP_STATUS = 599
PROBE_ARGUMENT_COUNT = 2
MAX_COMMAND_BYTES = 65536
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
DIGEST = re.compile(r"[0-9a-f]{64}")
OPERATIONS = frozenset(
    {
        "create",
        "deploy",
        "rollback",
        "rename",
        "suspend",
        "resume",
        "export",
        "import",
        "reconcile",
        "archive",
        "restore",
        "delete",
    }
)
ERRORS = frozenset(
    {
        "archive_unavailable",
        "busy",
        "capacity_exceeded",
        "conflict",
        "denied",
        "invalid_artifact",
        "invalid_request",
        "not_found",
        "not_implemented",
        "publication_disabled",
        "state_drift",
        "unavailable",
    }
)
CATEGORIES = frozenset(
    {
        "provider_response",
        "provider_read_timeout",
        "provider_connect_timeout",
        "provider_connection_closed",
        "provider_tls",
        "provider_connection",
        "provider_stream",
        "provider_sdk",
        "archive_validation",
        "archive_transport",
        "archive_configuration",
        "state_validation",
        "local_timeout",
        "local_connection",
        "local_permission",
        "local_memory",
        "local_io",
        "local_storage_full",
        "unexpected",
    }
)
PROVIDER_CODES = frozenset(
    {
        "access_denied",
        "invalid_access_key",
        "signature_mismatch",
        "clock_skew",
        "request_timeout",
        "slow_down",
        "internal_error",
        "service_unavailable",
        "bad_digest",
        "invalid_digest",
        "invalid_request",
        "no_such_bucket",
        "no_such_key",
        "no_such_version",
        "not_implemented",
        "other",
    }
)
PROVIDER_OPERATIONS = frozenset(
    {
        "get_bucket_versioning",
        "list_object_versions",
        "list_multipart_uploads",
        "put_object",
        "get_object",
        "delete_object",
        "other",
    }
)
FILESYSTEMS = frozenset({"ext4", "xfs", "btrfs", "overlay", "tmpfs", "nfs", "nfs4", "9p", "fuse"})
LOCAL_PATHS = {
    "intents": "/var/lib/lowerduckpond/static/intents",
    "intake": "/var/lib/lowerduckpond/static/intake",
    "exports": "/var/lib/lowerduckpond/static/exports",
    "staging": "/srv/lowerduckpond/sites/.staging",
    "caddy_intents": "/etc/caddy/intents",
}


def bounded_command(
    arguments: list[str], *, timeout: float = 5, stdin: bytes = b""
) -> bytes | None:
    """Bound time and captured bytes, discard stderr, and never expose tool errors."""
    executable = shutil.which(arguments[0])
    if executable is None:
        return None
    with tempfile.TemporaryFile() as source:
        source.write(stdin)
        source.seek(0)
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed diagnostic commands, no shell
                [executable, *arguments[1:]],
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            return None
        assert process.stdout is not None  # noqa: S101 - PIPE established above
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + timeout
                output = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not ready.select(remaining):
                        return None
                    block = os.read(process.stdout.fileno(), 4096)
                    if not block:
                        remaining = max(0.001, deadline - time.monotonic())
                        return bytes(output) if process.wait(timeout=remaining) == 0 else None
                    output.extend(block)
                    if len(output) > MAX_COMMAND_BYTES:
                        return None
        except OSError, subprocess.TimeoutExpired:
            return None
        finally:
            # Kill the command group, including helper grandchildren retaining its pipe.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            process.stdout.close()


def label(value: object, choices: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in choices else UNKNOWN


def matching(value: object, pattern: re.Pattern[str]) -> str:
    return value if isinstance(value, str) and pattern.fullmatch(value) else UNKNOWN


def count(value: object) -> int | str:
    return value if type(value) is int and 0 <= value <= MAX_ENTRIES else UNKNOWN


def filesystem(path: Path) -> str:
    output = bounded_command(
        ["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(path)]
    )
    return (
        label(output.decode("ascii", errors="replace").strip(), FILESYSTEMS) if output else UNKNOWN
    )


def boolean(value: object) -> bool | str:
    return value if type(value) is bool else UNKNOWN


def document(path: Path) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("not a regular record")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("record over budget")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("record is not an object")
        return data
    finally:
        os.close(descriptor)


def diagnostic(text: str) -> dict[str, object]:
    """Extract literal runtime labels, discarding every unrecognized byte."""
    fields = dict(re.findall(r"(?:^| )(category|operation|code|http_status)=([^ ]+)", text))
    status = fields.get("http_status", "")
    return {
        "category": label(fields.get("category"), CATEGORIES),
        "operation": label(fields.get("operation"), PROVIDER_OPERATIONS),
        "code": label(fields.get("code"), PROVIDER_CODES),
        "http_status": int(status) if re.fullmatch(r"[1-5][0-9]{2}", status) else UNKNOWN,
    }


def safe_diagnostic(raw: dict[str, object]) -> dict[str, object]:
    status = raw.get("http_status")
    return {
        "category": label(raw.get("category"), CATEGORIES),
        "operation": label(raw.get("operation"), PROVIDER_OPERATIONS),
        "code": label(raw.get("code"), PROVIDER_CODES),
        "http_status": status
        if type(status) is int and MIN_HTTP_STATUS <= status <= MAX_HTTP_STATUS
        else UNKNOWN,
    }


def sanitize(raw: dict[str, object]) -> dict[str, object]:
    """Rebuild the entire public boundary; neither arbitrary keys nor text survive."""

    def section(name: str) -> dict[str, object]:
        value = raw.get(name)
        return value if isinstance(value, dict) else {}

    job, local, remote, service = (section(k) for k in ("job", "local", "remote", "service"))
    # The host emits an already-sanitized nested diagnostic. Revalidate it when
    # the controller receives that payload or reads its retained snapshot.
    remote_diagnostic = remote.get("diagnostic")
    if not isinstance(remote_diagnostic, dict):
        remote_diagnostic = remote
    return {
        "artifact_sha256": matching(raw.get("artifact_sha256"), DIGEST),
        "state_filesystem": label(raw.get("state_filesystem"), FILESYSTEMS),
        "job": {
            "job_id": matching(job.get("job_id"), UUID),
            "correlation_id": matching(job.get("correlation_id"), UUID),
            "operation": label(job.get("operation"), OPERATIONS),
            "phase": label(
                job.get("phase"), frozenset({"pending", "claimed", "completed", "failed"})
            ),
            "execution_validated": boolean(job.get("execution_validated")),
            "result_status": label(job.get("result_status"), frozenset({"succeeded", "failed"})),
            "result_error": label(job.get("result_error"), ERRORS | {"none"}),
            "executor_failure": boolean(job.get("executor_failure")),
        },
        "local": {
            **{name: count(local.get(name)) for name in LOCAL_PATHS},
            "quarantine": boolean(local.get("quarantine")),
        },
        "remote": {
            "versions_and_markers": count(remote.get("versions_and_markers")),
            "multipart_uploads": count(remote.get("multipart_uploads")),
            "category": label(remote.get("category"), CATEGORIES | {"observed"}),
            "diagnostic": safe_diagnostic(remote_diagnostic),
        },
        "service": safe_diagnostic(service),
    }


def directory_count(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with os.scandir(descriptor) as entries:
            total = 0
            for _ in entries:
                total += 1
                if total > MAX_ENTRIES:
                    raise ValueError("inventory over budget")
            return total
    finally:
        os.close(descriptor)


def job_observation(correlation: str) -> dict[str, object]:
    from lowerduckpond_static_contracts import ContractKind, validate_contract  # noqa: PLC0415

    root = Path("/var/lib/lowerduckpond/static/authorization")
    binding = document(root / "correlations" / f"{correlation}.json")
    validate_contract(binding, expected_kind=ContractKind.AUTHORIZATION_JOB)
    job_id = matching(binding.get("jobId"), UUID)
    if job_id == UNKNOWN:
        raise ValueError("no bound job")
    job = document(root / "jobs" / f"{job_id}.json")
    validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
    request = job["request"]
    if not isinstance(request, dict) or request.get("correlationId") != correlation:
        raise ValueError("correlation binding mismatch")
    if job.get("jobId") != job_id or binding.get("request") != request:
        raise ValueError("job binding mismatch")
    observed = {
        "job_id": job_id,
        "correlation_id": correlation,
        "operation": request.get("operation"),
        "phase": job.get("phase"),
        "execution_validated": job.get("executionValidated"),
    }
    try:
        result = document(root / "results" / f"{job_id}.json")
    except FileNotFoundError:
        return observed
    validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
    if result.get("correlationId") != correlation or result.get("operation") != request.get(
        "operation"
    ):
        raise ValueError("result binding mismatch")
    if result.get("provenance") != {"kind": "authorization-job", "jobId": job_id}:
        raise ValueError("result provenance mismatch")
    observed.update(
        {
            "result_status": result.get("status"),
            "result_error": result.get("errorCode", "none"),
            "executor_failure": result.get("failurePublisher") == "authorization-executor",
        }
    )
    return observed


def remote_observation() -> dict[str, object]:
    from lowerduckpond_static_host_agent.archive_configuration import (  # noqa: PLC0415
        load_archive_configuration,
    )
    from lowerduckpond_static_host_agent.archive_diagnostics import (  # noqa: PLC0415
        archive_failure_diagnostic,
    )

    try:
        inventory = load_archive_configuration().remote_store().inventory()
        return {
            "versions_and_markers": len(inventory.versions),
            "multipart_uploads": len(inventory.multipart_uploads),
            "category": "observed",
        }
    except Exception as error:  # Provider text never crosses the fixture boundary.
        return diagnostic(archive_failure_diagnostic(error))


def probe(correlation: str) -> dict[str, object]:
    raw: dict[str, object] = {}
    raw["state_filesystem"] = filesystem(Path("/var/lib/lowerduckpond/static"))
    local: dict[str, object] = {}
    for name, path in LOCAL_PATHS.items():
        with contextlib.suppress(OSError, ValueError):
            local[name] = directory_count(Path(path))
    try:
        quarantine = Path("/var/lib/lowerduckpond/static/platform/archive-quarantine.json")
        quarantine.lstat()
        local["quarantine"] = True
    except FileNotFoundError:
        # A missing parent is unknown, not proof of absence.
        if quarantine.parent.is_dir():
            local["quarantine"] = False
    except OSError:
        pass
    raw["local"] = local
    journal = bounded_command(
        [
            "journalctl",
            "--no-pager",
            "--output=cat",
            "--lines=20",
            "--grep=^archive_(construction|export|cleanup)_service_failed( |$)",
        ]
    )
    if journal:
        for line in journal.decode("utf-8", errors="replace").splitlines():
            if re.match(r"^archive_(construction|export|cleanup)_service_failed ", line):
                raw["service"] = diagnostic(line)
    try:
        selected = Path("/opt/lowerduckpond/static-host-agent/current").resolve(strict=True)
        if selected.parent != Path("/opt/lowerduckpond/static-host-agent") or not DIGEST.fullmatch(
            selected.name
        ):
            raise ValueError("invalid selected artifact")
        raw["artifact_sha256"] = selected.name
        sys.path.insert(0, str(selected / "site-packages"))
        if UUID.fullmatch(correlation):
            with contextlib.suppress(Exception):
                raw["job"] = job_observation(correlation)
        # This is a runtime-key observation, never the independent operator proof.
        raw["remote"] = remote_observation()
    except Exception:
        raw["remote"] = {"category": "archive_configuration"}
    return sanitize(raw)


def main() -> None:
    # Termination cannot be swallowed by the optional per-section exception
    # handlers, allowing later SDK work to run without a remaining deadline.
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(45)  # Also bounds the host process if the controller disconnects.
    correlation = sys.argv[1] if len(sys.argv) == PROBE_ARGUMENT_COUNT else UNKNOWN
    print(json.dumps(probe(correlation), sort_keys=True))


if __name__ == "__main__":
    main()
