"""Collect allowlisted failure diagnostics without retrying or changing host state."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.qualification_context import host_name  # noqa: E402
from scripts.qualification_probe import (  # noqa: E402 - standalone entry point import root
    DIGEST,
    OPERATIONS,
    UNKNOWN,
    UUID,
    bounded_command,
    document,
    filesystem,
    label,
    matching,
    sanitize,
)

REQUIRED_TOOLS = ("docker", "git", "rsync", "ssh", "uv")
MAX_HELPERS = 8
MAX_EXIT_STATUS = 255
FORMAT = "lowerduckpond-qualification-failure-v1"
CONTAINER = "lowerduckpond-ubuntu-2604"
PHASES = frozenset(
    {
        "dependencies",
        "state-inputs",
        "provider-preflight",
        "storage-acceptance",
        "create",
        "prepare",
        "converge",
        "idempotence",
        "verify",
        "final-storage-proof",
        "destroy",
        "package",
        "cleanup",
        "syntax",
        "other-playbook",
    }
)
GROUPS = frozenset(
    {
        "unclassified",
        "storage-credentials",
        "archive-credentials",
        "core",
        "export-import",
        "archive",
        "deletion",
        "reboot-capture",
        "reboot-verify",
        "transport-recovery",
        "quarantine-recovery",
        "accounting",
    }
)
FAILURES = frozenset(
    {
        "assertion",
        "operator-transport",
        "admission-burst-exhausted",
        "ordinary-delete-ineligible",
        "test-error",
        "command-failed",
    }
)
TEST_FILES = frozenset(
    {
        "test_lifecycle.py",
        "test_archive_lifecycle.py",
        "test_archive_credentials.py",
        "test_export_import.py",
        "test_deletion.py",
        "test_reboot.py",
        "test_transport_recovery.py",
        "test_quarantine_recovery.py",
        "test_archive_completion.py",
    }
)
MAX_SOURCE_LINE = 100000


def source_line(value: object) -> int | str:
    return value if type(value) is int and 1 <= value <= MAX_SOURCE_LINE else UNKNOWN


def _directory() -> Path | None:
    events = os.environ.get("LDP_QUALIFICATION_TIMING_EVENTS")
    return Path(events).parent if events else None


def _write(path: Path, payload: dict[str, object], *, first: bool = False) -> None:
    # Replacement does not follow an old leaf symlink or block on an old FIFO.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.close()
            if first:
                with suppress(FileExistsError):
                    os.link(temporary, path)
            else:
                temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def _optional(path: Path) -> dict[str, object]:
    try:
        return document(path)
    except Exception:
        return {}


def record_phase(phase: str) -> None:
    directory = _directory()
    if directory and not (directory / "failure-snapshot.json").exists():
        try:
            _write(directory / "failure-phase.json", {"phase": label(phase, PHASES)})
        except Exception:
            print("Qualification diagnostic context unavailable.", file=sys.stderr)


def record_submission(request: dict[str, object]) -> None:
    directory = _directory()
    if directory:
        try:
            _write(
                directory / "failure-submission.json",
                {
                    "operation": label(request.get("operation"), OPERATIONS),
                    "correlation_id": matching(request.get("correlationId"), UUID),
                    "group": label(os.environ.get("LDP_QUALIFICATION_TIMING_GROUP"), GROUPS),
                },
            )
        except Exception:
            print("Qualification submission context unavailable.", file=sys.stderr)


def record_test_failure(category: str, *, file: str = UNKNOWN, line: int | str = UNKNOWN) -> None:
    directory = _directory()
    if directory:
        try:
            submission = _optional(directory / "failure-submission.json")
            _write(
                directory / "failure-test.json",
                {
                    "category": label(category, FAILURES),
                    "group": label(os.environ.get("LDP_QUALIFICATION_TIMING_GROUP"), GROUPS),
                    "file": label(file, TEST_FILES),
                    "line": source_line(line),
                    "submission": {
                        "operation": label(submission.get("operation"), OPERATIONS),
                        "correlation_id": matching(submission.get("correlation_id"), UUID),
                        "group": label(submission.get("group"), GROUPS),
                    },
                },
                first=True,
            )
        except Exception:
            print("Qualification failure context unavailable.", file=sys.stderr)


def capture_fixture() -> None:
    """Bind inspection to this run's concrete container, never a later namesake."""
    directory = _directory()
    if directory is None or (directory / "failure-fixture.json").exists():
        return
    try:
        output = bounded_command(["docker", "inspect", "--format", "{{.Id}}", host_name()])
        identity = matching(output.decode("ascii").strip() if output else None, DIGEST)
        if identity != UNKNOWN:
            _write(directory / "failure-fixture.json", {"container_id": identity})
    except Exception:
        print("Qualification fixture context unavailable.", file=sys.stderr)


def required_tools() -> dict[str, str]:
    result = {}
    for name in REQUIRED_TOOLS:
        try:
            result[name] = "present" if shutil.which(name) else "missing"
        except OSError:
            result[name] = UNKNOWN
    return result


def helper_check() -> str:  # noqa: PLR0911 - distinct bounded environment outcomes
    config = Path(os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))) / "config.json"
    if not config.exists():
        return "not-configured"
    try:
        data = document(config)
        helpers = data.get("credHelpers", {})
        if not isinstance(helpers, dict):
            return UNKNOWN
        names = list(helpers.values())
        if data.get("credsStore"):
            names.append(data["credsStore"])
        if len(names) > MAX_HELPERS or any(
            not isinstance(n, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", n) for n in names
        ):
            return UNKNOWN
        if not names:
            return "not-configured"
        for name in set(names):
            executable = shutil.which(f"docker-credential-{name}")
            if not executable:
                return "missing"
            # Read-only list is a usability check, not registry authentication proof.
            if bounded_command([executable, "list"], timeout=2) is None:
                return "unavailable"
        return "available"
    except OSError, ValueError:
        return UNKNOWN


def temporary_crosses_mount() -> bool | str:
    """Identify the separate-TMPDIR condition rejected by archive sandbox fixtures."""
    identifiers: list[str] = []
    try:
        for path in (Path("/"), Path(tempfile.gettempdir()).resolve()):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with Path(f"/proc/self/fdinfo/{descriptor}").open() as stream:
                    raw = stream.read(4096)
                match = re.search(r"(?m)^mnt_id:\s*([0-9]+)$", raw)
                if match is None:
                    return UNKNOWN
                identifiers.append(match[1])
            finally:
                os.close(descriptor)
    except OSError:
        return UNKNOWN
    return identifiers[0] != identifiers[1]


def _observe(directory: Path, correlation: str) -> tuple[str, dict[str, object]]:
    fixture = _optional(directory / "failure-fixture.json")
    identity = matching(fixture.get("container_id"), DIGEST)
    if identity == UNKNOWN:
        return "unbound", sanitize({})
    output = bounded_command(
        [
            "docker",
            "exec",
            "--interactive",
            identity,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-",
            correlation,
        ],
        timeout=55,
        stdin=(ROOT / "scripts/qualification_probe.py").read_bytes(),
    )
    if output is None:
        return "unavailable", sanitize({})
    try:
        raw = json.loads(output)
        if not isinstance(raw, dict):
            raise ValueError("invalid probe")
        return "observed", sanitize(raw)
    except ValueError:
        return "incomplete", sanitize({})


def _last_submission(directory: Path) -> tuple[str, dict[str, object], str]:
    context = _optional(directory / "failure-test.json")
    group = label(context.get("group"), GROUPS)
    frozen = context.get("submission")
    last = frozen if isinstance(frozen, dict) else _optional(directory / "failure-submission.json")
    correlation = (
        matching(last.get("correlation_id"), UUID) if last.get("group") == group else UNKNOWN
    )
    return group, last, correlation


def capture_failure_observation() -> None:
    """Observe a failed outer playbook before Molecule's existing local teardown."""
    directory = _directory()
    if directory is None or (directory / "failure-snapshot.json").exists():
        return
    try:
        _, _, correlation = _last_submission(directory)
        started = datetime.now(UTC).isoformat()
        host_status, observed = _observe(directory, correlation)
        _write(
            directory / "failure-snapshot.json",
            {
                "started_at": started,
                "completed_at": datetime.now(UTC).isoformat(),
                "correlation_id": correlation,
                "host_status": host_status,
                "observation": observed,
            },
        )
    except Exception:
        print("Qualification failure snapshot unavailable.", file=sys.stderr)


def _snapshot(directory: Path, correlation: str) -> tuple[str, str, dict[str, object]] | None:
    raw = _optional(directory / "failure-snapshot.json")
    try:
        start, end = raw["started_at"], raw["completed_at"]
        if not isinstance(start, str) or not isinstance(end, str):
            return None
        first, last = datetime.fromisoformat(start), datetime.fromisoformat(end)
        if (
            first.tzinfo != UTC
            or last.tzinfo != UTC
            or not first <= last <= datetime.now(UTC)
            or raw.get("host_status") != "observed"
            or raw.get("correlation_id") != correlation
            or not isinstance(raw.get("observation"), dict)
        ):
            return None
        observed = raw["observation"]
        assert isinstance(observed, dict)  # noqa: S101 - validated above
        return first.isoformat(), last.isoformat(), sanitize(observed)
    except KeyError, ValueError:
        return None


def disposition(observation: dict[str, object]) -> str:
    job = observation["job"]
    assert isinstance(job, dict)  # noqa: S101 - sanitized shape
    if (
        job["phase"] == "completed"
        and job["result_status"] == "succeeded"
        and job["execution_validated"] is True
    ):
        return "operation-succeeded"
    if (
        job["phase"] == "failed"
        and job["result_status"] == "failed"
        and job["execution_validated"] is True
    ):
        if job["executor_failure"] is True:
            return "validated-failure-before-execution"
        if job["executor_failure"] is False:
            return "validated-rollback-recorded"
        return UNKNOWN
    if job["phase"] in {"pending", "claimed"} or job["execution_validated"] is False:
        return "unresolved-recovery"
    return UNKNOWN


def local_obligations(observation: dict[str, object]) -> str:
    local = observation["local"]
    assert isinstance(local, dict)  # noqa: S101 - sanitized shape
    if (
        any(type(value) is int and value > 0 for value in local.values())
        or local["quarantine"] is True
    ):
        return "present"
    return UNKNOWN if UNKNOWN in local.values() else "none-observed"


def collect(directory: Path, status: int | None = None, phase: str | None = None) -> Path:
    directory = directory.resolve(strict=True)
    original = _optional(directory / "failure-exit.json")
    if status is None:
        recorded = original.get("exit_status")
        if type(recorded) is not int:
            raise ValueError("no original failure status")
        status = recorded
    if type(status) is not int or not 1 <= status <= MAX_EXIT_STATUS:
        raise ValueError("a nonzero original exit status is required")
    if original and original.get("exit_status") != status:
        raise ValueError("original failure status cannot change")
    context = _optional(directory / "failure-test.json")
    group, last, correlation = _last_submission(directory)
    failed_phase = label(
        original.get("phase")
        or phase
        or ("verify" if context else _optional(directory / "failure-phase.json").get("phase")),
        PHASES,
    )
    if not original:
        _write(directory / "failure-exit.json", {"exit_status": status, "phase": failed_phase})
    started = datetime.now(UTC).isoformat()
    host_status, observed = _observe(directory, correlation)
    completed = datetime.now(UTC).isoformat()
    origin = "fresh" if host_status == "observed" else "unavailable"
    prior = _snapshot(directory, correlation)
    if host_status != "observed" and prior is not None:
        started, completed, observed = prior
        origin = "captured-before-teardown"
    metadata = _optional(directory / "timing-start.json")
    omissions = [
        section
        for section in ("artifact_sha256", "state_filesystem", "local")
        if UNKNOWN in json.dumps(observed[section])
    ]
    remote = observed["remote"]
    if not isinstance(remote, dict) or any(
        remote.get(key) == UNKNOWN for key in ("versions_and_markers", "multipart_uploads")
    ):
        omissions.append("remote")
    if correlation != UNKNOWN and UNKNOWN in json.dumps(observed["job"]):
        omissions.append("job")
    if host_status != "observed":
        omissions.append("host")
    if matching(metadata.get("source_revision"), re.compile(r"[0-9a-f]{40}")) == UNKNOWN:
        omissions.append("source_revision")
    tools = required_tools()
    operation = label(last.get("operation"), OPERATIONS) if correlation != UNKNOWN else UNKNOWN
    report: dict[str, object] = {
        "format": FORMAT,
        "authority": "diagnostic-only",
        "scenario": "m3_8",
        "original_exit_status": status,
        "phase": failed_phase,
        "group": group,
        "last_submission": {
            "correlation_id": correlation,
            "operation": operation,
        },
        "failure_category": label(context.get("category", "command-failed"), FAILURES),
        "test_location": {
            "file": label(context.get("file"), TEST_FILES),
            "line": source_line(context.get("line")),
        },
        "source_revision": matching(metadata.get("source_revision"), re.compile(r"[0-9a-f]{40}")),
        "backend": label(metadata.get("backend"), frozenset({"minio", "spaces"})),
        "observation_started_at": started,
        "observation_completed_at": completed,
        "observation_origin": origin,
        "host_observation": host_status,
        "collection": "partial" if omissions else "complete",
        "collection_omissions": omissions,
        "observation": observed,
        "last_submission_disposition": disposition(observed),
        "local_obligations": local_obligations(observed),
        "journal_scope": "recent-fixture-labels-not-bound-to-last-submission",
        "accounting_authority": "observations-only-not-locked",
        "independent_operator_storage_proof": "not-collected",
        "cleanup_authority": "none",
        "environment": {
            "required_tools": tools,
            "docker_credential_helper": helper_check(),
            "controller_worktree_filesystem": filesystem(ROOT),
            "controller_tmp_filesystem": filesystem(Path(tempfile.gettempdir())),
            "controller_tmp_crosses_mount": temporary_crosses_mount(),
            "filesystem_primitives": "not-tested-read-only",
        },
    }
    destination = directory / "failure.json"
    if destination.exists():
        destination = directory / (
            "failure-observation-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + ".json"
        )
    _write(destination, report)
    print(f"Failure diagnostics: {destination}")
    print(f"  {report['phase']} / {group}: {report['failure_category']}; original exit {status}.")
    print(
        f"  Last submission: {operation}; "
        f"outcome: {report['last_submission_disposition']}; host: {host_status}."
    )
    print(
        f"  Local obligations: {report['local_obligations']}; "
        "independent storage proof: not collected."
    )
    missing = [name for name, state in tools.items() if state == "missing"]
    if missing:
        print("  Controller prerequisites missing: " + ", ".join(missing) + ".")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("directory", type=Path)
    collect_parser.add_argument("--status", type=int)
    collect_parser.add_argument("--phase", choices=sorted(PHASES))
    sub.add_parser("fixture")
    args = parser.parse_args()
    try:
        if args.action == "fixture":
            capture_fixture()
        else:
            collect(args.directory, args.status, args.phase)
    except Exception:
        print(
            "Qualification failure diagnostics unavailable; original failure retained.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
