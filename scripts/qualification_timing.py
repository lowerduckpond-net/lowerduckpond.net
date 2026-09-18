"""Allowlisted monotonic diagnostics; timing output never authorizes qualification."""

from __future__ import annotations

import argparse
import contextlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import TypedDict, cast

ROOT = Path(__file__).resolve().parents[1]
EVENT_ENV = "LDP_QUALIFICATION_TIMING_EVENTS"
CONTEXT_ENV = "LDP_QUALIFICATION_TIMING_GROUP"
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
KINDS = frozenset(
    {
        "create",
        "prepare",
        "converge",
        "idempotence",
        "verify",
        "destroy",
        "cleanup",
        "group",
        "pacing",
        "operator",
        "ansible-reapply",
        "reboot",
        "reboot-caddy",
        "reboot-reconcile",
        "other-playbook",
    }
)
MAX_EVENTS_BYTES = 8 * 1024 * 1024
FORMAT = "lowerduckpond-qualification-timing-v1"
MAX_CPU_COUNT = 4096
POLICY = "production-admission-conservative-host-clock-v1"


class Event(TypedDict):
    kind: str
    group: str
    start_ns: int
    elapsed_ns: int
    outcome: str


class Category(TypedDict):
    kind: str
    group: str
    count: int
    failed: int
    summed_seconds: float
    union_seconds: float


def record_span(kind: str, start: int, outcome: str = "completed") -> None:
    """Best-effort fixed fields only; never serialize arguments or exceptions."""
    destination = os.environ.get(EVENT_ENV)
    if not destination:
        return
    try:
        group = os.environ.get(CONTEXT_ENV, "unclassified")
        if kind not in KINDS or group not in GROUPS or outcome not in {"completed", "failed"}:
            raise ValueError("unknown timing label")
        event: Event = {
            "kind": kind,
            "group": group,
            "start_ns": start,
            "elapsed_ns": max(0, time.monotonic_ns() - start),
            "outcome": outcome,
        }
        raw = (json.dumps(event, separators=(",", ":")) + "\n").encode("ascii")
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size >= MAX_EVENTS_BYTES:
                raise OSError("timing budget exhausted")
            os.write(descriptor, raw)
        finally:
            os.close(descriptor)
    except Exception:  # Timing diagnostics must not replace the command result.
        # Missing events are visible as incomplete attribution, never a test pass.
        print("Qualification timing event unavailable.", file=sys.stderr)


@contextlib.contextmanager
def measure(kind: str) -> Iterator[None]:
    start = time.monotonic_ns()
    outcome = "failed"
    try:
        yield
        outcome = "completed"
    finally:
        record_span(kind, start, outcome)


def _tool_output(arguments: list[str]) -> str:
    executable = shutil.which(arguments[0])
    if executable is None:
        return "unknown"
    try:
        result = subprocess.run(  # noqa: S603 - fixed read-only metadata commands
            [executable, *arguments[1:]],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except Exception:  # Metadata queries are optional diagnostics.
        return "unknown"
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _version(value: str) -> str:
    return value if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value) else "unknown"


def capture_fixture_identity() -> None:
    try:
        _capture_fixture_identity()
    except Exception:
        print("Qualification timing fixture identity unavailable.", file=sys.stderr)


def _capture_fixture_identity() -> None:
    destination = os.environ.get(EVENT_ENV)
    if not destination:
        return
    path = Path(destination).with_name("timing-fixture.json")
    if path.exists():
        return
    selected = _tool_output(
        [
            "docker",
            "exec",
            "lowerduckpond-ubuntu-2604",
            "readlink",
            "--canonicalize-existing",
            "/opt/lowerduckpond/static-host-agent/current",
        ]
    )
    matched = re.fullmatch(r"/opt/lowerduckpond/static-host-agent/([0-9a-f]{64})", selected)
    image = _tool_output(
        ["docker", "inspect", "--format", "{{.Image}}", "lowerduckpond-ubuntu-2604"]
    )
    observed = {
        "artifact_sha256": matched[1] if matched else "unknown",
        "image_sha256": image[7:] if re.fullmatch(r"sha256:[0-9a-f]{64}", image) else "unknown",
    }
    try:
        with path.open("x", encoding="ascii") as stream:
            json.dump(observed, stream)
    except OSError:
        print("Qualification timing fixture identity unavailable.", file=sys.stderr)


def _read(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("timing input is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("timing input exceeds budget")
        return raw
    finally:
        os.close(descriptor)


def start_run(directory: Path, backend: str) -> None:
    started = time.monotonic_ns()
    versions = {"python": platform.python_version()}
    for package in ("ansible-core", "molecule", "molecule-plugins", "pytest", "pytest-testinfra"):
        try:
            versions[package] = _version(importlib.metadata.version(package))
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "unknown"
    versions["uv"] = _version(_tool_output(["uv", "--version"]).removeprefix("uv "))
    versions["docker"] = _version(
        _tool_output(["docker", "version", "--format", "{{.Server.Version}}"])
    )
    source = _tool_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    tree_status = _tool_output(
        ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"]
    )
    metadata = {
        "format": FORMAT,
        "started_ns": started,
        "scenario": "m3_8",
        "source_revision": source if re.fullmatch(r"[0-9a-f]{40}", source) else "unknown",
        "backend": backend if backend in {"minio", "spaces"} else "unknown",
        "policy": POLICY,
        "source_tree_state": "unknown"
        if tree_status == "unknown"
        else ("dirty" if tree_status else "clean"),
        "runner": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "workstation",
        "architecture": platform.machine()
        if platform.machine() in {"x86_64", "aarch64"}
        else "unknown",
        "cpu_count": os.cpu_count(),
        "kernel_version": _version(platform.release().split("-")[0]),
        "tools": versions,
        # Queue/setup outside this entry point come from the CI job metadata.
        "queue_seconds": None,
        "cache_state": "unmeasured",
        "operator_interventions": None,
    }
    with (directory / "timing-start.json").open("x", encoding="ascii") as stream:
        json.dump(metadata, stream, sort_keys=True)
        stream.write("\n")
    (directory / "timing-events.jsonl").touch(exist_ok=False)


def _metadata(directory: Path) -> dict[str, object]:
    value = json.loads(_read(directory / "timing-start.json", 8192))
    keys = {
        "format",
        "started_ns",
        "scenario",
        "source_revision",
        "backend",
        "policy",
        "runner",
        "architecture",
        "cpu_count",
        "kernel_version",
        "tools",
        "queue_seconds",
        "cache_state",
        "operator_interventions",
        "source_tree_state",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("invalid timing metadata fields")
    if (
        value["format"] != FORMAT
        or value["scenario"] != "m3_8"
        or value["policy"] != POLICY
        or value["source_tree_state"] not in {"clean", "dirty", "unknown"}
        or value["backend"] not in {"minio", "spaces", "unknown"}
        or value["runner"] not in {"github-actions", "workstation"}
        or value["architecture"] not in {"x86_64", "aarch64", "unknown"}
        or value["queue_seconds"] is not None
        or value["operator_interventions"] is not None
        or value["cache_state"] != "unmeasured"
        or (
            value["source_revision"] != "unknown"
            and re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]) is None
        )
        or (
            value["cpu_count"] is not None
            and (type(value["cpu_count"]) is not int or not 0 < value["cpu_count"] <= MAX_CPU_COUNT)
        )
        or (value["kernel_version"] != "unknown" and _version(value["kernel_version"]) == "unknown")
    ):
        raise ValueError("invalid timing metadata values")
    versions = value["tools"]
    if (
        not isinstance(versions, dict)
        or set(versions)
        != {
            "python",
            "ansible-core",
            "molecule",
            "molecule-plugins",
            "pytest",
            "pytest-testinfra",
            "uv",
            "docker",
        }
        or any(
            not isinstance(version, str)
            or (version != "unknown" and _version(version) == "unknown")
            for version in versions.values()
        )
    ):
        raise ValueError("invalid timing versions")
    return dict(value)


def union_ns(intervals: Sequence[tuple[int, int]]) -> int:
    total = 0
    end = 0
    for start, stop in sorted(intervals):
        total += max(0, stop - max(start, end))
        end = max(end, stop)
    return total


def _events(path: Path) -> list[Event]:
    raw = _read(path, MAX_EVENTS_BYTES)
    events: list[Event] = []
    for line in raw.splitlines():
        event = json.loads(line)
        if (
            not isinstance(event, dict)
            or set(event) != {"kind", "group", "start_ns", "elapsed_ns", "outcome"}
            or event["kind"] not in KINDS
            or event["group"] not in GROUPS
            or event["outcome"] not in {"completed", "failed"}
            or type(event["start_ns"]) is not int
            or event["start_ns"] < 0
            or type(event["elapsed_ns"]) is not int
            or event["elapsed_ns"] < 0
        ):
            raise ValueError("invalid timing event")
        events.append(cast(Event, event))
    return events


def finish_run(directory: Path, status: int) -> dict[str, object]:
    ended = time.monotonic_ns()
    metadata = _metadata(directory)
    started = metadata.pop("started_ns")
    if metadata["format"] != FORMAT or type(started) is not int or not 0 <= started <= ended:
        raise ValueError("invalid timing start")
    events = _events(directory / "timing-events.jsonl")
    if any(e["start_ns"] < started or e["start_ns"] + e["elapsed_ns"] > ended for e in events):
        raise ValueError("timing events span different runs")
    categories: list[Category] = []
    for kind, group in sorted({(e["kind"], e["group"]) for e in events}):
        selected = [e for e in events if e["kind"] == kind and e["group"] == group]
        intervals = [(e["start_ns"], e["start_ns"] + e["elapsed_ns"]) for e in selected]
        categories.append(
            {
                "kind": kind,
                "group": group,
                "count": len(selected),
                "failed": sum(e["outcome"] == "failed" for e in selected),
                "summed_seconds": sum(e["elapsed_ns"] for e in selected) / 1e9,
                "union_seconds": union_ns(intervals) / 1e9,
            }
        )
    fixture = {"artifact_sha256": "unknown", "image_sha256": "unknown"}
    identity_path = directory / "timing-fixture.json"
    if identity_path.exists():
        observed = json.loads(_read(identity_path, 1024))
        if (
            not isinstance(observed, dict)
            or set(observed) != set(fixture)
            or any(
                not isinstance(value, str)
                or (value != "unknown" and re.fullmatch(r"[0-9a-f]{64}", value) is None)
                for value in observed.values()
            )
        ):
            raise ValueError("invalid fixture identity")
        fixture = observed
    all_intervals = [(e["start_ns"], e["start_ns"] + e["elapsed_ns"]) for e in events]
    covered = union_ns(all_intervals)
    report: dict[str, object] = {
        **metadata,
        **fixture,
        "exit_status": status,
        "elapsed_seconds": (ended - started) / 1e9,
        "instrumented_union_seconds": covered / 1e9,
        "outside_instrumentation_seconds": (ended - started - covered) / 1e9,
        "categories": categories,
        "event_count": len(events),
        "authority": "diagnostic-only",
    }
    (directory / "timing.json").write_text(
        json.dumps(report, sort_keys=True) + "\n", encoding="ascii"
    )
    lines = [f"Qualification elapsed: {(ended - started) / 1e9:.1f}s; exit status: {status}."]
    lines.extend(
        f"{row['kind']} / {row['group']}: {row['summed_seconds']:.1f}s summed; "
        f"{row['union_seconds']:.1f}s union; {row['count']} spans."
        for row in categories
    )
    lines.append("Categories overlap; do not add them to obtain elapsed time.")
    (directory / "timing.txt").write_text("\n".join(lines) + "\n", encoding="ascii")
    print(lines[0])
    for row in sorted(
        (row for row in categories if row["kind"] == "group"),
        key=lambda row: row["union_seconds"],
        reverse=True,
    )[:5]:
        print(f"  {row['group']}: {row['union_seconds']:.1f}s")
    print(f"Timing diagnostics: {directory / 'timing.json'}")
    return report


def child_environment(directory: Path) -> dict[str, str]:
    return {
        **os.environ,
        EVENT_ENV: str(directory / "timing-events.jsonl"),
        CONTEXT_ENV: "unclassified",
        "ANSIBLE_CONFIG": str(ROOT / "config/ansible/ansible.cfg"),
        "ANSIBLE_CALLBACK_PLUGINS": str(ROOT / "config/ansible/plugins/callback"),
        "ANSIBLE_CALLBACKS_ENABLED": "ldp_timing",
    }


def run_command(command: list[str], directory: Path | None) -> int:
    root = (
        Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
        / "lowerduckpond.net/qualification"
    )
    try:
        if directory is None:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory = Path(tempfile.mkdtemp(prefix="timing-", dir=root))
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = directory.resolve()
        start_run(directory, os.environ.get("M3_10_ARCHIVE_BACKEND", "minio"))
    except Exception:  # Timing diagnostics must not replace the command result.
        print("Qualification timing setup unavailable.", file=sys.stderr)
        directory = None
    environment = child_environment(directory) if directory else os.environ.copy()
    if directory:
        print(f"Qualification timing directory: {directory}", flush=True)
    else:
        environment.pop(EVENT_ENV, None)
        environment.pop(CONTEXT_ENV, None)
    status = 130
    try:
        status = subprocess.call(  # noqa: S603 - explicit local qualification command
            command,
            cwd=ROOT / "config/ansible",
            env=environment,
        )
    except OSError as error:
        status = 127 if isinstance(error, FileNotFoundError) else 126
        print("Qualification command could not be started.", file=sys.stderr)
    finally:
        if directory:
            try:
                finish_run(directory, status)
            except Exception:  # Timing diagnostics cannot replace the command result.
                print("Qualification timing summary unavailable.", file=sys.stderr)
    return status if status >= 0 else 128 - status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    start = sub.add_parser("start")
    start.add_argument("directory", type=Path)
    start.add_argument("--backend", choices=("minio", "spaces"), required=True)
    finish = sub.add_parser("finish")
    finish.add_argument("directory", type=Path)
    finish.add_argument("--status", type=int, required=True)
    run = sub.add_parser("run")
    run.add_argument(
        "--directory", type=Path, default=os.environ.get("LDP_QUALIFICATION_TIMING_DIRECTORY")
    )
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == "run":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            parser.error("a command is required")
        return run_command(command, args.directory)
    try:
        if args.action == "start":
            start_run(args.directory, args.backend)
        else:
            finish_run(args.directory, args.status)
    except Exception:  # Timing diagnostics must not replace the command result.
        parser.exit(1, "Qualification timing diagnostics are unavailable.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
