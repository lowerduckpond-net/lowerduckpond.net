"""One immutable completion boundary; never replay a functional assertion."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_backup_removal import _once
from scripts.m3_11_owned_teardown import nodes
from scripts.m3_11_phase_receipts import FORMAT as PHASE_FORMAT
from scripts.m3_11_private_inputs import publish_private, read_private, read_private_bytes
from scripts.qualification_group_runner import Completion

FORMAT = "lowerduckpond-m3-11-functional-completion-v1"
PHASES = tuple(evidence.PHASE_CHECKS)[:-1]
FILES = (
    "combined-context.json",
    "combined-names.json",
    "combined-assertions.json",
    "combined.started.json",
    "paired-accounting.json",
    "installed.json",
    "qualification-inputs.json",
    "source-revision",
    "storage.json",
    "live-storage.json",
    "fixture.json",
    "create.passed",
    "prepare.passed",
    "converge.passed",
    "idempotence.passed",
)


def digest(value: object) -> str:
    return hashlib.sha256(evidence.canonical_bytes(value)).hexdigest()


def snapshot(path: Path) -> dict[str, object]:
    before = path.stat()
    raw = read_private_bytes(path)
    after = path.stat()
    if (before.st_ino, before.st_mtime_ns) != (after.st_ino, after.st_mtime_ns):
        raise ValueError("functional completion input changed while reading")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "mtime_ns": before.st_mtime_ns}


def files(directory: Path) -> dict[str, object]:
    names = [
        *FILES,
        *(f"combined-phases/{p}{suffix}.json" for p in PHASES for suffix in ("", ".started")),
    ]
    if (directory / "managed-credentials.json").exists():
        names.append("managed-credentials.json")
    return {name: snapshot(directory / name) for name in names}


def phase_receipt(directory: Path, name: str, context: dict[str, object]) -> dict[str, object]:
    opening = read_private(directory / "combined-phases" / f"{name}.started.json")
    value = evidence.fields(
        read_private(directory / "combined-phases" / f"{name}.json"),
        {"format", "context_sha256", "phase", "started_at", "completed_at", "observations"},
    )
    if (
        value["format"] != PHASE_FORMAT
        or value["context_sha256"] != digest(context)
        or value["phase"] != name
        or not value["observations"]
        or opening
        != {key: value[key] for key in ("format", "context_sha256", "phase", "started_at")}
    ):
        raise ValueError("functional phase lost its original observations")
    return {
        "started_at": value["started_at"],
        "completed_at": value["completed_at"],
        "evidence_sha256": digest(value),
        "checks": dict.fromkeys(evidence.PHASE_CHECKS[name], "passed"),
    }


def save(directory: Path, completion: Completion, status: int, environment: dict[str, str]) -> None:
    if completion.expected != nodes(environment) or not completion.passed(status):
        raise ValueError("functional completion requires every pytest stage to pass")
    context = read_private(directory / "combined-context.json")
    tests: dict[str, object] = {
        "nodes": list(completion.expected),
        "collected": completion.collected,
        "reports": {
            key: [list(item) for item in values] for key, values in completion.reports.items()
        },
        "exit_status": status,
    }
    _once(directory / "combined-tests.json", tests)
    publish_private(
        directory / "functional-completion.json",
        {
            "format": FORMAT,
            "context_sha256": digest(context),
            "tests": tests,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "files": files(directory),
            "phases": {name: phase_receipt(directory, name, context) for name in PHASES},
        },
    )


def load(directory: Path, environment: dict[str, str]) -> tuple[Completion, dict[str, object]]:
    if (directory / "diagnostic-origin.json").exists() or (
        directory / "diagnostic-origin.json"
    ).is_symlink():
        raise ValueError("diagnostic continuation has no qualification authority")
    value = evidence.fields(
        read_private(directory / "functional-completion.json"),
        {"format", "context_sha256", "tests", "completed_at", "files", "phases"},
    )
    context = read_private(directory / "combined-context.json")
    if (
        value["format"] != FORMAT
        or value["context_sha256"] != digest(context)
        or value["files"] != files(directory)
    ):
        raise ValueError("original functional completion evidence changed")
    tests = evidence.fields(value["tests"], {"nodes", "collected", "reports", "exit_status"})
    completion = Completion(nodes(environment))
    expected = {
        "nodes": list(completion.expected),
        "collected": list(completion.expected),
        "reports": {
            node: [[stage, "passed", False] for stage in ("setup", "call", "teardown")]
            for node in completion.expected
        },
        "exit_status": 0,
    }
    if (
        tests != expected
        or type(tests["exit_status"]) is not int
        or read_private(directory / "combined-tests.json") != tests
    ):
        raise ValueError("functional completion lacks exact pytest success")
    completion.collected = list(completion.expected)
    completion.reports = {
        node: [(stage, "passed", False) for stage in ("setup", "call", "teardown")]
        for node in completion.expected
    }
    phases = {name: phase_receipt(directory, name, context) for name in PHASES}
    if phases != value["phases"]:
        raise ValueError("original functional phase receipts changed")
    # Functional success is historical evidence. Validate its original 24-hour
    # chronology at completion; live recovery separately requires current lease
    # authority and fresh final absence, without changing these timestamps.
    now = evidence.parse_timestamp(value["completed_at"])
    if now > datetime.now(UTC):
        raise ValueError("functional completion is future-dated")
    previous = evidence.timestamp(context["captured_at"], now=now, maximum_age=timedelta(hours=24))
    for phase in phases.values():
        started, completed = [
            evidence.timestamp(phase[key], now=now, maximum_age=timedelta(hours=24))
            for key in ("started_at", "completed_at")
        ]
        if not previous <= started <= completed:
            raise ValueError("original functional phase chronology changed")
        previous = completed
    completed = evidence.timestamp(value["completed_at"], now=now, maximum_age=timedelta(hours=24))
    if completed < previous:
        raise ValueError("pytest completion precedes its assertions")
    assertions = read_private(directory / "combined-assertions.json")
    evidence._recovery(assertions["recovery"])
    evidence._public_ca(assertions["public_ca"])
    evidence._accounting(assertions["accounting"], dict.fromkeys(evidence.ZERO_TEARDOWN, 0))
    return completion, value
