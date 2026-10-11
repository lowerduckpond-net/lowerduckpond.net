"""Full finalization/report composition with synthetic provider boundaries."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_finalization as recovery
from scripts import m3_11_functional_completion as functional
from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_11_combined_inputs import _environment
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_owned_teardown import nodes
from scripts.m3_11_phase_receipts import FORMAT
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_group_runner import Completion

from .test_m3_11_qualification_report import TARGET, Run, child, mapping
from .test_m3_11_qualification_report import run as run  # noqa: PLC0414 - shared fixture


def prepared(run: Run, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, str], Mock]:
    directory = run.directory.parent / "attempt/qualification/synthetic"
    directory.parent.mkdir(parents=True)
    run.directory.rename(directory)
    run.directory = directory
    proof = mapping(run.create()["combined"])
    context = mapping(proof["context"])
    environment = _environment(directory, str(context["run_id"]), "unix:///synthetic.sock")
    (directory / "combined-phases").mkdir(mode=0o700)
    for name in evidence.PHASE_CHECKS:
        receipt = child(proof, "phases", name)
        opening = {
            "format": FORMAT,
            "context_sha256": functional.digest(context),
            "phase": name,
            "started_at": receipt["started_at"],
        }
        details = (
            {"teardown": proof["teardown"]} if name == "owned-teardown" else {"synthetic": name}
        )
        value = {**opening, "completed_at": receipt["completed_at"], "observations": details}
        write_private(directory / f"combined-phases/{name}.started.json", opening)
        write_private(directory / f"combined-phases/{name}.json", value)
        receipt["evidence_sha256"] = functional.digest(value)
    path = directory / "combined.json"
    mtime = path.stat().st_mtime_ns
    path.write_bytes(evidence.canonical_bytes(proof))
    path.chmod(0o600)
    os.utime(path, ns=(mtime, mtime))
    write_private(
        directory / "combined-assertions.json",
        {key: proof[key] for key in ("recovery", "public_ca", "accounting")},
    )
    write_private(
        directory / "fixture.json",
        {
            "format": "lowerduckpond-m3-11-live-fixture-v1",
            "run_id": context["run_id"],
            "environment": environment,
        },
    )
    for name in functional.FILES:
        path = directory / name
        if not path.exists():
            write_private(path, {"synthetic": name})
        path.chmod(0o600)
    completion = Completion(nodes(environment))
    completion.collected = list(completion.expected)
    completion.reports = {
        node: [(phase, "passed", False) for phase in ("setup", "call", "teardown")]
        for node in completion.expected
    }
    completed = datetime.fromisoformat(str(child(proof, "phases", "owned-teardown")["started_at"]))
    with monkeypatch.context() as patch:
        patch.setattr(functional, "datetime", SimpleNamespace(now=lambda _zone: completed))
        functional.save(directory, completion, 0, environment)
    for name in ("verify.passed", "destroy.passed", "final-proof.started-at"):
        (directory / name).unlink()
    write_private(
        directory.parent.parent / "journey-result.json", {"outcome": "failed", "exit_status": 124}
    )
    storage = Mock(
        environment=environment, binding={key: context[key] for key in evidence.BINDING_FIELDS}
    )
    monkeypatch.setattr(LiveStorage, "_retained", Mock(return_value=storage))
    removal = Mock(root=directory / "owned-teardown")
    removal.root.mkdir(mode=0o700)
    write_private(removal.root / "intent.json", {"synthetic": "original authorization"})
    removal.run.return_value = {"teardown": proof["teardown"]}
    monkeypatch.setattr(recovery, "Teardown", Mock(return_value=removal))
    monkeypatch.setattr(recovery, "require_live", lambda _: None)
    monkeypatch.setattr(recovery, "ROOT", run.repository)
    monkeypatch.setattr(recovery, "storage_target_digest", lambda: TARGET)
    return environment, removal


@pytest.mark.parametrize("failure", ["storage", "destroy", "package"])
def test_late_failure_retries_only_finalization_and_emits_valid_bound_report(
    run: Run, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    environment, removal = prepared(run, monkeypatch)
    original = functional.files(run.directory)
    failure_bytes = (run.directory.parent.parent / "journey-result.json").read_bytes()
    commands = []
    failed = False

    def command(argv: list[str], env: dict[str, str], log: Path, **kwargs: object) -> None:
        nonlocal failed
        name = "destroy" if "molecule" in argv else "storage"
        commands.append(name)
        if name == failure and not failed:
            failed = True
            raise OSError("synthetic external failure")

    monkeypatch.setattr(recovery, "_command", command)
    first, second = run.directory / "retry-one", run.directory / "retry-two"
    first.mkdir(mode=0o700)
    second.mkdir(mode=0o700)
    with monkeypatch.context() as patch:
        if failure == "package":
            patch.setattr(
                reports,
                "publish_report",
                Mock(side_effect=OSError("synthetic publication failure")),
            )
        with pytest.raises(OSError):
            recovery.finish(run.directory, first, environment)
    recovery.finish(run.directory, second, environment)
    report = read_private(run.directory / "qualification.json")
    assert mapping(report["finalization_recovery"])["original_outcome"] == "failed"
    assert functional.files(run.directory) == original
    assert (run.directory.parent.parent / "journey-result.json").read_bytes() == failure_bytes
    assert commands.count("storage") == 2  # noqa: PLR2004 - fresh proof on both attempts
    assert removal.run.call_count == 2  # noqa: PLR2004 - fresh teardown absence on retry
    reports.verify_report(
        run.directory / "qualification.json",
        source=run.source,
        artifact="b" * 64,
        repository=run.repository,
        storage_target=TARGET,
        milestone="3.11",
    )


@pytest.mark.parametrize("fault", ["outcome", "result", "checkpoint", "functional-time"])
def test_stale_recovery_binding_cannot_resume_cleanup_or_package(
    run: Run, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    environment, removal = prepared(run, monkeypatch)
    monkeypatch.setattr(recovery, "_command", lambda *args, **kwargs: None)
    first = run.directory / "first"
    first.mkdir(mode=0o700)
    with monkeypatch.context() as patch:
        patch.setattr(reports, "publish_report", Mock(side_effect=OSError("interrupted")))
        with pytest.raises(OSError):
            recovery.finish(run.directory, first, environment)
    summary = run.directory / "finalization-recovery.json"
    original_summary = summary.read_bytes()
    if fault in {"outcome", "result"}:
        path = run.directory.parent.parent / "journey-result.json"
        value = read_private(path)
        value["outcome" if fault == "outcome" else "exit_status"] = (
            "interrupted" if fault == "outcome" else 1
        )
    else:
        path = run.directory / "functional-completion.json"
        value = read_private(path)
        if fault == "checkpoint":
            value["changed"] = True
        else:
            value["completed_at"] = str(value["completed_at"]).replace("Z", "+00:00")
    path.write_bytes(evidence.canonical_bytes(value))
    removal.reset_mock()
    with pytest.raises(ValueError):
        recovery.finish(run.directory, first, environment)
    removal.run.assert_not_called()
    with pytest.raises(ValueError, match="original evidence binding"):
        run.create()
    assert summary.read_bytes() == original_summary
    assert not (run.directory / "qualification.json").exists()
