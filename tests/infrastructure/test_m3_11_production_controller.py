"""The executable controller consumes original proof and preserves its provenance."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest

from infrastructure.test_m3_11_production_journal import records as records  # noqa: PLC0414
from infrastructure.test_m3_11_production_replica import OWNER, snapshot
from infrastructure.test_m3_11_production_workflow import Actions
from infrastructure.test_m3_11_qualification_report import (
    TARGET,
    Run,
    child,
    commit,
    rehash,
    shift_times,
)
from infrastructure.test_m3_11_qualification_report import run as run  # noqa: PLC0414
from scripts import m3_11_production_controller as rollout
from scripts import m3_11_production_converge as converge
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_preflight as preflight
from scripts import production_qualification_inputs as inputs
from scripts.m3_11_production_replica import Replica
from scripts.m3_11_production_session import Session

ARTIFACT = b"original qualified artifact fixture\n"


@pytest.fixture
def prepared(run: Run, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    monkeypatch.setattr(rollout, "ROOT", run.repository)
    monkeypatch.setattr(inputs, "storage_target_digest", lambda: TARGET)
    state, attempt = run.directory / "production", run.directory / "attempt"
    for path in (state, attempt):
        path.mkdir(mode=0o700)
    report = run.create()
    report["artifact_sha256"] = journal.digest(ARTIFACT)
    child(report, "combined", "context")["artifact_sha256"] = journal.digest(ARTIFACT)
    rehash(report)
    path = run.directory / "qualification.json"
    path.write_bytes(journal.canonical(report))

    def build(directory: Path, name: str, command: list[str]) -> bytes:
        assert name == "build-artifact" and command == [
            str(run.repository / "scripts/build-static-host-agent"),
            str(directory / "artifact.tar"),
        ]
        (directory / "artifact.tar").write_bytes(ARTIFACT)
        return (journal.digest(ARTIFACT) + "\n").encode()

    monkeypatch.setattr(preflight, "run", build)
    return state, attempt, path


def original(candidate: rollout.Candidate) -> dict[str, object]:
    return cast(
        dict[str, object],
        json.loads(
            rollout._original(
                candidate,
                {
                    "storage_target_sha256": TARGET,
                    "candidate_source": candidate.source,
                    "observation": {"predecessor": "f" * 64 + " " + "1" * 40 + " " + TARGET + "\n"},
                    "repository_binding": "2" * 64,
                },
            )
        ),
    )


def test_candidate_retains_exact_report_and_qualified_source_across_records_only_descendant(
    run: Run, prepared: tuple[Path, Path, Path]
) -> None:
    state, attempt, report = prepared
    raw = report.read_bytes()
    directory = run.repository / "docs/records"
    directory.mkdir(parents=True)
    (directory / "rollout.md").write_text("Original completion evidence.\n")
    consumer = commit(run.repository)
    candidate = rollout.Candidate(state, attempt, None)
    candidate.qualify(report, completed=False)
    proposal = original(candidate)
    assert candidate.source == consumer != run.source
    assert cast(dict[str, str], proposal["candidate"])["source_revision"] == run.source
    assert (state / "qualification.json").read_bytes() == raw
    assert journal.validate([("original", journal.canonical(proposal))])["phase"] == "original"


@pytest.mark.parametrize("fault", ["artifact", "report", "worktree", "head", "target"])
def test_phase_guard_refuses_changed_original_inputs(
    run: Run, prepared: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    state, attempt, report = prepared
    candidate = rollout.Candidate(state, attempt, None)
    candidate.qualify(report, completed=False)
    if fault in {"artifact", "report"}:
        path = candidate.artifact if fault == "artifact" else candidate.report_path
        path.chmod(0o600)
        path.write_bytes(b"changed\n")
        path.chmod(0o400)
    elif fault in {"worktree", "head"}:
        (run.repository / "runtime.py").write_text("changed = True\n")
        if fault == "head":
            commit(run.repository)
    else:
        monkeypatch.setattr(inputs, "storage_target_digest", lambda: "f" * 64)
    with pytest.raises(ValueError):
        candidate.guard()


def test_completed_original_does_not_require_new_qualification_or_rebuild(
    run: Run, prepared: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    state, attempt, report = prepared
    # Model a previously accepted original proof whose original timestamps have
    # aged. The completion's report hash continues to bind those exact bytes.
    document = json.loads(report.read_bytes())
    shift_times(document, timedelta(days=-30))
    rehash(document)
    raw = journal.canonical(document)
    (state / "artifact.tar").write_bytes(ARTIFACT)
    (state / "artifact.tar").chmod(0o400)
    (state / "qualification.json").write_bytes(raw)
    (state / "qualification.json").chmod(0o400)
    binding = {key: document[key] for key in journal.CANDIDATE - {"report_sha256"}}
    binding["report_sha256"] = journal.digest(raw)
    prior: dict[str, object] = {"candidate": binding}
    before = (state / "qualification.json").stat()
    candidate = rollout.Candidate(state, attempt, prior)
    candidate.qualify(report, completed=True)
    assert candidate.raw == raw and candidate.report_path.stat().st_ino == before.st_ino
    assert candidate.report_path.stat().st_mtime_ns == before.st_mtime_ns
    assert not (attempt / "artifact.tar").exists()
    candidate.guard()
    # The same old proof cannot authorize unfinished phase work.
    candidate.completed = False
    with pytest.raises(ValueError, match="stale"):
        candidate.guard()


def test_resumed_transaction_cannot_accept_another_report(
    prepared: tuple[Path, Path, Path],
) -> None:
    state, attempt, report = prepared
    candidate = rollout.Candidate(state, attempt, None)
    candidate.qualify(report, completed=False)
    proposal = original(candidate)
    other = state.parent / "second-attempt"
    other.mkdir(mode=0o700)
    changed = json.loads(report.read_bytes())
    changed["storage_report_sha256"] = "9" * 64
    report.write_bytes(journal.canonical(changed))
    before = candidate.report_path.read_bytes()
    with pytest.raises(ValueError):
        rollout.Candidate(state, other, proposal).qualify(report, completed=False)
    assert candidate.report_path.read_bytes() == before


def test_published_input_refuses_symlink_or_changed_bytes_without_overwriting(
    tmp_path: Path,
) -> None:
    target, staged = tmp_path / "original", tmp_path / "staged"
    target.write_bytes(b"original")
    target.chmod(0o400)
    staged.write_bytes(b"proposed")
    staged.chmod(0o400)
    with pytest.raises(ValueError):
        rollout._retain(target, staged, journal.digest(b"proposed"))
    linked = tmp_path / "linked"
    linked.symlink_to(target)
    with pytest.raises(OSError):
        rollout._retain(linked, staged, journal.digest(b"proposed"))
    assert target.read_bytes() == b"original" and staged.read_bytes() == b"proposed"


def test_execute_runs_original_transaction_and_then_only_inspects_completion(
    run: Run,
    prepared: tuple[Path, Path, Path],
    records: list[tuple[str, bytes]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, attempt, report = prepared
    peers: list[Actions] = []
    commands: list[str] = []
    root = state.parent / "host"
    root.mkdir(mode=0o700)
    build = preflight.run

    def run_command(directory: Path, name: str, command: list[str]) -> bytes:
        commands.append(name)
        return build(directory, name, command) if name == "build-artifact" else b""

    @contextmanager
    def session(ssh: list[str], directory: Path) -> Iterator[Session]:
        assert ssh == ["fixture-ssh"]
        peer = Actions(
            root / "m3-11",
            directory / "calls",
            {name: json.loads(raw)["observations"] for name, raw in records[2::2]},
        )
        peers.append(peer)
        yield cast(Session, peer)

    def playbook(pair: Replica, stage: str, artifact: Path, *, idempotent: bool = False) -> str:
        assert journal.validate(pair.synchronize())["phase"] == converge.PHASES[stage][0]
        assert artifact.read_bytes() == ARTIFACT
        peers[-1].actions.append(stage)
        return "a" * 64

    for name in ("SPACES_BACKUP_BUCKET", "SPACES_ARCHIVE_BUCKET", "SPACES_REGION"):
        monkeypatch.setenv(name, "fixture")
    monkeypatch.setattr(rollout, "controller", session)
    monkeypatch.setattr(preflight, "ssh", lambda: ["fixture-ssh"])
    monkeypatch.setattr(preflight, "run", run_command)
    monkeypatch.setattr(
        preflight,
        "preflight",
        lambda _: {
            "candidate_source": run.source,
            "storage_target_sha256": TARGET,
            "observation": {"predecessor": "f" * 64 + " " + "1" * 40 + " " + TARGET + "\n"},
            "repository_binding": "2" * 64,
        },
    )
    monkeypatch.setattr(converge, "playbook", playbook)
    monkeypatch.setattr(rollout, "_controls", lambda pair, _: commands.append("live-controls"))
    rollout.execute(state, attempt, report)
    with journal.locked(state / "journal", owner=OWNER) as local:
        assert local.inspect()["phase"] == "complete"
    before = tuple(
        snapshot(path) for path in (root / "m3-11", state / "journal", state / "proposals")
    )
    second = attempt.with_name("second-attempt")
    second.mkdir(mode=0o700)
    rollout.execute(state, second, report)
    assert peers[-1].actions == ["inspect"]
    assert commands == ["build-artifact", "credentials", "credentials", "live-controls"]
    assert (
        tuple(snapshot(path) for path in (root / "m3-11", state / "journal", state / "proposals"))
        == before
    )


@pytest.mark.parametrize("fault", ["none", "missing-report", "legacy-rollback"])
def test_actual_shell_dispatches_before_legacy_host_mutation(tmp_path: Path, fault: str) -> None:
    commands = tmp_path / "bin"
    commands.mkdir()
    program = (
        f"#!{sys.executable}\n"
        + """
import os,sys
from pathlib import Path
name=Path(sys.argv[0]).name
args=sys.argv[1:]
if name == 'git':
    if 'branch' in args: print('main')
    elif 'rev-parse' in args: print('a'*40)
elif name == 'tofu':
    if 'output' in args: print('{}' if '-json' in args else 'fixture-runtime-value')
elif name == 'uv':
    if 'scripts.m3_11_production_controller' in args:
        assert all(os.environ.get(key) for key in (
            'SPACES_BACKUP_ACCESS_KEY_ID','SPACES_BACKUP_SECRET_ACCESS_KEY',
            'SPACES_ARCHIVE_ACCESS_KEY_ID','SPACES_ARCHIVE_SECRET_ACCESS_KEY',
            'BACKUP_REPOSITORY','ANSIBLE_CONFIG','M3_11_QUALIFICATION_REPORT'))
        print('fixture-controller-dispatched')
    elif any(a.endswith('read_production_ansible_inventory.py') for a in args):
        sys.stdin.read()
        print('192.0.2.1')
    else: raise SystemExit('unexpected uv invocation')
elif name == 'ssh': raise SystemExit('legacy host mutation must not run')
"""
    )
    for command in ("git", "tofu", "uv", "ssh", "ssh-keygen"):
        path = commands / command
        path.write_text(program)
        path.chmod(0o755)
    key = tmp_path / "fixture-key"
    key.touch()
    environment = {
        **os.environ,
        **dict.fromkeys(
            (
                "ADMIN_SOURCE_CIDRS_JSON",
                "CADDY_CLOUDFLARE_API_TOKEN",
                "CADDY_ORIGIN_PULL_CA_PATHS_JSON",
                "OPENTOFU_ENCRYPTION_PASSPHRASE",
                "OPENTOFU_STATE_ACCESS_KEY_ID",
                "OPENTOFU_STATE_BUCKET",
                "OPENTOFU_STATE_SECRET_ACCESS_KEY",
                "RESTIC_PASSWORD",
                "SPACES_REGION",
                "STATIC_OPERATOR_PRINCIPAL",
                "STATIC_OPERATOR_PUBLIC_KEY",
            ),
            "fixture",
        ),
        "PATH": str(commands) + os.pathsep + os.environ["PATH"],
        "ANSIBLE_PRIVATE_KEY_FILE": str(key),
        "CADDY_ORIGIN_PULL_ENFORCEMENT_ENABLED": "true",
        "M3_11_QUALIFICATION_REPORT": ""
        if fault == "missing-report"
        else str(tmp_path / "report.json"),
        "M3_11_PRODUCTION_STATE_DIRECTORY": str(tmp_path / "state"),
        "M3_DARK_HOST_ROLLBACK_ARTIFACT_PATH": "/fixture.tar" if fault == "legacy-rollback" else "",
        "M3_DARK_HOST_ROLLBACK_ARTIFACT_SHA256": "",
    }
    result = subprocess.run(  # noqa: S603 - actual wrapper, fixture-only administrative commands
        [str(Path(__file__).resolve().parents[2] / "scripts/configure-production")],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == (0 if fault == "none" else 2), result.stderr
    assert ("fixture-controller-dispatched" in result.stdout) == (fault == "none")
    assert "legacy host mutation" not in result.stderr
