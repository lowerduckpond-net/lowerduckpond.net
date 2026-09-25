"""Converge or inspect the original qualified, dark M3.11 production transaction."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.backup_identity import RepositoryIdentity

from scripts import m3_10_qualification_report as qualification
from scripts import m3_11_production_journal as journal
from scripts import m3_11_production_preflight as preflight
from scripts import m3_11_production_workflow as workflow
from scripts import m3_11_qualification_evidence as evidence
from scripts import production_qualification_inputs as inputs
from scripts.m3_11_production_proposals import Proposals
from scripts.m3_11_production_replica import Replica
from scripts.m3_11_production_session import controller

ROOT = Path(__file__).resolve().parents[1]


def _directory(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    journal._metadata(path.stat(follow_symlinks=False), os.geteuid(), 0o700, directory=True)


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _digest(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        journal._metadata(before, os.geteuid(), 0o400)
        result = hashlib.file_digest(stream, "sha256").hexdigest()
        after = path.stat(follow_symlinks=False)
        if any(
            getattr(before, key) != getattr(after, key)
            for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        ):
            raise ValueError("retained production input changed while reading")
        return result


def _retain(path: Path, staged: Path, expected: str) -> None:
    if path.exists() or path.is_symlink():
        if _digest(path) != expected:
            raise ValueError("retained production input differs from the original")
    else:
        if _digest(staged) != expected:
            raise ValueError("staged production input differs from its verified bytes")
        staged.rename(path)
    _sync(path.parent)


class Candidate:
    def __init__(self, state: Path, attempt: Path, original: dict[str, object] | None) -> None:
        self.state, self.attempt = state, attempt
        self.source = inputs.git(ROOT, "rev-parse", "HEAD").decode("ascii").strip()
        self.target = inputs.storage_target_digest()
        self.artifact = state / "artifact.tar"
        if original is None:
            staged = attempt / "artifact.tar"
            raw = preflight.run(
                attempt,
                "build-artifact",
                [str(ROOT / "scripts/build-static-host-agent"), str(staged)],
            )
            expected = raw.decode("ascii").strip()
            journal._hex(expected)
            staged.chmod(0o400)
            with staged.open("rb") as stream:
                os.fsync(stream.fileno())
            _retain(self.artifact, staged, expected)
        self.artifact_sha256 = _digest(self.artifact)
        self.report_path = state / "qualification.json"
        self.original = original

    def qualify(self, report_path: Path, *, completed: bool) -> None:
        if completed:
            raw, report = evidence.read_document(self.report_path)
            candidate = cast(dict[str, str], cast(dict[str, object], self.original)["candidate"])
            current = inputs.candidate_inputs(ROOT, self.source, self.artifact_sha256)
            if (
                not inputs.equivalent_completion(
                    ROOT,
                    source=self.source,
                    completed=candidate["source_revision"],
                    artifact=self.artifact_sha256,
                )
                or current != candidate["qualification_inputs_sha256"]
            ):
                raise ValueError("completed rollout requires its equivalent original inputs")
            inputs.assert_not_revoked(
                inputs.current_candidate(ROOT, self.source),
                source=candidate["source_revision"],
                artifact=self.artifact_sha256,
                inputs=current,
                report=raw,
            )
        else:
            raw = qualification.verify_report(
                report_path,
                source=self.source,
                artifact=self.artifact_sha256,
                repository=ROOT,
                storage_target=self.target,
                milestone="3.11",
            )
            report = json.loads(raw)
        self.raw, self.report = raw, report
        self.completed = completed
        self.binding = {
            **{key: report[key] for key in journal.CANDIDATE - {"report_sha256"}},
            "report_sha256": journal.digest(raw),
        }
        if (
            report["artifact_sha256"] != self.artifact_sha256
            or report["storage_target_sha256"] != self.target
            or (self.original is not None and self.original["candidate"] != self.binding)
        ):
            raise ValueError("production candidate changed its original qualification")
        staged = self.attempt / "qualification.json"
        preflight.save(staged, raw)
        staged.chmod(0o400)
        with staged.open("rb") as stream:
            os.fsync(stream.fileno())
        _retain(self.report_path, staged, journal.digest(raw))
        self.guard()

    def guard(self) -> None:
        # Initial qualification checks all committed input contents. Thereafter
        # require the same clean HEAD and immutable retained report/artifact.
        inputs.current_candidate(ROOT, self.source)
        if (
            inputs.storage_target_digest() != self.target
            or _digest(self.artifact) != self.artifact_sha256
            or _digest(self.report_path) != journal.digest(self.raw)
        ):
            raise ValueError("production inputs changed during the original transaction")
        if not self.completed:
            evidence.timestamp(
                self.report["oldest_evidence_at"],
                now=datetime.now(UTC),
                maximum_age=qualification.PROVIDER_EVIDENCE_MAX_AGE,
            )


def _credentials(directory: Path) -> None:
    preflight.run(
        directory,
        "credentials",
        [
            "uv",
            "run",
            "--quiet",
            "--frozen",
            "ldp-m3-archive",
            "credential-check",
            "--backup-bucket",
            os.environ["SPACES_BACKUP_BUCKET"],
            "--archive-bucket",
            os.environ["SPACES_ARCHIVE_BUCKET"],
            "--region",
            os.environ["SPACES_REGION"],
        ],
    )


def _controls(pair: Replica, directory: Path) -> None:
    chain = pair.synchronize()
    original = cast(dict[str, object], journal.validate(chain)["original"])
    observed = workflow.action(pair, "observe")
    if (
        observed.get("format") != "lowerduckpond-m3-11-production-observation-v1"
        or observed.get("original_sha256") != journal.digest(chain[0][1])
        or observed.get("last_sha256") != journal.digest(chain[-1][1])
        or RepositoryIdentity(
            cast(str, observed["repository_config_id"]),
            cast(str, observed["repository_node"]),
            cast(str, observed["repository_locator"]),
        ).binding()["value"]
        != original["repository_binding"]
    ):
        raise ValueError("production observation changed the original repository authority")
    authority = cast(dict[str, object], observed["archive_authority"])
    authority_path = directory / "archive-authority.json"
    preflight.save(authority_path, journal.canonical(authority))
    preflight.run(
        directory,
        "operator",
        [
            str(ROOT / "scripts/check-m3-6-operator-identity"),
            os.environ["ANSIBLE_PRIVATE_KEY_FILE"],
        ],
    )
    # An interrupted convergence may legitimately have Caddy stopped. Its
    # initial dark-host proof and phase-bound root observer remain authority;
    # final acceptance must restore service before completion is published.
    if journal.validate(chain)["phase"] == "complete":
        preflight.run(
            directory, "dark-host", [str(ROOT / "scripts/preflight-m3-dark-host-production")]
        )
    preflight.run(
        directory,
        "provider",
        [
            sys.executable,
            "-m",
            "scripts.check_m3_10_provider",
            "--allow-existing-archives",
            "--archive-authority",
            str(authority_path),
            "--artifact",
            cast(str, authority["artifactSha256"]),
            "--source",
            cast(str, authority["sourceRevision"]),
        ],
    )
    preflight.run(
        directory, "firewall", [sys.executable, "-m", "scripts.check_m3_10_host_firewall"]
    )
    preflight.run(
        directory, "backup-policy", [sys.executable, "-m", "scripts.check_m3_11_backup_policy"]
    )


def _original(candidate: Candidate, observed: dict[str, object]) -> bytes:
    if (
        observed["storage_target_sha256"] != candidate.target
        or observed["candidate_source"] != candidate.source
    ):
        raise ValueError("production preflight changed its qualified inputs")
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return journal.canonical(
        {
            "format": journal.FORMAT,
            "transaction_id": str(uuid.uuid7()),
            "started_at": now,
            "candidate": candidate.binding,
            "predecessor": cast(dict[str, object], observed["observation"])["predecessor"],
            "repository_binding": observed["repository_binding"],
            "namespace": {
                "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
                "kind": "PlatformNamespace",
                "tenantOriginSuffix": "lowerduckpond.com",
                "initializedAt": now,
            },
        }
    )


def execute(state: Path, attempt: Path, report: Path) -> None:
    for name in ("journal", "proposals"):
        _directory(state / name)
    _sync(state)
    with (
        journal.locked(state / "journal", owner=os.geteuid(), create=True) as local,
        journal.locked(state / "proposals", owner=os.geteuid(), create=True) as retained,
    ):
        chain = retained.records()
        status = journal.validate(chain)
        original = cast(dict[str, object] | None, status.get("original"))
        candidate = Candidate(state, attempt, original)
        candidate.qualify(report, completed=status["phase"] == "complete")
        checks = attempt / "preflight"
        _directory(checks)
        _credentials(checks)
        raw = _original(candidate, preflight.preflight(checks)) if original is None else None
        candidate.guard()
        logs = attempt / "remote"
        _directory(logs)
        with controller(preflight.ssh(), logs) as session:
            pair, proposals = Replica(local, session), Proposals(retained, attempt)
            proposals.recover(pair)
            if raw is not None:
                proposals.publish(pair, "original", raw)
            else:
                _controls(pair, checks)
            workflow.run(pair, candidate.artifact, proposals, candidate.guard)


def main() -> int:
    attempt: Path | None = None
    try:
        if len(sys.argv) != 1:
            raise ValueError("unexpected production controller arguments")
        report = Path(os.environ["M3_11_QUALIFICATION_REPORT"])
        state = Path(
            os.environ.get(
                "M3_11_PRODUCTION_STATE_DIRECTORY", str(report.parent / "production-convergence")
            )
        )
        if not report.is_absolute() or not state.is_absolute():
            raise ValueError("production report and state directory must be absolute")
        _directory(state)
        _directory(state / "attempts")
        attempt = Path(tempfile.mkdtemp(prefix="attempt-", dir=state / "attempts"))
        _sync(state / "attempts")
        execute(state, attempt, report)
    except ValueError, OSError, KeyError, TypeError, RecursionError:
        print(
            f"M3.11 production transaction failed. Private diagnostics: {attempt or 'not created'}",
            file=sys.stderr,
        )
        return 1
    print(f"M3.11 dark production transaction verified. Original records: {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
