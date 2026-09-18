from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lowerduckpond_m3_archive.report import ArchiveQualificationReport
from lowerduckpond_m3_archive.storage import AcceptanceEvidence

from scripts import production_qualification_inputs
from scripts.m3_10_qualification_report import (
    EMPTY_ACCOUNTING,
    PHASES,
    create_report,
    verify_report,
)
from scripts.production_qualification_inputs import (
    REVOCATIONS,
    candidate_inputs,
    equivalent_completion,
    fingerprint,
    git,
)

ROOT = Path(__file__).parents[2]
ARTIFACT = "b" * 64
TARGET = "c" * 64


def commit(repository: Path) -> str:
    git(repository, "add", ".")
    git(repository, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture revision")
    return git(repository, "rev-parse", "HEAD").decode().strip()


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "Qualification fixture")
    git(root, "config", "user.email", "qualification@example.test")
    git(root, "config", "core.hooksPath", "/dev/null")
    (root / REVOCATIONS).parent.mkdir(parents=True)
    (root / REVOCATIONS).write_bytes((ROOT / REVOCATIONS).read_bytes())
    (root / "runtime.py").write_text("qualified = True\n")
    return root, commit(root)


@pytest.mark.parametrize(
    "path", ["docs/records/convergence.md", "docs/threat-model/evidence/run/qualification.json"]
)
def test_record_only_descendant_reuses_inputs_without_rewriting_source(
    repository: tuple[Path, str], path: str
) -> None:
    root, source = repository
    original = fingerprint(root, source)
    record = root / path
    record.parent.mkdir(parents=True)
    record.write_text("historical evidence\n")
    descendant = commit(root)
    assert descendant != source
    assert fingerprint(root, descendant) == original
    assert equivalent_completion(root, source=descendant, completed=source, artifact=ARTIFACT)


@pytest.mark.parametrize(
    "path",
    [
        "runtime.py",
        "uv.lock",
        "config/ansible/roles/caddy/tasks/main.yml",
        "config/ansible/molecule/m3_8/tests/test_lifecycle.py",
        "docs/adr/security.md",
        "docs/plans/milestone-3.md",
        "docs/operations/runbook.md",
        "new-unknown-file",
        "docs/records/tool.py",
    ],
)
def test_runtime_policy_harness_requirements_and_unknown_inputs_invalidate(
    repository: tuple[Path, str], path: str
) -> None:
    root, source = repository
    changed = root / path
    changed.parent.mkdir(parents=True, exist_ok=True)
    changed.write_text("changed input\n")
    descendant = commit(root)
    assert not equivalent_completion(root, source=descendant, completed=source, artifact=ARTIFACT)


def test_executable_record_is_an_input(repository: tuple[Path, str]) -> None:
    root, source = repository
    record = root / "docs/records/executable.md"
    record.parent.mkdir(parents=True)
    record.write_text("executable record\n")
    record.chmod(0o755)
    assert not equivalent_completion(root, source=commit(root), completed=source, artifact=ARTIFACT)


def test_symbolic_record_cannot_hide_an_external_input(repository: tuple[Path, str]) -> None:
    root, _ = repository
    record = root / "docs/records/symlink.md"
    record.parent.mkdir(parents=True)
    record.symlink_to("../../runtime.py")
    with pytest.raises(ValueError, match="unsupported"):
        candidate_inputs(root, commit(root), ARTIFACT)


@pytest.mark.parametrize("dirty", ["tracked", "untracked", "staged"])
def test_dirty_candidate_cannot_use_committed_evidence(
    repository: tuple[Path, str], dirty: str
) -> None:
    root, source = repository
    (root / ("untracked" if dirty == "untracked" else "runtime.py")).write_text("drift\n")
    if dirty == "staged":
        git(root, "add", ".")
    with pytest.raises(ValueError, match="clean"):
        candidate_inputs(root, source, ARTIFACT)


def test_missing_and_nonancestor_sources_fail_closed(repository: tuple[Path, str]) -> None:
    root, source = repository
    with pytest.raises(ValueError, match="Git inputs"):
        equivalent_completion(root, source=source, completed="0" * 40, artifact=ARTIFACT)
    git(root, "checkout", "--quiet", "--orphan", "unrelated")
    (root / "runtime.py").write_text("unrelated root commit\n")
    unrelated = commit(root)
    with pytest.raises(ValueError, match="Git inputs"):
        equivalent_completion(root, source=unrelated, completed=source, artifact=ARTIFACT)


def test_revoked_artifact_never_inherits_completion(repository: tuple[Path, str]) -> None:
    root, source = repository
    policy = json.loads((root / REVOCATIONS).read_text())
    policy["artifacts"] = [ARTIFACT]
    (root / REVOCATIONS).write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="revoked"):
        equivalent_completion(root, source=commit(root), completed=source, artifact=ARTIFACT)


@pytest.fixture
def evidence(repository: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root, source = repository
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setattr(production_qualification_inputs, "storage_target_digest", lambda: TARGET)
    production_qualification_inputs.capture_run(run, repository=root, source=source)
    (run / "source-revision").write_text(source + "\n")
    ArchiveQualificationReport.create(
        AcceptanceEvidence(True, True, True, True, True, True, True), source_revision=source
    ).write(run / "storage.json")
    for phase in PHASES[:-1]:
        (run / f"{phase}.passed").write_text("passed\n")
    (run / "installed.json").write_text(
        json.dumps({"artifact_sha256": ARTIFACT, **EMPTY_ACCOUNTING})
    )
    (run / "final-proof.started-at").write_text(
        datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    (run / "destroy.passed").write_text("passed\n")
    report = run / "qualification.json"
    report.write_text(json.dumps(create_report(run, repository=root, storage_target=TARGET)))
    return report


def test_bound_report_retains_original_bytes_across_record_only_commit(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, source = repository
    before = evidence.read_bytes()
    record = root / "docs/records/deployed.md"
    record.parent.mkdir(parents=True)
    record.write_text("deployment complete\n")
    verify_report(
        evidence, source=commit(root), artifact=ARTIFACT, repository=root, storage_target=TARGET
    )
    assert evidence.read_bytes() == before
    assert json.loads(before)["source_revision"] == source


@pytest.mark.parametrize("days,accepted", [(2, True), (6, True), (8, False), (-1, False)])
def test_provider_evidence_uses_the_original_oldest_timestamp(
    repository: tuple[Path, str], evidence: Path, days: int, accepted: bool
) -> None:
    root, source = repository
    report = json.loads(evidence.read_text())
    timestamp = (datetime.now(UTC) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
    for field in ("completed_at", "oldest_evidence_at"):
        report[field] = timestamp
    evidence.write_text(json.dumps(report))
    if accepted:
        verify_report(
            evidence, source=source, artifact=ARTIFACT, repository=root, storage_target=TARGET
        )
    else:
        with pytest.raises(ValueError, match="stale or future"):
            verify_report(
                evidence, source=source, artifact=ARTIFACT, repository=root, storage_target=TARGET
            )


@pytest.mark.parametrize(
    "field,value",
    [
        ("qualification_inputs_sha256", "f" * 64),
        ("input_policy", "unknown"),
        ("storage_target_sha256", "f" * 64),
        ("phases", {}),
        ("format", "diagnostic"),
    ],
)
def test_partial_foreign_or_relabelled_evidence_fails(
    repository: tuple[Path, str], evidence: Path, field: str, value: object
) -> None:
    root, source = repository
    report = json.loads(evidence.read_text())
    report[field] = value
    evidence.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        verify_report(
            evidence, source=source, artifact=ARTIFACT, repository=root, storage_target=TARGET
        )


def test_refreshed_envelope_does_not_refresh_oldest_evidence(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, source = repository
    report = json.loads(evidence.read_text())
    report["oldest_evidence_at"] = (
        (datetime.now(UTC) - timedelta(days=8)).isoformat().replace("+00:00", "Z")
    )
    evidence.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="stale"):
        verify_report(
            evidence, source=source, artifact=ARTIFACT, repository=root, storage_target=TARGET
        )


def test_revoked_report_fails_before_equivalence(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, _ = repository
    policy = json.loads((root / REVOCATIONS).read_text())
    policy["reports"] = [hashlib.sha256(evidence.read_bytes()).hexdigest()]
    (root / REVOCATIONS).write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="revoked"):
        verify_report(
            evidence, source=commit(root), artifact=ARTIFACT, repository=root, storage_target=TARGET
        )


def test_worktree_changes_do_not_alter_historical_fingerprint(repository: tuple[Path, str]) -> None:
    root, source = repository
    before = fingerprint(root, source)
    (root / "runtime.py").write_text("uncommitted drift\n")
    assert fingerprint(root, source) == before


def test_executable_mode_change_invalidates(repository: tuple[Path, str]) -> None:
    root, source = repository
    (root / "runtime.py").chmod(0o755)
    assert not equivalent_completion(root, source=commit(root), completed=source, artifact=ARTIFACT)


def test_legacy_report_cannot_be_promoted_across_record_only_revision(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, _ = repository
    legacy = create_report(evidence.parent)
    evidence.write_text(json.dumps(legacy))
    record = root / "docs/records/closeout.md"
    record.parent.mkdir(parents=True)
    record.write_text("complete\n")
    with pytest.raises(ValueError, match="source and artifact"):
        verify_report(
            evidence, source=commit(root), artifact=ARTIFACT, repository=root, storage_target=TARGET
        )


def test_v2_packaging_cannot_refresh_an_expired_phase(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, _ = repository
    timestamp = (datetime.now(UTC) - timedelta(days=2)).timestamp()
    os.utime(evidence.parent / "verify.passed", (timestamp, timestamp))
    with pytest.raises(ValueError, match="stale"):
        create_report(evidence.parent, repository=root, storage_target=TARGET)


@pytest.mark.parametrize(
    "field,value", [("sources", [1]), ("artifacts", "all"), ("format", "unknown")]
)
def test_malformed_revocation_policy_fails_closed(
    repository: tuple[Path, str], field: str, value: object
) -> None:
    root, _ = repository
    policy = json.loads((root / REVOCATIONS).read_text())
    policy[field] = value
    (root / REVOCATIONS).write_text(json.dumps(policy))
    with pytest.raises(ValueError, match="revocation"):
        candidate_inputs(root, commit(root), ARTIFACT)


def test_shallow_candidate_fails_closed(repository: tuple[Path, str], tmp_path: Path) -> None:
    root, source = repository
    destination = tmp_path / "shallow"
    git(root, "clone", "--quiet", "--depth=1", root.as_uri(), str(destination))
    with pytest.raises(ValueError, match="complete candidate"):
        candidate_inputs(destination, source, ARTIFACT)


@pytest.mark.parametrize("target_change", ["none", "region", "archive", "backup", "legacy"])
def test_cli_binds_completion_to_each_storage_target_input(
    repository: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    target_change: str,
) -> None:
    root, source = repository
    keys = {
        "region": "SPACES_REGION",
        "archive": "SPACES_ARCHIVE_BUCKET",
        "backup": "SPACES_BACKUP_BUCKET",
    }
    for label, key in keys.items():
        monkeypatch.setenv(key, "nyc3" if label == "region" else f"fixture-{label}")
    original_target = production_qualification_inputs.storage_target_digest()
    if target_change in keys:
        monkeypatch.setenv(keys[target_change], "ams3")
    target = production_qualification_inputs.storage_target_digest()
    monkeypatch.setattr(production_qualification_inputs, "ROOT", root)
    monkeypatch.setattr(
        "sys.argv",
        [
            "inputs",
            "--source",
            source,
            "--artifact",
            ARTIFACT,
            "--completed-source",
            source,
            "--completed-storage-target",
            "" if target_change == "legacy" else original_target,
        ],
    )
    assert production_qualification_inputs.main() == 0
    mode = "completed" if target_change == "none" else "changed"
    assert capsys.readouterr().out == f"{mode} {target}\n"


def test_storage_target_requires_all_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SPACES_REGION", "nyc3")
    monkeypatch.setenv("SPACES_ARCHIVE_BUCKET", "fixture-archive")
    monkeypatch.delenv("SPACES_BACKUP_BUCKET", raising=False)
    with pytest.raises(ValueError, match="storage target"):
        production_qualification_inputs.storage_target_digest()


def test_packaging_cannot_bind_old_proof_to_a_new_target(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, _ = repository
    with pytest.raises(ValueError, match="inputs changed"):
        create_report(evidence.parent, repository=root, storage_target="d" * 64)


def test_input_capture_cannot_overwrite_existing_run(
    repository: tuple[Path, str], evidence: Path
) -> None:
    root, source = repository
    with pytest.raises(FileExistsError):
        production_qualification_inputs.capture_run(evidence.parent, repository=root, source=source)
