from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from lowerduckpond_m3_archive.report import ArchiveQualificationReport
from lowerduckpond_m3_archive.storage import AcceptanceEvidence

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_qualification_evidence as combined
from scripts.production_qualification_inputs import (
    POLICY,
    REVOCATIONS,
    candidate_inputs,
    fingerprint,
    git,
)

ARTIFACT = "b" * 64
TARGET = "c" * 64
ROOT = Path(__file__).resolve().parents[2]


def utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def commit(repository: Path) -> str:
    git(repository, "add", ".")
    git(repository, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fixture revision")
    return git(repository, "rev-parse", "HEAD").decode().strip()


def mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def child(value: dict[str, object], *keys: str) -> dict[str, object]:
    for key in keys:
        value = mapping(value[key])
    return value


@dataclass
class Run:
    repository: Path
    source: str
    directory: Path

    def create(self) -> dict[str, object]:
        return reports.create_report(
            self.directory, repository=self.repository, storage_target=TARGET, milestone="3.11"
        )

    def verify(self, report: dict[str, object], *, source: str | None = None) -> bytes:
        raw = combined.canonical_bytes(report)
        path = self.directory / "qualification.json"
        path.write_bytes(raw)
        verified = reports.verify_report(
            path,
            source=source or self.source,
            artifact=ARTIFACT,
            repository=self.repository,
            storage_target=TARGET,
            milestone="3.11",
        )
        assert verified == raw
        assert path.read_bytes() == raw
        return verified


@pytest.fixture
def run(tmp_path: Path) -> Run:
    repository = tmp_path / "repository"
    repository.mkdir()
    git(repository, "init", "--quiet")
    git(repository, "config", "user.name", "Qualification fixture")
    git(repository, "config", "user.email", "qualification@example.test")
    git(repository, "config", "core.hooksPath", "/dev/null")
    (repository / REVOCATIONS).parent.mkdir()
    (repository / REVOCATIONS).write_bytes((ROOT / REVOCATIONS).read_bytes())
    (repository / "runtime.py").write_text("qualified = True\n")
    source = commit(repository)
    directory = tmp_path / "evidence"
    directory.mkdir()
    start = datetime.now(UTC) - timedelta(minutes=5)
    binding = {
        "source_revision": source,
        "artifact_sha256": ARTIFACT,
        "input_policy": POLICY,
        "qualification_inputs_sha256": fingerprint(repository, source),
        "storage_target_sha256": TARGET,
    }
    captured = {key: value for key, value in binding.items() if key != "artifact_sha256"}
    (directory / "qualification-inputs.json").write_bytes(combined.canonical_bytes(captured))
    (directory / "source-revision").write_text(source + "\n")
    storage = ArchiveQualificationReport.create(
        AcceptanceEvidence(True, True, True, True, True, True, True), source_revision=source
    )
    replace(storage, generated_at=utc(start)).write(directory / "storage.json")
    for index, phase in enumerate(reports.PHASES):
        path = directory / f"{phase}.passed"
        path.write_text("passed\n")
        offset = {"verify": 110, "destroy": 130}.get(phase, index)
        moment = (start + timedelta(seconds=offset)).timestamp()
        os.utime(path, (moment, moment))
    installed = directory / "installed.json"
    installed.write_bytes(
        combined.canonical_bytes({"artifact_sha256": ARTIFACT, **reports.EMPTY_ACCOUNTING})
    )
    moment = (start + timedelta(seconds=105)).timestamp()
    os.utime(installed, (moment, moment))
    (directory / "final-proof.started-at").write_text(utc(start + timedelta(seconds=120)))
    run_id = str(uuid.uuid7())
    nonce = str(uuid.uuid7())
    context: dict[str, object] = {
        "format": combined.CONTEXT_FORMAT,
        "run_id": run_id,
        "captured_at": utc(start + timedelta(seconds=10)),
        **binding,
        "storage_run_id": storage.run_id,
        "storage_report_sha256": hashlib.sha256(
            (directory / "storage.json").read_bytes()
        ).hexdigest(),
        **{key: hashlib.sha256(key.encode()).hexdigest() for key in combined.IDENTITY_FIELDS},
        "subject_set_sha256": combined.subject_digest(nonce),
    }
    proof = {
        "format": combined.FORMAT,
        "environment": combined.ENVIRONMENT,
        "context": context,
        "phases": {
            name: {
                "started_at": utc(start + timedelta(seconds=20 + index * 10)),
                "completed_at": utc(start + timedelta(seconds=25 + index * 10)),
                "checks": dict.fromkeys(checks, "passed"),
                "evidence_sha256": hashlib.sha256(name.encode()).hexdigest(),
            }
            for index, (name, checks) in enumerate(combined.PHASE_CHECKS.items())
        },
        "recovery": {
            **dict.fromkeys(combined.RECOVERY_FIELDS, "d" * 64),
            "protected_segments": 2,
            "retained_releases": 4,
            "tenant_states": dict.fromkeys(("active", "suspended", "archived", "undeployed"), 1),
        },
        "public_ca": {
            "issuer": combined.ISSUER,
            "trust": "system-public-roots",
            "subject_count": 4,
            "zone_count": 2,
            "certificates_sha256": "e" * 64,
        },
        "accounting": {
            **dict.fromkeys(combined.ZERO_ACCOUNTING, 0),
            "source_state": "fenced",
            "source_fence_sha256": "f" * 64,
            "source_pending_inputs_sha256": "a" * 64,
            "destination_quarantine": False,
        },
        "teardown": dict.fromkeys(combined.ZERO_TEARDOWN, 0),
    }
    names = {
        "format": combined.NAMES_FORMAT,
        "run_id": run_id,
        "nonce": nonce,
        "subjects": combined.subjects(nonce),
    }
    for name, value, offset in (
        ("combined-context.json", context, 10),
        ("combined-names.json", names, 10),
        ("combined.json", proof, 100),
    ):
        path = directory / name
        path.write_bytes(combined.canonical_bytes(value))
        moment = (start + timedelta(seconds=offset)).timestamp()
        os.utime(path, (moment, moment))
    return Run(repository, source, directory)


def rehash(report: dict[str, object]) -> None:
    report["combined_report_sha256"] = hashlib.sha256(
        combined.canonical_bytes(report["combined"])
    ).hexdigest()


def test_complete_combined_report_keeps_original_evidence_and_named_checks(run: Run) -> None:
    proof_raw = (run.directory / "combined.json").read_bytes()
    storage_raw = (run.directory / "storage.json").read_bytes()
    report = run.create()
    assert report["format"] == combined.REPORT_FORMAT
    assert report["combined_report_sha256"] == hashlib.sha256(proof_raw).hexdigest()
    assert combined.canonical_bytes(report["combined"]) == proof_raw
    assert report["phases"] == dict.fromkeys(reports.PHASES, "passed")
    context = child(report, "combined", "context")
    assert context["storage_run_id"] == report["storage_run_id"]
    assert context["storage_report_sha256"] == hashlib.sha256(storage_raw).hexdigest()
    raw = run.verify(report)
    assert b"lowerduckpond.net" not in raw  # Public report contains only the subject digest.
    assert b"secret-canary" not in raw
    assert (run.directory / "storage.json").read_bytes() == storage_raw


@pytest.mark.parametrize("replacement", [b"{}\n", None])
def test_verified_bytes_survive_report_path_replacement_during_input_checks(
    run: Run, monkeypatch: pytest.MonkeyPatch, replacement: bytes | None
) -> None:
    original = combined.canonical_bytes(run.create())
    path = run.directory / "qualification.json"
    path.write_bytes(original)

    def replace_during_check(repository: Path, source: str, artifact: str) -> str:
        inputs = candidate_inputs(repository, source, artifact)
        if replacement is None:
            path.unlink()
        else:
            changed = path.with_suffix(".replacement")
            changed.write_bytes(replacement)
            changed.replace(path)
        return inputs

    monkeypatch.setattr(reports, "candidate_inputs", replace_during_check)
    verified = reports.verify_report(
        path,
        source=run.source,
        artifact=ARTIFACT,
        repository=run.repository,
        storage_target=TARGET,
        milestone="3.11",
    )
    assert verified == original
    if replacement is None:
        assert not path.exists()
    else:
        assert path.read_bytes() == replacement


@pytest.mark.parametrize("boundary", ["before-start", "during-teardown", "before-completion"])
def test_packaging_rejects_receipts_written_before_all_checks_complete(
    run: Run, boundary: str
) -> None:
    path = run.directory / "combined.json"
    original, proof = combined.read_document(path)
    phases = child(proof, "phases")
    if boundary == "before-start":
        moment = child(phases, "backup-mutation-overlap")["started_at"]
    elif boundary == "during-teardown":
        moment = child(phases, "owned-teardown")["started_at"]
    else:
        moment = child(phases, "owned-teardown")["completed_at"]
    assert isinstance(moment, str)
    timestamp = (datetime.fromisoformat(moment) - timedelta(milliseconds=1)).timestamp()
    os.utime(path, (timestamp, timestamp))
    with pytest.raises(ValueError, match="original context and proof"):
        run.create()
    assert path.read_bytes() == original


def test_receipt_written_at_completion_is_accepted(run: Run) -> None:
    path = run.directory / "combined.json"
    _, proof = combined.read_document(path)
    moment = child(proof, "phases", "owned-teardown")["completed_at"]
    assert isinstance(moment, str)
    timestamp = datetime.fromisoformat(moment).timestamp()
    os.utime(path, (timestamp, timestamp))
    run.verify(run.create())


@pytest.mark.parametrize("fault", ["another-run", "changed-bytes"])
def test_packaging_rejects_another_legacy_run_with_identical_candidate_and_chronology(
    run: Run, fault: str
) -> None:
    path = run.directory / "storage.json"
    raw, storage = combined.read_document(path)
    if fault == "another-run":
        storage["run_id"] = str(uuid.uuid7())
        changed = combined.canonical_bytes(storage)
    else:
        changed = raw + b"\n"  # Same ID and semantics, different original report bytes.
    replace_file(path, changed)
    with pytest.raises(ValueError, match="identity"):
        run.create()
    assert path.read_bytes() == changed


@pytest.mark.parametrize("key", ["storage_run_id", "storage_report_sha256"])
def test_consumption_rejects_combined_receipt_moved_to_another_legacy_envelope(
    run: Run, key: str
) -> None:
    report = run.create()
    report[key] = str(uuid.uuid7()) if key == "storage_run_id" else "0" * 64
    with pytest.raises(ValueError, match="identity"):
        run.verify(report)


@pytest.mark.parametrize("milestone", ["3.10", "3.11"])
def test_legacy_and_combined_reports_cannot_satisfy_each_others_gate(
    run: Run, milestone: str
) -> None:
    report = (
        run.create()
        if milestone == "3.10"
        else reports.create_report(run.directory, repository=run.repository, storage_target=TARGET)
    )
    path = run.directory / "qualification.json"
    path.write_bytes(combined.canonical_bytes(report))
    with pytest.raises(ValueError):
        reports.verify_report(
            path,
            source=run.source,
            artifact=ARTIFACT,
            repository=run.repository,
            storage_target=TARGET,
            milestone=milestone,
        )


@pytest.mark.parametrize("phase", combined.PHASE_CHECKS)
@pytest.mark.parametrize("status", ["missing", "skipped", "failed"])
def test_every_combined_phase_is_required(run: Run, phase: str, status: str) -> None:
    report = run.create()
    phases = child(report, "combined", "phases")
    if status == "missing":
        del phases[phase]
    else:
        checks = child(phases, phase, "checks")
        checks[next(iter(checks))] = status
    rehash(report)
    with pytest.raises(ValueError):
        run.verify(report)


@pytest.mark.parametrize(
    "phase,check",
    [(phase, check) for phase, checks in combined.PHASE_CHECKS.items() for check in checks],
)
def test_no_individual_installed_check_can_be_omitted(run: Run, phase: str, check: str) -> None:
    report = run.create()
    del child(report, "combined", "phases", phase, "checks")[check]
    rehash(report)
    with pytest.raises(ValueError, match="every declared check"):
        run.verify(report)


@pytest.mark.parametrize("key", combined.BINDING_FIELDS)
def test_combined_evidence_cannot_be_mixed_between_candidates_or_targets(
    run: Run, key: str
) -> None:
    report = run.create()
    child(report, "combined", "context")[key] = "foreign"
    rehash(report)
    with pytest.raises(ValueError, match="identity"):
        run.verify(report)


@pytest.mark.parametrize(
    "part",
    [
        (),
        ("context",),
        ("recovery",),
        ("public_ca",),
        ("accounting",),
        ("teardown",),
        ("phases",),
        ("phases", "reconstruction"),
        ("phases", "reconstruction", "checks"),
    ],
)
def test_unknown_fields_are_rejected_before_sharing(run: Run, part: tuple[str, ...]) -> None:
    report = run.create()
    child(report, "combined", *part)["credential"] = "secret-canary"
    rehash(report)
    with pytest.raises(ValueError):
        run.verify(report)


@pytest.mark.parametrize(
    "container,field",
    [("accounting", key) for key in combined.ZERO_ACCOUNTING]
    + [("teardown", key) for key in combined.ZERO_TEARDOWN],
)
@pytest.mark.parametrize("value", [1, False, 0.0, "0", -1])
def test_unsettled_or_coerced_accounting_cannot_qualify(
    run: Run, container: str, field: str, value: object
) -> None:
    report = run.create()
    child(report, "combined", container)[field] = value
    rehash(report)
    with pytest.raises(ValueError, match="count"):
        run.verify(report)


@pytest.mark.parametrize(
    "container,field,value",
    [
        ("recovery", "protected_segments", 1),
        ("recovery", "retained_releases", True),
        ("public_ca", "subject_count", 3),
        ("public_ca", "zone_count", True),
        ("public_ca", "issuer", "https://acme-staging-v02.api.letsencrypt.org/directory"),
        ("public_ca", "trust", "local-ca"),
        ("accounting", "source_state", "unknown"),
        ("accounting", "destination_quarantine", 0),
    ],
)
def test_insufficient_reconstruction_or_public_ca_proof_is_rejected(
    run: Run, container: str, field: str, value: object
) -> None:
    report = run.create()
    child(report, "combined", container)[field] = value
    rehash(report)
    with pytest.raises(ValueError):
        run.verify(report)


@pytest.mark.parametrize(
    "bad_run", ["00000000-0000-0000-0000-000000000000", str(uuid.uuid4()), "latest", 1]
)
def test_public_names_require_canonical_run_identity(bad_run: object) -> None:
    with pytest.raises(ValueError):
        combined.subjects(bad_run)


def test_public_subjects_are_four_run_owned_names_in_two_zones() -> None:
    run_id = str(uuid.uuid7())
    names = combined.subjects(run_id)
    assert len(names) == 4  # noqa: PLR2004 - two apex/wildcard pairs
    assert all("m3-11-" + uuid.UUID(run_id).hex in name for name in names)
    assert sum(name.startswith("*.") for name in names) == 2  # noqa: PLR2004 - both zones
    assert sum(name.endswith(".lowerduckpond.net") for name in names) == 2  # noqa: PLR2004
    assert sum(name.endswith(".lowerduckpond.com") for name in names) == 2  # noqa: PLR2004
    assert combined.subject_digest(run_id) != combined.subject_digest(str(uuid.uuid7()))


@pytest.mark.parametrize("fault", ["same-host", "local", "diagnostic", "receipt-hash"])
def test_local_relabelled_or_unbound_proofs_fail(run: Run, fault: str) -> None:
    report = run.create()
    context = child(report, "combined", "context")
    if fault == "same-host":
        context["destination_fixture_sha256"] = context["source_fixture_sha256"]
    elif fault == "local":
        child(report, "combined")["environment"] = "minio"
    elif fault == "diagnostic":
        child(report, "combined")["format"] = "diagnostic-only"
    if fault != "receipt-hash":
        rehash(report)
    else:
        report["combined_report_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        run.verify(report)


def test_record_only_descendant_reuses_exact_report_bytes(run: Run) -> None:
    report = run.create()
    original = run.verify(report)
    record = run.repository / "docs/records/complete.md"
    record.parent.mkdir(parents=True)
    record.write_text("Original deployment recorded.\n")
    descendant = commit(run.repository)
    assert run.verify(report, source=descendant) == original
    assert report["source_revision"] == run.source


@pytest.mark.parametrize(
    "field,value",
    [("runtime.py", "changed input\n"), ("docs/records/tool.py", "new executable input\n")],
)
def test_changed_candidate_inputs_cannot_reuse_report(run: Run, field: str, value: str) -> None:
    report = run.create()
    path = run.repository / field
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    with pytest.raises(ValueError, match="inputs or storage target"):
        run.verify(report, source=commit(run.repository))


def test_revoked_combined_report_cannot_be_reused(run: Run) -> None:
    report = run.create()
    raw = run.verify(report)
    path = run.repository / REVOCATIONS
    revocations = json.loads(path.read_bytes())
    revocations["reports"] = [hashlib.sha256(raw).hexdigest()]
    path.write_text(json.dumps(revocations))
    with pytest.raises(ValueError, match="revoked"):
        run.verify(report, source=commit(run.repository))


def replace_file(path: Path, raw: bytes) -> None:
    before = path.stat()
    path.write_bytes(raw)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))


@pytest.mark.parametrize(
    "fault", ["production", "foreign-run", "foreign-nonce", "shared-nonce", "foreign-digest"]
)
def test_packaging_binds_private_public_ca_names_without_disclosing_them(
    run: Run, fault: str
) -> None:
    path = run.directory / "combined-names.json"
    _, names = combined.read_document(path)
    if fault == "production":
        names["subjects"] = [
            "lowerduckpond.net",
            "*.lowerduckpond.net",
            "lowerduckpond.com",
            "*.lowerduckpond.com",
        ]
    elif fault == "foreign-run":
        names["run_id"] = str(uuid.uuid7())
    elif fault == "foreign-nonce":
        names["nonce"] = str(uuid.uuid7())
    elif fault == "shared-nonce":
        names["nonce"] = names["run_id"]
        names["subjects"] = combined.subjects(names["nonce"])
    else:
        proof_path = run.directory / "combined.json"
        _, proof = combined.read_document(proof_path)
        child(proof, "context")["subject_set_sha256"] = "a" * 64
        replace_file(proof_path, combined.canonical_bytes(proof))
        replace_file(
            run.directory / "combined-context.json", combined.canonical_bytes(proof["context"])
        )
    replace_file(path, combined.canonical_bytes(names))
    with pytest.raises(ValueError, match="subjects"):
        run.create()


@pytest.mark.parametrize(
    "name",
    [
        "combined.json",
        "combined-context.json",
        "combined-names.json",
        *(f"{phase}.passed" for phase in reports.PHASES),
    ],
)
def test_combined_evidence_cannot_replace_any_legacy_phase_or_required_input(
    run: Run, name: str
) -> None:
    (run.directory / name).unlink()
    with pytest.raises(OSError):
        run.create()


@pytest.mark.parametrize(
    "name",
    [
        "storage.json",
        "installed.json",
        "qualification-inputs.json",
        "combined.json",
        "combined-context.json",
        "combined-names.json",
    ],
)
def test_duplicate_private_input_fields_cannot_be_silently_overwritten(run: Run, name: str) -> None:
    path = run.directory / name
    raw, document = combined.read_document(path)
    key = next(iter(document))
    duplicate = combined.canonical_bytes({key: document[key]})[1:-2]
    replace_file(path, b"{" + duplicate + b"," + raw[1:])
    with pytest.raises(ValueError, match="duplicate"):
        run.create()


@pytest.mark.parametrize("fault", ["duplicate", "noncanonical", "oversize", "nonobject"])
def test_report_parser_rejects_ambiguous_or_unbounded_documents(run: Run, fault: str) -> None:
    report = run.create()
    raw = combined.canonical_bytes(report)
    if fault == "duplicate":
        raw = b'{"format":"ignored",' + raw[1:]
    elif fault == "noncanonical":
        raw = json.dumps(report, indent=2).encode()
    elif fault == "oversize":
        raw += b" " * combined.MAX_BYTES
    else:
        raw = b"[]"
    path = run.directory / "qualification.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        reports.verify_report(
            path,
            source=run.source,
            artifact=ARTIFACT,
            repository=run.repository,
            storage_target=TARGET,
            milestone="3.11",
        )


def shift_times(document: dict[str, object], delta: timedelta) -> None:
    for key, value in document.items():
        if isinstance(value, dict):
            shift_times(mapping(value), delta)
        elif isinstance(value, str) and value.endswith("Z"):
            # Legacy phase observations use phase names as their keys.
            document[key] = utc(datetime.fromisoformat(value) + delta)


@pytest.mark.parametrize("days,accepted", [(2, True), (6, True), (8, False), (-1, False)])
def test_original_combined_observations_control_seven_day_consumption(
    run: Run, days: int, accepted: bool
) -> None:
    report = run.create()
    shift_times(report, -timedelta(days=days))
    rehash(report)
    if accepted:
        run.verify(report)
    else:
        with pytest.raises(ValueError, match="stale or future"):
            run.verify(report)


def test_refreshed_outer_envelope_cannot_hide_stale_combined_proof(run: Run) -> None:
    report = run.create()
    shift_times(child(report, "combined"), -timedelta(days=8))
    rehash(report)
    with pytest.raises(ValueError, match="stale"):
        run.verify(report)


def test_original_packaging_must_finish_within_twenty_four_hours(run: Run) -> None:
    report = run.create()
    shift_times(report, -timedelta(days=2))
    report["packaged_at"] = utc(datetime.now(UTC))
    rehash(report)
    with pytest.raises(ValueError, match="packaging window"):
        run.verify(report)


@pytest.mark.parametrize(
    "fault",
    [
        "phase-overlap",
        "negative-phase",
        "context-after-proof",
        "proof-after-final",
        "oldest-after-context",
        "packaged-before-final",
        "future-proof",
    ],
)
def test_combined_phase_and_envelope_chronology_is_mandatory(run: Run, fault: str) -> None:
    report = run.create()
    first = child(report, "combined", "phases", "backup-mutation-overlap")
    second = child(report, "combined", "phases", "protected-rotation")
    if fault == "phase-overlap":
        second["started_at"] = first["started_at"]
    elif fault == "negative-phase":
        first["started_at"] = second["started_at"]
    elif fault == "context-after-proof":
        child(report, "combined", "context")["captured_at"] = second["started_at"]
    elif fault == "proof-after-final":
        report["completed_at"] = first["completed_at"]
    elif fault == "oldest-after-context":
        report["oldest_evidence_at"] = first["started_at"]
    elif fault == "packaged-before-final":
        report["packaged_at"] = first["started_at"]
    else:
        first["started_at"] = utc(datetime.now(UTC) + timedelta(seconds=1))
    rehash(report)
    with pytest.raises(ValueError):
        run.verify(report)


@pytest.mark.parametrize("name", ["combined.json", "combined-context.json", "combined-names.json"])
def test_packaging_rejects_expired_or_late_created_private_inputs(run: Run, name: str) -> None:
    path = run.directory / name
    # An input created after the final proof cannot attest to the earlier run.
    path.touch()
    with pytest.raises(ValueError, match="original context"):
        run.create()
    timestamp = (datetime.now(UTC) - timedelta(days=2)).timestamp()
    os.utime(path, (timestamp, timestamp))
    with pytest.raises(ValueError, match="stale"):
        run.create()


def test_milestone_evidence_requires_bound_repository_and_known_version(run: Run) -> None:
    with pytest.raises(ValueError, match="Git inputs"):
        reports.create_report(run.directory, milestone="3.11")
    with pytest.raises(ValueError, match="unknown qualification milestone"):
        reports.create_report(run.directory, milestone="future")


def test_cli_preserves_explicit_milestone_and_never_overwrites_evidence(
    run: Run, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(reports, "ROOT", run.repository)
    monkeypatch.setattr(reports, "storage_target_digest", lambda: TARGET)
    arguments = ["report", str(run.directory), "--milestone", "3.11"]
    monkeypatch.setattr("sys.argv", arguments)
    assert reports.main() == 0
    assert "Sanitized M3.11" in capsys.readouterr().out
    path = run.directory / "qualification.json"
    original = path.read_bytes()
    checksum = (run.directory / "qualification.sha256").read_text()
    assert checksum == hashlib.sha256(original).hexdigest() + "  qualification.json\n"
    with pytest.raises(SystemExit) as caught:
        reports.main()
    assert caught.value.code == 1
    assert path.read_bytes() == original
    monkeypatch.setattr(
        "sys.argv",
        [
            "report",
            str(path),
            "--milestone",
            "3.11",
            "--verify",
            "--source",
            run.source,
            "--artifact",
            ARTIFACT,
        ],
    )
    assert reports.main() == 0
    assert "M3.11 live qualification binds" in capsys.readouterr().out


@pytest.mark.parametrize(
    "fault",
    ["late-storage", "early-installed", "late-combined", "early-destroy", "reordered-setup"],
)
def test_combined_envelope_retains_and_checks_the_complete_legacy_chronology(
    run: Run, fault: str
) -> None:
    report = run.create()
    observations = child(report, "legacy_observations")
    phases = child(observations, "phases")
    if fault == "late-storage":
        observations["storage_at"] = phases["verify"]
    elif fault == "early-installed":
        observations["installed_at"] = phases["prepare"]
    elif fault == "late-combined":
        phases["verify"] = child(report, "combined", "phases", "backup-mutation-overlap")[
            "completed_at"
        ]
    elif fault == "early-destroy":
        phases["destroy"] = phases["verify"]
    else:
        phases["prepare"], phases["converge"] = phases["converge"], phases["prepare"]
    with pytest.raises(ValueError, match="legacy observation chronology"):
        run.verify(report)
