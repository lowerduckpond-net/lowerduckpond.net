"""Finish a functionally complete managed run; never repeat installed assertions."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import traceback
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts import m3_10_qualification_report as reports
from scripts import m3_11_functional_completion as functional
from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_deadline
from scripts.m3_11_backup_removal import _once
from scripts.m3_11_combined_inputs import environment_for
from scripts.m3_11_dns_witness import removal_absence
from scripts.m3_11_finalization_access import access, require_live
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_owned_teardown import Teardown
from scripts.m3_11_phase_receipts import FORMAT as PHASE_FORMAT
from scripts.m3_11_private_inputs import publish_private as write_private
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_unattended.model import strings
from scripts.m3_11_unattended.state import RunState
from scripts.production_qualification_inputs import candidate_inputs, storage_target_digest
from scripts.qualification_context import run_lease
from scripts.qualification_storage_lease import FD_ENV, storage_lease

ROOT = Path(__file__).resolve().parents[1]
SECONDS = 30 * 60


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def combined(directory: Path, storage: LiveStorage) -> None:
    environment = dict(storage.environment)
    completion, checkpoint = functional.load(directory, environment)
    context = read_private(directory / "combined-context.json")
    evidence.validate_names(directory / "combined-names.json", context)
    phase = directory / "combined-phases/owned-teardown.json"
    opening_path = directory / "combined-phases/owned-teardown.started.json"
    if not opening_path.exists():
        write_private(
            opening_path,
            {
                "format": PHASE_FORMAT,
                "context_sha256": functional.digest(context),
                "phase": "owned-teardown",
                "started_at": now(),
            },
        )
    opening = read_private(opening_path)
    retirement = Teardown(
        directory,
        storage,
        lambda: (
            removal_absence(
                directory,
                storage,
                before_authorization=not (retirement.root / "intent.json").exists(),
            ).sha256
        ),
        guard=lambda: require_live(directory),
    )
    if not (retirement.root / "intent.json").exists():
        retirement.authorize(completion, 0)
    details = retirement.run()
    require_live(directory)
    if not phase.exists():
        write_private(phase, {**opening, "completed_at": now(), "observations": details})
    elif read_private(phase)["observations"] != details:
        raise ValueError("original teardown completion changed")
    phases = evidence.fields(checkpoint["phases"], set(functional.PHASES))
    phases["owned-teardown"] = functional.phase_receipt(directory, "owned-teardown", context)
    envelope = {
        "format": evidence.FORMAT,
        "environment": evidence.ENVIRONMENT,
        "context": context,
        "phases": phases,
        **read_private(directory / "combined-assertions.json"),
        "teardown": details["teardown"],
    }
    evidence.validate(envelope, binding=storage.binding, maximum_age=timedelta(hours=24))
    _once(directory / "combined.json", envelope)


def _command(command: list[str], environment: dict[str, str], log: Path, *, cwd: Path) -> None:
    with log.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        status = subprocess.run(  # noqa: S603 - fixed cleanup/check commands under bounded supervisor
            command,
            cwd=cwd,
            env=environment,
            stdout=stream,
            stderr=stream,
            check=False,
            pass_fds=(int(environment[FD_ENV]),),
        ).returncode
    if status:
        raise ValueError("finalization check failed; original logs retained")


def finish(directory: Path, recovery: Path, environment: dict[str, str]) -> None:
    require_live(directory)
    storage = LiveStorage._retained(environment)
    _, checkpoint = functional.load(directory, environment)
    if (directory / "finalization-recovery.json").exists():
        reports.recovery_summary(directory)
    binding = storage.binding
    if (
        candidate_inputs(ROOT, str(binding["source_revision"]), str(binding["artifact_sha256"]))
        != binding["qualification_inputs_sha256"]
        or storage_target_digest() != binding["storage_target_sha256"]
    ):
        raise ValueError("finalization source, artifact, or target changed")
    combined(directory, storage)
    # The combined command is the final verify task. Its checkpoint binds all
    # preceding installed phases; completing it is the remaining verify work.
    reports.write_once(directory / "verify.passed", b"passed\n")
    proof = now()
    require_live(directory)
    write_private(recovery / "storage-proof.started.json", {"started_at": proof})
    _command(
        [sys.executable, "-m", "scripts.check_m3_10_provider", "--storage-only"],
        environment,
        recovery / "storage-proof.log",
        cwd=ROOT,
    )
    write_private(
        recovery / "storage-proof.completed.json", {"started_at": proof, "completed_at": now()}
    )
    # Preserve an earlier final proof's conservative timestamp. A failed read
    # cannot be turned into success: the fresh successful observation above is
    # retained separately and is mandatory on every recovery invocation.
    if not (directory / "final-proof.started-at").exists():
        reports.write_once(directory / "final-proof.started-at", (proof + "\n").encode("ascii"))
    if not (directory / "destroy.passed").exists():
        require_live(directory)
        _command(
            ["uv", "run", "--frozen", "molecule", "destroy", "--scenario-name", "m3_8"],
            environment,
            recovery / "destroy.log",
            cwd=ROOT / "config/ansible",
        )
        reports.write_once(directory / "destroy.passed", b"passed\n")
    functional.load(directory, environment)
    require_live(directory)
    original = read_private(directory.parent.parent / "journey-result.json")
    summary = directory / "finalization-recovery.json"
    if not summary.exists() and not (directory / "qualification.json").exists():
        write_private(
            summary,
            {
                "functional_completed_at": checkpoint["completed_at"],
                "completed_at": now(),
                "original_outcome": original["outcome"],
                "original_result_sha256": functional.digest(original),
                "checkpoint_sha256": functional.digest(checkpoint),
            },
        )
    reports.publish_report(
        directory,
        repository=ROOT,
        storage_target=str(binding["storage_target_sha256"]),
        milestone="3.11",
    )


def run(directory: Path, recovery: Path) -> None:
    saved = strings(read_private(directory / "fixture.json")["environment"])
    if (directory / "qualification.json").exists():
        # A complete report has already proved final absence. Repairing only
        # its publication pair needs no credentials, new proof, or fixture work.
        with RunState(directory.parent.parent).lock(), run_lease(directory):
            environment = environment_for(directory, {"DOCKER_HOST": saved["DOCKER_HOST"]})
            functional.load(directory, environment)
            context = read_private(directory / "combined-context.json")
            reports.publish_report(
                directory,
                repository=ROOT,
                storage_target=str(context["storage_target_sha256"]),
                milestone="3.11",
            )
        return
    with access(directory) as ambient:
        environment = environment_for(
            directory, {**ambient, "DOCKER_HOST": str(saved["DOCKER_HOST"])}
        )
        with storage_lease(environment) as fd, run_lease(directory):
            environment[FD_ENV] = str(fd)
            environment["ANSIBLE_CONFIG"] = str(ROOT / "config/ansible/ansible.cfg")
            # Provider helpers use this explicit environment; no bootstrap inputs
            # or ambient provider overrides enter the recovery process.
            os.environ.clear()
            os.environ.update(environment)
            finish(directory, recovery, environment)


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            run(args.directory, args.worker)
            return 0
        except OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError:
            with (args.worker / "error.log").open("x", encoding="utf-8") as stream:
                traceback.print_exc(file=stream)
            print("Finalization incomplete; private recovery evidence retained.", file=sys.stderr)
            return 1
    directory = args.directory.resolve(strict=True)
    if directory != args.directory or (directory / "diagnostic-origin.json").exists():
        parser.error("use the original canonical managed qualification directory")
    # Unique recovery attempts append their outcomes; interrupted logs and the
    # original controller's failure are never replaced.
    recovery = directory / ("finalization-" + uuid.uuid7().hex)
    recovery.mkdir(mode=0o700)
    write_private(recovery / "started.json", {"started_at": now(), "seconds": SECONDS})
    result = qualification_deadline.execute(
        [
            sys.executable,
            "-m",
            "scripts.m3_11_finalization",
            str(directory),
            "--worker",
            str(recovery),
        ],
        dict(os.environ),
        seconds=SECONDS,
    )
    write_private(recovery / "result.json", asdict(result))
    return result.status


if __name__ == "__main__":
    raise SystemExit(main())
