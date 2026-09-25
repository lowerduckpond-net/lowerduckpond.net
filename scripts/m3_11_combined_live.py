"""Fixed live combined test followed by owned teardown and original evidence.

Invoked only as the final task of the existing complete Spaces verify playbook.
All provider credentials and original private observations stay on the secure
workstation. A failed or partial attempt cannot be resumed into qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from datetime import timedelta
from pathlib import Path

import pytest

from scripts import m3_11_qualification_evidence as evidence
from scripts.m3_10_qualification_report import EMPTY_ACCOUNTING, _empty_accounting
from scripts.m3_11_combined_inputs import environment_for
from scripts.m3_11_dns_witness import DnsWitness
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_owned_teardown import Teardown, nodes
from scripts.m3_11_phase_receipts import Recorder
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.qualification_context import ARTIFACT_ENV, host_name, run_lease
from scripts.qualification_group_runner import SCENARIO, Completion


class Attempt:
    def __init__(self, directory: Path, storage: LiveStorage) -> None:
        self.directory = directory
        self.storage = storage
        self.context = read_private(directory / "combined-context.json")
        evidence.validate_names(directory / "combined-names.json", self.context)
        if self.context["run_id"] != storage.target.run_id or any(
            self.context[key] != storage.binding[key] for key in evidence.BINDING_FIELDS
        ):
            raise ValueError("combined live attempt differs from its original storage context")
        # Exclusive phase allocation is the durable failed-attempt latch. Never
        # reload earlier phases or delete this directory to retry an assertion.
        self.recorder = Recorder(directory, self.context)
        self.witness: DnsWitness | None = None
        self.results: dict[str, object] = {}

    @pytest.fixture
    def m3_11_attempt(self) -> Attempt:
        return self

    def record(
        self,
        witness: DnsWitness,
        recovery: dict[str, object],
        public_ca: dict[str, object],
        accounting: dict[str, object],
    ) -> None:
        if self.results or self.witness is not None:
            raise ValueError("combined live assertions cannot replace their original results")
        evidence._recovery(recovery)
        evidence._public_ca(public_ca)
        evidence._accounting(accounting, dict.fromkeys(evidence.ZERO_TEARDOWN, 0))
        if witness.context_sha256 != self.recorder.context_sha256:
            raise ValueError("combined live DNS witness belongs to another context")
        self.results = {"recovery": recovery, "public_ca": public_ca, "accounting": accounting}
        write_private(self.directory / "combined-assertions.json", self.results)
        self.witness = witness

    def finish(self, completion: Completion, status: int) -> None:
        if (
            self.witness is None
            or not self.results
            or read_private(self.directory / "combined-assertions.json") != self.results
        ):
            raise ValueError("combined live attempt lacks its original completed assertions")
        witness = self.witness
        retirement = Teardown(
            self.directory, self.storage, lambda: witness.require_absent("teardown").sha256
        )
        with self.recorder.phase("owned-teardown") as observations:
            retirement.authorize(completion, status)
            details = retirement.run()
            observations.update(details)
        envelope = {
            "format": evidence.FORMAT,
            "environment": evidence.ENVIRONMENT,
            "context": self.context,
            "phases": self.recorder.receipts(),
            **self.results,
            "teardown": details["teardown"],
        }
        evidence.validate(envelope, binding=self.storage.binding, maximum_age=timedelta(hours=24))
        write_private(self.directory / "combined.json", envelope)


def _legacy(directory: Path, storage: LiveStorage) -> str:
    raw, installed = evidence.read_document(directory / "installed.json")
    evidence.fields(installed, {"artifact_sha256", *EMPTY_ACCOUNTING})
    _empty_accounting({key: installed[key] for key in EMPTY_ACCOUNTING})
    if installed["artifact_sha256"] != storage.binding["artifact_sha256"] or any(
        (directory / f"{phase}.passed").read_bytes() != b"passed\n"
        for phase in ("create", "prepare", "converge", "idempotence")
    ):
        raise ValueError("combined live attempt lacks the original legacy installed journey")
    return hashlib.sha256(raw).hexdigest()


def run() -> int:
    environment = dict(os.environ)
    directory = Path(environment[ARTIFACT_ENV]).parent.parent
    environment_for(directory, environment)
    with run_lease(directory, create=True):
        return _run(directory, environment)


def _run(directory: Path, environment: dict[str, str]) -> int:
    storage = LiveStorage.load(environment)
    legacy_sha256 = _legacy(directory, storage)
    attempt = Attempt(directory, storage)
    write_private(
        directory / "combined.started.json",
        {
            "context_sha256": attempt.recorder.context_sha256,
            "installed_sha256": legacy_sha256,
        },
    )
    completion = Completion(nodes(environment))
    status = int(
        pytest.main(
            [
                "--verbose",
                f"--hosts=docker://{host_name(environment)}",
                *(f"{SCENARIO}/{value}" for value in completion.expected),
            ],
            plugins=[completion, attempt],
        )
    )
    if not completion.passed(status):
        return status or 2
    if _legacy(directory, storage) != legacy_sha256:
        raise ValueError("combined live attempt changed the original legacy evidence")
    attempt.finish(completion, status)
    return 0


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
