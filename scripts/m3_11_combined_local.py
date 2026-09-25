"""Append combined reconstruction to the original complete local journey.

Requires the same owned MinIO fixture, exact installed test completion and fresh
paired/storage proofs. This entry point never emits live qualification evidence.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import pytest

from scripts import qualification_restore as restore
from scripts.m3_11_private_inputs import write_private
from scripts.qualification_case import independent_storage_absence, owned_containers
from scripts.qualification_context import ARCHIVE_ENV, ARTIFACT_ENV, RUN_ENV, host_name
from scripts.qualification_group_runner import SCENARIO, Completion
from scripts.qualification_groups import node
from scripts.qualification_retirement import artifact_digest

FORMAT = "lowerduckpond-m3-11-complete-local-v1"


def run() -> int:
    environment = dict(os.environ)
    host = host_name(environment)
    if (
        not environment.get(RUN_ENV)
        or environment.get("M3_10_ARCHIVE_BACKEND") != "minio"
        or environment.get("M3_10_INSTALLED_REPORT")
        or environment.get("M3_11_COMBINED_BACKEND")
    ):
        raise ValueError("complete local reconstruction requires its owned MinIO journey")
    directory = Path(environment[ARTIFACT_ENV]).parent.parent
    identities = owned_containers(environment)
    started: dict[str, object] = {
        "format": FORMAT,
        "run_id": environment[RUN_ENV],
        "artifact_sha256": artifact_digest(Path(environment[ARTIFACT_ENV])),
        "identities": identities,
    }
    write_private(directory / "complete-combined.started.json", started)
    nodes = tuple(
        value.format(host=f"docker://{host}")
        for value in (
            node("combined_reconstruction", "complete_journey_combined_reconstruction"),
            node("restore_accounting", "installed_restore_paired_accounting"),
        )
    )
    completion = Completion(nodes)
    status = int(
        pytest.main(
            ["--verbose", f"--hosts=docker://{host}", *(f"{SCENARIO}/{value}" for value in nodes)],
            plugins=[completion],
        )
    )
    if not completion.passed(status):
        return status or 2
    restore.require_source_idempotence(environment, archived_prefix=True)
    pair = restore.paired_proof(environment)
    if owned_containers(environment) != identities:
        raise ValueError("complete journey fixture changed before independent accounting")
    independent_storage_absence(environment, identities[ARCHIVE_ENV])
    if restore.paired_proof(environment) != pair or owned_containers(environment) != identities:
        raise ValueError("complete journey accounting changed before paired teardown")
    restore.remove_pair(environment, pair)
    write_private(directory / "complete-combined.json", {**started, "nodes": list(nodes)})
    # The unchanged outer Molecule sequence still destroys its source/archive
    # and the controller removes the owned image after its full sequence passes.
    return 0


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
