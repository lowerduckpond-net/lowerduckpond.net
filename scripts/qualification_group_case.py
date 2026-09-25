"""Fresh owned fixtures for fixed groups, with exact test and accounting receipts."""

from __future__ import annotations

import json
from pathlib import Path

from scripts import qualification_restore as restore
from scripts.qualification_case import (
    ROOT,
    independent_storage_absence,
    installed_receipt,
    owned_containers,
    phase,
    record_created_containers,
    remove_owned_image,
)
from scripts.qualification_context import ARCHIVE_ENV, HOST_ENV, RUN_ENV, host_name, run_lease
from scripts.qualification_failure import record_accounting_check, record_phase
from scripts.qualification_group_runner import FORMAT as STAGE_FORMAT
from scripts.qualification_groups import GROUP_REPORT_FORMAT, GROUPS
from scripts.qualification_probe import document
from scripts.qualification_retirement import local_proof

FORMAT = GROUP_REPORT_FORMAT


def stage_receipts(
    directory: Path, environment: dict[str, str], case: str
) -> dict[str, object] | None:
    group = GROUPS[case]
    for stage in group.stages:
        expected = {
            "format": STAGE_FORMAT,
            "run_id": environment[RUN_ENV],
            "case": case,
            "stage": stage,
            "nodes": list(group.nodes(stage, host_name(environment))),
        }
        if document(directory / f"group-{stage}.json") != expected:
            raise ValueError("the group did not pass every declared installed test")
    if case == "full-size-archive":
        return installed_receipt(directory, environment)
    if group.reconstruction:
        restore.require_source_idempotence(environment, archived_prefix=group.protected_history)
    return None


def run_group(directory: Path, environment: dict[str, str], uv: str, case: str) -> int:
    group = GROUPS[case]
    with run_lease(directory, create=True):
        environment = {
            **environment,
            "NO_COLOR": "1",
            "PY_COLORS": "0",
            "ANSIBLE_FORCE_COLOR": "0",
            "ANSIBLE_NOCOLOR": "1",
        }
        # The private playbook supplies the fixed registry key. No ambient variable
        # or arbitrary selector can change the complete/live verifier.
        playbook = [
            {
                "name": f"Run owned installed group {case}",
                "hosts": "localhost",
                "gather_facts": False,
                "vars": {
                    "m3_8_group": case,
                    "m3_8_group_reboots": bool(group.after_reboot),
                    "m3_8_qualification_host": "{{ groups['hosting_nodes'] | first }}",
                    "m3_8_group_root": str(ROOT),
                },
                "tasks": [
                    {
                        "ansible.builtin.include_tasks": str(
                            ROOT / "config/ansible/molecule/m3_8/tasks/groups.yml"
                        )
                    }
                ],
            }
        ]
        verify = directory / "verify.yml"
        with verify.open("x", encoding="ascii") as stream:
            json.dump(playbook, stream)
        with (directory / "case-base.yml").open("x", encoding="ascii") as stream:
            json.dump(
                {
                    "scenario": {"create_sequence": ["dependency", "create"]},
                    "ansible": {"playbooks": {"verify": str(verify)}},
                },
                stream,
            )
        identities: dict[str, str] = {}
        for name in group.phases:
            status = phase(directory, environment, uv, name)
            if name == "create":
                try:
                    identities = record_created_containers(directory, environment, status)
                except Exception:
                    if not status:
                        raise
                    print("Created fixture ownership could not be fully recorded.", flush=True)
            if status:
                return status
        record_phase("final-accounting")
        record_accounting_check(case, "stage-receipts")
        installed = stage_receipts(directory, environment, case)
        record_accounting_check(case, "fixture-identity-before-storage")
        if owned_containers(environment) != identities:
            raise ValueError("owned fixture changed before accounting")
        record_accounting_check(case, "local-before-storage")
        pair = restore.paired_proof(environment) if group.reconstruction else None
        if (
            not group.reconstruction
            and local_proof(environment, identities[HOST_ENV]) != "quiescent-installed"
        ):
            raise ValueError("installed group accounting is incomplete")
        record_phase("final-storage-proof")
        record_accounting_check(case, "storage-absence")
        independent_storage_absence(environment, identities[ARCHIVE_ENV])
        record_phase("final-accounting")
        record_accounting_check(case, "fixture-identity-before-teardown")
        if owned_containers(environment) != identities:
            raise ValueError("owned fixture changed before teardown")
        record_accounting_check(case, "local-before-teardown")
        if (
            restore.paired_proof(environment) != pair
            if group.reconstruction
            else local_proof(environment, identities[HOST_ENV]) != "quiescent-installed"
        ):
            raise ValueError("installed group accounting changed before teardown")
        record_accounting_check(case, "destroy")
        if pair is not None:
            restore.remove_pair(environment, pair)
        status = phase(directory, environment, uv, "destroy")
        if status:
            return status
        record_accounting_check(case, "image-cleanup")
        remove_owned_image(environment)
        with (directory / "case.json").open("x", encoding="ascii") as stream:
            json.dump(
                {
                    "format": FORMAT,
                    "authority": "diagnostic-only",
                    "case": case,
                    "run_id": environment[RUN_ENV],
                    "backend": "minio",
                    "status": "passed",
                    "local_accounting": "passed",
                    "independent_storage_absence": "passed",
                    "destroy": "passed",
                    **({"installed": installed} if installed is not None else {}),
                },
                stream,
                sort_keys=True,
            )
            stream.write("\n")
        print(f"Installed group passed: {directory / 'case.json'}", flush=True)
        return 0
