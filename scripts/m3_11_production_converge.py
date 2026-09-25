"""Run the real production playbooks through the original migration session."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import cast

from scripts import m3_11_production_journal as journal
from scripts.m3_11_production_preflight import save
from scripts.m3_11_production_replica import Replica
from scripts.m3_11_production_session import Result

ROOT = Path(__file__).resolve().parents[1]
HOST = "lowerduckpond_production_01"
PHASES = {
    "bootstrap": ("namespace.started", "m3-11-bootstrap.yml", False, False),
    "converged": ("converged.started", "site.yml", True, False),
    "rotation-enabled": ("rotation-enabled.started", "site.yml", True, True),
    "accepted": ("accepted.started", "acceptance.yml", True, True),
}
COUNTERS = {"ok", "changed", "failures", "unreachable", "skipped", "rescued", "ignored"}
MAX_RECEIPT_BYTES = 4096
PRIVATE_MODE = 0o600


def recap(path: Path, context: str, *, idempotent: bool) -> tuple[bytes, dict[str, int]]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != PRIVATE_MODE
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_RECEIPT_BYTES
        ):
            raise ValueError("production playbook recap metadata is unsafe")
        raw = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
    finally:
        os.close(descriptor)
    value = json.loads(raw)
    if (
        type(value) is not dict
        or set(value) != {"format", "context_sha256", "hosts"}
        or value["format"] != "lowerduckpond-m3-11-playbook-recap-v1"
        or value["context_sha256"] != context
        or type(value["hosts"]) is not dict
        or set(value["hosts"]) != {HOST}
        or journal.canonical(value) != raw
    ):
        raise ValueError("production playbook did not report exactly its intended host and inputs")
    counters = value["hosts"][HOST]
    if (
        type(counters) is not dict
        or set(counters) != COUNTERS
        or any(type(count) is not int or count < 0 for count in counters.values())
        or not counters["ok"]
        or any(counters[name] for name in ("failures", "unreachable", "rescued", "ignored"))
        or (idempotent and counters["changed"])
    ):
        raise ValueError("production playbook failed or its second pass was not idempotent")
    return raw, cast(dict[str, int], counters)


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _variables(stage: str, artifact: Path, artifact_sha256: str) -> dict[str, object]:
    recovery, rotation = PHASES[stage][2:]
    return {
        "static_host_agent_artifact_path": str(artifact),
        "static_host_agent_artifact_sha256": artifact_sha256,
        # Full convergence retains the candidate's newly initialized lineage.
        # The root phase guard independently proves the selected authority.
        "static_host_agent_verified_completed_candidate": stage != "bootstrap",
        "static_host_agent_archive_lifecycle_enabled": True,
        "caddy_generation_enabled": True,
        "static_publication_enabled": False,
        "host_recovery_bootstrap_enabled": False,
        "backup_static_recovery_enabled": recovery,
        "backup_audit_rotation_enabled": rotation,
    }


def playbook(pair: Replica, stage: str, artifact: Path, *, idempotent: bool = False) -> str:
    """Retain actual recap and logs; neither exit zero nor text alone proves a pass."""
    if stage not in PHASES:
        raise ValueError("unsupported production playbook stage")
    chain = pair.synchronize()
    authority = journal.validate(chain)
    if authority["phase"] != PHASES[stage][0]:
        raise ValueError("production journal does not authorize this playbook")
    original = cast(dict[str, object], authority["original"])
    candidate = cast(dict[str, str], original["candidate"])
    if (
        artifact.is_symlink()
        or not artifact.is_file()
        or _digest(artifact) != candidate["artifact_sha256"]
    ):
        raise ValueError("production playbook artifact differs from its original transaction")
    directory = Path(tempfile.mkdtemp(prefix=stage + "-", dir=pair.session.logs.directory))
    inventory: dict[str, object] = {
        "all": {
            "children": {
                "hosting_nodes": {
                    "hosts": {
                        HOST: {
                            "ansible_connection": "ldp_m3_11",
                            "ansible_ssh_transfer_method": "piped",
                            "ansible_ssh_use_tty": False,
                            "ansible_ssh_retries": 0,
                        }
                    }
                }
            }
        }
    }
    # Host-scoped inventory overrides keep delegated localhost artifact checks
    # on their local connection, outside the production SSH action unit.
    save(directory / "connection.json", journal.canonical(inventory))
    save(
        directory / "variables.json",
        journal.canonical(_variables(stage, artifact.resolve(), candidate["artifact_sha256"])),
    )
    selected = ROOT / "config/ansible/playbooks" / PHASES[stage][1]
    context = journal.canonical(
        {
            "original_sha256": authority["original_sha256"],
            "phase_sha256": authority["last_sha256"],
            "playbook_sha256": _digest(selected),
            "variables_sha256": _digest(directory / "variables.json"),
            "connection_sha256": _digest(directory / "connection.json"),
            "idempotent": idempotent,
        }
    )
    save(directory / "context.json", context)
    environment = pair.session.ansible_environment(os.environ)
    environment.update(
        ANSIBLE_CONFIG=str(ROOT / "config/ansible/ansible.cfg"),
        ANSIBLE_CALLBACK_PLUGINS=str(ROOT / "config/ansible/plugins/callback"),
        ANSIBLE_CALLBACKS_ENABLED="ldp_m3_11_receipt",
        ANSIBLE_STDOUT_CALLBACK="default",
        ANSIBLE_RUN_TAGS="all",
        ANSIBLE_SKIP_TAGS="",
        LDP_M3_11_PLAYBOOK_CONTEXT=journal.digest(context),
        LDP_M3_11_PLAYBOOK_RECEIPT=str(directory / "recap.json"),
    )
    pair.session.require_owner()
    result = pair.session.logs.run(
        "ansible-" + stage,
        [
            "uv",
            "run",
            "--directory",
            str(ROOT),
            "--frozen",
            "ansible-playbook",
            "--inventory",
            str(ROOT / "config/ansible/inventories/production/hosts.yml"),
            "--inventory",
            str(directory / "connection.json"),
            str(selected),
            "--extra-vars",
            "@" + str(directory / "variables.json"),
        ],
        environment=environment,
    )
    pair.session.require_owner()
    if result.status or pair.synchronize() != chain:
        raise ValueError("production playbook failed or changed its original phase")
    raw, _ = recap(directory / "recap.json", journal.digest(context), idempotent=idempotent)
    return _receipt(directory, context, raw, result)


def _receipt(directory: Path, context: bytes, recap_bytes: bytes, result: Result) -> str:
    proof = journal.canonical(
        {
            "context_sha256": journal.digest(context),
            "recap_sha256": journal.digest(recap_bytes),
            "stdout_sha256": _digest(result.stdout),
            "stderr_sha256": _digest(result.stderr),
        }
    )
    save(directory / "verified.json", proof)
    return journal.digest(proof)


def converge(pair: Replica, artifact: Path, *, rotation: bool = False) -> dict[str, object]:
    stage = "rotation-enabled" if rotation else "converged"
    first = playbook(pair, stage, artifact)
    second = playbook(pair, stage, artifact, idempotent=True)
    result: dict[str, object] = {
        "first_converge_sha256": first,
        "second_converge_sha256": second,
        "changed": 0,
        "rotation_enabled": rotation,
        "publication_enabled": False,
    }
    if not rotation:
        result.update(artifact_sha256=_digest(artifact), recovery_enabled=True)
    return result
