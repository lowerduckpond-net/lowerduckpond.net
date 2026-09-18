"""Prove quiescent local fixture accounting before explicit owned retirement."""

from __future__ import annotations

import json
import os
import signal
import stat
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

MAX_RECORD_BYTES = 1024 * 1024
MAX_ENTRIES = 10000
PENDING = ("intents", "intake", "exports")


def directory_exists(path: Path, *, missing: bool = False) -> bool:
    for ancestor in reversed((path, *path.parents)):
        try:
            metadata = ancestor.lstat()
        except FileNotFoundError:
            if missing:
                return False
            raise
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("accounting path is not a directory")
    return True


def entries(path: Path, *, missing: bool = False) -> list[Path]:
    if not directory_exists(path, missing=missing):
        return []
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with os.scandir(descriptor) as iterator:
            names = []
            for item in iterator:
                names.append(path / item.name)
                if len(names) > MAX_ENTRIES:
                    raise ValueError("accounting inventory exceeds the bound")
        return names
    finally:
        os.close(descriptor)


def record(path: Path) -> dict[str, object]:
    directory_exists(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("accounting record is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_RECORD_BYTES + 1)
        if len(data) > MAX_RECORD_BYTES:
            raise ValueError("accounting record exceeds the bound")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("invalid accounting record")
        return value
    finally:
        os.close(descriptor)


def uninstalled(state: Path, caddy: Path, sites: Path) -> None:
    paths = [state / name for name in (*PENDING, "tenants", "audit", "platform")]
    paths += [state / "authorization" / name for name in ("jobs", "results", "correlations")]
    paths += [caddy / "intents", caddy / "routes.d", sites]
    for path in paths:
        children = entries(path, missing=True)
        if path == sites:
            children = [child for child in children if child.name != ".staging"]
            if entries(sites / ".staging", missing=True):
                raise ValueError("pre-installation staging is not empty")
        if children:
            raise ValueError("pre-installation fixture has retained state")


def authorization_is_terminal(state: Path) -> None:
    from lowerduckpond_static_contracts import (  # noqa: PLC0415
        ContractKind,
        validate_contract,
        validate_uuid7,
    )
    from lowerduckpond_static_host_agent.correlations import _durable_binding  # noqa: PLC0415
    from lowerduckpond_static_host_agent.job_runtime import (  # noqa: PLC0415
        _validate_result_for_job,
    )

    jobs: dict[str, dict[str, object]] = {}
    for path in entries(state / "authorization/jobs"):
        job_id = validate_uuid7(path.stem)
        job = record(path)
        validate_contract(job, expected_kind=ContractKind.AUTHORIZATION_JOB)
        if (
            path.name != f"{job_id}.json"
            or job["jobId"] != job_id
            or job["phase"] not in {"completed", "failed"}
            or job.get("executionValidated") is not True
        ):
            raise ValueError("fixture has a nonterminal authorization job")
        result = record(state / "authorization/results" / path.name)
        validate_contract(result, expected_kind=ContractKind.OPERATION_RESULT)
        _validate_result_for_job(job, result)
        expected_phase = "completed" if result["status"] == "succeeded" else "failed"
        if job["phase"] != expected_phase:
            raise ValueError("fixture job phase differs from its terminal result")
        jobs[job_id] = job
    if {path.name for path in entries(state / "authorization/results")} != {
        f"{job_id}.json" for job_id in jobs
    }:
        raise ValueError("fixture has orphaned terminal results")
    bound = set()
    for path in entries(state / "authorization/correlations"):
        correlation_id = validate_uuid7(path.stem)
        binding = record(path)
        validate_contract(binding, expected_kind=ContractKind.AUTHORIZATION_JOB)
        job_id = str(binding["jobId"])
        request = binding["request"]
        if (
            path.name != f"{correlation_id}.json"
            or not isinstance(request, dict)
            or request["correlationId"] != correlation_id
            or job_id in bound
            or job_id not in jobs
            or _durable_binding(jobs[job_id]) != _durable_binding(binding)
        ):
            raise ValueError("fixture authorization indexes need reconciliation")
        bound.add(job_id)
    if bound != set(jobs):
        raise ValueError("fixture authorization indexes are incomplete")


def installed(state: Path, caddy: Path, sites: Path, *, owner: int = 0) -> None:
    # Imports resolve from the selected, integrity-checked installed artifact.
    from lowerduckpond_static_contracts import (  # noqa: PLC0415
        ContractKind,
        manifest_digest,
        validate_contract,
        validate_uuid7,
    )
    from lowerduckpond_static_host_agent.locks import (  # noqa: PLC0415
        LockManager,
        LockMode,
        LockName,
    )

    with LockManager(state / "locks", expected_owner=owner) as locks, ExitStack() as held:
        for name in LockName:
            held.enter_context(locks.acquire(name, mode=LockMode.SHARED))
        for path in [*(state / name for name in PENDING), caddy / "intents", sites / ".staging"]:
            if entries(path):
                raise ValueError("fixture has pending local accounting")
        if os.path.lexists(state / "platform/archive-quarantine.json"):
            raise ValueError("fixture has archive quarantine")
        authorization_is_terminal(state)
        for path in entries(state / "tenants"):
            validate_uuid7(path.name)
            desired = record(path / "desired.json")
            validate_contract(desired, expected_kind=ContractKind.SITE)
            spec = desired["spec"]
            if not isinstance(spec, dict) or spec.get("desiredState") == "archived":
                raise ValueError("fixture retains an archived tenant")
            observed = record(path / "observed.json")
            validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)
            if (
                observed["tenantId"] != path.name
                or observed["observedState"] != spec["desiredState"]
                or observed["desiredManifestDigest"] != manifest_digest(desired).to_dict()
                or entries(path / "archives")
            ):
                raise ValueError("fixture tenant accounting is not settled")


def main() -> int:
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.alarm(30)
    state = Path("/var/lib/lowerduckpond/static")
    caddy = Path("/etc/caddy")
    sites = Path("/srv/lowerduckpond/sites")
    current = Path("/opt/lowerduckpond/static-host-agent/current")
    try:
        if not os.path.lexists(current):
            uninstalled(state, caddy, sites)
            print('{"state":"empty-before-installation"}')
            return 0
        selected = current.resolve(strict=True)
        if selected.parent != current.parent:
            raise ValueError("selected artifact is outside its immutable root")
        subprocess.run(  # noqa: S603 - fixed installed integrity verifier, owned host only
            ["/usr/local/libexec/lowerduckpond/verify-static-host-agent-artifact", str(selected)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        sys.path.insert(0, str(selected / "site-packages"))
        installed(state, caddy, sites)
        print(json.dumps({"state": "quiescent-installed", "artifact_sha256": selected.name}))
        return 0
    except Exception:
        print("Owned fixture accounting could not be proven quiescent.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
