"""Explicitly retire an inactive owned archive fixture after fresh independent proofs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

from scripts.qualification_case import (
    independent_storage_absence,
    owned_containers,
    private_document,
)
from scripts.qualification_context import (
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    HOST_ENV,
    RESOURCE_ENV,
    RUN_ENV,
    resource_names,
    run_lease,
)
from scripts.qualification_local import FORMAT as FIXTURE_FORMAT
from scripts.qualification_local import docker_endpoint
from scripts.qualification_probe import bounded_command, document

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "lowerduckpond-local-fixture-retirement-v1"
REMOVAL_FORMAT = "lowerduckpond-local-fixture-removal-v1"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_TIMESTAMP_LENGTH = 64
MAX_EXIT_STATUS = 255


def artifact_digest(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= MAX_ARTIFACT_BYTES:
            raise ValueError("invalid retained artifact")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        current = os.fstat(descriptor)
        if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise ValueError("retained artifact changed during verification")
        return digest
    finally:
        os.close(descriptor)


def environment_for(directory: Path) -> dict[str, str]:
    manifest = document(directory / "fixture.json")
    if manifest.get("format") != FIXTURE_FORMAT or not isinstance(manifest.get("run_id"), str):
        raise ValueError("invalid owned fixture manifest")
    expected = resource_names(str(manifest["run_id"]))
    expected[ARTIFACT_ENV] = str(directory / "fixture/static-host-agent.tar")
    expected["MOLECULE_EPHEMERAL_DIRECTORY"] = str(directory / "fixture/molecule")
    if (
        manifest.get("environment") != expected
        or manifest.get("host") != expected[HOST_ENV]
        or manifest.get("archive") != expected[ARCHIVE_ENV]
    ):
        raise ValueError("owned fixture paths or names changed")
    endpoint = manifest.get("docker_endpoint")
    if not isinstance(endpoint, str):
        raise ValueError("missing original Docker endpoint")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in RESOURCE_ENV
        and not key.startswith(
            ("SPACES_", "CLOUDFLARE_", "M3_8_", "MOLECULE_", "LDP_QUALIFICATION_")
        )
        and key not in {"DOCKER_CONTEXT", "M3_10_INSTALLED_REPORT"}
    }
    environment.update(expected)
    environment["DOCKER_HOST"] = docker_endpoint({"DOCKER_HOST": endpoint})
    environment["M3_10_ARCHIVE_BACKEND"] = "minio"
    return environment


def local_proof(environment: dict[str, str], host_id: str) -> str:
    output = bounded_command(
        ["docker", "exec", "--interactive", host_id, "/usr/bin/python3", "-I", "-B", "-"],
        timeout=40,
        environment=environment,
        stdin=(ROOT / "scripts/qualification_retirement_probe.py").read_bytes(),
    )
    if output is None:
        raise ValueError("local accounting is not proven quiescent")
    proof = json.loads(output)
    if proof == {"state": "empty-before-installation"}:
        return "empty-before-installation"
    if not isinstance(proof, dict) or proof.get("state") != "quiescent-installed":
        raise ValueError("unknown local accounting proof")
    digest = artifact_digest(Path(environment[ARTIFACT_ENV]))
    if proof.get("artifact_sha256") != digest:
        raise ValueError("selected artifact differs from the retained run's artifact")
    return "quiescent-installed"


def uninstalled_storage_absence(environment: dict[str, str], archive_id: str) -> None:
    # Before converge, the owned pinned fixture has no TLS configuration/buckets.
    # These are its fixed disposable root credentials, never production inputs.
    endpoint = "http://molecule-m3-10-root:molecule-m3-10-disposable-root-secret@127.0.0.1:443"
    output = bounded_command(
        [
            "docker",
            "exec",
            "--env",
            f"MC_HOST_m310={endpoint}",
            archive_id,
            "mc",
            "--json",
            "ls",
            "m310/",
        ],
        timeout=15,
        environment=environment,
    )
    if output is None or output.strip():
        raise ValueError("pre-installation storage absence is not proven")


def snapshot(environment: dict[str, str], identity: str) -> dict[str, object]:
    output = bounded_command(
        [
            "docker",
            "inspect",
            "--format",
            '{"id":{{json .Id}},"owner":'
            '{{json (index .Config.Labels "lowerduckpond.qualification.run")}},'
            '"started_at":{{json .State.StartedAt}},"restarts":{{json .RestartCount}},'
            '"running":{{json .State.Running}},"paused":{{json .State.Paused}},'
            '"status":{{json .State.Status}}}',
            identity,
        ],
        environment=environment,
    )
    data = json.loads(output) if output is not None else {}
    if (
        data.get("id") != identity
        or data.get("owner") != environment[RUN_ENV]
        or not isinstance(data.get("started_at"), str)
        or not 1 <= len(data["started_at"]) <= MAX_TIMESTAMP_LENGTH
        or type(data.get("restarts")) is not int
        or data["restarts"] < 0
        or type(data.get("running")) is not bool
        or data.get("paused") is not False
        or data.get("status") not in {"created", "running", "exited"}
        or data["running"] != (data["status"] == "running")
    ):
        raise ValueError("owned container state is unavailable or unsuitable")
    return {key: data[key] for key in ("started_at", "restarts", "running", "status")}


def incarnation(value: dict[str, object]) -> dict[str, object]:
    return {key: value[key] for key in ("started_at", "restarts")}


def valid_incarnation(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"started_at", "restarts"}
        and isinstance(value["started_at"], str)
        and 1 <= len(value["started_at"]) <= MAX_TIMESTAMP_LENGTH
        and type(value["restarts"]) is int
        and value["restarts"] >= 0
    )


def never_started(value: dict[str, object]) -> bool:
    return (
        value["status"] == "created"
        and value["running"] is False
        and value["restarts"] == 0
        and str(value["started_at"]).startswith("0001-01-01T00:00:00")
    )


def storage_proof(environment: dict[str, str], identity: str, state: str) -> None:
    if state == "empty-before-installation":
        try:
            independent_storage_absence(environment, identity)
        except ValueError:
            uninstalled_storage_absence(environment, identity)
    else:
        independent_storage_absence(environment, identity)


def fresh_proofs(
    environment: dict[str, str], bound: dict[str, str], *, failed_create: bool
) -> tuple[str, dict[str, dict[str, object]]]:
    print("Owned fixture retirement: fresh local and independent storage proofs", flush=True)
    before = {key: snapshot(environment, identity) for key, identity in bound.items()}

    def local() -> str:
        if failed_create and (HOST_ENV not in bound or never_started(before[HOST_ENV])):
            return "empty-before-installation"
        return local_proof(environment, bound[HOST_ENV])

    state = local()
    if set(bound) != {HOST_ENV, ARCHIVE_ENV} and state != "empty-before-installation":
        raise ValueError("partial creation cannot authorize installed fixture retirement")
    if ARCHIVE_ENV in bound and not (failed_create and never_started(before[ARCHIVE_ENV])):
        storage_proof(environment, bound[ARCHIVE_ENV], state)
    if owned_containers(environment, allow_missing=True) != bound or local() != state:
        raise ValueError("fixture changed during retirement checks")
    after = {key: snapshot(environment, identity) for key, identity in bound.items()}
    if before != after:
        raise ValueError("fixture restarted during retirement checks")
    return state, {key: incarnation(value) for key, value in after.items()}


def removal_intent(
    directory: Path, environment: dict[str, str], bound: dict[str, str], *, failed_create: bool
) -> dict[str, object]:
    path = directory / "retirement-removal.json"
    if path.exists():
        intent = document(path)
        if (
            set(intent) != {"format", "containers", "phase", "incarnations", "state", "artifact"}
            or intent["format"] != REMOVAL_FORMAT
            or intent["containers"] != bound
            or intent["phase"] not in {"host", "archive"}
            or intent["state"] not in {"empty-before-installation", "quiescent-installed"}
            or not isinstance(intent["incarnations"], dict)
            or set(intent["incarnations"]) != set(bound)
            or any(not valid_incarnation(value) for value in intent["incarnations"].values())
        ):
            raise ValueError("invalid fixture removal transaction")
        if intent["artifact"] != (
            artifact_digest(Path(environment[ARTIFACT_ENV]))
            if intent["state"] == "quiescent-installed"
            else None
        ):
            raise ValueError("retained removal artifact changed")
        return intent
    if owned_containers(environment, allow_missing=True) != bound:
        raise ValueError("retained container identities changed")
    state, incarnations = fresh_proofs(environment, bound, failed_create=failed_create)
    intent = {
        "format": REMOVAL_FORMAT,
        "containers": bound,
        "phase": "host",
        "incarnations": incarnations,
        "state": state,
        "artifact": artifact_digest(Path(environment[ARTIFACT_ENV]))
        if state == "quiescent-installed"
        else None,
    }
    private_document(directory, path.name, intent)
    return intent


def remove(environment: dict[str, str], identity: str) -> None:
    docker = shutil.which("docker")
    if docker is None:
        raise ValueError("Docker is unavailable")
    # No graceful stop/restart or lifecycle retry: continue only the authorized
    # destruction of this exact container, including an interrupted Docker removal.
    subprocess.run(  # noqa: S603 - exact owned ID, fixed removal command
        [docker, "rm", "--force", "--volumes", identity],
        env=environment,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=40,
    )


def continue_removal(  # noqa: PLR0912 - explicit two-resource removal recovery
    directory: Path,
    environment: dict[str, str],
    bound: dict[str, str],
    intent: dict[str, object],
    *,
    failed_create: bool,
) -> None:
    current = owned_containers(environment, allow_missing=True)
    if any(bound.get(key) != identity for key, identity in current.items()):
        raise ValueError("retained container identities changed")
    incarnations = intent["incarnations"]
    if not isinstance(incarnations, dict):
        raise ValueError("invalid removal incarnations")
    if intent["phase"] == "host":
        if ARCHIVE_ENV in bound and ARCHIVE_ENV not in current:
            raise ValueError("storage disappeared before authorized removal")
        if HOST_ENV in current:
            host = snapshot(environment, current[HOST_ENV])
            if host["running"]:
                state, fresh = fresh_proofs(environment, bound, failed_create=failed_create)
                if state != intent["state"]:
                    raise ValueError("fixture accounting changed after removal authorization")
                incarnations = fresh
                intent.update(state=state, incarnations=fresh)
                private_document(directory, "retirement-removal.json", intent)
            elif incarnation(host) != incarnations[HOST_ENV]:
                raise ValueError("stopped host restarted after removal authorization")
            print("Owned fixture retirement: remove the bound host", flush=True)
            remove(environment, current[HOST_ENV])
        current = owned_containers(environment, allow_missing=True)
        if current != {key: value for key, value in bound.items() if key == ARCHIVE_ENV}:
            raise ValueError("owned host removal is incomplete or identities changed")
    elif HOST_ENV in current:
        raise ValueError("removed host reappeared")
    if ARCHIVE_ENV in current:
        archive = snapshot(environment, current[ARCHIVE_ENV])
        if archive["running"]:
            storage_proof(environment, current[ARCHIVE_ENV], str(intent["state"]))
        elif intent["phase"] == "archive":
            if incarnation(archive) != incarnations[ARCHIVE_ENV]:
                raise ValueError("stopped storage restarted after removal authorization")
        elif not (failed_create and never_started(archive)):
            raise ValueError("storage cannot supply fresh removal evidence")
        if (
            snapshot(environment, current[ARCHIVE_ENV]) != archive
            or owned_containers(environment, allow_missing=True) != current
        ):
            raise ValueError("storage changed before removal")
        incarnations[ARCHIVE_ENV] = incarnation(archive)
        intent.update(phase="archive", incarnations=incarnations)
        private_document(directory, "retirement-removal.json", intent)
        print("Owned fixture retirement: remove the bound storage container", flush=True)
        remove(environment, current[ARCHIVE_ENV])
    if owned_containers(environment, allow_missing=True):
        raise ValueError("owned fixture removal is incomplete")


def retire(directory: Path) -> Path:
    directory = directory.resolve(strict=True)
    with run_lease(directory):
        print("Owned fixture retirement: verify ownership and removal progress", flush=True)
        environment = environment_for(directory)
        raw = document(directory / "case-containers.json")
        creation = (
            document(directory / "case-create.json")
            if (directory / "case-create.json").exists()
            else {}
        )
        creation_status = creation.get("exit_status")
        failed_create = type(creation_status) is int and 0 < creation_status <= MAX_EXIT_STATUS
        if (
            not set(raw) <= {HOST_ENV, ARCHIVE_ENV}
            or any(
                not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in raw.values()
            )
            or (set(raw) != {HOST_ENV, ARCHIVE_ENV} and not failed_create)
        ):
            raise ValueError("invalid retained container identities")
        bound = {key: str(value) for key, value in raw.items()}
        intent = removal_intent(directory, environment, bound, failed_create=failed_create)
        continue_removal(directory, environment, bound, intent, failed_create=failed_create)
        private_document(
            directory,
            "retirement.json",
            {
                "format": FORMAT,
                "authority": "diagnostic-only",
                "outcome": "retired",
                "local_accounting": intent["state"],
                "independent_storage_absence": "passed",
            },
        )
    return directory / "retirement.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        destination = retire(args.directory)
    except Exception:
        print("Fixture retirement did not complete; private evidence remains in the run directory.")
        return 2
    print(f"Owned fixture retired; private evidence retained at {destination.parent}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
