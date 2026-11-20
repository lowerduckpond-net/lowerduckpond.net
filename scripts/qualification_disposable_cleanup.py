"""Dispose only a locally owned MinIO fixture, retaining its diagnostic records.

This is not the live retirement protocol and never establishes accounting or
production qualification. A controller must have stopped before recovery uses
this entry point; Docker identities and the original daemon are checked again.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.qualification_case import private_document, remove_owned_image
from scripts.qualification_context import (
    ARCHIVE_ENV,
    ARTIFACT_ENV,
    RUN_ENV,
    host_name,
    resource_names,
)
from scripts.qualification_disposition import DISPOSABLE_CLEANUP
from scripts.qualification_mutation import ownership
from scripts.qualification_probe import bounded_command, document

FORMAT = "lowerduckpond-disposable-cleanup-v1"
LABEL = "lowerduckpond.qualification.run"
ROLES = ("destination", "acme", "host", "archive")
CLEANUP_ROLES = (*ROLES, "unused-archive")
RETAIN_FORMAT = "lowerduckpond-disposable-retention-v1"
RESULT_FORMAT = "lowerduckpond-disposable-result-v1"
SAFE_ERRORS = frozenset(
    {
        "disposable cleanup requires the original local Docker socket",
        "Docker identity is unavailable",
        "Docker identity is invalid",
        "fixture inventory is unavailable",
        "fixture inventory is ambiguous",
        "fixture identity or ownership changed",
        "fixture identities overlap",
        "fixture owner has unexpected or missing containers",
        "Docker is unavailable",
        "disposable cleanup does not accept live fixtures",
        "disposable fixture daemon binding changed",
        "disposable diagnostic evidence is missing",
        "invalid disposable run lock",
        "disposable fixture daemon changed",
        "recorded fixture identity changed",
        "recorded reconstruction identity changed",
        "disposable cleanup intent changed",
        "disposable cleanup journal or identities changed",
        "fixture identity changed before disposal",
        "disposable fixture removal is incomplete",
        "disposable fixture directory is unsafe",
        "disposable fixture contains a mounted filesystem",
        "disposable retirement directory is unsafe",
        "disposable disk image is unsafe",
        "auxiliary fixture identity is invalid",
        "auxiliary fixture inventory is unavailable",
        "auxiliary fixture inventory is ambiguous",
        "auxiliary fixture identity changed",
    }
)


def error_detail(error: Exception) -> dict[str, str]:
    """Expose fixed causes, never arbitrary provider output or command arguments."""
    message = str(error)
    reason = (
        message
        if type(error) is ValueError
        and (
            message in SAFE_ERRORS
            or re.fullmatch(r"disposable container removal failed with exit [0-9]{1,3}", message)
        )
        else "unclassified"
    )
    return {"category": type(error).__name__, "reason": reason}


def daemon_id(environment: dict[str, str]) -> str:
    if not environment.get("DOCKER_HOST", "").startswith("unix:///"):
        raise ValueError("disposable cleanup requires the original local Docker socket")
    output = bounded_command(
        ["docker", "info", "--format", "{{.ID}}"], environment=environment, check=True
    )
    if output is None:
        raise ValueError("Docker identity is unavailable")
    result = output.decode("ascii").strip()
    if re.fullmatch(r"[A-Za-z0-9:_-]{3,128}", result) is None:
        raise ValueError("Docker identity is invalid")
    return result


def bind(directory: Path, environment: dict[str, str]) -> None:
    """Bind the empty run to its original daemon before any fixture allocation."""
    host_name(environment)
    private_document(
        directory,
        "disposable-cleanup-binding.json",
        {
            "format": FORMAT,
            "run_id": environment[RUN_ENV],
            "endpoint": environment["DOCKER_HOST"],
            "daemon_id": daemon_id(environment),
        },
    )


def reserve_auxiliary(
    directory: Path, environment: dict[str, str], auxiliary: dict[str, str], image: str
) -> None:
    """Record the fixed extra native fixture before submitting its Docker creation."""
    host_name(environment)
    host_name(auxiliary)
    if (
        environment[RUN_ENV] == auxiliary[RUN_ENV]
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None
    ):
        raise ValueError("auxiliary fixture identity is invalid")
    path = directory / "native-unused-fixture.json"
    if os.path.lexists(path):
        raise ValueError("native unused fixture was already allocated")
    private_document(
        directory,
        path.name,
        {
            "format": "lowerduckpond-native-unused-fixture-v1",
            "parent_run_id": environment[RUN_ENV],
            "run_id": auxiliary[RUN_ENV],
            "name": auxiliary[ARCHIVE_ENV],
            "image": image,
            "id": None,
        },
    )


def complete_auxiliary(directory: Path, identity: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise ValueError("auxiliary fixture identity is invalid")
    path = directory / "native-unused-fixture.json"
    value = document(path)
    if (
        value.get("format") != "lowerduckpond-native-unused-fixture-v1"
        or value.get("id") is not None
    ):
        raise ValueError("auxiliary fixture completion changed")
    value["id"] = identity
    private_document(directory, path.name, value)


def inventory(environment: dict[str, str]) -> dict[str, str]:  # noqa: PLR0912 - distinct fixture identity checks
    """Inspect only this run's four fixed names; remove later by immutable ID."""
    owner = environment[RUN_ENV]
    result: dict[str, str] = {}
    for role in ROLES:
        name = f"ldp-m3-{owner}-{role}"
        raw = bounded_command(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{name}$",
                "--format",
                "{{.ID}}",
            ],
            environment=environment,
            check=True,
        )
        if raw is None:
            raise ValueError("fixture inventory is unavailable")
        identity = raw.decode("ascii").strip()
        if not identity:
            continue
        if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
            raise ValueError("fixture inventory is ambiguous")
        detail = bounded_command(
            [
                "docker",
                "inspect",
                "--format",
                '{"id":{{json .Id}},"name":{{json .Name}},"owner":'
                '{{json (index .Config.Labels "lowerduckpond.qualification.run")}}}',
                identity,
            ],
            environment=environment,
            check=True,
        )
        if detail is None or json.loads(detail) != {
            "id": identity,
            "name": "/" + name,
            "owner": owner,
        }:
            raise ValueError("fixture identity or ownership changed")
        result[role] = identity
    if len(set(result.values())) != len(result):
        raise ValueError("fixture identities overlap")
    raw = bounded_command(
        [
            "docker",
            "ps",
            "--all",
            "--no-trunc",
            "--filter",
            f"label={LABEL}={owner}",
            "--format",
            "{{.ID}}",
        ],
        environment=environment,
        check=True,
    )
    if raw is None or set(raw.decode("ascii").splitlines()) != set(result.values()):
        raise ValueError("fixture owner has unexpected or missing containers")
    auxiliary = Path(environment[ARTIFACT_ENV]).parent.parent / "native-unused-fixture.json"
    if auxiliary.exists() or auxiliary.is_symlink():
        record = document(auxiliary)
        auxiliary_id = record.get("run_id")
        if not isinstance(auxiliary_id, str):
            raise ValueError("auxiliary fixture identity is invalid")
        expected = resource_names(auxiliary_id)
        name = expected[ARCHIVE_ENV]
        image = record.get("image")
        bound_id = record.get("id")
        if (
            record
            != {
                "format": "lowerduckpond-native-unused-fixture-v1",
                "parent_run_id": owner,
                "run_id": auxiliary_id,
                "name": name,
                "image": image,
                "id": bound_id,
            }
            or auxiliary_id == owner
            or not isinstance(image, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None
            or (
                bound_id is not None
                and (
                    not isinstance(bound_id, str) or re.fullmatch(r"[0-9a-f]{64}", bound_id) is None
                )
            )
        ):
            raise ValueError("auxiliary fixture identity is invalid")
        listed = bounded_command(
            [
                "docker",
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                f"label={LABEL}={auxiliary_id}",
                "--format",
                "{{.ID}}",
            ],
            environment=environment,
            check=True,
        )
        if listed is None:
            raise ValueError("auxiliary fixture inventory is unavailable")
        identities = listed.decode("ascii").splitlines()
        if len(identities) > 1 or any(
            re.fullmatch(r"[0-9a-f]{64}", item) is None for item in identities
        ):
            raise ValueError("auxiliary fixture inventory is ambiguous")
        if identities:
            identity = identities[0]
            if bound_id is not None and identity != bound_id:
                raise ValueError("auxiliary fixture identity changed")
            detail = bounded_command(
                [
                    "docker",
                    "inspect",
                    "--format",
                    '{"id":{{json .Id}},"name":{{json .Name}},"owner":'
                    '{{json (index .Config.Labels "lowerduckpond.qualification.run")}},'
                    '"image":{{json .Image}}}',
                    identity,
                ],
                environment=environment,
                check=True,
            )
            if detail is None or json.loads(detail) != {
                "id": identity,
                "name": "/" + name,
                "owner": auxiliary_id,
                "image": image,
            }:
                raise ValueError("auxiliary fixture identity changed")
            result["unused-archive"] = identity
    return result


def remove_exact(environment: dict[str, str], identity: str) -> None:
    """Remove an already verified ID without imposing a new teardown deadline."""
    docker = shutil.which("docker")
    if docker is None:
        raise ValueError("Docker is unavailable")
    result = subprocess.run(  # noqa: S603 - fixed command and validated immutable ID
        [docker, "rm", "--force", "--volumes", identity],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode:
        raise ValueError(f"disposable container removal failed with exit {result.returncode}")


def remove_local_data(directory: Path) -> None:
    """Remove only private fixture inputs and fixed disposable disk-image copies."""
    fixture = directory / "fixture"
    if fixture.exists() or fixture.is_symlink():
        metadata = fixture.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or os.path.ismount(fixture)
            or not shutil.rmtree.avoids_symlink_attacks
        ):
            raise ValueError("disposable fixture directory is unsafe")
        for root, directories, _ in os.walk(fixture, followlinks=False):
            for name in directories:
                child = Path(root) / name
                if not child.is_symlink() and (
                    child.stat().st_dev != metadata.st_dev or os.path.ismount(child)
                ):
                    raise ValueError("disposable fixture contains a mounted filesystem")
        shutil.rmtree(fixture)
    retirement = directory / "failed-archive-retirement"
    if retirement.exists() or retirement.is_symlink():
        descriptor = os.open(retirement, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (
                metadata.st_uid != os.geteuid()
                or metadata.st_dev != directory.stat().st_dev
                or os.path.ismount(retirement)
            ):
                raise ValueError("disposable retirement directory is unsafe")
            for name in ("source.ext4", "destination.ext4"):
                try:
                    image = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (
                    not stat.S_ISREG(image.st_mode)
                    or image.st_uid != os.geteuid()
                    or image.st_nlink != 1
                ):
                    raise ValueError("disposable disk image is unsafe")
                os.unlink(name, dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def cleanup(directory: Path) -> None:  # noqa: PLR0912, PLR0915 - explicit ownership and recovery checks
    """Remove exact local fixture containers after the producing process has drained."""
    from scripts.qualification_retirement import environment_for  # noqa: PLC0415

    directory = directory.resolve(strict=True)
    manifest = document(directory / "fixture.json")
    if manifest.get("format") != "lowerduckpond-local-qualification-fixture-v1":
        raise ValueError("disposable cleanup does not accept live fixtures")
    environment = environment_for(directory)
    expected = {
        "format": FORMAT,
        "run_id": environment[RUN_ENV],
        "endpoint": environment["DOCKER_HOST"],
        "daemon_id": daemon_id(environment),
    }
    if document(directory / "disposable-cleanup-binding.json") != expected:
        raise ValueError("disposable fixture daemon binding changed")
    result = document(directory / "disposable-result.json")
    if (
        set(result) != {"format", "run_id", "outcome", "diagnostics"}
        or result.get("format") != RESULT_FORMAT
        or result.get("run_id") != environment[RUN_ENV]
        or result.get("outcome") not in {"passed", "failed", "debug"}
        or result.get("diagnostics") not in {"completed-run", "captured"}
        or (result["outcome"] != "passed" and result["diagnostics"] != "captured")
        or (
            result["diagnostics"] == "captured"
            and not (directory / "failure-snapshot.json").is_file()
        )
    ):
        raise ValueError("disposable diagnostic evidence is missing")
    descriptor = os.open(directory / "run.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004 - private lease
            or metadata.st_nlink != 1
        ):
            raise ValueError("invalid disposable run lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ownership(directory, exclusive=True):
            if daemon_id(environment) != expected["daemon_id"]:
                raise ValueError("disposable fixture daemon changed")
            current = inventory(environment)
            recorded = directory / "case-containers.json"
            if recorded.exists() or recorded.is_symlink():
                values = document(recorded)
                for role, key in (
                    ("host", "LDP_QUALIFICATION_HOST"),
                    ("archive", "LDP_QUALIFICATION_ARCHIVE"),
                ):
                    if role in current and key in values and values[key] != current[role]:
                        raise ValueError("recorded fixture identity changed")
            for role, receipt_name in (
                ("host", "source"),
                ("destination", "destination"),
                ("acme", "acme"),
            ):
                receipt = directory / "restore" / f"{receipt_name}.json"
                if role in current and (receipt.exists() or receipt.is_symlink()):
                    value = document(receipt)
                    if (
                        value.get("id") != current[role]
                        or value.get("owner") != environment[RUN_ENV]
                    ):
                        raise ValueError("recorded reconstruction identity changed")
            marker = directory / DISPOSABLE_CLEANUP
            if marker.exists() or marker.is_symlink():
                if document(marker) != expected:
                    raise ValueError("disposable cleanup intent changed")
            else:
                private_document(directory, DISPOSABLE_CLEANUP, expected)
            journal = directory / "disposable-cleanup.json"
            if journal.exists() or journal.is_symlink():
                prior = document(journal)
                before = prior.get("containers")
                if (
                    not isinstance(before, dict)
                    or prior != {**expected, "state": prior.get("state"), "containers": before}
                    or prior.get("state") not in {"started", "complete"}
                    or any(
                        role not in CLEANUP_ROLES
                        or not isinstance(identity, str)
                        or re.fullmatch(r"[0-9a-f]{64}", identity) is None
                        for role, identity in before.items()
                    )
                    or any(before.get(role) != identity for role, identity in current.items())
                    or (prior["state"] == "complete" and current)
                ):
                    raise ValueError("disposable cleanup journal or identities changed")
            else:
                before = current
                private_document(
                    directory,
                    "disposable-cleanup.json",
                    {**expected, "state": "started", "containers": before},
                )
            for role, identity in current.items():
                if inventory(environment).get(role) != identity:
                    raise ValueError("fixture identity changed before disposal")
                remove_exact(environment, identity)
            if inventory(environment):
                raise ValueError("disposable fixture removal is incomplete")
            remove_owned_image(environment)
            remove_local_data(directory)
            private_document(
                directory,
                "disposable-cleanup.json",
                {**expected, "state": "complete", "containers": before},
            )
    finally:
        os.close(descriptor)


def expiry(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("retention expiry must be an ISO 8601 timestamp with timezone") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("retention expiry requires an explicit timezone")
    return result.astimezone(UTC)


def retain_until(directory: Path, until: datetime) -> None:
    """Record explicit expiry and start a local best-effort disposal watcher."""
    if until <= datetime.now(UTC):
        raise ValueError("retention expiry must be in the future")
    private_document(
        directory,
        "disposable-retention.json",
        {"format": RETAIN_FORMAT, "expires_at": until.isoformat()},
    )
    root = Path(__file__).resolve().parents[1]
    environment = {
        key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL") if key in os.environ
    }
    environment["PYTHONPATH"] = str(root)
    subprocess.Popen(  # noqa: S603 - fixed local cleanup entry point
        [
            sys.executable,
            "-m",
            "scripts.qualification_disposable_cleanup",
            "--wait-for-expiry",
            str(directory),
        ],
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )


def wait_for_expiry(directory: Path) -> None:
    value = document(directory / "disposable-retention.json")
    if set(value) != {"format", "expires_at"} or value["format"] != RETAIN_FORMAT:
        raise ValueError("invalid disposable retention record")
    if not isinstance(value["expires_at"], str):
        raise ValueError("invalid disposable retention expiry")
    until = expiry(value["expires_at"])
    while (remaining := (until - datetime.now(UTC)).total_seconds()) > 0:
        time.sleep(min(remaining, 60))
    while True:
        try:
            cleanup(directory)
            return
        except BlockingIOError:
            # A supported debugger holds the original lease; never remove its fixture.
            time.sleep(5)
        except Exception as error:
            private_document(
                directory,
                "disposable-retention-error.json",
                {
                    "format": RETAIN_FORMAT,
                    "stage": "expiry-cleanup",
                    **error_detail(error),
                },
            )
            raise


def recover_interrupted(directory: Path) -> None:  # noqa: PLR0912 - explicit interrupted-run checks
    """Capture an interrupted local run after its controller and children have stopped."""
    from scripts import qualification_failure as failure  # noqa: PLC0415
    from scripts.qualification_retirement import environment_for  # noqa: PLC0415

    directory = directory.resolve(strict=True)
    if document(directory / "fixture.json").get("format") != (
        "lowerduckpond-local-qualification-fixture-v1"
    ):
        raise ValueError("interrupted cleanup does not accept live fixtures")
    environment = environment_for(directory)
    binding = {
        "format": FORMAT,
        "run_id": environment[RUN_ENV],
        "endpoint": environment["DOCKER_HOST"],
        "daemon_id": daemon_id(environment),
    }
    if document(directory / "disposable-cleanup-binding.json") != binding:
        raise ValueError("interrupted fixture daemon binding changed")
    descriptor = os.open(directory / "run.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600  # noqa: PLR2004 - private lease
            or metadata.st_nlink != 1
        ):
            raise ValueError("invalid interrupted run lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with ownership(directory, exclusive=True):
            if daemon_id(environment) != binding["daemon_id"]:
                raise ValueError("interrupted fixture daemon changed")
            inventory(environment)
            marker = directory / DISPOSABLE_CLEANUP
            if marker.exists() or marker.is_symlink():
                if document(marker) != binding:
                    raise ValueError("interrupted cleanup intent changed")
            else:
                private_document(directory, DISPOSABLE_CLEANUP, binding)
            updates = {
                **environment,
                "LDP_QUALIFICATION_TIMING_EVENTS": str(directory / "timing-events.jsonl"),
            }
            previous = {key: os.environ.get(key) for key in updates}
            os.environ.update(updates)
            try:
                failure.capture_fixture()
                failure.capture_failure_observation()
                if not (directory / "failure-snapshot.json").is_file():
                    raise ValueError("interrupted diagnostic snapshot is unavailable")
                prior = (
                    document(directory / "failure-exit.json")
                    if (directory / "failure-exit.json").exists()
                    else {}
                )
                status = prior.get("exit_status", 130)
                if type(status) is not int or not 1 <= status <= 255:  # noqa: PLR2004 - exit status range
                    raise ValueError("invalid original failure status")
                failure.collect(directory, status)
                private_document(
                    directory,
                    "disposable-result.json",
                    {
                        "format": RESULT_FORMAT,
                        "run_id": environment[RUN_ENV],
                        "outcome": "failed",
                        "diagnostics": "captured",
                    },
                )
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value
    finally:
        os.close(descriptor)
    cleanup(directory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--wait-for-expiry", action="store_true")
    parser.add_argument("--capture-interrupted", action="store_true")
    args = parser.parse_args()
    try:
        if args.wait_for_expiry and args.capture_interrupted:
            raise ValueError("choose one cleanup action")
        if args.wait_for_expiry:
            wait_for_expiry(args.directory)
        elif args.capture_interrupted:
            recover_interrupted(args.directory)
        else:
            cleanup(args.directory)
    except Exception as error:
        detail = error_detail(error)
        print(
            "Disposable cleanup did not complete; retain the run and retry after investigation. "
            f"Category: {detail['category']}; reason: {detail['reason']}."
        )
        return 2
    print("Disposable fixture removed; diagnostic records retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
