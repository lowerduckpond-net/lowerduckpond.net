"""Capture original inputs and owned resources for the secure-workstation drill."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import stat
import sys
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.report import ArchiveQualificationReport

from scripts import m3_11_qualification_evidence as evidence
from scripts import qualification_restore as owned
from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_live_storage import LiveStorage
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_restore_reservation import reserve
from scripts.production_qualification_inputs import POLICY, candidate_inputs, revision
from scripts.qualification_context import (
    ARTIFACT_ENV,
    HOST_ENV,
    RESOURCE_ENV,
    RUN_ENV,
    resource_names,
)
from scripts.qualification_retirement import artifact_digest

FORMAT = "lowerduckpond-m3-11-live-fixture-v1"
PRIVATE_DIRECTORY_MODE = 0o700


def _directory(directory: Path) -> None:
    metadata = directory.lstat()
    if (
        directory != directory.resolve(strict=True)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        or metadata.st_uid != os.geteuid()
    ):
        raise ValueError("combined qualification needs its canonical private run directory")


def _local(environment: Mapping[str, str]) -> str:
    endpoint = environment.get("DOCKER_HOST", "")
    if not endpoint.startswith("unix:///") or environment.get("DOCKER_CONTEXT"):
        raise ValueError("combined qualification requires its pinned local Docker endpoint")
    return endpoint


def _environment(directory: Path, run_id: str, endpoint: str) -> dict[str, str]:
    return {
        **resource_names(evidence.uuid7(run_id).hex),
        ARTIFACT_ENV: str(directory / "fixture/static-host-agent.tar"),
        "MOLECULE_EPHEMERAL_DIRECTORY": str(directory / "fixture/molecule"),
        "DOCKER_HOST": endpoint,
        "M3_10_ARCHIVE_BACKEND": "spaces",
        "M3_11_COMBINED_BACKEND": "spaces",
        "M3_10_INSTALLED_REPORT": str(directory / "installed.json"),
    }


def allocate(directory: Path, ambient: Mapping[str, str]) -> dict[str, str]:
    """Allocate names only; a failed attempt never reuses an existing run root."""
    _directory(directory)
    endpoint = _local(ambient)
    if any(key in ambient for key in (*RESOURCE_ENV, "MOLECULE_EPHEMERAL_DIRECTORY")):
        raise ValueError("combined qualification cannot inherit another fixture")
    run_id = str(uuid.uuid7())
    environment = _environment(directory, run_id, endpoint)
    (directory / "fixture").mkdir(mode=0o700)
    write_private(
        directory / "fixture.json", {"format": FORMAT, "run_id": run_id, "environment": environment}
    )
    return {**ambient, **environment}


def environment_for(directory: Path, ambient: Mapping[str, str]) -> dict[str, str]:
    _directory(directory)
    fixture = evidence.fields(
        read_private(directory / "fixture.json"), {"format", "run_id", "environment"}
    )
    run_id = str(evidence.uuid7(fixture["run_id"]))
    expected = _environment(directory, run_id, _local(ambient))
    if (
        fixture["format"] != FORMAT
        or fixture["environment"] != expected
        or any(key in ambient and ambient[key] != value for key, value in expected.items())
    ):
        raise ValueError("combined qualification fixture context changed")
    return {**ambient, **expected}


def _target(environment: Mapping[str, str]) -> Target:
    return Target(
        str(uuid.UUID(environment[RUN_ENV])),
        environment["SPACES_REGION"],
        environment["SPACES_BACKUP_BUCKET"],
        environment["SPACES_ARCHIVE_BUCKET"],
    )


def binding(directory: Path, repository: Path, environment: Mapping[str, str]) -> dict[str, object]:
    """Compare original pre-provider capture with current clean executable inputs."""
    source = revision((directory / "source-revision").read_text(encoding="ascii").strip())
    artifact = artifact_digest(Path(environment[ARTIFACT_ENV]))
    expected = {
        "source_revision": source,
        "input_policy": POLICY,
        "qualification_inputs_sha256": candidate_inputs(repository, source, artifact),
        "storage_target_sha256": _target(environment).storage_target_sha256,
    }
    if read_private(directory / "qualification-inputs.json") != expected:
        raise ValueError("combined qualification differs from the original input capture")
    raw, _ = evidence.read_document(directory / "storage.json")
    storage = ArchiveQualificationReport.from_json(raw.decode("ascii"))
    if storage.source_revision != source:
        raise ValueError("combined qualification storage report belongs to another source")
    evidence.timestamp(storage.generated_at, now=datetime.now(UTC), maximum_age=timedelta(hours=24))
    return {
        **expected,
        "artifact_sha256": artifact,
        "storage_run_id": storage.run_id,
        "storage_report_sha256": hashlib.sha256(raw).hexdigest(),
    }


def prepare_storage(directory: Path, repository: Path, ambient: Mapping[str, str]) -> LiveStorage:
    environment = environment_for(directory, ambient)
    if (directory / "live-storage.json").exists() or (directory / "live-storage.json").is_symlink():
        raise ValueError("combined qualification already has its original storage inputs")
    target = _target(environment)
    captured = binding(directory, repository, environment)
    source = owned.inspect(environment, environment[HOST_ENV])
    if source.get("name") != "/" + environment[HOST_ENV] or source.get("running") is not True:
        raise ValueError("combined qualification source is not its running owned fixture")
    writer, observer = target.clients(environment)
    version = target.begin(writer, observer, captured)
    result = LiveStorage(target, captured, version, environment, secrets.token_hex(32))
    result.save()
    return result


def _caddy(environment: dict[str, str], repository: Path) -> str:
    versions = yaml.safe_load((repository / "platform/versions.yml").read_bytes())[
        "platform_versions"
    ]
    path = "/usr/local/lib/lowerduckpond/caddy-{}-xcaddy-{}-cloudflare-{}".format(
        versions["caddy"], versions["xcaddy"], versions["caddy_cloudflare_module"]
    )
    result = (
        owned.command(
            environment,
            "docker",
            "exec",
            environment[HOST_ENV],
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            """
import hashlib, os, stat, sys
from pathlib import Path
path = Path(sys.argv[1])
assert Path('/usr/local/bin/caddy').resolve(strict=True) == path
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(descriptor, 'rb') as stream:
    before = os.fstat(stream.fileno())
    assert stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
    assert 0 < before.st_size <= 256 * 1024 * 1024
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = os.fstat(stream.fileno())
    assert (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns)
print(digest)
""",
            path,
        )
        .decode("ascii")
        .strip()
    )
    evidence.digest(result)
    return result


def capture(directory: Path, repository: Path, ambient: Mapping[str, str]) -> dict[str, object]:
    """Called after legacy idempotence, before any combined phase or public DNS use."""
    environment = environment_for(directory, ambient)
    storage = LiveStorage.load(environment)
    if storage.binding != binding(directory, repository, environment):
        raise ValueError("combined qualification changed its original storage run")
    for name in ("combined-context.json", "combined-names.json"):
        if (directory / name).exists() or (directory / name).is_symlink():
            raise ValueError("combined qualification context cannot be recaptured")
    caddy_digest = _caddy(environment, repository)
    reservation = reserve(storage)
    nonce = str(uuid.uuid7())
    if nonce == storage.target.run_id:
        raise ValueError("combined qualification public names require an independent nonce")
    write_private(
        directory / "combined-names.json",
        {
            "format": evidence.NAMES_FORMAT,
            "run_id": storage.target.run_id,
            "nonce": nonce,
            "subjects": list(evidence.subjects(nonce)),
        },
    )
    context = {
        "format": evidence.CONTEXT_FORMAT,
        "run_id": storage.target.run_id,
        "captured_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        **storage.binding,
        **{
            kind + "_fixture_sha256": hashlib.sha256(
                evidence.canonical_bytes(reservation[kind])
            ).hexdigest()
            for kind in ("source", "destination")
        },
        "backup_repository_sha256": reservation["backup_repository_sha256"],
        "caddy_binary_sha256": caddy_digest,
        "subject_set_sha256": evidence.subject_digest(nonce),
    }
    write_private(directory / "combined-context.json", context)
    evidence.validate_names(directory / "combined-names.json", context)
    return context


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("allocate", "capture-public", "prepare-storage", "capture")
    )
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    directory = arguments.directory
    repository = Path(__file__).resolve().parents[1]
    if arguments.action == "allocate":
        allocate(directory, os.environ)
        # Only fixed, non-secret fixture coordinates enter the shell. Never
        # print the merged ambient environment or construct shell source text.
        fixture = read_private(directory / "fixture.json")
        environment = evidence.fields(
            fixture["environment"],
            set(_environment(directory, str(fixture["run_id"]), _local(os.environ))),
        )
        for key, value in environment.items():
            sys.stdout.buffer.write(key.encode() + b"\0" + str(value).encode() + b"\0")
    elif arguments.action == "capture-public":
        from scripts.m3_11_public_inputs import capture as capture_public  # noqa: PLC0415

        capture_public(directory, dict(os.environ))
    elif arguments.action == "prepare-storage":
        prepare_storage(directory, repository, os.environ)
    else:
        capture(directory, repository, os.environ)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
