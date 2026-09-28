"""Private diagnostic workspaces derived from a permanently failed live run."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from pathlib import Path
from typing import cast

from scripts.m3_11_combined_inputs import _directory, _environment, environment_for
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, read_document

FORMAT = "lowerduckpond-m3-11-debug-v1"
MARKER = "diagnostic-origin.json"
COPY_FILES = (
    "combined-context.json",
    "combined-names.json",
    "live-storage.json",
    "fixture/static-host-agent.tar",
    "restore/source.json",
    "restore/destination.json",
    "restore/acme.json",
    "restore/acme-readiness.json",
    "restore/source-idempotence.json",
    "restore/operator-transport.json",
    "restore/inputs/target.json",
    "source-idempotence.json",
    "public-inputs/original.json",
    "public-inputs/roots.pem",
    "public-inputs/hosts",
    "public-inputs/resolv.conf",
)
MAX_FILE = 256 * 1024 * 1024


def fingerprint(path: Path) -> str:
    if path.resolve() != path:
        raise ValueError("diagnostic input path is redirected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_FILE
        ):
            raise ValueError("diagnostic input has unsafe metadata")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("diagnostic input changed while reading")
        return digest


def copy(source: Path, target: Path) -> None:
    expected = fingerprint(source)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _directory(target.parent)
    if target.exists() or target.is_symlink():
        if fingerprint(target) != expected:
            raise ValueError("diagnostic copy differs from original evidence")
        return
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with (
        os.fdopen(descriptor, "rb") as incoming,
        tempfile.NamedTemporaryFile(dir=target.parent, delete_on_close=False) as outgoing,
    ):
        while block := incoming.read(1024 * 1024):
            outgoing.write(block)
        outgoing.flush()
        os.fsync(outgoing.fileno())
        if fingerprint(Path(outgoing.name)) != expected or fingerprint(source) != expected:
            raise ValueError("diagnostic input changed during its copy")
        Path(outgoing.name).replace(target)
    if fingerprint(target) != expected or fingerprint(source) != expected:
        raise ValueError("diagnostic input changed during its copy")


def original(run: Path) -> tuple[dict[str, str], dict[str, str]]:
    _directory(run)
    manifest = read_private(run / "fixture.json")
    environment = environment_for(run, cast("dict[str, str]", manifest["environment"]))
    _, failure = read_document(run / "failure-exit.json")
    status = failure.get("exit_status")
    if type(status) is not int or status <= 0 or failure.get("phase") != "verify":
        raise ValueError("diagnostic continuation requires an original failed verification")
    if any(
        (run / path).exists() or (run / path).is_symlink()
        for path in (
            "qualification.json",
            "combined.json",
            "owned-teardown",
            "failed-archive-retirement",
        )
    ):
        raise ValueError("diagnostic continuation cannot adopt completed or retired authority")
    protected = (
        "fixture.json",
        "failure.json",
        "failure-exit.json",
        "source-revision",
        "combined.started.json",
        *COPY_FILES,
    )
    hashes = {name: fingerprint(run / name) for name in protected if (run / name).exists()}
    for path in sorted((run / "combined-phases").glob("*.json")):
        hashes[str(path.relative_to(run))] = fingerprint(path)
    return environment, hashes


def workspace(run: Path) -> Path:
    """Keep original bytes and snapshot authority; all new reports live separately."""
    environment, hashes = original(run)
    root = run / "diagnostics"
    root.mkdir(mode=0o700, exist_ok=True)
    _directory(root)
    target = root / "workspace"
    target.mkdir(mode=0o700, exist_ok=True)
    _directory(target)
    marker: dict[str, object] = {
        "format": FORMAT,
        "original_run": str(run),
        "original_files": hashes,
        "qualification_authority": "none",
    }
    # Mark both trees before any fixture action. Neither tree can package a pass.
    if not (run / MARKER).exists():
        write_private(run / MARKER, marker)
    elif read_private(run / MARKER) != marker:
        raise ValueError("diagnostic adoption differs from its original authority")
    once(target / MARKER, marker)
    for name in COPY_FILES:
        if (run / name).exists():
            copy(run / name, target / name)
    manifest = read_private(run / "fixture.json")
    once(
        target / "fixture.json",
        {
            **manifest,
            "environment": _environment(
                target, str(manifest["run_id"]), environment["DOCKER_HOST"]
            ),
        },
    )
    (target / "attempts").mkdir(mode=0o700, exist_ok=True)
    _directory(target / "attempts")
    require_original_unchanged(target)
    return target


def once(path: Path, value: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        if read_private(path) != value:
            raise ValueError("diagnostic original record changed")
    else:
        write_private(path, value)


def replace_private(path: Path, value: dict[str, object]) -> None:
    """Replace only diagnostic scheduling hints, never original evidence."""
    _directory(path.parent)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete_on_close=False) as stream:
        stream.write(canonical_bytes(value))
        stream.flush()
        os.fsync(stream.fileno())
        Path(stream.name).replace(path)


def require_original_unchanged(root: Path) -> None:
    marker = read_private(root / MARKER)
    if marker.get("format") != FORMAT or marker.get("qualification_authority") != "none":
        raise ValueError("diagnostic workspace lacks its original failed-run binding")
    run = Path(str(marker["original_run"]))
    _directory(run)
    _directory(root)
    hashes = cast("dict[str, str]", marker["original_files"])
    if root != run / "diagnostics/workspace" or read_private(run / MARKER) != marker:
        raise ValueError("diagnostic workspace has another original binding")
    if any(fingerprint(run / name) != digest for name, digest in hashes.items()):
        raise ValueError("original failure evidence changed")
    if any(fingerprint(root / name) != hashes[name] for name in COPY_FILES if name in hashes):
        raise ValueError("diagnostic copies changed")
    manifest = read_private(run / "fixture.json")
    endpoint = cast("dict[str, str]", manifest["environment"])["DOCKER_HOST"]
    if read_private(root / "fixture.json") != {
        **manifest,
        "environment": _environment(root, str(manifest["run_id"]), endpoint),
    }:
        raise ValueError("diagnostic fixture coordinates changed")


def diagnostic_digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
