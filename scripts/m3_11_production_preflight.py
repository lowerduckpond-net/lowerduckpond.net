"""Observe the accepted dark M3.10 predecessor without mutating production."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

from lowerduckpond_static_host_agent.backup_identity import RepositoryIdentity

from scripts import m3_11_production_probe as probe
from scripts.m3_11_production_journal import canonical
from scripts.production_qualification_inputs import git, storage_target_digest

ROOT = Path(__file__).resolve().parents[1]


def save(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def run(directory: Path, name: str, command: list[str], *, program: bytes = b"") -> bytes:
    # Fixed read-only commands. Retain even failed observations privately;
    # provider/SSH exception text is never copied to the terminal.
    result = subprocess.run(  # noqa: S603 - fixed program/argv and verified SSH destination
        command, input=program, capture_output=True, check=False
    )
    save(directory / (name + ".stdout"), result.stdout)
    save(directory / (name + ".stderr"), result.stderr)
    if result.returncode:
        raise ValueError(f"production preflight step failed: {name}")
    return result.stdout


def ssh() -> list[str]:
    address = os.environ["PRODUCTION_ORIGIN_IPV4"]
    if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", address) is None:
        raise ValueError("production transport identity is invalid")
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "HostKeyAlias=lowerduckpond.net",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-i",
        os.environ["ANSIBLE_PRIVATE_KEY_FILE"],
        "ldp-admin@" + address,
    ]


def observation(directory: Path, name: str) -> dict[str, object]:
    region, bucket = os.environ["SPACES_REGION"], os.environ["SPACES_BACKUP_BUCKET"]
    # These coordinates go into the fixed remote argv, never shell syntax.
    if (
        re.fullmatch(r"[a-z]{3}[1-9][0-9]?", region) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) is None
    ):
        raise ValueError("production storage coordinates are invalid")
    raw = run(
        directory,
        name,
        [*ssh(), f"sudo --non-interactive /usr/bin/python3 -I -B - {region} {bucket}"],
        program=(ROOT / "scripts/m3_11_production_probe.py").read_bytes(),
    )
    value = json.loads(raw, object_pairs_hook=probe.unique_object)
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "format",
            "predecessor",
            "repository_config_id",
            "repository_node",
            "repository_locator",
            "backup_configuration_sha256",
            "publication_configuration_sha256",
            "capacity",
        }
        or value["format"] != "lowerduckpond-m3-11-predecessor-observation-v1"
        or not isinstance(value["predecessor"], str)
        or re.fullmatch(r"[0-9a-f]{64} [0-9a-f]{40}( [0-9a-f]{64})?\n", value["predecessor"])
        is None
        or value["repository_node"] != probe.NODE
        or value["repository_locator"]
        != f"s3:https://{region}.digitaloceanspaces.com/{bucket}/backups/{probe.NODE}"
        or any(
            not isinstance(value[key], str) or re.fullmatch(r"[0-9a-f]{64}", value[key]) is None
            for key in (
                "repository_config_id",
                "backup_configuration_sha256",
                "publication_configuration_sha256",
            )
        )
        or not isinstance(value["capacity"], list)
        or len(value["capacity"]) != len(probe.CAPACITY_PATHS)
    ):
        raise ValueError("production predecessor returned invalid observations")
    return cast(dict[str, object], value)


def preflight(directory: Path) -> dict[str, object]:
    run(
        directory,
        "operator",
        [
            str(ROOT / "scripts/check-m3-6-operator-identity"),
            os.environ["ANSIBLE_PRIVATE_KEY_FILE"],
        ],
    )
    run(directory, "dark-host", [str(ROOT / "scripts/preflight-m3-dark-host-production")])
    original = observation(directory, "predecessor-before")
    predecessor = cast(str, original["predecessor"]).split()
    artifact, source = predecessor[:2]
    target = storage_target_digest()
    if len(predecessor) > 2 and predecessor[2] != target:  # noqa: PLR2004 - optional original target binding
        raise ValueError("production storage target differs from completed M3.10")
    candidate = git(ROOT, "rev-parse", "HEAD").decode("ascii").strip()
    git(ROOT, "merge-base", "--is-ancestor", source, candidate)
    authority = run(
        directory,
        "archive-authority",
        [*ssh(), f"sudo --non-interactive /bin/bash -s -- {artifact} upgrade-host {source}"],
        program=(ROOT / "scripts/m3-10-completed-host-preflight").read_bytes(),
    )
    authority_path = directory / "archive-authority.json"
    save(authority_path, authority)
    run(
        directory,
        "provider",
        [
            sys.executable,
            "-m",
            "scripts.check_m3_10_provider",
            "--allow-existing-archives",
            "--archive-authority",
            str(authority_path),
            "--artifact",
            artifact,
            "--source",
            source,
        ],
    )
    run(directory, "firewall", [sys.executable, "-m", "scripts.check_m3_10_host_firewall"])
    run(directory, "backup-policy", [sys.executable, "-m", "scripts.check_m3_11_backup_policy"])
    final = observation(directory, "predecessor-after")
    if any(original[key] != final[key] for key in original if key != "capacity"):
        raise ValueError("production authority changed during preflight")
    identity = RepositoryIdentity(
        cast(str, original["repository_config_id"]),
        cast(str, original["repository_node"]),
        cast(str, original["repository_locator"]),
    )
    receipt: dict[str, object] = {
        "format": "lowerduckpond-m3-11-predecessor-preflight-v1",
        "candidate_source": candidate,
        "storage_target_sha256": target,
        "repository_binding": identity.binding()["value"],
        "observation": final,
    }
    save(directory / "preflight.json", canonical(receipt))
    return receipt


def main() -> int:
    directory = Path(tempfile.mkdtemp(prefix="lowerduckpond-m3-11-preflight-"))
    try:
        if len(sys.argv) != 1:
            raise ValueError("unexpected production preflight arguments")
        preflight(directory)
    except ValueError, OSError, KeyError, TypeError, RecursionError:
        print(
            f"M3.11 read-only preflight failed. Private diagnostics: {directory}", file=sys.stderr
        )
        return 1
    print(f"M3.11 read-only predecessor preflight passed. Private observations: {directory}")
    print("Qualification and explicit production convergence remain separate gates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
