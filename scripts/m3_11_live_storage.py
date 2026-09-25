"""Explicit Spaces inputs for the combined disposable source/destination pair."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from scripts.m3_11_backup_fixture import Target
from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import BINDING_FIELDS, fields, uuid7
from scripts.qualification_context import ARTIFACT_ENV, RUN_ENV, host_name
from scripts.qualification_retirement import artifact_digest

FORMAT = "lowerduckpond-m3-11-private-live-storage-v1"
PRIVATE_DIRECTORY_MODE = 0o700


def _path(environment: Mapping[str, str]) -> Path:
    artifact = Path(environment[ARTIFACT_ENV])
    if (
        not artifact.is_absolute()
        or artifact.name != "static-host-agent.tar"
        or artifact.parent.name != "fixture"
        or environment.get("M3_10_INSTALLED_REPORT")
        != str(artifact.parent.parent / "installed.json")
    ):
        raise ValueError("combined Spaces evidence paths disagree with their owned fixture")
    root = artifact.parent.parent
    metadata = root.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        or metadata.st_uid != os.geteuid()
    ):
        raise ValueError("combined Spaces run directory must be private and owned")
    return root / "live-storage.json"


@dataclass(frozen=True)
class LiveStorage:
    target: Target
    binding: dict[str, object]
    owner_version: str
    environment: Mapping[str, str] = field(repr=False)
    restic_password: str = field(repr=False)

    @classmethod
    def load(cls, environment: Mapping[str, str]) -> LiveStorage:
        """Read only the original private record in this fixture's owned run root."""
        result = cls._retained(environment)
        result.require_owner()
        return result

    @classmethod
    def _retained(cls, environment: Mapping[str, str]) -> LiveStorage:
        """Read local inputs; an authorized cleanup may already have deleted its owner.

        Normal qualification must additionally require_owner. The cleanup caller
        must validate the original durable teardown intent before any mutation.
        """
        document = fields(
            read_private(_path(environment)),
            {
                "format",
                "run_id",
                "region",
                "backup_bucket",
                "archive_bucket",
                "binding",
                "owner_version",
                "restic_password",
            },
        )
        strings = {key: value for key, value in document.items() if isinstance(value, str)}
        if set(strings) != set(document) - {"binding"} or strings["format"] != FORMAT:
            raise ValueError("combined Spaces private inputs are invalid")
        target = Target(
            strings["run_id"],
            strings["region"],
            strings["backup_bucket"],
            strings["archive_bucket"],
        )
        binding = fields(document["binding"], BINDING_FIELDS)
        result = cls(
            target, binding, strings["owner_version"], environment, strings["restic_password"]
        )
        result._require_inputs(environment)
        return result

    def save(self) -> None:
        """Persist the original owner version/password once, before any Restic use."""
        self.require_source(self.environment)
        write_private(
            _path(self.environment),
            {
                "format": FORMAT,
                "run_id": self.target.run_id,
                "region": self.target.region,
                "backup_bucket": self.target.backup_bucket,
                "archive_bucket": self.target.archive_bucket,
                "binding": self.binding,
                "owner_version": self.owner_version,
                "restic_password": self.restic_password,
            },
        )

    def require_source(self, environment: Mapping[str, str]) -> None:
        """Reject ambient/local overrides before attaching any live credentials."""
        self._require_inputs(environment)
        self.require_owner()

    def _require_inputs(self, environment: Mapping[str, str]) -> None:
        host_name(environment)
        if (
            environment.get(RUN_ENV) != uuid7(self.target.run_id).hex
            or environment.get("M3_10_ARCHIVE_BACKEND") != "spaces"
            or environment.get("M3_11_COMBINED_BACKEND") != "spaces"
            or not environment.get("DOCKER_HOST", "").startswith("unix:///")
            or environment.get("DOCKER_CONTEXT")
        ):
            raise ValueError("combined Spaces reconstruction requires its owned local fixture")
        _path(environment)
        self.target.manifest(self.binding)
        if (
            re.fullmatch(r"[0-9a-f]{64}", self.restic_password) is None
            or self.restic_password == self.environment.get("RESTIC_PASSWORD")
            or self.binding["artifact_sha256"] != artifact_digest(Path(environment[ARTIFACT_ENV]))
        ):
            raise ValueError("combined Spaces reconstruction inputs changed")

    def require_owner(self) -> None:
        writer, observer = self.target.clients(self.environment)
        for client in (writer, observer):
            self.target.require_owner(client, self.binding, version=self.owner_version)

    def variables(self) -> dict[str, object]:
        """Private Ansible inputs; callers must use no_log and a private inventory."""
        self.require_owner()
        required = ("SPACES_ARCHIVE_ACCESS_KEY_ID", "SPACES_ARCHIVE_SECRET_ACCESS_KEY")
        if any(not self.environment.get(key) for key in required):
            raise ValueError("combined Spaces reconstruction archive inputs are unavailable")
        if self.environment[required[0]] in {
            self.environment["SPACES_BACKUP_ACCESS_KEY_ID"],
            self.environment["SPACES_ACCESS_KEY_ID"],
        }:
            raise ValueError("combined Spaces service credentials are not separated")
        return {
            "backup_repository": self.target.repository,
            "backup_restic_password": self.restic_password,
            "backup_spaces_access_key_id": self.environment["SPACES_BACKUP_ACCESS_KEY_ID"],
            "backup_spaces_secret_access_key": self.environment["SPACES_BACKUP_SECRET_ACCESS_KEY"],
            "backup_spaces_region": self.target.region,
            "backup_node_name": "m3-11-" + uuid7(self.target.run_id).hex,
            "static_host_agent_archive_configuration": {
                "format": "lowerduckpond-archive-configuration-v1",
                "region": self.target.region,
                "bucket": self.target.archive_bucket,
                "accessKeyId": self.environment["SPACES_ARCHIVE_ACCESS_KEY_ID"],
                "secretAccessKey": self.environment["SPACES_ARCHIVE_SECRET_ACCESS_KEY"],
            },
        }


def main() -> int:
    # Only no_log Ansible tasks consume this private stdout; never a shareable receipt.
    if sys.argv[1:] != ["--variables"]:
        print("Usage: python -m scripts.m3_11_live_storage --variables", file=sys.stderr)
        return 2
    try:
        storage = LiveStorage.load(os.environ)
        variables = storage.variables()
    except ValueError, OSError, KeyError:
        print("Combined Spaces private storage validation failed.", file=sys.stderr)
        return 1
    print(json.dumps(variables, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
