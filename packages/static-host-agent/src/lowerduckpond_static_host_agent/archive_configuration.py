"""Load dedicated archive credentials only from a private root-owned file."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from lowerduckpond_static_contracts import ContractError, decode_json_object

from lowerduckpond_static_host_agent.archive_remote import (
    ArchiveRemoteStore,
    make_archive_client,
)
from lowerduckpond_static_host_agent.durable import DurableDirectory, StatePathError

ARCHIVE_CONFIGURATION_PATH: Final = Path("/etc/lowerduckpond/archive/credentials.json")
_FORMAT: Final = "lowerduckpond-archive-configuration-v1"
_MAXIMUM_BYTES: Final = 4096
_MAXIMUM_CREDENTIAL_BYTES: Final = 1024
_FIELDS: Final = frozenset({"format", "region", "bucket", "accessKeyId", "secretAccessKey"})


class ArchiveConfigurationError(RuntimeError):
    """Dedicated archive configuration is unavailable or violates its boundary."""


@dataclass(frozen=True, slots=True)
class ArchiveConfiguration:
    """Keep credential values out of ordinary diagnostic representations."""

    region: str
    bucket: str
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.region) is not str
            or re.fullmatch(r"[a-z]{3}[1-9][0-9]?", self.region) is None
            or type(self.bucket) is not str
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", self.bucket) is None
        ):
            raise ArchiveConfigurationError("archive storage location is invalid")
        for credential in (self.access_key_id, self.secret_access_key):
            if (
                type(credential) is not str
                or not 0 < len(credential) <= _MAXIMUM_CREDENTIAL_BYTES
                or not credential.isascii()
                or not credential.isprintable()
                or credential != credential.strip()
            ):
                raise ArchiveConfigurationError("dedicated archive credentials are invalid")

    def remote_store(self) -> ArchiveRemoteStore:
        """Construct the regional client with these explicit credentials only."""

        return ArchiveRemoteStore(
            make_archive_client(
                region=self.region,
                access_key_id=self.access_key_id,
                secret_access_key=self.secret_access_key,
            ),
            bucket=self.bucket,
        )


def load_archive_configuration(
    path: Path = ARCHIVE_CONFIGURATION_PATH, *, expected_owner: int = 0
) -> ArchiveConfiguration:
    """Read one bounded stable file; never substitute ambient SDK credentials.

    Installed callers must use the fixed path. A request received over the
    archive socket must not select this path, its owner, or any configuration field.
    """

    try:
        with DurableDirectory.open(
            path.parent, expected_owner=expected_owner, expected_directory_mode=0o700
        ) as directory:
            raw = directory.read_regular(
                (path.name,),
                expected_owner=expected_owner,
                expected_mode=0o600,
                maximum_bytes=_MAXIMUM_BYTES,
            )
        document = decode_json_object(raw, maximum_bytes=_MAXIMUM_BYTES)
        if set(document) != _FIELDS or document["format"] != _FORMAT:
            raise ArchiveConfigurationError("archive configuration fields are invalid")
        return ArchiveConfiguration(
            _string(document, "region"),
            _string(document, "bucket"),
            _string(document, "accessKeyId"),
            _string(document, "secretAccessKey"),
        )
    except (OSError, StatePathError, ContractError) as error:
        raise ArchiveConfigurationError("private archive configuration is unavailable") from error


def _string(document: dict[str, object], field_name: str) -> str:
    value = document[field_name]
    if type(value) is not str:
        raise ArchiveConfigurationError("archive configuration values are invalid")
    return value
