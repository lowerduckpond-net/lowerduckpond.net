"""One fixed-source snapshot request; retries belong to durable discovery."""

from __future__ import annotations

from collections.abc import Mapping

from lowerduckpond_static_contracts import decode_json_object

from lowerduckpond_static_host_agent import audit_archive_formats as formats
from lowerduckpond_static_host_agent.audit_archive_restic import SNAPSHOT_SOURCE
from lowerduckpond_static_host_agent.backup_identity import BackupIdentityError
from lowerduckpond_static_host_agent.backup_restic import _restic

_MAX_OUTPUT = 32 * 1024


def create_rotation_snapshot(record: dict[str, object], environment: Mapping[str, str]) -> str:
    formats.validate_rotation(record)
    node = environment.get("LOWERDUCKPOND_BACKUP_NODE_NAME")
    if not node:
        raise BackupIdentityError("audit snapshot requires its bound node identity")
    arguments = ["backup", "--json", "--quiet", "--host", node]
    for tag in formats.required_archive_tags(record):
        arguments.extend(("--tag", tag))
    arguments.append(SNAPSHOT_SOURCE)
    # The existing five-minute child bound and service envelope apply. A
    # partial capture, malformed response or lost reply keeps the prepared
    # attempt; the next invocation must discover before making any request.
    output = _restic(tuple(arguments), environment, _MAX_OUTPUT)
    summary = decode_json_object(output, maximum_bytes=_MAX_OUTPUT)
    if summary.get("message_type") != "summary":
        raise BackupIdentityError("audit snapshot response has no terminal summary")
    return formats.full_snapshot_id(summary.get("snapshot_id"))
