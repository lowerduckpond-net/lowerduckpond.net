"""Fixed administrative SSH/sudo entry point, absent from ordinary worker transport."""

from __future__ import annotations

import os
import pwd
import sys
from contextlib import ExitStack
from typing import cast

from lowerduckpond_static_contracts import canonical_json_bytes, validate_uuid7

from lowerduckpond_static_host_agent import entrypoints
from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.emergency_delete import EmergencyDeletion
from lowerduckpond_static_host_agent.emergency_remote import (
    finish_emergency_retirement,
    verify_emergency_terminal,
)
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.intents import IntentDiscovery
from lowerduckpond_static_host_agent.repository import StateRepository

_ADMINISTRATOR = "ldp-admin"
_COMMAND_ARGUMENTS = 6
_MAXIMUM_REASON_LENGTH = 1024


def emergency_delete_main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    try:
        recovering = values == ["--recover"]
        if (
            os.geteuid() != 0
            or (not recovering and not _administrative_sudo())
            or (recovering and "SUDO_USER" in os.environ and not _administrative_sudo())
        ):
            return _fail("emergency_administrator_required", 77)
        if not recovering and (
            len(values) != _COMMAND_ARGUMENTS
            or values[::2] != ["--tenant", "--correlation", "--reason"]
            or not values[5].strip()
            or len(values[5]) > _MAXIMUM_REASON_LENGTH
        ):
            return _fail("invalid_emergency_delete_invocation", 64)
        with ExitStack() as resources:
            repository = resources.enter_context(
                StateRepository(entrypoints._STATE_ROOT, expected_owner=0)
            )
            if recovering:
                pending = _pending_administration(repository)
                if pending is None:
                    return 0
                tenant, correlation, principal, reason = pending
            else:
                tenant, correlation = validate_uuid7(values[1]), validate_uuid7(values[3])
                principal, reason = _ADMINISTRATOR, values[5]
            spool = resources.enter_context(ExportSpool(entrypoints._STATE_ROOT, expected_owner=0))
            store = resources.enter_context(entrypoints._open_deployment_release_store())
            runtime = resources.enter_context(entrypoints._open_caddy_control_runtime())

            def cleanup(retirement: dict[str, object] | None, audit: dict[str, object]) -> None:
                verify_emergency_terminal(repository, audit)
                if cast(dict[str, object], audit["deletionEvidence"])["mode"] == "emergency":
                    if retirement is not None:
                        raise ValueError("archive-free emergency retained a remote journal")
                    return
                configuration = load_archive_configuration()
                remote = configuration.remote_store()
                quarantine = ArchiveQuarantine(
                    entrypoints._STATE_ROOT,
                    bucket=remote.bucket,
                    expected_owner=0,
                    locks=spool.locks,
                )
                journal = ArchiveJournal(
                    repository,
                    spool,
                    remote,
                    expected_owner=0,
                    quarantine=quarantine.record,
                    require_quarantine_empty=quarantine.require_empty,
                )
                finish_emergency_retirement(journal, retirement, audit)
                quarantine.resolve(repository, remote)

            result = EmergencyDeletion(repository, spool, runtime, store, cleanup=cleanup).execute(
                tenant, correlation, operator_principal=principal, reason=reason
            )
            if not recovering:
                sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
            return 0
    except Exception:
        # Provider or state exceptions can contain private details; preserve only the fixed code.
        return _fail("emergency_delete_failed", 1)


def _administrative_sudo() -> bool:
    if os.environ.get("SUDO_USER") != _ADMINISTRATOR:
        return False
    account = pwd.getpwnam(_ADMINISTRATOR)
    return os.environ.get("SUDO_UID") == str(account.pw_uid) and account.pw_uid != 0


def _pending_administration(repository: StateRepository) -> tuple[str, str, str, str] | None:
    discovery = IntentDiscovery(repository).discover(blocking=True)
    for intent in discovery.intents:
        document = intent.record.document
        if document["kind"] == "EmergencyDeletionIntent":
            return (
                str(document["tenantId"]),
                str(document["correlationId"]),
                str(document["operatorPrincipal"]),
                str(document["reason"]),
            )
        provenance = document.get("provenance")
        if (
            document["kind"] == "ArchiveRetirementIntent"
            and type(provenance) is dict
            and provenance["kind"] == "emergency-administrator"
        ):
            return (
                str(document["tenantId"]),
                str(document["correlationId"]),
                str(document["operatorPrincipal"]),
                str(provenance["reason"]),
            )
    return None


def _fail(code: str, status: int) -> int:
    print(code, file=sys.stderr)
    return status
