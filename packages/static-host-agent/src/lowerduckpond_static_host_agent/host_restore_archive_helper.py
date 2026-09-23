"""Credential-isolated archive proof and exact-version cleanup for host restoration."""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import sys
from pathlib import Path
from typing import cast

from lowerduckpond_static_contracts import decode_json_object, validate_uuid7

from lowerduckpond_static_host_agent.archive_configuration import load_archive_configuration
from lowerduckpond_static_host_agent.archive_journal import ArchiveJournal
from lowerduckpond_static_host_agent.archive_quarantine import ArchiveQuarantine
from lowerduckpond_static_host_agent.backup_caddy import CaddyBackupEvidence
from lowerduckpond_static_host_agent.backup_identity import framed_digest
from lowerduckpond_static_host_agent.caddy_bootstrap import require_exact_file
from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.export_spool import ExportSpool
from lowerduckpond_static_host_agent.host_restore_archive_authority import collect_restore_archives
from lowerduckpond_static_host_agent.host_restore_archives import verify_restore_archives
from lowerduckpond_static_host_agent.host_restore_authority import require_saved_authority
from lowerduckpond_static_host_agent.host_restore_diagnostics import diagnostic
from lowerduckpond_static_host_agent.host_restore_gate import RECOVERY_ROOT
from lowerduckpond_static_host_agent.host_restore_inputs import INPUT_ROOT, RestoreInputs
from lowerduckpond_static_host_agent.host_restore_ipc import (
    REPLY_SCHEMA,
    SELECTION_LOCK,
    SOCKET_PATH,
    _peer,
    receive_message,
    require_lease,
    require_request,
    send_message,
)
from lowerduckpond_static_host_agent.host_restore_journal import (
    LOCK,
    HostRestoreError,
    RestorePhase,
    RestoreStore,
)
from lowerduckpond_static_host_agent.host_restore_local import DONE_SCHEMA, WORK_SCHEMA
from lowerduckpond_static_host_agent.host_restore_remote import _bound, finish_restore_remote
from lowerduckpond_static_host_agent.repository import StateRepository

# The two fixed units bind the appropriate private/installed source here. The
# request carries no paths and cannot select a credential file or storage URL.
STATE_ROOT = Path("/restore-state")
WORKSPACE = Path("/restore-archives")


def original_ca(
    inputs: RestoreInputs, *, root: Path = INPUT_ROOT, owner: int = 0
) -> tuple[bytes, ...]:
    digests = cast(list[str], inputs.caddy["originalOriginPullCaSha256"])
    result = tuple(
        ssl.PEM_cert_to_DER_cert(
            require_exact_file(
                root / f"original-origin-pull-ca-{number}.pem",
                owner=owner,
                group=owner,
                modes=(0o600,),
                maximum_bytes=32 * 1024,
            ).decode("ascii")
        )
        for number in range(len(digests))
    )
    if [hashlib.sha256(value).hexdigest() for value in result] != digests:
        raise HostRestoreError("restore_archive_original_trust_changed")
    return result


def require_helper_state(store: RestoreStore, state: Path) -> None:
    current = store.read()
    if current is None:
        raise HostRestoreError("restore_archive_state_unbound")
    metadata = state.stat(follow_symlinks=False)
    identity = {"device": metadata.st_dev, "inode": metadata.st_ino}
    if current.phase is RestorePhase.VALIDATED:
        receipt = decode_json_object(store.read_bytes("materialize-state.json"))
        expected: object = {"device": receipt["device"], "inode": receipt["inode"]}
    elif current.phase in {RestorePhase.INSTALLED, RestorePhase.VERIFIED, RestorePhase.COMPLETE}:
        receipt = decode_json_object(store.read_bytes("root-install.json"))
        expected = cast(dict[str, dict[str, object]], receipt["roots"])["state"]["candidate"]
    else:
        raise HostRestoreError("restore_archive_state_phase_invalid")
    if identity != expected:
        raise HostRestoreError("restore_archive_state_identity_changed")


def helper_evidence(
    store: RestoreStore,
    journal: ArchiveJournal,
    action: str,
    *,
    workspace: Path = WORKSPACE,
) -> dict[str, object]:
    inputs, descriptor = require_saved_authority(store)
    journal._require_lock()
    if action == "verify":
        obligations = collect_restore_archives(
            store,
            journal,
            CaddyBackupEvidence.from_dict(descriptor["caddy"]),
            original_ca(inputs),
            journal.remote.inventory(),
        )
        return verify_restore_archives(journal.remote, obligations, workspace, owner=store.owner)
    if action == "cleanup":
        current = store.read()
        assert current is not None  # noqa: S101 - saved authority requires it
        done = decode_json_object(store.read_bytes("local-done.json"))
        work = store.read_bytes("local-work.json")
        if (
            done.get("schema") != DONE_SCHEMA
            or done.get("validatedJournalDigest") != current.digest
            or done.get("workDigest") != framed_digest(WORK_SCHEMA, work)
            or type(done.get("remoteIntents")) is not list
        ):
            raise HostRestoreError("restore_archive_local_completion_unbound")
        for identity in cast(list[object], done["remoteIntents"]):
            finish_restore_remote(store, journal, validate_uuid7(identity), workspace)
    elif action != "verify-installed":
        raise HostRestoreError("restore_archive_action_invalid")
    if journal.repository.measure_intent_records().records:
        raise HostRestoreError("restore_archive_local_intent_remains")
    return verify_restore_archives(journal.remote, _bound(journal), workspace, owner=store.owner)


def archive_helper_main(artifact: str, *, installed: bool) -> int:
    """Only the fixed systemd launcher calls this; neither credential set is inherited."""
    if os.geteuid() != 0 or sys.argv[1:]:
        print("restore_archive_invalid_invocation", file=sys.stderr)
        return 64
    descriptors: tuple[int, ...] = ()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as stream:
            stream.settimeout(30)
            stream.connect(str(SOCKET_PATH))
            _peer(stream, 0)
            request, descriptors = receive_message(stream, descriptor_count=2)
            require_lease(RECOVERY_ROOT / LOCK, descriptors[0], exclusive=True)
            require_lease(SELECTION_LOCK, descriptors[1], exclusive=False)
            with DurableDirectory.open(
                RECOVERY_ROOT, expected_owner=0, expected_directory_mode=0o700
            ) as directory:
                store = RestoreStore(directory, 0, lease_descriptor=descriptors[0])
                action = require_request(request, store, artifact, installed=installed)
                inputs, _ = require_saved_authority(store)
                configuration = load_archive_configuration()
                if inputs.document["archiveTarget"] != {
                    "region": configuration.region,
                    "bucket": configuration.bucket,
                }:
                    raise HostRestoreError("restore_archive_target_mismatch")
                require_helper_state(store, STATE_ROOT)
                with (
                    StateRepository(
                        STATE_ROOT,
                        expected_owner=0,
                        recovery_root=RECOVERY_ROOT,
                        private_reconciliation=True,
                    ) as repository,
                    ExportSpool(STATE_ROOT, expected_owner=0) as spool,
                    spool.construction(),
                ):
                    quarantine = ArchiveQuarantine(
                        STATE_ROOT, bucket=configuration.bucket, expected_owner=0, locks=spool.locks
                    )
                    journal = ArchiveJournal(
                        repository,
                        spool,
                        configuration.remote_store(),
                        expected_owner=0,
                        quarantine=quarantine.record,
                        require_quarantine_empty=quarantine.require_empty,
                    )
                    evidence = helper_evidence(store, journal, action)
                # Check that no phase or target changed while remote proof ran.
                require_request(request, store, artifact, installed=installed)
                require_helper_state(store, STATE_ROOT)
                send_message(
                    stream,
                    {
                        "schema": REPLY_SCHEMA,
                        "nonce": request["nonce"],
                        "verified": True,
                        "evidence": evidence,
                    },
                )
        return 0
    except Exception as error:
        # No provider messages, restored content, object keys or credentials are
        # exposed through the journal. The caller treats missing reply as failure.
        print("restore_archive_unverified " + diagnostic(error), file=sys.stderr)
        return 1
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
