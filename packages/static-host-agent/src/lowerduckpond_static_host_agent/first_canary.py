"""Bound production jobs for the original, independently reviewed first launch."""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path
from typing import Protocol

from lowerduckpond_static_host_agent.durable import DurableDirectory
from lowerduckpond_static_host_agent.host_restore_gate import require_restore_admission
from lowerduckpond_static_host_agent.repository import StateRecordPath, StoredContract
from scripts.m3_12_contracts import (
    CANARY_TRANSACTION,
    FIRST_CANARY,
    MAX_RECORD_BYTES,
    Document,
    decode,
    decode_launch_admission,
    digest,
    encode,
    require,
)

AUTHORITY = Path("/var/lib/lowerduckpond/convergence/m3-12")
OWNER = 0
VIEW = "first-canary-publication"
FENCE = ("fenced",)
OPERATIONS = {
    "deploy",
    "rollback",
    "suspend",
    "resume",
    "rename",
    "export",
    "import",
    "archive",
    "restore",
    "delete",
}


def project_launch(source: DurableDirectory, owner: int) -> None:
    """Expose only the four sealed public records to network-isolated workers."""
    fd = source.duplicate_descriptor()
    try:
        with suppress(FileExistsError):
            os.mkdir(VIEW, mode=0o700, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    with source.open_descendant((VIEW,)) as view:
        for name in (
            "transaction.json",
            "admission.json",
            "launch-intent.json",
            "launch-receipt.json",
        ):
            key = (name,)
            raw = source.read_regular(
                key, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
            )
            try:
                existing = view.read_regular(
                    key, expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
                )
            except FileNotFoundError:
                view.create_immutable(key, raw)
            else:
                require(existing == raw, "first-canary-view-conflict")


def fence_worker_view(source: DurableDirectory, owner: int, *, closed: bool) -> None:
    try:
        view = source.open_descendant((VIEW,))
    except FileNotFoundError:
        return  # Before first launch there is no worker view to open.
    with view:
        if not closed:
            view.remove(FENCE, missing_ok=True)
            return
        try:
            raw = view.read_regular(
                FENCE, expected_owner=owner, expected_mode=0o600, maximum_bytes=1
            )
        except FileNotFoundError:
            view.create_immutable(FENCE, b"1")
        else:
            require(raw == b"1", "first-canary-fence-changed")


class JobStateReader(Protocol):
    def read(self, path: StateRecordPath) -> StoredContract: ...


def require_job(reader: JobStateReader, job: Document) -> None:
    """Called with tenant-state locked, before reconciliation or job allocation."""
    if not os.path.lexists(AUTHORITY / "transaction.json"):
        if os.path.lexists(AUTHORITY / "admission.json"):
            with DurableDirectory.open(
                AUTHORITY, expected_owner=OWNER, expected_directory_mode=0o700
            ) as records:
                raw = records.read_regular(
                    ("admission.json",),
                    expected_owner=OWNER,
                    expected_mode=0o600,
                    maximum_bytes=MAX_RECORD_BYTES,
                )
                require(
                    decode_launch_admission(raw)["format"] != FIRST_CANARY,
                    "first-canary-job-closed",
                )
        return  # Ordinary pre-successor, installed and disposable admission.
    owner = OWNER
    with DurableDirectory.open(
        AUTHORITY, expected_owner=owner, expected_directory_mode=0o700
    ) as records:

        def read(name: str) -> bytes:
            return records.read_regular(
                (name,), expected_owner=owner, expected_mode=0o600, maximum_bytes=MAX_RECORD_BYTES
            )

        original = decode(read("transaction.json"), "transaction")
        admission = decode_launch_admission(read("admission.json"))
        if admission["format"] != FIRST_CANARY:
            require(original["transactionId"] != CANARY_TRANSACTION, "first-canary-job-closed")
            return
        require_restore_admission()
        launch: Document = reader.read(StateRecordPath.platform_launch()).document
        require(
            original["transactionId"] == CANARY_TRANSACTION
            and not os.path.lexists(AUTHORITY / "revoked")
            and not os.path.lexists(AUTHORITY / "canary-closed")
            and admission["binding"] == original["binding"]
            and digest(admission["decision"]) == original["authorizationSha256"]
            and launch["acceptanceEvidenceDigest"]["value"] == digest(admission),
            "first-canary-job-closed",
        )
        decision = admission["decision"]
        request = job["request"]
        principal = decision["operatorPrincipal"]
        require(job["operatorPrincipal"] == principal, "first-canary-wrong-principal")
        correlation = request["correlationId"]
        if request["operation"] == "create":
            require(
                {
                    "correlationId": correlation,
                    "slug": request["slug"],
                    "requestSha256": digest(request),
                }
                in decision["creates"],
                "first-canary-create-not-reviewed",
            )
            return

        require(
            request["operation"] in OPERATIONS
            and ("slug" not in request or request["slug"] == decision["renameSlug"]),
            "first-canary-operation-not-reviewed",
        )
        # The tenant ID and, for imports, artifact digest become known only after
        # creation/export. Reopen a protected exact request grant and its original create.
        grant = read("canary-job-" + correlation + ".json")
        for slot in decision["creates"]:
            if grant != encode(
                {
                    "format": "lowerduckpond-m3-12-first-canary-job-v1",
                    "authoritySha256": original["authorizationSha256"],
                    "createCorrelationId": slot["correlationId"],
                    "requestSha256": digest(request),
                }
            ):
                continue
            create: Document = reader.read(
                StateRecordPath.authorization_correlation(slot["correlationId"])
            ).document
            result: Document = reader.read(
                StateRecordPath.authorization_result(create["jobId"])
            ).document
            require(
                create["operatorPrincipal"] == principal
                and create["request"]["operation"] == "create"
                and create["request"]["slug"] == slot["slug"]
                and create["request"]["correlationId"] == slot["correlationId"]
                and digest(create["request"]) == slot["requestSha256"]
                and result["provenance"] == {"kind": "authorization-job", "jobId": create["jobId"]}
                and result["operation"] == "create"
                and result["correlationId"] == slot["correlationId"]
                and result["status"] == "succeeded"
                and result["manifest"]["metadata"]["slug"] == slot["slug"]
                and result["manifest"]["metadata"]["id"]
                == request["tenantId"]
                == result["tenantId"],
                "first-canary-wrong-tenant",
            )
            return
        raise ValueError("first-canary-job-not-reviewed")
