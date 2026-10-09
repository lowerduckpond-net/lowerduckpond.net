"""Operator-only renewal of the two cleanup clients, preserving both Connect servers."""

from __future__ import annotations

import argparse
import copy
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended import connect_action as action
from scripts.m3_11_unattended import connect_renewal as renewal
from scripts.m3_11_unattended.connect_activate import readers, retain
from scripts.m3_11_unattended.connect_auth import READ, READ_WRITE, inspect
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.connect_checkpoint_key import credential
from scripts.m3_11_unattended.connect_control import BACKEND, SETTING, GitHub
from scripts.m3_11_unattended.connect_delivery import Delivery, bundles
from scripts.m3_11_unattended.connect_diagnostics import failure
from scripts.m3_11_unattended.connect_setup import (
    Operator,
    _create_token,
    _provider_receipt,
    _receipt,
    directory,
    role_vaults,
)
from scripts.m3_11_unattended.github_checkpoint import GitHubArtifacts
from scripts.m3_11_unattended.model import LifecycleError, digest
from scripts.production_qualification_inputs import current_candidate


def previous(
    root: Path, approved: dict[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    controller = read_private(root / "controller-connect.json")
    cleanup = read_private(root / "github-connect.json")
    bundles(root)
    if digest(controller) != approved["previous_bundle_sha256"]:
        raise LifecycleError("cleanup renewal differs from the installed bootstrap bundle")
    configured = readers(controller)
    old_reader = cast(dict[str, object], configured["cleanup"]["entry"])
    old_independent = cast(dict[str, object], cleanup["token"])
    if (
        old_reader["server"] != approved["shared_server"]
        or old_independent["server"] != approved["independent_server"]
    ):
        raise LifecycleError("cleanup renewal cannot replace either existing server")
    return controller, cleanup


def prepare(
    operator: Operator,
    approved: dict[str, object],
    *,
    original: Path,
    output: Path,
) -> None:
    """Persist issuance before every call; retries reuse the original returned token."""
    renewal.request(approved, now=datetime.now(UTC))
    controller, cleanup = previous(original, approved)
    directory(output)
    retain(output / "renewal-request.json", approved)
    manifest = cast(dict[str, object], controller["manifest"])
    vaults = role_vaults(manifest)
    grants = [vaults["cleanup"] + ",r", vaults["journal"] + ",rw"]
    nonce = str(approved["renewal_id"]).replace("-", "")
    renewed = copy.deepcopy(controller)
    renewed_cleanup = copy.deepcopy(cleanup)
    for role, server in (
        ("cleanup", str(approved["shared_server"])),
        ("github-cleanup", str(approved["independent_server"])),
    ):
        saved = _receipt(
            _create_token(
                operator, output, server=server, name=f"ldp-m311-{nonce}-{role}", grants=grants
            )
        )
        metadata = _provider_receipt(operator, output, server, role)
        access = inspect(
            saved,
            metadata,
            expected={vaults["cleanup"]: READ, vaults["journal"]: READ_WRITE},
            now=datetime.now(UTC),
        )
        if role == "cleanup":
            cast(dict[str, object], renewed["tokens"])["cleanup"] = saved
            renewed["provider_metadata"] = metadata
        else:
            # This value remains exclusively in independent GitHub cleanup.
            # Its old expiration is irrelevant to decryption, never to API use.
            key = cleanup.get(
                "checkpoint_token", cast(dict[str, object], cleanup["token"])["token"]
            )
            legacy = {"checkpoint_token": key}
            checkpoint_key = credential(legacy, access)
            renewed_cleanup.update(
                token=saved, provider_metadata=metadata, checkpoint_token=checkpoint_key
            )
            renewed["renewal"] = renewal.public_receipt(approved, access, checkpoint_key)
    readers(renewed)
    retain(output / "controller-connect.json", renewed)
    retain(output / "github-connect.json", renewed_cleanup)
    bundles(output)


def selected_helper(
    github: GitHub, revision: str, approved: dict[str, object]
) -> dict[str, object]:
    """The installed merged action must understand renewal before its secret changes."""
    github.protection()
    github.merged(revision)
    variables = github.variables()
    value = json.loads(variables.get(SETTING, "null"))
    if not isinstance(value, dict):
        raise LifecycleError("cleanup renewal needs an existing active epoch")
    selected = action.selection(value, helper=revision)
    request = cast(dict[str, object], selected["request"])
    proof = cast(dict[str, object], selected["receipt"])
    if (
        variables.get(BACKEND) != "connect"
        or selected["stage"] != "active"
        or selected["active_helper"] != revision
        or request.get("shared_server") != approved["shared_server"]
        or proof.get("independent_server") != approved["independent_server"]
    ):
        raise LifecycleError("cleanup renewal helper or server lineage is not installed")
    return selected


def verify_history(original: Path, selected: dict[str, object], output: Path) -> None:
    """Prove the retained key reads the pinned original genesis before issuance."""
    cleanup = read_private(original / "github-connect.json")
    key = cleanup.get("checkpoint_token", cast(dict[str, object], cleanup["token"])["token"])
    if not isinstance(key, str):
        raise LifecycleError("original cleanup checkpoint key is unavailable")
    proof = cast(dict[str, object], selected["receipt"])
    reference = fields(proof["genesis"], {"identity", "sha256"})
    store = GitHubArtifacts(
        epoch=str(proof["epoch"]),
        registry_revision=str(proof["registry_revision"]),
        token=key,
        directory=output / "history-readback",
    )
    original_genesis = store.read(
        Stored(cast(int, reference["identity"]), str(reference["sha256"]))
    )
    if (
        original_genesis.get("epoch") != proof["epoch"]
        or original_genesis.get("sequence") != 1
        or original_genesis.get("previous") is not None
    ):
        raise LifecycleError("cleanup renewal cannot substitute another checkpoint epoch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--request-sha256", required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--unraid")
    parser.add_argument("--workspace")
    parser.add_argument("--workspace-id")
    args = parser.parse_args()
    os.umask(0o077)
    stage = "validate-revision-and-request"
    try:
        current_candidate(Path(__file__).resolve().parents[2], args.revision)
        approved = renewal.request(read_private(args.request), now=datetime.now(UTC))
        if (
            digest(approved) != args.request_sha256
            or args.original.resolve() == args.output.resolve()
        ):
            raise LifecycleError("cleanup renewal requires an exact request and separate output")
        stage = "verify-original-private-bundles"
        previous(args.original, approved)
        stage = "verify-installed-helper"
        selected = selected_helper(GitHub(), args.revision, approved)
        destination = (args.unraid, args.workspace, args.workspace_id)
        delivery = None
        if any(destination):
            if not all(destination) or not args.apply:
                raise LifecycleError("cleanup renewal delivery needs all destination fields")
            delivery = Delivery(*destination)
            stage = "verify-delivery-destination"
            delivery.preflight()
        if args.apply:
            directory(args.output)
            stage = "verify-original-encrypted-genesis"
            verify_history(args.original, selected, args.output)
            stage = "issue-and-inspect-cleanup-clients"
            prepare(Operator(), approved, original=args.original, output=args.output)
            if delivery:
                stage = "deliver-private-cleanup-bundles"
                selected_helper(GitHub(), args.revision, approved)
                delivery.install(args.output, renewal_id=str(approved["renewal_id"]))
            print(
                "Cleanup clients staged; original servers and encrypted history retained. "
                "Independent verification and controller installation remain required."
            )
        else:
            print(
                json.dumps(
                    {
                        "renewal_id": approved["renewal_id"],
                        "clients": ["shared-cleanup", "independent-cleanup"],
                        "client_lifetime": "7 days",
                        "same_servers_and_vault_grants": True,
                        "provider_credentials_created": False,
                        "original_inputs_retained": True,
                    }
                )
            )
    except (LifecycleError, OSError, ValueError, TypeError, KeyError) as error:
        print(
            json.dumps(
                {
                    "status": "unresolved",
                    "stage": stage,
                    "failure": failure(error),
                    "message": "Retain private setup files. No qualification launched.",
                }
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
