"""Offline complete remote closeout proof for later credential-free disposal.

The local effect plan binds the exact selected native receipt bytes. A later
read-only absence observation may resolve resource disposition without forging
the lost request's acknowledgment or rewriting any original removal journal.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from lowerduckpond_m3_archive.storage import S3Client

from scripts import m3_11_frozen_backups as backups
from scripts.m3_11_backup_fixture import Target, _version
from scripts.m3_11_backup_removal import Removal
from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_remote import FORMAT
from scripts.m3_11_frozen_stage import Effects, authorization, read_plan
from scripts.m3_11_live_storage import FORMAT as STORAGE_FORMAT
from scripts.m3_11_private_inputs import read_private
from scripts.m3_11_qualification_evidence import BINDING_FIELDS, fields
from scripts.m3_11_retirement_files import digest, directory
from scripts.m3_11_unattended.model import LeaseManifest
from scripts.qualification_fence import registry


class NoProvider:
    def __getattr__(self, _name: str) -> object:
        raise ValueError("offline remote proof cannot call a provider")


def metadata(value: dict[str, object], manifest: LeaseManifest, path: Path) -> Removal:
    require(value.get("format") == STORAGE_FORMAT, "remote proof original storage format differs")
    target = Target(
        str(value["run_id"]),
        str(value["region"]),
        str(value["backup_bucket"]),
        str(value["archive_bucket"]),
    )
    require(
        target.region == manifest.targets.region
        and target.backup_bucket == manifest.targets.backup_bucket
        and target.archive_bucket == manifest.targets.archive_bucket,
        "remote proof storage differs from original lease",
    )
    binding = fields(value["binding"], BINDING_FIELDS)
    target.manifest(binding)
    return Removal(
        target,
        binding,
        _version(value["owner_version"]),
        cast(S3Client, NoProvider()),
        cast(S3Client, NoProvider()),
        path,
        lambda: "offline-only",
    )


def verify(  # noqa: PLR0913, PLR0917 - all independent retained bindings
    run: Path,
    retired: dict[str, object],
    fixture: dict[str, object],
    manifest: LeaseManifest,
    remote: Path,
    receipt: dict[str, object],
    *,
    guard: Callable[[], None],
    original_storage: dict[str, object] | None = None,
    fixture_id: str | None = None,
) -> dict[str, object]:
    directory(remote)
    selected = read_plan(remote)
    approved = authorization(
        read_private(remote / "authorization.json"), selected, stage="remote-cleanup"
    )
    from scripts.m3_11_frozen_stage_receipt import remote as validate_receipt  # noqa: PLC0415
    from scripts.m3_11_unattended.model import instant  # noqa: PLC0415

    validate_receipt(receipt, selected, observing="backup_removal" not in receipt)
    require(
        all(
            instant(receipt[key]) >= instant(approved["approved_at"])
            for key in ("archive_observed_at", "dns_observed_at")
        ),
        "remote proof observation predates original separate authority",
    )
    owner = (
        str(read_private(run / "fixture.json")["run_id"]) if fixture_id is None else fixture_id
    ).replace("-", "")
    root = registry(run)
    require(root is not None, "remote proof requires original managed ownership")
    require(
        remote
        == cast(Path, root) / ("identity-" + owner + ".retired") / ("remote-" + digest(selected)),
        "remote proof escaped original persistent registry",
    )
    require(
        selected.get("format") == FORMAT
        and selected.get("retirement_plan") == retired
        and selected.get("fixture") == fixture
        and receipt.get("format") == FORMAT
        and receipt.get("plan_sha256") == digest(selected)
        and receipt.get("authorization_sha256") == digest(approved)
        and receipt.get("actors_retained") is True
        and receipt.get("archive_delete_submissions") == 0
        and receipt.get("credential_mutations") == 0
        and receipt.get("lease_released") is False,
        "remote proof differs from its exact stage authority",
    )
    removal = metadata(
        read_private(run / "live-storage.json") if original_storage is None else original_storage,
        manifest,
        remote / "backup-removal",
    )
    expected = cast(dict[str, object], selected["backup_inventory"])
    intent = removal._saved_intent()
    require(
        intent["inventory"] == expected and intent["quiescent_sha256"] == digest(fixture),
        "remote removal intent differs from exact preserved inventory",
    )
    effects = Effects(remote, plan=selected, approval=approved)
    batch: dict[str, object] = {"inventory_sha256": digest(expected)}
    require(
        effects.submitted("remote-cleanup", batch), "remote proof lost its original batch intent"
    )
    acknowledged = 0
    for _kind, key, version in cast(list[list[str]], expected["versions"]):
        parameters: dict[str, object] = {
            "Bucket": removal.target.backup_bucket,
            "Key": key,
            "VersionId": version,
        }
        name = "delete-backup-" + digest(parameters)
        require(
            effects.submitted(name, parameters), "remote proof lost an exact version submission"
        )
        ack = remote / (name + ".acknowledged.json")
        if ack.exists() or ack.is_symlink():
            require(
                read_private(ack)
                == {"submission_sha256": digest(effects._value(name, parameters))},
                "remote version acknowledgment differs",
            )
            acknowledged += 1
    original = {"intent_sha256": digest(intent)}
    require(
        read_private(removal.directory / "owner-delete.started.json") == original,
        "remote proof lacks final exact owner-removal intent",
    )
    if "backup_removal" in receipt:
        require(
            receipt["backup_removal"] == {**original, "remaining_backup_objects": 0}
            and read_private(removal.directory / "removed.json") == receipt["backup_removal"]
            and read_private(remote / "completed.json") == receipt,
            "remote completed proof differs from original journal",
        )
    else:
        observation = cast(dict[str, object], receipt.get("observation"))
        require(
            isinstance(observation, dict)
            and observation.get("absent") is True
            and observation.get("effect") == "remote-cleanup"
            and observation.get("submission_sha256")
            == digest(effects._value("remote-cleanup", batch))
            and observation.get("mutation_submissions") == 0
            and observation.get("no_replay") is True
            and receipt.get("mutation_submissions") == 0
            and receipt.get("no_replay") is True,
            "remote observation has not proved absence without replay",
        )
    saved = backups.verify(
        removal,
        expected,
        remote / "backup-evidence",
        maximum_bytes=cast(int, selected["maximum_backup_bytes"]),
        guard=guard,
    )
    require(
        digest(saved) == receipt.get("backup_preservation_sha256"),
        "remote proof backup bytes changed",
    )
    archive = cast(dict[str, object], retired["archive"])
    versions = receipt.get("archive_versions")
    require(
        versions in ([], [[archive["key"], archive["version"]]])
        and receipt.get("whole_archive_bucket_empty") is (versions == []),
        "remote proof archive outcome differs from exact original identity",
    )
    return {
        "receipt_sha256": digest(receipt),
        "preservation_sha256": digest(saved),
        "delete_submissions": len(cast(list[object], expected["versions"])),
        "acknowledged_submissions": acknowledged,
        "archive_versions": versions,
        "uncertainty_preserved": True,
        "provider_calls": 0,
    }
