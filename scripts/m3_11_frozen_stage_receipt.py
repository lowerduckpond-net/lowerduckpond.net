"""Closed staged result schemas, bound to the actual sealed input plan."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from scripts.m3_11_frozen_context import require
from scripts.m3_11_frozen_retirement import fingerprint
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.model import instant


def local(result: dict[str, object], plan: dict[str, object], *, observing: bool) -> None:
    common = {
        "format",
        "plan_sha256",
        "authorization_sha256",
        "export_sha256",
        "terminal_proof_sha256",
        "remote_proof_sha256",
        "actor_exports",
        "fixture_execution",
        "provider_calls",
    }
    extra = (
        {
            "removed_actor_ids",
            "image_present",
            "tree",
            "pending_effects",
            "mutation_submissions",
            "no_replay",
            "completion_recorded",
        }
        if observing
        else {"qualification_changed", "lease_changed", "original_directory"}
    )
    fields(result, common | extra)
    require(
        result["format"] == "lowerduckpond-m3-11-frozen-local-disposal-v1"
        and result["fixture_execution"] == "permanently-excluded"
        and type(result["provider_calls"]) is int
        and result["provider_calls"] == 0,
        "local outcome format or execution fence differs",
    )
    for key in ("export_sha256", "terminal_proof_sha256", "remote_proof_sha256"):
        fingerprint(result[key])
    copies = result["actor_exports"]
    fixture = cast(dict[str, object], plan["fixture"])
    ids = {str(row["id"]) for row in cast(list[dict[str, object]], fixture["actors"])}
    require(
        isinstance(copies, dict) and bool(ids) and set(copies) == ids,
        "local outcome lacks every original actor export",
    )
    for checksum in cast(dict[str, object], copies).values():
        fingerprint(checksum)
    if observing:
        removed = result["removed_actor_ids"]
        require(
            isinstance(removed, list)
            and len(removed) == len(set(removed))
            and set(removed) <= ids
            and type(result["image_present"]) is bool
            and type(result["completion_recorded"]) is bool
            and isinstance(result["pending_effects"], list),
            "local resource observation differs",
        )
        require(
            result["mutation_submissions"] == 0 and result["no_replay"] is True,
            "local observation performed mutations or replay",
        )
        state = fields(result["tree"], {"absent", "unsubmitted", "pending"})
        all_paths = []
        for paths in state.values():
            require(
                isinstance(paths, list) and all(isinstance(path, str) for path in paths),
                "local residual observation is malformed",
            )
            all_paths.extend(cast(list[str], paths))
        require(
            len(all_paths) == len(set(all_paths)) and "." in all_paths,
            "local residual observation is ambiguous",
        )
    else:
        require(
            result["qualification_changed"] is False
            and result["lease_changed"] is False
            and result["original_directory"] == "absent",
            "local disposal outcome differs",
        )


def remote(result: dict[str, object], plan: dict[str, object], *, observing: bool) -> None:
    common = {
        "format",
        "plan_sha256",
        "authorization_sha256",
        "backup_preservation_sha256",
        "archive_versions",
        "whole_archive_bucket_empty",
        "archive_observed_at",
        "dns_observed_at",
        "actors_retained",
        "archive_delete_submissions",
        "credential_mutations",
        "lease_released",
    }
    fields(
        result,
        common
        | (
            {"observation", "mutation_submissions", "no_replay"}
            if observing
            else {"backup_removal", "backup_observed_at", "observed_at"}
        ),
    )
    require(
        result["format"] == "lowerduckpond-m3-11-frozen-remote-closeout-v1"
        and result["actors_retained"] is True
        and result["lease_released"] is False
        and type(result["archive_delete_submissions"]) is int
        and result["archive_delete_submissions"] == 0
        and type(result["credential_mutations"]) is int
        and result["credential_mutations"] == 0,
        "remote outcome format differs",
    )
    fingerprint(result["backup_preservation_sha256"])
    retired = cast(dict[str, object], plan["retirement_plan"])
    original = cast(dict[str, object], retired["archive"])
    versions = result["archive_versions"]
    require(
        versions in ([], [[original["key"], original["version"]]])
        and type(result["whole_archive_bucket_empty"]) is bool
        and result["whole_archive_bucket_empty"] == (versions == []),
        "remote outcome changed archive identity or claimed whole-bucket emptiness",
    )
    for key in ("archive_observed_at", "dns_observed_at"):
        require(
            instant(result[key]) <= datetime.now(UTC), "remote observation time is in the future"
        )
    if observing:
        require(
            result["mutation_submissions"] == 0 and result["no_replay"] is True,
            "remote observation performed mutations or replay",
        )
        observed = fields(
            result["observation"],
            {
                "effect",
                "submission_sha256",
                "observed_at",
                "absent",
                "mutation_submissions",
                "no_replay",
            },
        )
        fingerprint(observed["submission_sha256"])
        require(
            observed["effect"] == "remote-cleanup"
            and type(observed["absent"]) is bool
            and observed["mutation_submissions"] == 0
            and observed["no_replay"] is True
            and instant(observed["observed_at"])
            <= instant(result["archive_observed_at"])
            <= instant(result["dns_observed_at"])
            <= datetime.now(UTC),
            "remote observation lost its original no-replay submission identity",
        )
    else:
        removed = fields(result["backup_removal"], {"intent_sha256", "remaining_backup_objects"})
        fingerprint(removed["intent_sha256"])
        require(
            removed["remaining_backup_objects"] == 0
            and instant(result["backup_observed_at"])
            <= instant(result["archive_observed_at"])
            <= instant(result["dns_observed_at"])
            <= instant(result["observed_at"])
            <= datetime.now(UTC),
            "remote completed outcome lacks actual bounded absence observations",
        )
