"""Explicit cleanup-client renewal within an existing Connect server and epoch."""

from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime, timedelta
from typing import cast

from scripts.m3_11_qualification_evidence import digest as sha256
from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.connect_auth import Access
from scripts.m3_11_unattended.connect_auth import identity as connect_identity
from scripts.m3_11_unattended.model import LifecycleError, digest, identity, instant, stamp

FORMAT = "lowerduckpond-m3-11-connect-cleanup-renewal-v1"
REQUEST_FIELDS = {
    "format",
    "renewal_id",
    "previous_bundle_sha256",
    "previous_controller_sha256",
    "shared_server",
    "independent_server",
    "cleanup_expires_at",
    "approved_at",
    "apply_before",
    "approval_reference",
}


def request(raw: object, *, now: datetime | None = None) -> dict[str, object]:
    value = fields(raw, REQUEST_FIELDS)
    identity(value["renewal_id"])
    for key in ("shared_server", "independent_server"):
        connect_identity(value[key])
    for key in ("previous_bundle_sha256", "previous_controller_sha256"):
        text = value[key]
        sha256(text)
    before, approved, expiry = (
        instant(value[key]) for key in ("apply_before", "approved_at", "cleanup_expires_at")
    )
    if (
        value["format"] != FORMAT
        or not approved < before < expiry
        or before - approved > timedelta(days=1)
        or expiry - approved > timedelta(days=8)
        or value["shared_server"] == value["independent_server"]
        or not isinstance(value["approval_reference"], str)
        or not value["approval_reference"]
        or len(value["approval_reference"]) > 256  # noqa: PLR2004 - bounded approval text
        or any(ord(character) < 32 for character in value["approval_reference"])  # noqa: PLR2004 - control characters
        or (now is not None and not approved <= now < before)
    ):
        raise LifecycleError("cleanup renewal authorization is absent or expired")
    return value


def receipt(raw: object) -> dict[str, object]:
    value = fields(raw, {"request", "independent_access", "checkpoint_token_sha256"})
    request(value["request"])
    access = fields(
        value["independent_access"],
        {
            "server_sha256",
            "token_id_sha256",
            "expires_at",
            "exact_native_and_signed_policy",
            "authenticated",
        },
    )
    instant(access["expires_at"])
    if access["exact_native_and_signed_policy"] is not True or access["authenticated"] is not False:
        raise LifecycleError("cleanup renewal client metadata is invalid")
    for text in (
        access["server_sha256"],
        access["token_id_sha256"],
        value["checkpoint_token_sha256"],
    ):
        sha256(text)
    return value


def expires(raw: object) -> str:
    value = receipt(raw)
    approved = cast(dict[str, object], value["request"])
    access = cast(dict[str, object], value["independent_access"])
    return stamp(min(instant(approved["cleanup_expires_at"]), instant(access["expires_at"])))


def authority_receipt(raw: object) -> dict[str, object]:
    """Closed public fields accepted from a verified native cleanup artifact."""
    value = fields(
        raw, {"identity_sha256", "valid_until", "connect_access", "checkpoint_token_sha256"}
    )
    access = fields(
        value["connect_access"],
        {
            "server_sha256",
            "token_id_sha256",
            "expires_at",
            "exact_native_and_signed_policy",
            "authenticated",
        },
    )
    for text in (
        value["identity_sha256"],
        value["checkpoint_token_sha256"],
        access["server_sha256"],
        access["token_id_sha256"],
    ):
        sha256(text)
    instant(value["valid_until"])
    instant(access["expires_at"])
    if access["exact_native_and_signed_policy"] is not True or access["authenticated"] is not True:
        raise LifecycleError("cleanup authority receipt lacks authenticated exact policy")
    return value


def verify_native(raw: object, native: dict[str, object], genesis: dict[str, object]) -> None:
    """Called only after verification of the native GitHub execution and artifact."""
    value = receipt(raw)
    authority = authority_receipt(native.get("authority"))
    expected = {**cast(dict[str, object], value["independent_access"]), "authenticated": True}
    if (
        native.get("status") != "ready"
        or authority["identity_sha256"] != genesis["authority_sha256"]
        or authority["valid_until"] != expires(raw)
        or authority["connect_access"] != expected
        or authority["checkpoint_token_sha256"] != value["checkpoint_token_sha256"]
    ):
        raise LifecycleError(
            "renewed cleanup lacks matching independent lifetime and history proof"
        )


def permit_install(previous: dict[str, object], value: dict[str, object], raw: object) -> None:
    """Permit only cleanup client/lifetime changes; never replace targets or history."""
    renewal = receipt(raw)
    approved = request(renewal["request"], now=datetime.now(UTC))
    if digest(previous) != approved["previous_controller_sha256"]:
        raise LifecycleError("cleanup renewal no longer matches the installed controller")
    normalized = copy.deepcopy(value)
    for role in ("provision", "cleanup"):
        old = cast(dict[str, object], previous[role])
        new = cast(dict[str, object], normalized[role])
        old_reader = cast(dict[str, object], old["reader"])
        new_reader = cast(dict[str, object], new["reader"])
        new_reader["metadata"] = old_reader["metadata"]
        new["independent_expires_at"] = old["independent_expires_at"]
        cast(dict[str, object], new["witness"])["active_helper"] = cast(
            dict[str, object], old["witness"]
        )["active_helper"]
        if role == "cleanup":
            old_entry = cast(dict[str, object], old_reader["entry"])
            new_entry = cast(dict[str, object], new_reader["entry"])
            if (
                new_entry["server"] != old_entry["server"]
                or new_entry["token"] == old_entry["token"]
            ):
                raise LifecycleError(
                    "cleanup renewal must replace only a client of the same server"
                )
            new_reader["entry"] = old_entry
    old_production = cast(dict[str, object], previous["production"])
    new_production = cast(dict[str, object], normalized["production"])
    cast(dict[str, object], new_production["connect"])["metadata"] = cast(
        dict[str, object], old_production["connect"]
    )["metadata"]
    if normalized != previous:
        raise LifecycleError("cleanup renewal changed another role, target or immutable history")


def public_receipt(
    approved: dict[str, object], independent: Access, checkpoint_token: str
) -> dict[str, object]:
    return receipt(
        {
            "request": request(approved),
            "independent_access": independent.receipt(),
            "checkpoint_token_sha256": hashlib.sha256(checkpoint_token.encode()).hexdigest(),
        }
    )
