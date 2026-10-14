"""The shared Connect reader is independent of obsolete journal/witness configuration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from scripts.m3_11_unattended import connect_configuration as config
from scripts.m3_11_unattended.connect_auth import authenticate, claims
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_connect_auth import Endpoint, token
from .test_m3_11_lease_configuration import mapping, reader_document


def journal_grant(value: dict[str, object], permission: object = 496) -> None:
    entry = mapping(value["entry"])
    payload = claims(str(entry["token"]))
    journal = mapping(value["vaults"])["journal"]
    policies = cast(list[dict[str, object]], payload["1password.com/vts"])
    next(row for row in policies if str(row["u"]).lower() == journal)["a"] = permission
    token(entry, payload)


@pytest.mark.parametrize("role", ["provision", "cleanup"])
def test_observed_journal_profile_retains_permissions_without_claiming_create(role: str) -> None:
    value = reader_document(role, now=datetime.now(UTC).replace(microsecond=0))
    journal_grant(value)
    _, access = config.reader_access(value)
    vaults = mapping(value["vaults"])
    assert access.grants == {vaults[role]: 48, vaults["journal"]: 496}
    endpoint = Endpoint(access.token)
    endpoint.visible = set(access.grants)
    forbidden = {str(vault) for vault in vaults.values()} - access.grants.keys()
    receipt = authenticate(endpoint, access, forbidden=forbidden)
    assert receipt["authenticated"] is True
    assert receipt["create_verified"] is False
    grants = cast(dict[str, int], receipt["signed_grants_by_vault_sha256"])
    assert sorted(grants.values()) == [48, 496]
    assert len(endpoint.paths) == len(forbidden)


@pytest.mark.parametrize("role", ["provision", "cleanup"])
@pytest.mark.parametrize("permission", [48, 176, 240, 368, 1520, True, "496", 496.0, None])
def test_role_profile_does_not_accept_other_masks_or_representations(
    role: str, permission: object
) -> None:
    value = reader_document(role, now=datetime.now(UTC).replace(microsecond=0))
    journal_grant(value, permission)
    with pytest.raises(LifecycleError):
        config.reader_access(value)


@pytest.mark.parametrize("fault", ["native-read-only", "extra-vault", "native-revoked", "server"])
def test_journal_profile_keeps_native_identity_and_scope_checks(fault: str) -> None:
    value = reader_document("cleanup", now=datetime.now(UTC).replace(microsecond=0))
    journal_grant(value)
    native = cast(list[dict[str, object]], mapping(value["metadata"])["tokens"])[0]
    if fault == "native-read-only":
        policies = cast(list[dict[str, object]], native["vaults"])
        next(row for row in policies if str(row["id"]).lower() == "j" * 26)["acl"] = [
            "allow_viewing"
        ]
    elif fault == "native-revoked":
        native["state"] = "REVOKED"
    elif fault == "server":
        native["integration_id"] = "X" * 26
    else:
        entry = mapping(value["entry"])
        payload = claims(str(entry["token"]))
        cast(list[dict[str, object]], payload["1password.com/vts"]).append({"u": "x" * 26, "a": 48})
        token(entry, payload)
    with pytest.raises(LifecycleError):
        config.reader_access(value)


@pytest.mark.parametrize("role", ["provision", "cleanup", "production"])
def test_reader_has_exact_native_role_grants_without_coordination_fields(role: str) -> None:
    value = reader_document(role, now=datetime.now(UTC).replace(microsecond=0))
    selected, access = config.reader_access(value)
    assert selected == value
    vaults = mapping(value["vaults"])
    expected = {vaults[role]: 48}
    if role != "production":
        expected[vaults["journal"]] = 1008
    assert access.grants == expected
    value["witness"] = {}
    with pytest.raises((ValueError, LifecycleError)):
        config.reader_access(value)


@pytest.mark.parametrize("role", ["provision", "cleanup", "production"])
@pytest.mark.parametrize("permission", [496, 1008])
def test_matching_native_and_signed_write_grants_cannot_expand_read_only_role(
    role: str, permission: int
) -> None:
    value = reader_document(role, now=datetime.now(UTC).replace(microsecond=0))
    vault = mapping(value["vaults"])[role]
    entry = mapping(value["entry"])
    payload = claims(cast(str, entry["token"]))
    policies = cast(list[dict[str, object]], payload["1password.com/vts"])
    next(row for row in policies if str(row["u"]).lower() == vault)["a"] = permission
    native = cast(list[dict[str, object]], mapping(value["metadata"])["tokens"])[0]
    policies = cast(list[dict[str, object]], native["vaults"])
    next(row for row in policies if str(row["id"]).lower() == vault)["acl"] = [
        "allow_viewing",
        "allow_editing",
    ]
    token(entry, payload)
    with pytest.raises(LifecycleError):
        config.reader_access(value)
