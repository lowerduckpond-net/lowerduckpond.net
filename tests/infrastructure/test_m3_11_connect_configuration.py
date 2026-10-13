"""The shared Connect reader is independent of obsolete journal/witness configuration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from scripts.m3_11_unattended import connect_configuration as config
from scripts.m3_11_unattended.connect_auth import claims
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_connect_auth import token
from .test_m3_11_lease_configuration import mapping, reader_document


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
def test_matching_native_and_signed_write_grants_cannot_expand_read_only_role(role: str) -> None:
    value = reader_document(role, now=datetime.now(UTC).replace(microsecond=0))
    vault = mapping(value["vaults"])[role]
    entry = mapping(value["entry"])
    payload = claims(cast(str, entry["token"]))
    policies = cast(list[dict[str, object]], payload["1password.com/vts"])
    next(row for row in policies if str(row["u"]).lower() == vault)["a"] = 1008
    native = cast(list[dict[str, object]], mapping(value["metadata"])["tokens"])[0]
    policies = cast(list[dict[str, object]], native["vaults"])
    next(row for row in policies if str(row["id"]).lower() == vault)["acl"] = [
        "allow_viewing",
        "allow_editing",
    ]
    token(entry, payload)
    with pytest.raises(LifecycleError):
        config.reader_access(value)
