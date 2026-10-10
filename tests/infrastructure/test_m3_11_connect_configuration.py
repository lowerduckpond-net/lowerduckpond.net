"""The shared Connect reader is independent of obsolete journal/witness configuration."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scripts.m3_11_unattended import connect_configuration as config
from scripts.m3_11_unattended.model import LifecycleError

from .test_m3_11_lease_configuration import mapping, reader_document


@pytest.mark.parametrize("role", ["provision", "cleanup", "production"])
def test_reader_has_exact_native_role_grants_without_coordination_fields(role: str) -> None:
    value = reader_document(role, now=datetime.now(UTC).replace(microsecond=0))
    selected, access = config.reader_access(value)
    assert selected == value
    assert access.grants.keys() == (
        {mapping(value["vaults"])[role]}
        | ({mapping(value["vaults"])["journal"]} if role != "production" else set())
    )
    value["witness"] = {}
    with pytest.raises((ValueError, LifecycleError)):
        config.reader_access(value)
