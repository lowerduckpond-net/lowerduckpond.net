"""Ingress probing must validate ownership before granting network capability."""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from unittest.mock import Mock

import pytest


@pytest.mark.parametrize("changed", ["destination", "acme"])
def test_peer_refuses_changed_fixture_before_network_setup(
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
    changed: str,
) -> None:
    module = installed_module("restore_peer")
    fixture = Mock(destination_id="destination", acme_id="acme")
    identities = {"destination": "destination", "acme": "acme", changed: "replacement"}
    monkeypatch.setattr(module.owned, "identities", Mock(return_value=identities))
    with pytest.raises(ValueError, match="owned restore peers"):
        module.check(fixture, opened=False)
    fixture.command.assert_not_called()
    fixture.destination.run.assert_not_called()
    fixture.acme.run.assert_not_called()


@pytest.mark.parametrize("address", ["", "172.17.0.2172.18.0.2", "172.17.0.2; false", "::1"])
def test_peer_refuses_ambiguous_network_before_setup(
    monkeypatch: pytest.MonkeyPatch,
    installed_module: Callable[[str], ModuleType],
    address: str,
) -> None:
    module = installed_module("restore_peer")
    fixture = Mock(destination_id="destination", acme_id="acme")
    monkeypatch.setattr(
        module.owned,
        "identities",
        Mock(return_value={"destination": "destination", "acme": "acme"}),
    )
    fixture.address.return_value = address
    with pytest.raises(ValueError):
        module.check(fixture, opened=False)
    fixture.command.assert_not_called()
    fixture.destination.run.assert_not_called()


def test_peer_does_not_probe_ingress_after_address_setup_fails(
    monkeypatch: pytest.MonkeyPatch, installed_module: Callable[[str], ModuleType]
) -> None:
    module = installed_module("restore_peer")
    fixture = Mock(destination_id="destination", acme_id="acme")
    monkeypatch.setattr(
        module.owned,
        "identities",
        Mock(return_value={"destination": "destination", "acme": "acme"}),
    )
    fixture.address.side_effect = ["172.17.0.2", "172.17.0.3"]
    fixture.command.side_effect = ValueError("network setup failed")
    with pytest.raises(ValueError, match="network setup failed"):
        module.check(fixture, opened=False)
    fixture.destination.run.assert_not_called()
    fixture.acme.run.assert_not_called()
