"""Explicit Connect role inputs; mixed or incomplete backends never fall back."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.m3_11_qualification_evidence import fields
from scripts.m3_11_unattended.connect_api import Connect
from scripts.m3_11_unattended.connect_auth import READ, READ_WRITE, Access, authenticate, inspect
from scripts.m3_11_unattended.connect_checkpoint import Stored
from scripts.m3_11_unattended.connect_journal import ConnectJournal, Witness
from scripts.m3_11_unattended.connect_ledger import ConnectLedger
from scripts.m3_11_unattended.model import LifecycleError, Targets, identity, instant, strings
from scripts.m3_11_unattended.production import REFERENCES

if TYPE_CHECKING:
    from scripts.m3_11_unattended.config import Bootstrap, Configuration

ROLE_FORMAT = "lowerduckpond-m3-11-connect-role-v1"
PROVIDER_REFERENCES = {
    "digitalocean",
    "digitalocean_metadata",
    "cloudflare_account",
    "cloudflare_user",
}
READER_FIELDS = {"url", "role", "vaults", "entry", "metadata"}
ROLE_FIELDS = {
    "format",
    "values",
    "reader",
    "witness",
    "initial",
    "anchor",
    "anchor_sha256",
    "independent_expires_at",
}


def reader_access(value: object) -> tuple[dict[str, object], Access]:
    selected = fields(value, READER_FIELDS)
    role, url = selected["role"], selected["url"]
    vaults = strings(fields(selected["vaults"], {"provision", "cleanup", "production", "journal"}))
    if (
        role not in {"provision", "cleanup", "production"}
        or not isinstance(role, str)
        or not isinstance(url, str)
        or len(set(vaults.values())) != len(vaults)
        or any(re.fullmatch(r"[a-z0-9]{26}", vault) is None for vault in vaults.values())
        or not isinstance(selected["entry"], dict)
        or not isinstance(selected["metadata"], dict)
    ):
        raise LifecycleError("Connect reader role or isolated vault identities are invalid")
    expected = {vaults[role]: READ}
    if role != "production":
        expected[vaults["journal"]] = READ_WRITE
    access = inspect(
        selected["entry"], selected["metadata"], expected=expected, now=datetime.now(UTC)
    )
    Connect(url, access.token)  # Validate the bare HTTPS origin without contacting it.
    return selected, access


def reader(value: object) -> Connect:
    selected, access = reader_access(value)
    url = selected["url"]
    if not isinstance(url, str):
        raise LifecycleError("Connect reader endpoint is invalid")
    client = Connect(url, access.token)
    vaults = strings(selected["vaults"])
    authenticate(client, access, forbidden=set(vaults.values()) - access.grants.keys())
    return client


def witness(value: object) -> Witness:
    selected = strings(
        fields(value, {"epoch", "helper", "server", "author", "genesis_id", "genesis_sha256"})
    )
    try:
        genesis = Stored(int(selected["genesis_id"]), selected["genesis_sha256"])
    except ValueError:
        raise LifecycleError("Connect witness genesis is invalid") from None
    return Witness(
        selected["epoch"], selected["helper"], selected["server"], selected["author"], genesis
    )


def _references(
    value: object, *, expected: set[str] | frozenset[str], vault: str
) -> dict[str, str]:
    references = strings(fields(value, set(expected)))
    if any(
        re.fullmatch(r"op://" + re.escape(vault) + r"/[a-z0-9]{26}/[A-Za-z0-9_/-]+", item) is None
        for item in references.values()
    ):
        raise LifecycleError("Connect role references leave their dedicated vault")
    return references


def parse_role(value: object) -> Bootstrap:
    from scripts.m3_11_unattended.config import Bootstrap  # noqa: PLC0415 - backend factory

    selected = fields(value, ROLE_FIELDS)
    configured, access = reader_access(selected["reader"])
    role, vaults = configured["role"], strings(configured["vaults"])
    if selected["format"] != ROLE_FORMAT or role not in {"provision", "cleanup"}:
        raise LifecycleError("Connect bootstrap has an unexpected role")
    values = _references(selected["values"], expected=PROVIDER_REFERENCES, vault=vaults[str(role)])
    independent = witness(selected["witness"])
    if independent.server == access.server_id:
        raise LifecycleError("Connect cleanup witness must use a separate server identity")
    instant(selected["independent_expires_at"])
    initial = strings(selected["initial"])
    if (
        not initial
        or not isinstance(selected["anchor"], str)
        or not isinstance(selected["anchor_sha256"], str)
        or re.fullmatch(r"[a-z0-9]{26}", selected["anchor"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", selected["anchor_sha256"]) is None
    ):
        raise LifecycleError("Connect role is missing its approved journal anchor")
    for key, expected_digest in initial.items():
        identity(key)
        if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
            raise LifecycleError("Connect initial inventory digest is invalid")
    return Bootstrap(values, selected)


def expires_at(settings: dict[str, object]) -> datetime:
    _selected, access = reader_access(settings["reader"])
    return min(access.expires_at, instant(settings["independent_expires_at"]))


def journal(bootstrap: Bootstrap, vault: str, *, directory: Path | None) -> ConnectJournal:
    settings = bootstrap.connect_settings
    if settings is None or directory is None:
        raise LifecycleError("Connect journal requires persistent private storage")
    configured, _access = reader_access(settings["reader"])
    vaults = strings(configured["vaults"])
    if vault != vaults["journal"]:
        raise LifecycleError("Connect journal differs from the dedicated approved vault")
    anchor, anchor_sha256 = settings["anchor"], settings["anchor_sha256"]
    if not isinstance(anchor, str) or not isinstance(anchor_sha256, str):
        raise LifecycleError("Connect journal anchor is invalid")
    return ConnectJournal(
        ConnectLedger(
            reader(settings["reader"]),
            vault,
            spool=directory,
            anchor=anchor,
            anchor_sha256=anchor_sha256,
            minimum=strings(settings["initial"]),
        ),
        witness(settings["witness"]),
        wait_seconds=120 if configured["role"] == "provision" else 0,
    )


def configuration(
    value: dict[str, object], provision: Bootstrap, cleanup: Bootstrap
) -> Configuration:
    from scripts.m3_11_unattended.config import Configuration  # noqa: PLC0415 - backend factory

    production = fields(value["production"], {"connect", "references"})
    settings = [provision.connect_settings, cleanup.connect_settings]
    if any(item is None for item in settings):
        raise LifecycleError("Connect controller cannot mix credential backends")
    readers, accesses = [], []
    for role, bootstrap in (("provision", provision), ("cleanup", cleanup)):
        if bootstrap.connect_settings is None:
            raise LifecycleError("Connect controller role is incomplete")
        configured, access = reader_access(bootstrap.connect_settings["reader"])
        if configured["role"] != role:
            raise LifecycleError("Connect controller role differs from its assigned authority")
        readers.append(configured)
        accesses.append(access)
    configured, access = reader_access(production["connect"])
    if configured["role"] != "production":
        raise LifecycleError("Connect production checking needs its separate reader")
    readers.append(configured)
    accesses.append(access)
    vaults = strings(configured["vaults"])
    _references(production["references"], expected=REFERENCES, vault=vaults["production"])
    if (
        value["journal_vault"] != vaults["journal"]
        or any(item["vaults"] != vaults or item["url"] != configured["url"] for item in readers)
        or len({item.token_id for item in accesses}) != len(accesses)
        or len({item.token for item in accesses}) != len(accesses)
        or len({item.server_id for item in accesses}) != 1
        or any(
            provision.connect_settings is None
            or cleanup.connect_settings is None
            or provision.connect_settings[key] != cleanup.connect_settings[key]
            for key in ("witness", "initial", "anchor", "anchor_sha256", "independent_expires_at")
        )
    ):
        raise LifecycleError("Connect controller roles, targets or independent bindings differ")
    return Configuration(
        Targets.parse(value["targets"]), vaults["journal"], provision, cleanup, production
    )
