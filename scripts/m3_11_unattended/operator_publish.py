"""Explicit normal-account publication of two staged attestation fields.

Use only after reviewed assembly, authorized publication, pinned CLI compatibility
verification and an exclusive editing interval for these exact two items.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import resource
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from scripts.m3_11_private_inputs import (
    publish_private,
    read_private,
    read_private_bytes,
    write_private,
)
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.config import LeaseConfiguration, validate_digitalocean_metadata
from scripts.m3_11_unattended.connect_setup import Operator
from scripts.m3_11_unattended.model import LifecycleError, digest, fingerprint, strings
from scripts.m3_11_unattended.operator_assemble import decode, reference
from scripts.m3_11_unattended.state import private_directory

FORMAT = "lowerduckpond-m3-11-attestation-publication-v1"
CLI_VERSION = "2.33.0"
ITEM_KEYS = {
    "id",
    "title",
    "version",
    "vault",
    "category",
    "fields",
    "sections",
    "urls",
    "tags",
    "favorite",
    "created_at",
    "updated_at",
    "last_edited_by",
    "additional_information",
}
FIELD_KEYS = {"id", "type", "purpose", "label", "value", "section", "reference"}
MAINTAINED = {"version", "created_at", "updated_at", "last_edited_by", "additional_information"}


def staged(
    manifest: Path, directory: Path, expected: str
) -> tuple[dict[str, object], LeaseConfiguration]:
    private_directory(directory)
    inputs = read_private(manifest)
    receipt = read_private(directory / "assembly-receipt.json")
    controller = directory / "controller-connect.json"
    if (
        hashlib.sha256(read_private_bytes(controller)).hexdigest() != fingerprint(expected)
        or receipt["operator_inputs_sha256"] != digest(inputs)
        or receipt.get("controller_sha256") != expected
    ):
        raise LifecycleError("publication differs from reviewed assembly")
    config = LeaseConfiguration.load(controller)
    destinations = {}
    for role, raw in fields(inputs["providers"], {"provision", "cleanup"}).items():
        selected = fields(raw, {"references", "expires_at", "digitalocean_observation"})
        refs = strings(selected["references"])
        password_ref = reference(refs["digitalocean"])
        metadata_ref = reference(refs["digitalocean_metadata"])
        if password_ref.rsplit("/", 1)[0] != metadata_ref.rsplit("/", 1)[0]:
            raise LifecycleError("attestation must use a separate field on the Password item")
        _, _, vault, item, label = metadata_ref.split("/")
        attestation = read_private(directory / (role + "-digitalocean-attestation.json"))
        observation = fields(
            fields(receipt["observations"], {"provision", "cleanup"})[role],
            {"input", "token_sha256", "assembled_at"},
        )
        if (
            fields(receipt["attestation_sha256"], {"provision", "cleanup"})[role]
            != digest(attestation)
            or observation["input"] != raw
            or observation["token_sha256"] != attestation["token_sha256"]
            or observation["assembled_at"] != attestation["verified_at"]
        ):
            raise LifecycleError("staged attestation differs from its original assembly receipt")
        generation = config.generations[config.active_generation][role].generation
        validate_digitalocean_metadata(attestation, generation, now=datetime.now(UTC))
        if (
            attestation["generation_id"] != generation.generation_id
            or attestation["token_sha256"] != generation.fingerprints["spaces"]
            or generation.generation_id != inputs["generation_id"]
            or refs != config.generations[config.active_generation][role].references
        ):
            raise LifecycleError("publication generation or references changed")
        destinations[role] = {
            "vault": vault,
            "item": item,
            "label": label,
            "reference": metadata_ref,
            "password_field": password_ref.rsplit("/", 1)[1],
            "password_sha256": attestation["token_sha256"],
            "attestation_sha256": digest(attestation),
        }
    return {
        "format": FORMAT,
        "account": inputs["onepassword_account_id"],
        "generation_id": inputs["generation_id"],
        "controller_sha256": expected,
        "assembly_sha256": digest(receipt),
        "destinations": destinations,
    }, config


def item(raw: bytes, destination: dict[str, object]) -> tuple[dict[str, object], str | None]:
    value = decode(raw)
    if (
        not isinstance(value, dict)
        or set(value) - ITEM_KEYS
        or not isinstance(value.get("fields"), list)
    ):
        raise LifecycleError("item contains unsupported template data")
    vault = value.get("vault")
    if (
        value.get("id") != destination["item"]
        or not isinstance(vault, dict)
        or vault.get("id") != destination["vault"]
        or value.get("category") != "PASSWORD"
        or type(value.get("version")) is not int
        or cast(int, value["version"]) < 1
        or set(vault) - {"id", "name"}
        or any(not isinstance(item, str) for item in vault.values())
        or not isinstance(value.get("title"), str)
        or not isinstance(value.get("tags", []), list)
        or any(not isinstance(tag, str) for tag in value.get("tags", []))
        or ("favorite" in value and type(value["favorite"]) is not bool)
        or any(key in value and not isinstance(value[key], str) for key in MAINTAINED - {"version"})
    ):
        raise LifecycleError("publication item identity differs")
    sections = value.get("sections", [])
    urls = value.get("urls", [])
    if (
        not isinstance(sections, list)
        or any(
            not isinstance(row, dict)
            or set(row) - {"id", "label"}
            or not isinstance(row.get("id"), str)
            or any(not isinstance(item, str) for item in row.values())
            for row in sections
        )
        or len({row["id"] for row in sections}) != len(sections)
        or not isinstance(urls, list)
        or any(
            not isinstance(row, dict)
            or set(row) - {"href", "label", "primary"}
            or not isinstance(row.get("href"), str)
            or ("label" in row and not isinstance(row["label"], str))
            or ("primary" in row and type(row["primary"]) is not bool)
            for row in urls
        )
    ):
        raise LifecycleError("item contains unsupported section or URL content")
    password, target = [], []
    ids: set[str] = set()
    for row in value["fields"]:
        if (
            not isinstance(row, dict)
            or set(row) - FIELD_KEYS
            or not isinstance(row.get("id"), str)
            or row["id"] in ids
            or row.get("type")
            not in {"STRING", "CONCEALED", "URL", "EMAIL", "OTP", "DATE", "MONTH_YEAR", "MENU"}
            or any(
                key in row and not isinstance(row[key], str)
                for key in ("value", "label", "reference")
            )
            or ("purpose" in row and row["purpose"] not in {"USERNAME", "PASSWORD", "NOTES"})
            or (
                "section" in row
                and (
                    not isinstance(row["section"], dict)
                    or set(row["section"]) - {"id", "label"}
                    or row["section"].get("id") not in {section["id"] for section in sections}
                    or any(not isinstance(item, str) for item in row["section"].values())
                )
            )
        ):
            raise LifecycleError("item contains unsupported or ambiguous fields")
        ids.add(row["id"])
        if destination["password_field"] in {row.get("id"), row.get("label")}:
            password.append(row)
        if destination["label"] in {row.get("id"), row.get("label")}:
            target.append(row)
    if (
        len(password) != 1
        or password[0].get("section") is not None
        or password[0].get("type") != "CONCEALED"
        or password[0].get("purpose") != "PASSWORD"
        or not isinstance(password[0].get("value"), str)
        or hashlib.sha256(password[0]["value"].encode()).hexdigest()
        != destination["password_sha256"]
    ):
        raise LifecycleError("publication Password binding changed")
    if len(target) > 1 or (
        target
        and (
            target[0].get("section") is not None
            or target[0].get("type") != "STRING"
            or not isinstance(target[0].get("value"), str)
        )
    ):
        raise LifecycleError("publication destination is ambiguous")
    return value, cast(str, target[0]["value"]) if target else None


def protected(value: dict[str, object], destination: dict[str, object]) -> str:
    result = {key: deepcopy(raw) for key, raw in value.items() if key not in MAINTAINED}
    result["fields"] = [
        row
        for row in cast(list[dict[str, object]], value["fields"])
        if destination["label"] not in {row.get("id"), row.get("label")}
    ]
    return digest(result)


def publish_one(  # noqa: PLR0913 - explicit independent item and publication bindings
    operator: Operator,
    *,
    account: str,
    role: str,
    destination: dict[str, object],
    attestation: dict[str, object],
    config: LeaseConfiguration,
    proposal_sha256: str,
    state: Path,
) -> None:
    if digest(attestation) != destination["attestation_sha256"]:
        raise LifecycleError("staged attestation changed before publication")
    validate_digitalocean_metadata(
        attestation,
        config.generations[config.active_generation][role].generation,
        now=datetime.now(UTC),
    )
    arguments = (
        str(destination["item"]),
        "--vault",
        str(destination["vault"]),
        "--account",
        account,
        "--format",
        "json",
        "--reveal",
        "--cache=false",
    )
    wanted = canonical_bytes(attestation).decode()
    identity = digest({"account": account, "destination": destination})
    pending, complete = state / (identity + ".pending.json"), state / (identity + ".complete.json")

    def get() -> tuple[dict[str, object], str | None]:
        return item(operator.command("item", "get", *arguments), destination)

    original, current = get()
    guard = protected(original, destination)
    intent: dict[str, object] = {
        "proposal_sha256": proposal_sha256,
        "destination": destination,
        "account": account,
        "protected_sha256": guard,
        "observed_version": original["version"],
    }
    retained = read_private(pending) if pending.exists() else None
    if retained is not None:
        if (
            retained["proposal_sha256"] != proposal_sha256
            or retained["destination"] != destination
            or retained["account"] != account
            or retained["protected_sha256"] != guard
        ):
            raise LifecycleError("publication pending binding changed")
        intent = retained
    if complete.exists() and read_private(complete) != intent:
        raise LifecycleError("publication completion binding changed")
    if current != wanted:
        if current is not None or retained is not None or complete.exists():
            raise LifecycleError(
                "publication conflicts or remains unobserved; reconcile without editing"
            )
        fresh, target = get()
        if (
            target is not None
            or fresh["version"] != original["version"]
            or protected(fresh, destination) != guard
        ):
            raise LifecycleError("item changed before attestation publication")
        template = deepcopy(fresh)
        cast(list[dict[str, object]], template["fields"]).append(
            {
                "id": destination["label"],
                "label": destination["label"],
                "type": "STRING",
                "value": wanted,
            }
        )
        write_private(pending, intent)
        operator.command("item", "edit", *arguments, stdin=canonical_bytes(template))
        after, current = get()
        if current != wanted or protected(after, destination) != guard:
            raise LifecycleError("attestation publication has not preserved the original item")
    bootstrap = config.generations[config.active_generation][role]
    client = bootstrap.reader()
    if client.read(str(destination["reference"])) != wanted:
        raise LifecycleError("attestation is not exactly visible through its runtime reader")
    # The provider parser independently checks generation, fingerprint and exact scopes.
    validate_digitalocean_metadata(
        decode(wanted.encode()), bootstrap.generation, now=datetime.now(UTC)
    )
    if not pending.exists():
        write_private(pending, intent)
    if not complete.exists():
        publish_private(complete, intent)


def run(  # noqa: PLR0913 - explicit assembly, state, proposal and application boundary
    *,
    manifest: Path,
    directory: Path,
    expected: str,
    state: Path,
    apply: bool,
    expected_proposal: str | None = None,
) -> dict[str, object]:
    proposal, config = staged(manifest, directory, expected)
    if not apply:
        return proposal
    if expected_proposal is None or fingerprint(expected_proposal) != digest(proposal):
        raise LifecycleError("publication requires the exact reviewed proposal digest")
    private_directory(state.parent)
    from scripts.m3_11_unattended.operator_assemble import ROOT  # noqa: PLC0415

    if state.resolve().is_relative_to(ROOT):
        raise LifecycleError("publication state must remain outside the source checkout")
    state.mkdir(mode=0o700, exist_ok=True)
    private_directory(state)
    identity = state / "publication.json"
    if identity.exists():
        if read_private(identity) != proposal:
            raise LifecycleError("publication state belongs to another generation or destination")
    else:
        write_private(identity, proposal)
    operator = Operator()
    if operator.command("--version").strip() != CLI_VERSION.encode():
        raise LifecycleError("publication requires the pinned 1Password CLI contract")
    for role, raw in cast(dict[str, dict[str, object]], proposal["destinations"]).items():
        lock = state / (
            digest({"account": proposal["account"], "vault": raw["vault"], "item": raw["item"]})
            + ".lock"
        )
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            publish_one(
                operator,
                account=str(proposal["account"]),
                role=role,
                destination=raw,
                attestation=read_private(directory / (role + "-digitalocean-attestation.json")),
                config=config,
                proposal_sha256=digest(proposal),
                state=state,
            )
        finally:
            os.close(fd)
    return proposal


def main() -> int:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["publish-attestations"])
    for name in ("manifest", "staged", "state"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-controller-sha256", required=True)
    parser.add_argument("--expected-proposal-sha256")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        proposal = run(
            manifest=args.manifest,
            directory=args.staged,
            expected=args.expected_controller_sha256,
            state=args.state,
            apply=args.apply,
            expected_proposal=args.expected_proposal_sha256,
        )
    except RuntimeError, OSError, ValueError, KeyError, TypeError:
        parser.exit(1, "Attestation publication incomplete; retain private state and reconcile.\n")
    print(canonical_bytes({"proposal": proposal, "sha256": digest(proposal)}).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
