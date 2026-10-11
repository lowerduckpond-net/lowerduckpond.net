"""Operator-side initial lease assembly; only local writes and normal-account op reads.

check never invokes op or reads server credentials. assemble does not authenticate
providers, publish attestations, migrate obligations, deliver bundles or activate.
Use a private Linux/WSL filesystem, outside source, with Python 3.14.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Never, cast

from scripts.m3_11_private_inputs import read_private_bytes, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.config import DO_READ_SCOPES
from scripts.m3_11_unattended.connect_action import INDEPENDENT_ORIGIN
from scripts.m3_11_unattended.connect_api import origin
from scripts.m3_11_unattended.connect_auth import identity as connect_identity
from scripts.m3_11_unattended.connect_configuration import PROVIDER_REFERENCES, reader_access
from scripts.m3_11_unattended.connect_delivery import MAX_SECRET_BYTES
from scripts.m3_11_unattended.connect_setup import Operator, assemble, prepare
from scripts.m3_11_unattended.model import (
    PROVIDERS,
    AuthorityGeneration,
    LeasePolicy,
    LifecycleError,
    Targets,
    digest,
    fingerprint,
    identity,
    instant,
    strings,
)
from scripts.m3_11_unattended.production import REFERENCES
from scripts.m3_11_unattended.state import private_directory

FORMAT = "lowerduckpond-m3-11-operator-inputs-v1"
HELPER = "181ab29f65d3dde19ddac3411b8b7e8928dd14da"
CLIENTS = {"provision", "cleanup", "production", "independent_cleanup"}
ROOT = Path(__file__).resolve().parents[2]
PROVIDER_KEYS = {
    "spaces": "digitalocean",
    "cloudflare-account": "cloudflare_account",
    "cloudflare-user": "cloudflare_user",
}


def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LifecycleError("duplicate input field")
        result[key] = value
    return result


def decode(raw: bytes) -> object:
    return json.loads(raw, object_pairs_hook=object_pairs)


def reference(value: object, *, vault: str | None = None) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"op://[a-z0-9]{26}/[a-z0-9]{26}/[A-Za-z0-9_-]+", value) is None
    ):
        raise LifecycleError("an exact vault/item/field reference is required")
    if vault is not None and value.split("/")[2] != vault:
        raise LifecycleError("reference escaped its approved vault")
    return value


def label(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 512  # noqa: PLR2004 - bounded operator observation
        or any(ord(char) < 32 for char in value)  # noqa: PLR2004
    ):
        raise LifecycleError("operator observation is incomplete")
    return value


def generation(
    manifest: dict[str, object], role: str, hashes: dict[str, str]
) -> AuthorityGeneration:
    providers = fields(manifest["providers"], {"provision", "cleanup"})
    selected = fields(providers[role], {"references", "expires_at", "digitalocean_observation"})
    clients = fields(manifest["clients"], CLIENTS)
    names = [role] + (["independent_cleanup"] if role == "cleanup" else [])
    expiry = min(
        instant(fields(clients[name], {"reference", "name", "expires_at"})["expires_at"])
        for name in names
    )
    return AuthorityGeneration(
        generation_id=str(manifest["generation_id"]),
        role=role,
        targets_sha256=digest(manifest["targets"]),
        principals=strings(manifest["principals"]),
        fingerprints=hashes,
        expires_at=strings(selected["expires_at"]),
        connect_expires_at=expiry.isoformat().replace("+00:00", "Z"),
        introduced_at=str(manifest["introduced_at"]),
        rotation_due_at=str(manifest["rotation_due_at"]),
    )


def validate(raw: object, *, now: datetime) -> dict[str, object]:  # noqa: PLR0912
    """Check only nonsecret declared inputs. Never infer approvals or provider facts."""
    manifest = fields(
        raw,
        {
            "format",
            "purpose",
            "onepassword_account_id",
            "targets",
            "vaults",
            "shared_url",
            "shared_server_id",
            "independent_server_id",
            "policy",
            "approved_policy_sha256",
            "generation_id",
            "introduced_at",
            "rotation_due_at",
            "principals",
            "migration_sha256",
            "clients",
            "providers",
            "production_references",
        },
    )
    if manifest["format"] != FORMAT or manifest["purpose"] != "initial-legacy-migration":
        raise LifecycleError("this assembler only stages the initial legacy migration")
    targets = Targets.parse(manifest["targets"])
    policy = LeasePolicy.parse(manifest["policy"])
    policy.require_start(now=now, approved_sha256=str(manifest["approved_policy_sha256"]))
    identity(manifest["generation_id"])
    fingerprint(manifest["migration_sha256"])
    account = connect_identity(manifest["onepassword_account_id"])
    servers = [
        connect_identity(manifest[key]) for key in ("shared_server_id", "independent_server_id")
    ]
    if servers[0].lower() == servers[1].lower() or not account:
        raise LifecycleError("separate existing Connect identities are required")
    origin(str(manifest["shared_url"]))
    if str(manifest["shared_url"]).rstrip("/") == INDEPENDENT_ORIGIN:
        raise LifecycleError("shared Connect endpoint is unavailable")
    vaults = strings(fields(manifest["vaults"], {"provision", "cleanup", "production", "journal"}))
    if len(set(vaults.values())) != 4 or any(  # noqa: PLR2004 - four isolated vaults
        re.fullmatch(r"[a-z0-9]{26}", vault) is None for vault in vaults.values()
    ):
        raise LifecycleError("four distinct runtime vaults are required")
    principals = strings(fields(manifest["principals"], set(PROVIDERS)))
    if (
        principals["cloudflare-account"] != targets.account_id
        or principals["cloudflare-user"] != targets.user_id
    ):
        raise LifecycleError("provider principals differ from approved targets")
    clients = fields(manifest["clients"], CLIENTS)
    references = []
    for value in clients.values():
        client = fields(value, {"reference", "name", "expires_at"})
        ref = reference(client["reference"])
        if ref.split("/")[2] in vaults.values() or ref in references:
            raise LifecycleError("Connect clients need distinct operator-only references")
        references.append(ref)
        label(client["name"])
        if instant(client["expires_at"]) <= now:
            raise LifecycleError("declared Connect expiry has elapsed")
    providers = fields(manifest["providers"], {"provision", "cleanup"})
    for role, value in providers.items():
        selected = fields(value, {"references", "expires_at", "digitalocean_observation"})
        role_references = strings(fields(selected["references"], PROVIDER_REFERENCES))
        if len(set(role_references.values())) != len(PROVIDER_REFERENCES):
            raise LifecycleError("provider secrets and metadata need separate field references")
        for provider_ref in role_references.values():
            reference(provider_ref, vault=vaults[role])
        observed = fields(
            selected["digitalocean_observation"],
            {
                "principal",
                "scopes",
                "observed_at",
                "attested_by",
                "principal_context",
            },
        )
        scopes = (
            DO_READ_SCOPES
            | {"spaces_key:delete"}
            | ({"spaces_key:create_credentials"} if role == "provision" else set())
        )
        if (
            observed["principal"] != principals["spaces"]
            or observed["scopes"] != sorted(scopes)
            or instant(observed["observed_at"]) > now
        ):
            raise LifecycleError("DigitalOcean console observation is incomplete")
        label(observed["attested_by"])
        label(observed["principal_context"])
        declared = generation(manifest, role, dict.fromkeys(PROVIDERS, "0" * 64))
        if not instant(declared.introduced_at) <= now < instant(declared.rotation_due_at):
            raise LifecycleError("generation is outside its approved rotation month")
        declared.require_coverage(policy=policy, deadline=policy.deadline(now))
    for production_ref in fields(manifest["production_references"], set(REFERENCES)).values():
        reference(production_ref, vault=vaults["production"])
    return manifest


def load_manifest(path: Path) -> dict[str, object]:
    private_directory(path.parent)
    return validate(decode(read_private_bytes(path)), now=datetime.now(UTC))


def secret(operator: Operator, account: str, ref: str) -> str:
    raw = operator.command("read", ref, "--account", account, "--no-newline")
    if re.fullmatch(rb"[\x21-\x7e]{1,65536}", raw) is None:
        raise LifecycleError("saved credential has an invalid encoding")
    return raw.decode("ascii")


def readers(manifest: dict[str, object], operator: Operator) -> dict[str, dict[str, object]]:
    account = str(manifest["onepassword_account_id"])
    operator.command("whoami", "--account", account, "--format", "json")
    native: dict[str, dict[str, object]] = {}
    for kind in ("shared", "independent"):
        server = str(manifest[kind + "_server_id"])
        native[kind] = {
            "server": decode(
                operator.command(
                    "connect", "server", "get", server, "--account", account, "--format", "json"
                )
            ),
            "tokens": decode(
                operator.command(
                    "connect",
                    "token",
                    "list",
                    "--server",
                    server,
                    "--account",
                    account,
                    "--format",
                    "json",
                )
            ),
        }
    result = {}
    for name, raw in fields(manifest["clients"], CLIENTS).items():
        selected = fields(raw, {"reference", "name", "expires_at"})
        kind = "independent" if name == "independent_cleanup" else "shared"
        reader = {
            "format": "lowerduckpond-connect-reader-v2",
            "approved_expires_at": selected["expires_at"],
            "url": INDEPENDENT_ORIGIN if kind == "independent" else manifest["shared_url"],
            "role": "cleanup" if kind == "independent" else name,
            "vaults": manifest["vaults"],
            "entry": {
                "token": secret(operator, account, str(selected["reference"])),
                "server": manifest[kind + "_server_id"],
                "name": selected["name"],
                "expires_at": selected["expires_at"],
            },
            "metadata": native[kind],
        }
        _, access = reader_access(reader)
        if access.account_id.lower() != account.lower():
            raise LifecycleError("Connect reader belongs to a different account")
        # Retain only the matching native row, avoiding unrelated inventory and size growth.
        reader["metadata"] = {
            "server": native[kind]["server"],
            "tokens": [
                row
                for row in cast(list[dict[str, object]], native[kind]["tokens"])
                if row.get("id") == access.token_id
            ],
        }
        result[name] = reader
    return result


def documents(
    manifest: dict[str, object], operator: Operator
) -> tuple[dict[str, object], dict[str, object], dict[str, dict[str, object]]]:
    configured = readers(manifest, operator)
    roles, attestations = {}, {}
    for role, raw in fields(manifest["providers"], {"provision", "cleanup"}).items():
        selected = fields(raw, {"references", "expires_at", "digitalocean_observation"})
        refs = strings(selected["references"])
        hashes = {
            kind: hashlib.sha256(
                secret(operator, str(manifest["onepassword_account_id"]), refs[key]).encode()
            ).hexdigest()
            for kind, key in PROVIDER_KEYS.items()
        }
        approved = generation(manifest, role, hashes)
        roles[role] = {
            "format": "lowerduckpond-m3-11-lease-bootstrap-v1",
            "generation": approved.document(),
            "reader": configured[role],
            "references": refs,
        }
        observed = cast(dict[str, object], selected["digitalocean_observation"])
        attestations[role] = {
            "format": "lowerduckpond-digitalocean-bootstrap-v2",
            "generation_id": approved.generation_id,
            "digitalocean_principal": approved.principals["spaces"],
            "token_sha256": approved.fingerprints["spaces"],
            "expires_at": approved.expires_at["spaces"],
            "scopes": observed["scopes"],
            "verified_at": observed["observed_at"],
            "verified_by": "operator-provider-console",
            "attested_by": observed["attested_by"],
            "principal_context": observed["principal_context"],
        }
    config = {
        "format": "lowerduckpond-m3-11-lease-config-v1",
        "mode": "controller",
        "targets": manifest["targets"],
        "journal_vault": strings(manifest["vaults"])["journal"],
        "policy": manifest["policy"],
        "approved_policy_sha256": manifest["approved_policy_sha256"],
        "active_generation": manifest["generation_id"],
        "generations": {str(manifest["generation_id"]): roles},
        "production": {
            "connect": configured["production"],
            "references": manifest["production_references"],
        },
        "independent_server_id": manifest["independent_server_id"],
        "helper_revision": HELPER,
        "migration_sha256": manifest["migration_sha256"],
    }
    return config, configured["independent_cleanup"], attestations


def run(manifest: dict[str, object], *, credentials: Path, output: Path) -> None:
    private_directory(output.parent)
    private_directory(credentials.parent)
    if (
        output.is_relative_to(ROOT)
        or credentials.is_relative_to(ROOT)
        or output.exists()
        or output.is_symlink()
    ):
        raise LifecycleError("use a new output directory outside source")
    # Read the retained native document without requiring it to have canonical formatting.
    native = decode(read_private_bytes(credentials))
    if not isinstance(native, dict) or not native:
        raise LifecycleError("retained independent server credentials are unavailable")
    output.mkdir(mode=0o700)
    private_directory(output)
    config, independent, attestations = documents(manifest, Operator())
    _controller, github = assemble(config, independent, native)
    if len(canonical_bytes(github)) > MAX_SECRET_BYTES:
        raise LifecycleError("independent bundle exceeds the existing delivery limit")
    receipt = prepare(config, independent, native, output=output)
    for role, attestation in attestations.items():
        write_private(output / (role + "-digitalocean-attestation.json"), attestation)
    write_private(
        output / "assembly-receipt.json",
        {
            "format": "lowerduckpond-m3-11-operator-assembly-receipt-v1",
            "status": "staged-only",
            **receipt,
            "helper_revision": HELPER,
            "provider_verification": "pending",
            "independent_server_verification": "pending",
            "attestation_publication": "pending",
            "migration_and_activation": "not-performed",
        },
    )


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise LifecycleError("invalid assembler arguments")


def main() -> int:
    os.umask(0o077)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if sys.platform != "linux":
            raise LifecycleError("use a private Linux or WSL environment")
        parser = Parser(description=__doc__)
        sub = parser.add_subparsers(dest="operation", required=True, parser_class=Parser)
        check = sub.add_parser("check", help="nonsecret input check; no op, credentials or writes")
        check.add_argument("--manifest", type=Path, required=True)
        assemble = sub.add_parser("assemble", help="normal-account reads and private staging only")
        assemble.add_argument("--manifest", type=Path, required=True)
        assemble.add_argument("--server-credentials", type=Path, required=True)
        assemble.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        manifest = load_manifest(args.manifest)
        if args.operation == "assemble":
            run(manifest, credentials=args.server_credentials, output=args.output)
    except Exception, KeyboardInterrupt:
        print(
            "Assembly incomplete; retain original access and any private staging files.",
            file=sys.stderr,
        )
        return 1
    print(
        "Nonsecret inputs checked; credentials were not read."
        if args.operation == "check"
        else "Private bundles staged only; provider verification and activation remain pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
