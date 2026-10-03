"""One-time local setup without secret values in command arguments or chat."""

from __future__ import annotations

import getpass
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.m3_11_private_inputs import read_private, write_private
from scripts.m3_11_qualification_evidence import canonical_bytes, fields
from scripts.m3_11_unattended.config import BOOTSTRAP_FIELDS, DO_READ_SCOPES, Configuration, connect
from scripts.m3_11_unattended.journal import OnePassword, event
from scripts.m3_11_unattended.model import LifecycleError, Targets, instant, stamp, strings
from scripts.m3_11_unattended.production import REFERENCES
from scripts.production_qualification_inputs import revision


def template() -> dict[str, object]:
    reference = "op://<dedicated-vault-id>/<item-id>/<field-id>"
    bootstrap = dict.fromkeys(
        BOOTSTRAP_FIELDS - {"service_account_token", "service_account_expires_at"}, reference
    )
    bootstrap["service_account_expires_at"] = "<UTC expiry from service-account creation>"
    return {
        "format": "lowerduckpond-m3-11-setup-v1",
        "targets": dict.fromkeys(Targets.__dataclass_fields__, "<approved value>"),
        "journal_vault": "<dedicated obligation vault ID>",
        "provision": dict(bootstrap),
        "cleanup": dict(bootstrap),
        "production": {
            "service_account_expires_at": "<UTC expiry from service-account creation>",
            "references": dict.fromkeys(sorted(REFERENCES), reference),
        },
    }


def document(manifest: object, tokens: dict[str, str]) -> dict[str, object]:
    value = fields(
        manifest, {"format", "targets", "journal_vault", "provision", "cleanup", "production"}
    )
    if value["format"] != "lowerduckpond-m3-11-setup-v1" or set(tokens) != {
        "provision",
        "cleanup",
        "production",
    }:
        raise LifecycleError("initial setup manifest is incomplete")
    result = {**value, "format": "lowerduckpond-m3-11-controller-config-v1"}
    for role in ("provision", "cleanup", "production"):
        names = (
            BOOTSTRAP_FIELDS - {"service_account_token"}
            if role != "production"
            else {
                "service_account_expires_at",
                "references",
            }
        )
        section = fields(value[role], names)
        result[role] = {**section, "service_account_token": tokens[role]}
    return result


def _vaults(op: OnePassword, expected: set[str]) -> None:
    value = json.loads(op.command("vault", "list", "--format", "json"))
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise LifecycleError("service-account vault access is unavailable")
    if {item.get("id") for item in value} != expected:
        raise LifecycleError("service account can access unexpected or missing vaults")


def validate(configuration: Configuration) -> None:
    """Read-only provider probes and a harmless external-journal write/readback."""
    now = datetime.now(UTC)
    vaults: set[str] = set()
    for role in (configuration.provision, configuration.cleanup):
        references = [
            role.values[key]
            for key in (
                "digitalocean",
                "digitalocean_metadata",
                "cloudflare_account",
                "cloudflare_user",
            )
        ]
        selected = {value.split("/")[2] for value in references if value.startswith("op://")}
        if len(selected) != 1 or configuration.journal_vault in selected:
            raise LifecycleError("bootstrap secrets need one separate dedicated vault per role")
        if vaults & selected:
            raise LifecycleError("provisioning and cleanup bootstrap vaults overlap")
        vaults.update(selected)
        _vaults(role.op(), selected | {configuration.journal_vault})
    production = configuration.production
    production_references = strings(production["references"])
    if set(production_references) != REFERENCES:
        raise LifecycleError("production reader references are incomplete")
    selected = {
        value.split("/")[2] for value in production_references.values() if value.startswith("op://")
    }
    if len(selected) != 1 or selected & (vaults | {configuration.journal_vault}):
        raise LifecycleError("production reader needs its own dedicated vault")
    token = production["service_account_token"]
    if not isinstance(token, str) or instant(
        production["service_account_expires_at"]
    ) < now + timedelta(hours=14):
        raise LifecycleError("production reader authority expires too soon")
    _vaults(OnePassword(token), selected)
    creator = connect(
        configuration.provision,
        targets=configuration.targets,
        vault=configuration.journal_vault,
        now=now,
        provisioning=True,
    )
    cleaner = connect(
        configuration.cleanup,
        targets=configuration.targets,
        vault=configuration.journal_vault,
        now=now,
    )
    cleaner.authority.require(now + timedelta(hours=14))
    creator.authority.require(now + timedelta(hours=14))
    if cleaner.authority.identity_sha256 == creator.authority.identity_sha256:
        raise LifecycleError("provisioning and cleanup authorities must be distinct")
    # Uses no production-state secret and creates no provider credential.
    import uuid  # noqa: PLC0415 - setup-only journal capability probe

    record = event("result", str(uuid.uuid7()), {"setup": "independent-journal-read-write"})
    creator.journal.append(record)
    cleaner.journal.refresh()
    if record not in cleaner.journal.records():
        raise LifecycleError("independent cleanup cannot read provisioning obligations")
    record = event("result", str(uuid.uuid7()), {"setup": "cleanup-journal-read-write"})
    cleaner.journal.append(record)
    creator.journal.refresh()
    if record not in creator.journal.records():
        raise LifecycleError("provisioning cannot observe independent cleanup")


def configure(manifest: Path, output: Path, *, token_file: Path | None = None) -> None:
    if output.exists() or output.is_symlink():
        raise LifecycleError("initial setup refuses to overwrite private configuration")
    tokens = (
        strings(read_private(token_file))
        if token_file is not None
        else {
            role: getpass.getpass(f"New dedicated {role} service-account token (hidden): ")
            for role in ("provision", "cleanup", "production")
        }
    )
    value = document(json.loads(manifest.read_bytes()), tokens)
    write_private(output, value)
    try:
        validate(Configuration.load(output))
    except BaseException:
        output.unlink()
        raise


def attest_digitalocean(*, reference: str, expires: str, provisioning: bool, output: Path) -> None:
    """Run by the operator after inspecting exact PAT scopes/expiry in the console.

    A read-only bootstrap service account reads the token from its dedicated
    vault. Only its bound metadata is written. Import that JSON into the separate
    metadata item's notesPlain field using the operator's usual 1Password UI.
    DigitalOcean does not expose PAT expiry/scopes through the Spaces API.
    """
    expiry = instant(expires)
    now = datetime.now(UTC)
    if expiry < now + timedelta(days=3):
        raise LifecycleError("bootstrap expiry cannot cover a new qualification and cleanup")
    op = OnePassword(getpass.getpass("Dedicated bootstrap reader service-account token (hidden): "))
    secret = op.read(reference)
    scopes = (
        DO_READ_SCOPES
        | {"spaces_key:delete"}
        | ({"spaces_key:create_credentials"} if provisioning else set())
    )
    write_private(
        output,
        {
            "format": "lowerduckpond-digitalocean-bootstrap-v1",
            "token_sha256": hashlib.sha256(secret.encode()).hexdigest(),
            "expires_at": stamp(expiry),
            "scopes": sorted(scopes),
            "verified_at": stamp(now),
            "verified_by": "operator-provider-console",
        },
    )


def install_github(config: Path, helper: str) -> None:
    """Explicit setup operation: main-only environment, no per-cleanup approver."""
    revision(helper)
    configuration = Configuration.load(config)
    executable = shutil.which("gh")
    if executable is None:
        raise LifecycleError("GitHub setup CLI is unavailable")

    def command(*arguments: str, stdin: bytes | None = None) -> bytes:
        result = subprocess.run(  # noqa: S603 - fixed repository and environment; secrets in stdin
            [executable, *arguments],
            input=stdin,
            capture_output=True,
            check=False,
            timeout=60,
        )
        if result.returncode:
            raise LifecycleError("protected GitHub cleanup setup is incomplete")
        return result.stdout

    repository = "lowerduckpond-net/lowerduckpond.net"
    environment = "m3-11-credential-cleanup"
    path = "repos/" + repository + "/environments/" + environment
    desired = {
        "wait_timer": 0,
        "reviewers": [],
        "prevent_self_review": False,
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    }
    # Do not edit an existing environment with a human-review policy. Setup must
    # use the specifically approved independent-cleanup environment.
    inventory = json.loads(command("api", "repos/" + repository + "/environments", "--paginate"))
    if not isinstance(inventory, dict) or not isinstance(inventory.get("environments"), list):
        raise LifecycleError("GitHub environment inventory is unavailable")
    existing = [item for item in inventory["environments"] if item.get("name") == environment]
    if existing:
        rules = json.loads(command("api", path))
        if (
            not isinstance(rules.get("protection_rules"), list)
            or any(rule.get("type") != "branch_policy" for rule in rules["protection_rules"])
            or rules.get("deployment_branch_policy") != desired["deployment_branch_policy"]
        ):
            raise LifecycleError(
                "existing cleanup environment needs an explicit protection-policy decision"
            )
    else:
        command("api", "--method", "PUT", path, "--input", "-", stdin=canonical_bytes(desired))
    policies_path = path + "/deployment-branch-policies"
    policies = json.loads(command("api", policies_path))
    entries = policies.get("branch_policies")
    if entries == []:
        command(
            "api",
            "--method",
            "POST",
            policies_path,
            "--input",
            "-",
            stdin=canonical_bytes({"name": "main", "type": "branch"}),
        )
    elif (
        not isinstance(entries, list)
        or len(entries) != 1
        or entries[0].get("name") != "main"
        or entries[0].get("type") != "branch"
    ):
        raise LifecycleError("cleanup environment must authorize only the main branch")
    command(
        "secret",
        "set",
        "M3_11_CLEANUP_CONFIG",
        "--repo",
        repository,
        "--env",
        environment,
        stdin=canonical_bytes(configuration.cleanup_document()),
    )
    command(
        "variable",
        "set",
        "M3_11_CLEANUP_REVISION",
        "--repo",
        repository,
        "--env",
        environment,
        "--body",
        helper,
    )
