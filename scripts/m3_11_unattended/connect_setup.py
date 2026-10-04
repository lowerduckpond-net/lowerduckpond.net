"""Operator-only Connect bootstrap; provider credentials are never fetched here.

The shared endpoint receives three separate clients. A second Connect identity
is restricted to cleanup and the journal, so GitHub need not reach that endpoint.
This module stages bootstrap material; it does not activate a qualification.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from scripts.m3_11_private_inputs import read_private, read_private_bytes, write_private
from scripts.m3_11_unattended.connect_delivery import Delivery
from scripts.m3_11_unattended.model import LifecycleError, Targets, digest, stamp, strings
from scripts.m3_11_unattended.production import REFERENCES
from scripts.production_qualification_inputs import current_candidate

FORMAT = "lowerduckpond-m3-11-connect-bootstrap-v1"
TOKEN_LIFETIME = timedelta(days=7)
MAXIMUM = 1024 * 1024
REFERENCE = re.compile(r"op://([a-z0-9]{26})/[a-z0-9]{26}/[A-Za-z0-9_/-]+")


def directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    stat = path.lstat()
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.st_uid != os.geteuid()
        or stat.st_mode & 0o077
    ):
        raise LifecycleError("Connect bootstrap needs an owned private directory")


class Operator:
    """Only the operator's normal login can grant vault access or issue clients."""

    def __init__(self, *, environment: Mapping[str, str] | None = None) -> None:
        self.environment = dict(os.environ if environment is None else environment)
        for key in ("OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN"):
            self.environment.pop(key, None)
        self.executable = shutil.which("op", path=self.environment.get("PATH"))
        if self.executable is None:
            raise LifecycleError("the operator's 1Password CLI is unavailable")

    def command(self, *arguments: str, cwd: Path | None = None) -> bytes:
        try:
            response = subprocess.run(  # noqa: S603 - fixed op calls; no secret arguments
                [cast(str, self.executable), *arguments],
                cwd=cwd,
                env=self.environment,
                capture_output=True,
                check=False,
                timeout=90,
            )
        except OSError, subprocess.SubprocessError:
            raise LifecycleError(
                "Connect setup operation failed; retain its creation intent"
            ) from None
        if response.returncode or len(response.stdout) > MAXIMUM:
            raise LifecycleError("Connect setup operation failed; retain its creation intent")
        return response.stdout


def manifest(operator: Operator, reference: str, expected_sha256: str) -> dict[str, object]:
    if (
        REFERENCE.fullmatch(reference) is None
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise LifecycleError("Connect setup needs an immutable manifest reference and digest")
    record = json.loads(operator.command("read", "--no-newline", reference))
    if not isinstance(record, dict) or digest(record) != expected_sha256:
        raise LifecycleError("the approved non-secret setup manifest changed")
    payload = record.get("payload")
    value = payload.get("manifest") if isinstance(payload, dict) else None
    if not isinstance(value, dict) or value.get("format") != "lowerduckpond-m3-11-setup-v1":
        raise LifecycleError("Connect setup manifest is unavailable")
    Targets.parse(value.get("targets"))
    return cast(dict[str, object], value)


def role_vaults(value: dict[str, object]) -> dict[str, str]:
    result = {}
    for role in ("provision", "cleanup", "production"):
        section = value.get(role)
        if not isinstance(section, dict):
            raise LifecycleError("Connect bootstrap role is incomplete")
        references = (
            strings(section.get("references"))
            if role == "production"
            else {
                key: section.get(key)
                for key in (
                    "digitalocean",
                    "digitalocean_metadata",
                    "cloudflare_account",
                    "cloudflare_user",
                )
            }
        )
        if not references:
            raise LifecycleError("Connect bootstrap references are incomplete")
        if role == "production" and set(references) != REFERENCES:
            raise LifecycleError("Connect production-check references are incomplete")
        vaults = set()
        for reference in references.values():
            if not isinstance(reference, str) or (match := REFERENCE.fullmatch(reference)) is None:
                raise LifecycleError("Connect bootstrap references need immutable identities")
            vaults.add(match[1])
        if len(vaults) != 1:
            raise LifecycleError("each Connect bootstrap role needs its own dedicated vault")
        result[role] = vaults.pop()
    journal = value.get("journal_vault")
    if not isinstance(journal, str) or re.fullmatch(r"[a-z0-9]{26}", journal) is None:
        raise LifecycleError("Connect journal vault identity is unavailable")
    result["journal"] = journal
    if len(set(result.values())) != 4:  # noqa: PLR2004 - three roles plus journal
        raise LifecycleError("Connect bootstrap vaults are not separated")
    return result


def endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise LifecycleError("the shared Connect endpoint must be a bare HTTPS origin") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or any(char.isspace() for char in value)
        or port == 0
    ):
        raise LifecycleError("the shared Connect endpoint must be a bare HTTPS origin")
    return value.rstrip("/")


def token_receipt(token: str, *, now: datetime) -> dict[str, object]:
    """Expiry claims are checked here; endpoint acceptance must verify the token later."""
    parts = token.split(".")
    if len(parts) != 3 or len(token) > 65536 or any(c.isspace() for c in token):  # noqa: PLR2004
        raise LifecycleError("Connect token creation returned an unexpected response")
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        if not isinstance(claims, dict):
            raise ValueError
        expiry = claims.get("exp")
        if not isinstance(expiry, int) or isinstance(expiry, bool):
            raise ValueError
        expires = datetime.fromtimestamp(expiry, UTC)
    except ValueError, TypeError, OverflowError:
        raise LifecycleError("Connect token has no usable native expiry claim") from None
    if not now + timedelta(days=6) <= expires <= now + TOKEN_LIFETIME + timedelta(minutes=5):
        raise LifecycleError("Connect token lifetime differs from the requested seven days")
    return {
        "expires_at": stamp(expires),
        "token_id_claim": claims.get("jti"),
        "authenticated": False,
    }


def _server_identity(operator: Operator, root: Path, server: str, role: str) -> str:
    path = root / f"{role}.server-identity.json"
    saved = read_private(path) if path.exists() else None
    if saved is not None and saved.get("requested_server") != server:
        raise LifecycleError("Connect server identity belongs to different setup inputs")
    selector = server if saved is None else saved.get("id")
    if not isinstance(selector, str):
        raise LifecycleError("Connect server identity is unavailable")
    response = json.loads(operator.command("connect", "server", "get", selector, "--format=json"))
    identity = response.get("id") if isinstance(response, dict) else None
    if not isinstance(identity, str) or re.fullmatch(r"[a-z0-9]{26}", identity) is None:
        raise LifecycleError("Connect server did not return an immutable identity")
    if saved is not None:
        if identity != saved["id"]:
            raise LifecycleError("Connect server identity changed")
    else:
        write_private(path, {"requested_server": server, "id": identity, "metadata": response})
    return identity


def _create_token(
    operator: Operator, root: Path, *, server: str, name: str, grants: list[str]
) -> dict[str, object]:
    role = name.split("-", 3)[-1]
    output = root / f"{role}.token.json"
    if output.exists():
        saved = read_private(output)
        if (
            saved.get("server") != server
            or saved.get("grants") != grants
            or saved.get("name") != name
        ):
            raise LifecycleError("an existing Connect token belongs to different setup inputs")
        return saved
    intent_path = root / f"{role}.intent.json"
    if intent_path.exists():
        # Inventory is retained for reconciling the exact recorded name. An
        # uncertain creation is never repeated, including an empty inventory.
        inventory = json.loads(
            operator.command("connect", "token", "list", "--server", server, "--format=json")
        )
        audit = root / f"{role}.reconciliation-{uuid.uuid4().hex}.json"
        write_private(audit, {"inventory": inventory, "intent": read_private(intent_path)})
        raise LifecycleError(
            "an interrupted Connect token creation needs reconciliation; no duplicate issued"
        )
    write_private(
        intent_path,
        {
            "name": name,
            "server": server,
            "grants": grants,
            "requested_lifetime": "7d",
            "created_at": stamp(datetime.now(UTC)),
        },
    )
    arguments = ["connect", "token", "create", name, "--server", server, "--expires-in=7d"]
    for grant in grants:
        arguments.extend(("--vault", grant))
    raw = operator.command(*arguments).decode().strip()
    # Retain the returned credential before parsing claims or doing any probe.
    saved = {"server": server, "name": name, "grants": grants, "token": raw}
    write_private(output, saved)
    return saved


def _cleanup_server(operator: Operator, root: Path, setup_id: str) -> tuple[str, dict[str, object]]:
    selected = root / "independent-cleanup"
    directory(selected)
    name = f"LDP M3.11 cleanup {setup_id[:12]}"
    credentials = selected / "1password-credentials.json"
    intent = selected / "creation-intent.json"
    expected: dict[str, object] = {"server": name, "setup_id": setup_id, "vaults": []}
    if credentials.exists():
        if not intent.exists() or read_private(intent) != expected:
            raise LifecycleError("independent Connect server has no matching creation intent")
        value = json.loads(read_private_bytes(credentials))
        if not isinstance(value, dict) or not value:
            raise LifecycleError("independent Connect server credentials are invalid")
        identity = _server_identity(operator, selected, name, "cleanup")
        return identity, value
    if intent.exists():
        inventory = json.loads(operator.command("connect", "server", "list", "--format=json"))
        write_private(
            selected / f"reconciliation-{uuid.uuid4().hex}.json", {"inventory": inventory}
        )
        raise LifecycleError(
            "independent Connect server creation is unresolved; no duplicate issued"
        )
    write_private(intent, expected)
    response = operator.command("connect", "server", "create", name, "--format=json", cwd=selected)
    write_private(selected / "creation-result.json", {"response": response.decode()})
    if not credentials.is_file():
        raise LifecycleError("independent Connect creation did not produce its credentials file")
    return _cleanup_server(operator, root, setup_id)


def _session(value: dict[str, object], url: str, server: str, output: Path) -> str:
    session_path = output / "setup.json"
    expected = {"manifest_sha256": digest(value), "url": url, "shared_server": server}
    if session_path.exists():
        session = read_private(session_path)
        if {key: session.get(key) for key in expected} != expected:
            raise LifecycleError("Connect setup inputs changed; the original attempt is retained")
    else:
        session = {**expected, "setup_id": uuid.uuid4().hex}
        write_private(session_path, session)
    setup_id = session["setup_id"]
    if not isinstance(setup_id, str):
        raise LifecycleError("Connect setup identity is unavailable")
    return setup_id


def _receipt(saved: dict[str, object]) -> dict[str, object]:
    token = saved.get("token")
    if not isinstance(token, str):
        raise LifecycleError("Connect token is unavailable")
    return {**saved, **token_receipt(token, now=datetime.now(UTC))}


def _grant(operator: Operator, root: Path, server: str, vault: str) -> None:
    path = root / f"grant-{server}-{vault}.json"
    desired: dict[str, object] = {"server": server, "vault": vault}
    if path.exists():
        if read_private(path) != desired:
            raise LifecycleError("a Connect vault grant belongs to different setup inputs")
        return
    operator.command("connect", "vault", "grant", "--server", server, "--vault", vault)
    write_private(path, desired)


def _provider_receipt(operator: Operator, root: Path, server: str, role: str) -> dict[str, object]:
    """Retain native identities/policies for the separate activation audit."""
    path = root / f"{role}.provider-receipt.json"
    if path.exists():
        return read_private(path)
    value = {
        "server": json.loads(operator.command("connect", "server", "get", server, "--format=json")),
        "tokens": json.loads(
            operator.command("connect", "token", "list", "--server", server, "--format=json")
        ),
        "checked_at": stamp(datetime.now(UTC)),
    }
    write_private(path, value)
    return value


def prepare(
    operator: Operator, value: dict[str, object], *, url: str, server: str, output: Path
) -> None:
    url = endpoint(url)
    vaults = role_vaults(value)
    directory(output)
    setup_id = _session(value, url, server, output)
    server = _server_identity(operator, output, server, "shared")
    for vault in vaults.values():
        _grant(operator, output, server, vault)
    tokens = {}
    for role in ("provision", "cleanup", "production"):
        grants = [vaults[role] + ",r"]
        if role != "production":
            grants.append(vaults["journal"] + ",rw")
        saved = _create_token(
            operator, output, server=server, name=f"ldp-m311-{setup_id[:12]}-{role}", grants=grants
        )
        tokens[role] = _receipt(saved)
    independent, credentials = _cleanup_server(operator, output, setup_id)
    for vault in (vaults["cleanup"], vaults["journal"]):
        _grant(operator, output, independent, vault)
    github = _receipt(
        _create_token(
            operator,
            output,
            server=independent,
            name=f"ldp-m311-{setup_id[:12]}-github-cleanup",
            grants=[vaults["cleanup"] + ",r", vaults["journal"] + ",rw"],
        )
    )
    controller: dict[str, object] = {
        "format": FORMAT,
        "manifest": value,
        "url": url,
        "tokens": tokens,
        "provider_metadata": _provider_receipt(operator, output, server, "shared"),
    }
    cleanup: dict[str, object] = {
        "format": FORMAT,
        "targets": value["targets"],
        "journal_vault": vaults["journal"],
        "cleanup": value["cleanup"],
        "token": github,
        "server_credentials": credentials,
        "provider_metadata": _provider_receipt(operator, output, independent, "independent"),
    }
    for name, document in (
        ("controller-connect.json", controller),
        ("github-connect.json", cleanup),
    ):
        path = output / name
        if path.exists():
            if read_private(path) != document:
                raise LifecycleError("Connect setup output changed; preserve the original bundle")
        else:
            write_private(path, document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--manifest-reference", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--shared-url", required=True)
    parser.add_argument("--shared-server", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--unraid")
    parser.add_argument("--workspace")
    parser.add_argument("--workspace-id")
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        current_candidate(Path(__file__).resolve().parents[2], arguments.revision)
        operator = Operator()
        value = manifest(operator, arguments.manifest_reference, arguments.manifest_sha256)
        vaults = role_vaults(value)
        endpoint(arguments.shared_url)
        delivery = None
        destination = (arguments.unraid, arguments.workspace, arguments.workspace_id)
        if any(destination):
            if not all(destination) or not arguments.apply:
                raise LifecycleError(
                    "private delivery needs --apply and all three destination fields"
                )
            delivery = Delivery(*destination)
            delivery.preflight()
        if arguments.apply:
            prepare(
                operator,
                value,
                url=arguments.shared_url,
                server=arguments.shared_server,
                output=arguments.output,
            )
            if delivery:
                delivery.install(arguments.output)
                print("Connect bootstrap delivered to LDP and protected GitHub cleanup storage.")
            print(
                "Connect bootstrap bundles saved privately. "
                "Authentication and independent cleanup readiness remain to be verified."
            )
        else:
            print(
                json.dumps(
                    {
                        "shared_server": arguments.shared_server,
                        "shared_vaults": vaults,
                        "independent_cleanup_vaults": [vaults["cleanup"], vaults["journal"]],
                        "client_lifetime": "7 days",
                        "provider_credentials_created": False,
                    },
                    indent=2,
                )
            )
    except (LifecycleError, OSError, ValueError, TypeError) as error:
        print(
            str(error)
            if isinstance(error, LifecycleError)
            else "Connect setup failed; private evidence was retained."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
