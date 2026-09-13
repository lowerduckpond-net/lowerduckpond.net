#!/usr/bin/env python3
"""Read-only Spaces policy/inventory and enforced Cloudflare edge checks."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import Final, Protocol, cast

from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]
from lowerduckpond_m3_archive.storage import (
    S3Client,
    assert_storage_empty,
)
from lowerduckpond_static_contracts import ContractKind, canonical_json_bytes, validate_contract
from lowerduckpond_static_host_agent.archive_configuration import ArchiveConfiguration
from lowerduckpond_static_host_agent.archive_remote import (
    MAX_REMOTE_VERSIONS,
    ArchiveClient,
    ArchiveRemoteError,
    ArchiveRemoteStore,
    RemoteVersion,
)

from scripts.check_m3_7_production_edge import (
    MAXIMUM_CERTIFICATE_BYTES,
    CloudflareClient,
    ProductionEdgePreflightError,
    _require_account_token_policies,
    _require_zone_identity,
    validate_ca_certificate,
    validate_leaf_certificate,
    verify_active_account_token,
)
from scripts.m3_10_page_rules import PageRulesClient
from scripts.m3_10_policy_client import make_policy_client

_MAXIMUM_TRUST_ANCHORS: Final = 2
_MAXIMUM_AUTHORITY_BYTES: Final = 128 * 1024
_PRIVATE_AUTHORITY_MODE: Final = 0o600


class GateError(RuntimeError):
    """A required live starting condition could not be proved."""


class PolicyClient(S3Client, Protocol):
    def get_bucket_acl(self, **kwargs: object) -> dict[str, object]: ...

    def get_object_acl(self, **kwargs: object) -> dict[str, object]: ...

    def get_bucket_policy(self, **kwargs: object) -> dict[str, object]: ...

    def get_bucket_lifecycle_configuration(self, **kwargs: object) -> dict[str, object]: ...


def _require_absent_configuration(
    operation: Callable[..., dict[str, object]], *, bucket: str, missing_code: str
) -> None:
    try:
        operation(Bucket=bucket)
    except ClientError as error:
        response = error.response
        if (
            response.get("Error", {}).get("Code") == missing_code
            and response.get("ResponseMetadata", {}).get("HTTPStatusCode") == HTTPStatus.NOT_FOUND
        ):
            return
        raise GateError("bucket configuration could not be read") from error
    raise GateError("archive bucket has an unexpected policy or lifecycle configuration")


def _private_acl_owner(acl: dict[str, object], *, expected_owner: str | None = None) -> str:
    owner = acl.get("Owner")
    grants = acl.get("Grants")
    if (
        not isinstance(owner, dict)
        or not isinstance(owner.get("ID"), str)
        or not owner["ID"]
        or (expected_owner is not None and owner["ID"] != expected_owner)
        or not isinstance(grants, list)
        or len(grants) != 1
        or not isinstance(grants[0], dict)
    ):
        raise GateError("archive ACL is not an exact private owner grant")
    grant = grants[0]
    grantee = grant.get("Grantee")
    if (
        grant.get("Permission") != "FULL_CONTROL"
        or not isinstance(grantee, dict)
        or grantee.get("Type") != "CanonicalUser"
        or grantee.get("ID") != owner["ID"]
    ):
        raise GateError("archive ACL is not an exact private owner grant")
    return cast(str, owner["ID"])


def read_archive_authority(
    path: Path, *, bucket: str, artifact: str, source_revision: str
) -> frozenset[RemoteVersion]:
    """Consume only the private snapshot from this runner's verified host check."""
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise GateError("archive authority must be an absolute file without symlinks")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_AUTHORITY_MODE
            or metadata.st_nlink != 1
        ):
            raise GateError("archive authority file metadata is unsafe")
        raw = stream.read(_MAXIMUM_AUTHORITY_BYTES + 1)
    if len(raw) > _MAXIMUM_AUTHORITY_BYTES:
        raise GateError("archive authority exceeds its bound")
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or set(document) != {"format", "artifactSha256", "sourceRevision", "archives"}
        or document["format"] != "lowerduckpond-m3-10-archive-authority-v1"
        or re.fullmatch(r"[0-9a-f]{64}", artifact) is None
        or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None
        or document["artifactSha256"] != artifact
        or document["sourceRevision"] != source_revision
        or canonical_json_bytes(document, maximum_bytes=_MAXIMUM_AUTHORITY_BYTES) != raw
    ):
        raise GateError("archive authority does not bind the current candidate")
    records = document["archives"]
    if not isinstance(records, list) or len(records) > MAX_REMOTE_VERSIONS:
        raise GateError("archive authority has an invalid inventory")
    versions = set()
    keys = set()
    for record in records:
        validate_contract(record, expected_kind=ContractKind.ARCHIVE_RECORD)
        if record["bucket"] != bucket or record["key"] in keys:
            raise GateError("archive authority has a foreign bucket or duplicate binding")
        keys.add(record["key"])
        versions.add(RemoteVersion(record["key"], record["versionId"], record["bundleSize"], False))
    return frozenset(versions)


def _check_retained_storage(
    client: PolicyClient, *, bucket: str, owner: str, expected: frozenset[RemoteVersion]
) -> None:
    store = ArchiveRemoteStore(cast(ArchiveClient, client), bucket=bucket)
    # Inventory on either side of the ACL reads must equal the validated host
    # records. No new reservation is required when the legitimate bucket is full.
    for pass_number in range(2):
        try:
            inventory = store.inventory()
        except ArchiveRemoteError as error:
            raise GateError("retained archive inventory could not be verified") from error
        if inventory.multipart_uploads:
            raise GateError("archive bucket has incomplete multipart uploads")
        if frozenset(inventory.versions) != expected:
            raise GateError("retained remote inventory differs from validated host authority")
        if pass_number == 0:
            for version in sorted(expected, key=lambda item: item.key):
                _private_acl_owner(
                    client.get_object_acl(
                        Bucket=bucket, Key=version.key, VersionId=version.version_id
                    ),
                    expected_owner=owner,
                )


def check_storage(
    client: PolicyClient,
    *,
    bucket: str,
    require_empty: bool = True,
    expected_versions: frozenset[RemoteVersion] | None = None,
) -> None:
    """Require private storage and exact empty or host-bound version accounting.

    Workstation operator authority reads ACLs; runtime keys retain object-only
    authority. Missing, ambiguous, foreign, or publicly granted state fails closed.
    """
    owner = _private_acl_owner(client.get_bucket_acl(Bucket=bucket))
    _require_absent_configuration(
        client.get_bucket_policy, bucket=bucket, missing_code="NoSuchBucketPolicy"
    )
    _require_absent_configuration(
        client.get_bucket_lifecycle_configuration,
        bucket=bucket,
        missing_code="NoSuchLifecycleConfiguration",
    )
    if require_empty:
        assert_storage_empty(client, bucket=bucket, prefix="")
    else:
        if expected_versions is None:
            raise GateError("retained archives require validated host authority")
        _check_retained_storage(client, bucket=bucket, owner=owner, expected=expected_versions)


def expected_rules(domain: str) -> dict[str, dict[str, object]]:
    host = f'(http.host eq "{domain}" or ends_with(http.host, ".{domain}"))'
    return {
        "http_request_cache_settings": {
            "action": "set_cache_settings",
            "expression": host,
            "enabled": True,
            "ref": "lowerduckpond_m3_cache_bypass",
            "action_parameters": {"cache": False},
        },
        "http_config_settings": {
            "action": "set_config",
            "expression": host,
            "enabled": True,
            "ref": "lowerduckpond_m3_transform_disable",
            "action_parameters": {
                "automatic_https_rewrites": False,
                "disable_rum": True,
                "disable_zaraz": True,
                "email_obfuscation": False,
                "fonts": False,
                "rocket_loader": False,
            },
        },
        "http_request_firewall_custom": {
            "action": "block",
            "expression": (
                f'{host} and (lower(http.request.uri.path) eq "/cdn-cgi" '
                'or starts_with(lower(http.request.uri.path), "/cdn-cgi/"))'
            ),
            "enabled": True,
            "ref": "lowerduckpond_m3_cdn_cgi_block",
        },
    }


def _zone_account(details: object, *, zone_id: str, domain: str) -> str:
    if (
        not isinstance(details, dict)
        or details.get("id") != zone_id
        or details.get("name") != domain
        or details.get("status") != "active"
        or details.get("paused") is not False
    ):
        raise GateError("edge zone identity, active status, or proxy pause state drifted")
    account = details.get("account")
    if not isinstance(account, dict):
        raise GateError("edge zone account identity is missing")
    account_id = account.get("id")
    if not isinstance(account_id, str) or re.fullmatch(r"[0-9a-f]{32}", account_id) is None:
        raise GateError("edge zone account identity is malformed")
    return account_id


def check_edge(  # noqa: PLR0912, PLR0913 - explicit enforced-edge identity and trust
    client: CloudflareClient,
    *,
    page_rules_client: PageRulesClient,
    zone_id: str,
    certificate_id: str,
    domain: str,
    origin: str,
    ca_path: Path,
    now: datetime,
) -> str:
    if (
        re.fullmatch(r"[0-9a-f]{32}", zone_id) is None
        or re.fullmatch(
            r"(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})", certificate_id
        )
        is None
    ):
        raise GateError("edge identity is malformed")
    zone = f"/zones/{zone_id}"
    account_id = _zone_account(client.get(zone), zone_id=zone_id, domain=domain)
    verify_active_account_token(client, account_id=account_id, label="OpenTofu edge")
    # Both collections are absent from Rulesets and have no pagination metadata.
    for label, endpoint, reader in (
        ("Workers routes", "workers/routes", client),
        ("Page Rules", "pagerules", page_rules_client),
    ):
        inventory = reader.get(f"{zone}/{endpoint}")
        if not isinstance(inventory, list) or inventory:
            raise GateError(f"edge {label} are present or malformed")
    records = client.get_collection(f"{zone}/dns_records")
    routing = [
        item
        for item in records
        if not isinstance(item, dict) or item.get("type") not in {"CAA", "MX", "TXT"}
    ]
    expected_names = {domain, f"*.{domain}"}
    if len(routing) != len(expected_names):
        raise GateError("edge routing inventory drifted")
    observed_names = set()
    for record in routing:
        if (
            not isinstance(record, dict)
            or record.get("type") != "A"
            or record.get("content") != origin
            or record.get("proxied") is not True
            or record.get("ttl") != 1
            or record.get("name") not in expected_names
        ):
            raise GateError("edge routing policy drifted")
        observed_names.add(record["name"])
    if observed_names != expected_names:
        raise GateError("edge routing identity drifted")
    for setting, expected in {
        "ssl": "strict",
        "always_online": "off",
        "always_use_https": "off",
    }.items():
        value = client.get(f"{zone}/settings/{setting}")
        if not isinstance(value, dict) or value.get("value") != expected:
            raise GateError("edge TLS or response policy drifted")
    aop = client.get_aop_setting(zone_id)
    if not isinstance(aop, dict) or aop.get("enabled") is not True:
        raise GateError("edge origin pulls are not enabled")
    # Cloudflare retains invalidated associations with enabled=null, even when
    # status is active. False still suppresses the zone-level client certificate.
    # Require explicit invalidation and a settled association, never a missing
    # flag or an update whose deployment/deletion has not finished.
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("hostname"), str)
        or not item["hostname"]
        or "enabled" not in item
        or item["enabled"] is not None
        or item.get("status") not in ("active", "deleted")
        for item in client.get_collection(f"{zone}/origin_tls_client_auth/hostnames")
    ):
        raise GateError(
            f"edge {domain} has unexpected or unsettled hostname-level origin-pull overrides"
        )
    certificates = client.get_collection(f"{zone}/origin_tls_client_auth")
    active = [
        certificate
        for certificate in certificates
        if isinstance(certificate, dict) and certificate.get("status") == "active"
    ]
    if (
        any(not isinstance(certificate, dict) for certificate in certificates)
        or len(active) != 1
        or active[0].get("id") != certificate_id
    ):
        raise GateError("edge active origin-pull certificate inventory drifted")
    validate_leaf_certificate(
        active[0], ca_path=ca_path, expected_zone=domain, expected_id=certificate_id, now=now
    )
    phase_rules = expected_rules(domain)
    inventory = client.get_cursor_collection(f"{zone}/rulesets")
    if any(
        not isinstance(item, dict) or item.get("kind") not in {"managed", "custom", "zone"}
        for item in inventory
    ):
        raise GateError("edge ruleset inventory is malformed")
    # Cloudflare also lists available account/managed rulesets. Only kind=zone
    # denotes this zone's configured phase entrypoint; every such phase must
    # match the reviewed inventory before any individual rule is accepted.
    phases = [
        item.get("phase") for item in inventory if isinstance(item, dict) and item["kind"] == "zone"
    ]
    if len(phases) != len(phase_rules) or any(
        not isinstance(phase, str) or phase not in phase_rules for phase in phases
    ):
        raise GateError("edge has unexpected or missing ruleset phases")
    if len(set(phases)) != len(phase_rules):
        raise GateError("edge ruleset phases are duplicated")
    for phase, expected_rule in phase_rules.items():
        entrypoint = client.get(f"{zone}/rulesets/phases/{phase}/entrypoint")
        rules = entrypoint.get("rules") if isinstance(entrypoint, dict) else None
        if not isinstance(rules, list) or len(rules) != 1 or not isinstance(rules[0], dict):
            raise GateError("edge ruleset inventory drifted")
        if any(rules[0].get(key) != value for key, value in expected_rule.items()):
            raise GateError("edge ruleset policy drifted")
        if "action_parameters" not in expected_rule and rules[0].get("action_parameters") not in (
            None,
            {},
        ):
            raise GateError("edge block response policy drifted")

    return account_id


def required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise GateError(f"required environment variable {name} is missing")
    return value


def check_caddy_token(environment: Mapping[str, str], *, account_id: str, now: datetime) -> None:
    """Bind the live runtime token to its exact non-expiring two-zone policy."""
    edge_token = required(environment, "CLOUDFLARE_API_TOKEN")
    caddy_token = required(environment, "CADDY_CLOUDFLARE_API_TOKEN")
    audit_token = required(environment, "M3_10_TOKEN_AUDIT_TOKEN")
    if len({edge_token, caddy_token, audit_token}) != 3:  # noqa: PLR2004 - three credential roles
        raise GateError("the Cloudflare token roles are not separated")
    caddy = CloudflareClient(caddy_token)
    zones = (
        (required(environment, "CLOUDFLARE_ZONE_ID"), "lowerduckpond.net"),
        (required(environment, "CLOUDFLARE_TENANT_ZONE_ID"), "lowerduckpond.com"),
    )
    for zone_id, domain in zones:
        if _require_zone_identity(caddy, zone_id, domain) != account_id:
            raise GateError("the Caddy token identified a different zone account")
    # M3.10's workstation edge reader also inspects routes and legacy settings.
    # Audit the installed runtime policy without imposing M3.7's narrower
    # OpenTofu policy on that separate workstation credential.
    _require_account_token_policies(
        audit_client=CloudflareClient(audit_token),
        caddy_client=caddy,
        edge_client=None,
        account_id=account_id,
        zone_ids=frozenset(zone_id for zone_id, _ in zones),
        now=now,
    )


def page_rules_client(environment: Mapping[str, str], *, now: datetime) -> PageRulesClient:
    token = required(environment, "M3_10_PAGE_RULES_TOKEN")
    if token in {
        required(environment, name)
        for name in (
            "CLOUDFLARE_API_TOKEN",
            "CADDY_CLOUDFLARE_API_TOKEN",
            "M3_10_TOKEN_AUDIT_TOKEN",
        )
    }:
        raise GateError("the Page Rules user token must be separate from the account tokens")
    return PageRulesClient(
        CloudflareClient(token),
        zone_ids=frozenset(
            required(environment, name)
            for name in ("CLOUDFLARE_ZONE_ID", "CLOUDFLARE_TENANT_ZONE_ID")
        ),
        now=now,
    )


@contextmanager
def verified_ca_bundle(*, now: datetime) -> Iterator[Path]:
    """Validate the one or two bounded public trust anchors used during rotation."""
    paths = json.loads(required(os.environ, "CADDY_ORIGIN_PULL_CA_PATHS_JSON"))
    if (
        not isinstance(paths, list)
        or not 1 <= len(paths) <= _MAXIMUM_TRUST_ANCHORS
        or any(not isinstance(path, str) or not path.startswith("/") for path in paths)
        or len(set(paths)) != len(paths)
    ):
        raise GateError("origin-pull trust requires one or two distinct absolute CA paths")
    with tempfile.TemporaryDirectory(prefix="m3-10-trust-") as temporary:
        certificates: list[bytes] = []
        for index, name in enumerate(paths):
            original = Path(name)
            if not original.is_file() or original.is_symlink():
                raise GateError("the production CA certificate path is unsafe")
            with original.open("rb") as source:
                pem = source.read(MAXIMUM_CERTIFICATE_BYTES + 1)
            # Validate the exact bytes that will be trusted, even if the public
            # input file changes before the provider returns its active leaf.
            copied = Path(temporary) / f"ca-{index}.pem"
            copied.write_bytes(pem)
            validate_ca_certificate(copied, pem, now=now)
            certificates.append(pem)
        bundle = Path(temporary) / "trust.pem"
        bundle.write_bytes(b"\n".join(certificates))
        yield bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--storage-only", action="store_true")
    parser.add_argument("--allow-existing-archives", action="store_true")
    parser.add_argument("--archive-authority", type=Path)
    parser.add_argument("--artifact")
    parser.add_argument("--source")
    arguments = parser.parse_args()
    try:
        configuration = ArchiveConfiguration(
            required(os.environ, "SPACES_REGION"),
            required(os.environ, "SPACES_ARCHIVE_BUCKET"),
            required(os.environ, "SPACES_ACCESS_KEY_ID"),
            required(os.environ, "SPACES_SECRET_ACCESS_KEY"),
        )
        expected_versions = None
        if arguments.allow_existing_archives:
            if not (arguments.archive_authority and arguments.artifact and arguments.source):
                raise GateError(
                    "completed storage checks require the current host authority snapshot"
                )
            expected_versions = read_archive_authority(
                arguments.archive_authority,
                bucket=configuration.bucket,
                artifact=arguments.artifact,
                source_revision=arguments.source,
            )
        elif arguments.archive_authority or arguments.artifact or arguments.source:
            raise GateError("host authority is only valid for completed storage checks")
        client = cast(PolicyClient, make_policy_client(configuration))
        check_storage(
            client,
            bucket=configuration.bucket,
            require_empty=not arguments.allow_existing_archives,
            expected_versions=expected_versions,
        )
        storage_proof = (
            "private/versioned/no-lifecycle storage"
            if arguments.allow_existing_archives
            else "private/versioned/no-lifecycle storage and whole-bucket absence"
        )
        if arguments.storage_only:
            print(f"M3.10 {storage_proof} passed.")
            return 0
        edge = CloudflareClient(required(os.environ, "CLOUDFLARE_API_TOKEN"))
        now = datetime.now(UTC)
        page_rules = page_rules_client(os.environ, now=now)
        account_ids: set[str] = set()
        with verified_ca_bundle(now=now) as ca_path:
            for domain, prefix in (
                ("lowerduckpond.net", "CLOUDFLARE"),
                ("lowerduckpond.com", "CLOUDFLARE_TENANT"),
            ):
                account_id = check_edge(
                    edge,
                    page_rules_client=page_rules,
                    zone_id=required(os.environ, f"{prefix}_ZONE_ID"),
                    certificate_id=required(os.environ, f"{prefix}_ORIGIN_PULL_CERTIFICATE_ID"),
                    domain=domain,
                    origin=required(os.environ, "PRODUCTION_ORIGIN_IPV4"),
                    ca_path=ca_path,
                    now=now,
                )
                account_ids.add(account_id)
        if len(account_ids) != 1:
            raise GateError("production edge zones belong to different accounts")
        check_caddy_token(os.environ, account_id=account_ids.pop(), now=now)
    except (BotoCoreError, ClientError, RuntimeError, ValueError, OSError) as error:
        # Provider exceptions can include request URLs, headers, and credentials.
        message = (
            str(error)
            if isinstance(error, (GateError, ProductionEdgePreflightError))
            else type(error).__name__
        )
        print(f"M3.10 provider preflight failed closed: {message}.", file=sys.stderr)
        return 1
    print(f"M3.10 {storage_proof} passed; both edges remain enforced.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
