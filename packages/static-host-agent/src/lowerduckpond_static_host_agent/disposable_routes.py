"""Project only native Caddy presentation fields for one disposable journey."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Any, cast
from urllib.parse import urlsplit

from lowerduckpond_static_contracts import (
    canonical_json_bytes,
    decode_json_object,
    validate_slug,
    validate_uuid7,
)
from lowerduckpond_static_contracts.identifiers import validate_tenant_origin_suffix

from lowerduckpond_static_host_agent.caddy_generation import (
    MAX_CADDY_CONFIGURATION_BYTES,
    caddy_route_state_digest,
)
from lowerduckpond_static_host_agent.caddy_routes import (
    PLATFORM_DOMAIN,
    TENANT_DOMAIN,
    CaddyRouteError,
    PlatformOnlyCaddyRoutes,
    TenantCaddyRoutes,
)

type Document = dict[str, Any]


@dataclass(frozen=True)
class DisposableRoutes:
    """A verified, exclusive mapping. It has neither a slug nor a second tenant ID."""

    allocation_sha256: str
    run_id: str
    invocation_id: str
    source_target: str
    restore_target: str
    platform: str
    tenant_scope: str
    tenants: tuple[tuple[str, str], ...]

    def document(self) -> Document:
        return {
            "format": "lowerduckpond-m3-12-disposable-routing-v1",
            "allocationSha256": self.allocation_sha256,
            "runId": self.run_id,
            "invocationId": self.invocation_id,
            "sourceTargetSha256": self.source_target,
            "restoreTargetSha256": self.restore_target,
            "platform": self.platform,
            "tenantScope": self.tenant_scope,
            "tenants": [
                {"tenantId": identity, "origin": origin} for identity, origin in self.tenants
            ],
        }

    @property
    def sha256(self) -> str:
        return sha256(canonical_json_bytes(self.document())).hexdigest()

    @property
    def certificate_subjects(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                (self.platform, f"*.{self.platform}", self.tenant_scope, f"*.{self.tenant_scope}")
            )
        )

    def expected_origin(self, identity: str) -> str:
        for tenant, origin in self.tenants:
            if tenant == identity:
                return origin
        raise CaddyRouteError("disposable route tenant is not enrolled")

    def __post_init__(self) -> None:
        validate_uuid7(self.run_id)
        validate_uuid7(self.invocation_id)
        if any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in (self.allocation_sha256, self.source_target, self.restore_target)
        ):
            raise CaddyRouteError("disposable route target binding is invalid")
        for suffix in (self.platform, self.tenant_scope):
            validate_tenant_origin_suffix(suffix)
            if any(
                suffix == right or suffix.endswith("." + right) or right.endswith("." + suffix)
                for right in (PLATFORM_DOMAIN, TENANT_DOMAIN)
            ):
                raise CaddyRouteError("disposable route scope crosses production")
        if (
            self.platform == self.tenant_scope
            or self.platform.endswith("." + self.tenant_scope)
            or self.tenant_scope.endswith("." + self.platform)
            or self.source_target == self.restore_target
            or tuple(sorted({identity for identity, _ in self.tenants}))
            != tuple(identity for identity, _ in self.tenants)
        ):
            raise CaddyRouteError("disposable route identities overlap")
        validate_tenant_origin_suffix("hosting." + self.platform)
        validate_tenant_origin_suffix("fixture." + self.tenant_scope)
        for identity, origin in self.tenants:
            canonical = validate_uuid7(identity)
            hostname = f"t-{canonical.replace('-', '')}.{self.tenant_scope}"
            validate_tenant_origin_suffix(hostname)
            if origin != f"https://{hostname}":
                raise CaddyRouteError(
                    "disposable route origin is not the exclusive derived HTTPS origin"
                )


def _hosts(state: Document, policy: DisposableRoutes) -> dict[str, str]:
    result = {
        PLATFORM_DOMAIN: policy.platform,
        f"*.{PLATFORM_DOMAIN}": f"*.{policy.platform}",
        **{
            f"{label}.{PLATFORM_DOMAIN}": f"{label}.{policy.platform}"
            for label in ("hosting", "www", "secure")
        },
        TENANT_DOMAIN: policy.tenant_scope,
        f"*.{TENANT_DOMAIN}": f"*.{policy.tenant_scope}",
    }
    for tenant in state.get("tenantStates", []):
        if tenant["routeSet"] != "present":
            continue  # Retain undeployed, suspended and archived identity without publishing it.
        original = tenant["desiredManifest"]["metadata"]
        projected = policy.expected_origin(original["id"]).removeprefix("https://")
        alias = validate_slug(original["slug"])
        scoped_alias = f"{alias}.{policy.tenant_scope}"
        validate_tenant_origin_suffix(scoped_alias)
        result[original["canonicalOrigin"]] = projected
        result[f"{alias}.{TENANT_DOMAIN}"] = scoped_alias
    if len(set(result.values())) != len(result):
        raise CaddyRouteError("disposable projected hostnames overlap")
    return result


def _host(hostnames: dict[str, str], original: str) -> str:
    try:
        return hostnames[original]
    except KeyError:
        raise CaddyRouteError("native route contains an unapproved hostname") from None


def _location(hostnames: dict[str, str], original: str) -> str:
    # The existing generator uses either a fixed root target or the exact
    # platform compatibility URI placeholder. It never supplies a user URL.
    url = urlsplit(original)
    if url.scheme != "https" or url.username or url.password or url.query or url.fragment:
        raise CaddyRouteError("native redirect is not projectable")
    if url.netloc.endswith("{http.request.uri}") and not url.path:
        base = url.netloc.removesuffix("{http.request.uri}")
        if base == PLATFORM_DOMAIN:
            return "https://" + _host(hostnames, base) + "{http.request.uri}"
    if url.hostname != url.netloc or url.path not in {"", "/"}:
        raise CaddyRouteError("native redirect is not projectable")
    return "https://" + _host(hostnames, url.netloc) + url.path


def _route_matches(hostnames: dict[str, str], route: Document) -> None:
    for match in route.get("match", []):
        if "host" in match:
            match["host"] = [_host(hostnames, name) for name in match["host"]]
    for handler in route["handle"]:
        headers = handler.get("headers", {})
        if "Location" in headers:
            headers["Location"] = [_location(hostnames, url) for url in headers["Location"]]


def project_native_routes[Routes: PlatformOnlyCaddyRoutes | TenantCaddyRoutes](
    routes: Routes,
    policy: DisposableRoutes,
) -> Routes:
    """Translate exact generated matchers, redirect targets, log names and certificate subjects."""
    metadata = deepcopy(routes.route_metadata)
    state = cast(Document, metadata["routeState"])
    hosts = _hosts(state, policy)
    # Caddy's logical compiler shares logger dictionaries between listeners.
    # Round trip the same JSON representation persisted for native verification.
    cfg = cast(
        Document,
        decode_json_object(
            canonical_json_bytes(routes.configuration, maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES),
            maximum_bytes=MAX_CADDY_CONFIGURATION_BYTES,
        ),
    )
    for server in cfg["apps"]["http"]["servers"].values():
        if "logs" in server:
            logger = server["logs"]["logger_names"]
            server["logs"]["logger_names"] = {
                _host(hosts, name): value for name, value in logger.items()
            }
        for route in server["routes"]:
            _route_matches(hosts, route)
    for automation in cfg["apps"]["tls"]["automation"]["policies"]:
        automation["subjects"] = sorted(_host(hosts, name) for name in automation["subjects"])
        if tuple(automation["subjects"]) != policy.certificate_subjects:
            raise CaddyRouteError("disposable certificate subjects changed")

    for entry in state["routes"]:
        if "hosts" in entry:
            entry["hosts"] = [_host(hosts, name) for name in entry["hosts"]]
        if "targetOrigin" in entry:
            entry["targetOrigin"] = _location(hosts, entry["targetOrigin"])
    state["logicalRouteStateDigest"] = metadata["routeStateDigest"]
    state["disposableRoutingSha256"] = policy.sha256
    state["platformDomain"] = policy.platform
    state["tenantDomain"] = policy.tenant_scope
    metadata["routeStateDigest"] = caddy_route_state_digest(state).to_dict()
    return replace(routes, configuration=cfg, http_app=cfg["apps"]["http"], route_metadata=metadata)
