"""Allowlisted Caddy routes derived from trusted platform publication state."""

from __future__ import annotations

import base64
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from typing import Final, cast

from lowerduckpond_static_contracts import (
    ContractError,
    ContractKind,
    deployment_record_digest,
    manifest_digest,
    validate_contract,
    validate_uuid7,
)
from lowerduckpond_static_contracts.identifiers import (
    MAX_DNS_HOSTNAME_BYTES,
    validate_canonical_origin,
)

from lowerduckpond_static_host_agent.caddy_generation import (
    CADDY_ROUTE_METADATA_SCHEMA,
    caddy_route_state_digest,
)

PLATFORM_DOMAIN: Final = "lowerduckpond.net"
TENANT_DOMAIN: Final = "lowerduckpond.com"
PLATFORM_APEX: Final = PLATFORM_DOMAIN
PLATFORM_COMPATIBILITY_HOSTS: Final = (
    f"hosting.{PLATFORM_DOMAIN}",
    f"www.{PLATFORM_DOMAIN}",
)
PLATFORM_SECURE_HOST: Final = f"secure.{PLATFORM_DOMAIN}"
PLATFORM_WILDCARD: Final = f"*.{PLATFORM_DOMAIN}"
TENANT_APEX: Final = TENANT_DOMAIN
TENANT_WILDCARD: Final = f"*.{TENANT_DOMAIN}"
PLATFORM_FIXTURE_ROOT: Final = "/srv/lowerduckpond/fixture"
TENANT_RELEASE_ROOT: Final = "/srv/lowerduckpond/sites"
PLATFORM_CANONICAL_ORIGIN: Final = f"https://{PLATFORM_APEX}"
CADDY_ADMIN_SOCKET: Final = "/run/caddy/admin.sock"
GENERIC_NOT_FOUND_BODY: Final = "No Lower Duck Pond site has been provisioned for this name."
ALIAS_REDIRECT_BODY: Final = "Redirecting to the canonical Lower Duck Pond site."
NO_TRANSFORM: Final = "no-transform"
NO_STORE_NO_TRANSFORM: Final = "no-store, no-transform"
MAXIMUM_ORIGIN_PULL_CA_CERTIFICATES: Final = 2
MAXIMUM_ORIGIN_PULL_CA_DER_BYTES: Final = 64 * 1024
CLOUDFLARE_PROXY_CIDRS: Final = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


@dataclass(frozen=True, slots=True)
class PlatformOnlyCaddyRoutes:
    """The complete production-dark Caddy config and its semantic route state."""

    configuration: dict[str, object]
    http_app: dict[str, object]
    route_metadata: dict[str, object]


class CaddyRouteError(RuntimeError):
    """Authoritative tenant state cannot produce one safe complete route set."""


@dataclass(frozen=True, slots=True)
class TenantRouteInput:
    """The exact desired, observed, and selected-deployment state for one tenant."""

    manifest: dict[str, object]
    observed_state: dict[str, object]
    deployment: dict[str, object] | None


@dataclass(frozen=True, slots=True)
class TenantCaddyRoutes:
    """One complete tenant-capable Caddy config and its authoritative route state."""

    configuration: dict[str, object]
    http_app: dict[str, object]
    route_metadata: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ValidatedTenantRoute:
    tenant_id: str
    slug: str
    canonical_origin: str
    lifecycle: str
    release_root: str | None
    manifest: dict[str, object]
    observed_state: dict[str, object]
    deployment: dict[str, object] | None


def build_platform_only_caddy_routes(
    *, origin_pull_ca_der: tuple[bytes, ...], origin_pull_required: bool
) -> PlatformOnlyCaddyRoutes:
    """Generate fixed platform routes with tenant publication unconditionally disabled."""

    trusted_ca_certs = _origin_pull_ca_certificates(origin_pull_ca_der)
    if type(origin_pull_required) is not bool:
        raise ValueError("origin-pull enforcement must be a boolean")
    route_state = _route_state(origin_pull_ca_der, origin_pull_required=origin_pull_required)
    access_logger_name = "log0"
    certificate_subjects = sorted((PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD))
    http_app: dict[str, object] = {
        "metrics": {},
        "servers": {
            "http": {
                "listen": [":80"],
                "logs": {
                    "logger_names": {
                        subject: [access_logger_name] for subject in certificate_subjects
                    }
                },
                "routes": [
                    _plain_http_platform_route(),
                    _plain_http_tenant_route(),
                    _catch_all_unknown_route(),
                ],
            },
            "production": {
                "listen": [":443"],
                "automatic_https": {"disable_redirects": True},
                "tls_connection_policies": [
                    {
                        "client_authentication": {
                            "ca": {
                                "provider": "inline",
                                "trusted_ca_certs": trusted_ca_certs,
                            },
                            "mode": (
                                "require_and_verify" if origin_pull_required else "verify_if_given"
                            ),
                        }
                    }
                ],
                "strict_sni_host": True,
                "trusted_proxies": {
                    "ranges": list(CLOUDFLARE_PROXY_CIDRS),
                    "source": "static",
                },
                "client_ip_headers": ["CF-Connecting-IP"],
                "trusted_proxies_strict": 1,
                "routes": [
                    _compatibility_redirect_route(),
                    _platform_apex_route(),
                    _platform_unknown_route(),
                    _tenant_namespace_dark_route(),
                    _catch_all_unknown_route(),
                ],
                "errors": {"routes": [_error_route()]},
                "logs": {
                    "logger_names": {
                        subject: [access_logger_name] for subject in certificate_subjects
                    }
                },
            },
        },
    }
    return PlatformOnlyCaddyRoutes(
        configuration={
            "admin": {"listen": f"unix/{CADDY_ADMIN_SOCKET}"},
            "apps": {
                "http": http_app,
                "tls": {
                    "automation": {
                        "policies": [
                            {
                                "issuers": [
                                    {
                                        "challenges": {
                                            "dns": {
                                                "provider": {
                                                    "api_token": ("{env.CLOUDFLARE_API_TOKEN}"),
                                                    "name": "cloudflare",
                                                }
                                            }
                                        },
                                        "module": "acme",
                                    }
                                ],
                                "subjects": certificate_subjects,
                            }
                        ]
                    }
                },
            },
            "logging": {
                "logs": {
                    "default": {"exclude": [f"http.log.access.{access_logger_name}"]},
                    access_logger_name: {
                        "encoder": {"format": "json"},
                        "include": [f"http.log.access.{access_logger_name}"],
                        "writer": {"output": "stdout"},
                    },
                }
            },
        },
        http_app=http_app,
        route_metadata={
            "routeState": route_state,
            "routeStateDigest": caddy_route_state_digest(route_state).to_dict(),
            "schema": CADDY_ROUTE_METADATA_SCHEMA,
        },
    )


def build_tenant_caddy_routes(
    *,
    platform_namespace: dict[str, object],
    tenants: tuple[TenantRouteInput, ...],
    runtime_generation_id: object,
    origin_pull_ca_der: tuple[bytes, ...],
    origin_pull_required: bool,
) -> TenantCaddyRoutes:
    """Derive a complete config solely from validated authoritative tenant state."""

    namespace = deepcopy(platform_namespace)
    if type(namespace) is not dict:
        raise CaddyRouteError("platform namespace must be one contract object")
    validate_contract(namespace, expected_kind=ContractKind.PLATFORM_NAMESPACE)
    if type(tenants) is not tuple or any(type(item) is not TenantRouteInput for item in tenants):
        raise CaddyRouteError("tenant route inputs must be one immutable tuple")
    try:
        generation_id = validate_uuid7(runtime_generation_id)
    except ContractError as error:
        raise CaddyRouteError("runtime generation ID is not a canonical UUIDv7") from error
    if type(origin_pull_required) is not bool:
        raise ValueError("origin-pull enforcement must be a boolean")
    trusted_ca_certs = _origin_pull_ca_certificates(origin_pull_ca_der)

    validated = tuple(
        sorted(
            (_validate_tenant_route_input(item, generation_id=generation_id) for item in tenants),
            key=lambda item: item.tenant_id,
        )
    )
    _require_unique_tenant_routes(validated)
    active = tuple(item for item in validated if item.lifecycle == "active")

    access_logger_name = "log0"
    alias_logger_name = "alias"
    certificate_subjects = sorted((PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD))
    logger_names = {
        PLATFORM_APEX: [access_logger_name],
        PLATFORM_WILDCARD: [access_logger_name],
        TENANT_APEX: [alias_logger_name],
        TENANT_WILDCARD: [alias_logger_name],
    }
    for tenant in active:
        logger_names[tenant.canonical_origin] = [access_logger_name]
        logger_names[f"{tenant.slug}.{TENANT_DOMAIN}"] = [alias_logger_name]
    server_logs = {"logger_names": dict(sorted(logger_names.items()))}

    http_app: dict[str, object] = {
        "metrics": {},
        "servers": {
            "http": {
                "listen": [":80"],
                "logs": server_logs,
                "routes": [
                    _plain_http_platform_route(),
                    *(_tenant_alias_route(tenant) for tenant in active),
                    _plain_http_tenant_route(),
                    _catch_all_unknown_route(),
                ],
            },
            "production": {
                "listen": [":443"],
                "automatic_https": {"disable_redirects": True},
                "tls_connection_policies": [
                    {
                        "client_authentication": {
                            "ca": {
                                "provider": "inline",
                                "trusted_ca_certs": trusted_ca_certs,
                            },
                            "mode": (
                                "require_and_verify" if origin_pull_required else "verify_if_given"
                            ),
                        }
                    }
                ],
                "strict_sni_host": True,
                "trusted_proxies": {
                    "ranges": list(CLOUDFLARE_PROXY_CIDRS),
                    "source": "static",
                },
                "client_ip_headers": ["CF-Connecting-IP"],
                "trusted_proxies_strict": 1,
                "routes": [
                    _compatibility_redirect_route(),
                    _platform_apex_route(),
                    _platform_unknown_route(),
                    *(_tenant_content_route(tenant) for tenant in active),
                    *(_tenant_alias_route(tenant) for tenant in active),
                    _tenant_namespace_dark_route(),
                    _catch_all_unknown_route(),
                ],
                "errors": {"routes": [_error_route()]},
                "logs": server_logs,
            },
        },
    }
    route_state = _tenant_route_state(
        namespace=namespace,
        tenants=validated,
        origin_pull_ca_der=origin_pull_ca_der,
        origin_pull_required=origin_pull_required,
    )
    return TenantCaddyRoutes(
        configuration={
            "admin": {"listen": f"unix/{CADDY_ADMIN_SOCKET}"},
            "apps": {
                "http": http_app,
                "tls": _tls_app(certificate_subjects),
            },
            "logging": {
                "logs": {
                    "default": {
                        "exclude": [
                            f"http.log.access.{access_logger_name}",
                            f"http.log.access.{alias_logger_name}",
                        ]
                    },
                    access_logger_name: _stdout_json_log(access_logger_name),
                    alias_logger_name: _sanitized_alias_log(alias_logger_name),
                }
            },
        },
        http_app=http_app,
        route_metadata={
            "routeState": route_state,
            "routeStateDigest": caddy_route_state_digest(route_state).to_dict(),
            "schema": CADDY_ROUTE_METADATA_SCHEMA,
        },
    )


def _validate_tenant_route_input(  # noqa: PLR0912, PLR0915 - explicit fail-closed bindings
    source: TenantRouteInput,
    *,
    generation_id: str,
) -> _ValidatedTenantRoute:
    manifest = deepcopy(source.manifest)
    observed = deepcopy(source.observed_state)
    deployment = deepcopy(source.deployment)
    if type(manifest) is not dict or type(observed) is not dict:
        raise CaddyRouteError("tenant desired and observed state must be contract objects")
    if deployment is not None and type(deployment) is not dict:
        raise CaddyRouteError("tenant deployment must be one contract object or absent")
    validate_contract(manifest, expected_kind=ContractKind.SITE)
    validate_contract(observed, expected_kind=ContractKind.TENANT_OBSERVED_STATE)

    metadata = cast(dict[str, object], manifest["metadata"])
    spec = cast(dict[str, object], manifest["spec"])
    tenant_id = cast(str, metadata["id"])
    slug = cast(str, metadata["slug"])
    canonical_origin = cast(str, metadata["canonicalOrigin"])
    validate_canonical_origin(tenant_id, canonical_origin)
    if observed["tenantId"] != tenant_id:
        raise CaddyRouteError("tenant desired and observed identities disagree")
    desired_digest = manifest_digest(manifest).to_dict()
    if observed["desiredManifestDigest"] != desired_digest:
        raise CaddyRouteError("tenant observed state does not bind the desired manifest")
    lifecycle = cast(str, spec["desiredState"])
    if observed["observedState"] != lifecycle:
        raise CaddyRouteError("tenant desired and observed lifecycle states disagree")
    if lifecycle == "archived":
        raise CaddyRouteError("archived route derivation is deferred until M3.10")

    alias_hostname = f"{slug}.{TENANT_DOMAIN}"
    try:
        alias_hostname.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:  # pragma: no cover - slug validation rejects this first
        raise CaddyRouteError("tenant alias hostname is not ASCII") from error
    if len(alias_hostname) > MAX_DNS_HOSTNAME_BYTES:
        raise CaddyRouteError("tenant alias hostname exceeds the DNS hostname limit")

    if lifecycle == "undeployed":
        if deployment is not None:
            raise CaddyRouteError("undeployed tenant unexpectedly retains a deployment")
        if (
            observed["activeDeploymentId"] is not None
            or observed["runtimeGenerationId"] is not None
        ):
            raise CaddyRouteError("undeployed tenant unexpectedly retains runtime state")
        release_root = None
    elif lifecycle in {"active", "suspended"}:
        if deployment is None:
            raise CaddyRouteError("deployed tenant has no selected deployment record")
        validate_contract(deployment, expected_kind=ContractKind.DEPLOYMENT_RECORD)
        desired_deployment = cast(dict[str, object], spec["desiredDeployment"])
        if (
            deployment["tenantId"] != tenant_id
            or deployment["id"] != desired_deployment["id"]
            or deployment["archiveSha256"] != desired_deployment["archiveSha256"]
            or observed["activeDeploymentId"] != deployment["id"]
        ):
            raise CaddyRouteError("selected deployment is not bound across tenant state")
        if lifecycle == "active" and observed["runtimeGenerationId"] != generation_id:
            raise CaddyRouteError("active tenant does not bind the candidate runtime generation")
        if lifecycle == "suspended" and observed["runtimeGenerationId"] is not None:
            raise CaddyRouteError("suspended tenant unexpectedly retains a runtime generation")
        release_root = f"{TENANT_RELEASE_ROOT}/{tenant_id}/releases/{deployment['id']}"
    else:  # pragma: no cover - the strict schema admits only the lifecycle enum
        raise CaddyRouteError("tenant lifecycle cannot produce routes")

    return _ValidatedTenantRoute(
        tenant_id=tenant_id,
        slug=slug,
        canonical_origin=canonical_origin,
        lifecycle=lifecycle,
        release_root=release_root,
        manifest=manifest,
        observed_state=observed,
        deployment=deployment,
    )


def _require_unique_tenant_routes(tenants: tuple[_ValidatedTenantRoute, ...]) -> None:
    def require_unique(values: tuple[str, ...], label: str) -> None:
        if len(values) != len(set(values)):
            raise CaddyRouteError(f"tenant route inputs contain a duplicate {label}")

    require_unique(tuple(item.tenant_id for item in tenants), "tenant identity")
    require_unique(tuple(item.slug for item in tenants), "slug")
    require_unique(tuple(item.canonical_origin for item in tenants), "canonical origin")
    deployments = tuple(
        cast(str, item.deployment["id"]) for item in tenants if item.deployment is not None
    )
    require_unique(deployments, "deployment identity")


def _tenant_route_state(
    *,
    namespace: dict[str, object],
    tenants: tuple[_ValidatedTenantRoute, ...],
    origin_pull_ca_der: tuple[bytes, ...],
    origin_pull_required: bool,
) -> dict[str, object]:
    state = _route_state(
        origin_pull_ca_der,
        origin_pull_required=origin_pull_required,
    )
    state["generationClass"] = "tenant-capable"
    state["publicationEnabled"] = True
    state["platformNamespace"] = deepcopy(namespace)
    state["tenantStates"] = [
        {
            "activeDeployment": deepcopy(item.deployment),
            "desiredManifest": deepcopy(item.manifest),
            "observedState": deepcopy(item.observed_state),
            "routeSet": "present" if item.lifecycle == "active" else "absent",
        }
        for item in tenants
    ]
    tenant_routes: list[dict[str, object]] = []
    for item in tenants:
        if item.lifecycle != "active":
            continue
        if item.deployment is None or item.release_root is None:  # pragma: no cover - internal type
            raise CaddyRouteError("validated active tenant lost its deployment binding")
        tenant_routes.extend(
            [
                {
                    "behavior": "serve-immutable-release",
                    "cacheControl": NO_TRANSFORM,
                    "class": "tenant-canonical",
                    "deploymentDigest": deployment_record_digest(item.deployment).to_dict(),
                    "hosts": [item.canonical_origin],
                    "releaseRoot": item.release_root,
                    "requestCookie": "remove",
                    "responseSetCookie": "remove",
                    "tenantId": item.tenant_id,
                },
                {
                    "behavior": "bare-root-canonical-redirect",
                    "cacheControl": NO_STORE_NO_TRANSFORM,
                    "class": "tenant-alias",
                    "hosts": [f"{item.slug}.{TENANT_DOMAIN}"],
                    "requestCookie": "remove",
                    "responseSetCookie": "remove",
                    "targetOrigin": f"https://{item.canonical_origin}",
                    "tenantId": item.tenant_id,
                },
            ]
        )
    routes = cast(list[dict[str, object]], state["routes"])
    routes[3:3] = tenant_routes
    state["tenantRouteCount"] = len(tenant_routes)
    return state


def _tenant_content_route(tenant: _ValidatedTenantRoute) -> dict[str, object]:
    if tenant.release_root is None:  # pragma: no cover - internal type invariant
        raise CaddyRouteError("validated active tenant lost its release binding")
    return {
        "handle": [
            {"handler": "headers", "request": {"delete": ["Cookie"]}},
            {"handler": "vars", "root": tenant.release_root},
            {
                "handler": "headers",
                "response": {
                    "deferred": True,
                    "delete": ["Set-Cookie"],
                    "set": {"Cache-Control": [NO_TRANSFORM]},
                },
            },
            {"handler": "file_server"},
        ],
        "match": [{"host": [tenant.canonical_origin]}],
        "terminal": True,
    }


def _tenant_alias_route(tenant: _ValidatedTenantRoute) -> dict[str, object]:
    return {
        "handle": [
            {"handler": "headers", "request": {"delete": ["Cookie"]}},
            {
                "handler": "headers",
                "response": {
                    "deferred": True,
                    "delete": ["Set-Cookie"],
                    "set": {
                        "Cache-Control": [NO_STORE_NO_TRANSFORM],
                        "Referrer-Policy": ["no-referrer"],
                    },
                },
            },
            {
                "body": ALIAS_REDIRECT_BODY,
                "handler": "static_response",
                "headers": {"Location": [f"https://{tenant.canonical_origin}/"]},
                "status_code": 302,
            },
        ],
        "match": [
            {
                "host": [f"{tenant.slug}.{TENANT_DOMAIN}"],
                "method": ["GET", "HEAD"],
                "path": ["/"],
                "query": {},
            }
        ],
        "terminal": True,
    }


def _tls_app(certificate_subjects: list[str]) -> dict[str, object]:
    return {
        "automation": {
            "policies": [
                {
                    "issuers": [
                        {
                            "challenges": {
                                "dns": {
                                    "provider": {
                                        "api_token": "{env.CLOUDFLARE_API_TOKEN}",
                                        "name": "cloudflare",
                                    }
                                }
                            },
                            "module": "acme",
                        }
                    ],
                    "subjects": certificate_subjects,
                }
            ]
        }
    }


def _stdout_json_log(name: str) -> dict[str, object]:
    return {
        "encoder": {"format": "json"},
        "include": [f"http.log.access.{name}"],
        "writer": {"output": "stdout"},
    }


def _sanitized_alias_log(name: str) -> dict[str, object]:
    return {
        "encoder": {
            "fields": {
                "request>headers": {"filter": "delete"},
                "request>uri": {"filter": "delete"},
            },
            "format": "filter",
            "wrap": {"format": "json"},
        },
        "include": [f"http.log.access.{name}"],
        "writer": {"output": "stdout"},
    }


def _route_state(
    origin_pull_ca_der: tuple[bytes, ...], *, origin_pull_required: bool
) -> dict[str, object]:
    return {
        "generationClass": "platform-only",
        "platformDomain": PLATFORM_DOMAIN,
        "publicationEnabled": False,
        "routes": [
            {
                "behavior": "serve-platform-fixture",
                "cacheControl": NO_TRANSFORM,
                "class": "platform-apex",
                "hosts": [PLATFORM_APEX],
            },
            {
                "behavior": "permanent-equivalent-uri-redirect",
                "cacheControl": NO_STORE_NO_TRANSFORM,
                "class": "platform-compatibility",
                "hosts": list(PLATFORM_COMPATIBILITY_HOSTS),
                "targetOrigin": PLATFORM_CANONICAL_ORIGIN,
            },
            {
                "behavior": "generic-not-found",
                "cacheControl": NO_STORE_NO_TRANSFORM,
                "class": "platform-reserved-or-unknown",
                "hosts": [PLATFORM_SECURE_HOST, PLATFORM_WILDCARD],
            },
            {
                "behavior": "generic-not-found",
                "cacheControl": NO_STORE_NO_TRANSFORM,
                "class": "tenant-namespace-dark",
                "hosts": [TENANT_APEX, TENANT_WILDCARD],
                "requestCookie": "remove",
                "responseSetCookie": "remove",
            },
            {
                "behavior": "generic-not-found",
                "cacheControl": NO_STORE_NO_TRANSFORM,
                "class": "unmatched-host",
                "match": "otherwise",
                "requestCookie": "remove",
                "responseSetCookie": "remove",
            },
        ],
        "errorPolicy": {
            "behavior": "generic-status-preserving-error",
            "cacheControl": NO_STORE_NO_TRANSFORM,
            "responseSetCookie": "remove",
        },
        "tenantDomain": TENANT_DOMAIN,
        "tenantRouteCount": 0,
        "originPullCaSha256": [
            hashlib.sha256(certificate).hexdigest() for certificate in origin_pull_ca_der
        ],
        "originPullRequired": origin_pull_required,
    }


def _origin_pull_ca_certificates(certificates: tuple[bytes, ...]) -> list[str]:
    if (
        type(certificates) is not tuple
        or not certificates
        or len(certificates) > MAXIMUM_ORIGIN_PULL_CA_CERTIFICATES
        or any(
            type(certificate) is not bytes
            or not certificate
            or len(certificate) > MAXIMUM_ORIGIN_PULL_CA_DER_BYTES
            for certificate in certificates
        )
        or len(set(certificates)) != len(certificates)
    ):
        raise ValueError("origin-pull trust must contain one or two distinct DER certificates")
    return [base64.b64encode(certificate).decode("ascii") for certificate in certificates]


def _compatibility_redirect_route() -> dict[str, object]:
    return {
        "handle": [
            _response_headers({"Cache-Control": [NO_STORE_NO_TRANSFORM]}),
            {
                "handler": "static_response",
                "headers": {
                    "Location": [
                        f"{PLATFORM_CANONICAL_ORIGIN}{{http.request.uri}}",
                    ]
                },
                "status_code": 301,
            },
        ],
        "match": [{"host": list(PLATFORM_COMPATIBILITY_HOSTS)}],
        "terminal": True,
    }


def _platform_apex_route() -> dict[str, object]:
    return {
        "handle": [
            {"handler": "vars", "root": PLATFORM_FIXTURE_ROOT},
            _response_headers({"Cache-Control": [NO_TRANSFORM]}),
            {"handler": "file_server"},
        ],
        "match": [{"host": [PLATFORM_APEX]}],
        "terminal": True,
    }


def _platform_unknown_route() -> dict[str, object]:
    return {
        "handle": [
            _response_headers({"Cache-Control": [NO_STORE_NO_TRANSFORM]}),
            _not_found_response(),
        ],
        "match": [{"host": [PLATFORM_SECURE_HOST, PLATFORM_WILDCARD]}],
        "terminal": True,
    }


def _tenant_namespace_dark_route() -> dict[str, object]:
    return {
        "handle": [
            {
                "handler": "headers",
                "request": {"delete": ["Cookie"]},
            },
            {
                "handler": "headers",
                "response": {
                    "deferred": True,
                    "delete": ["Set-Cookie"],
                    "set": {"Cache-Control": [NO_STORE_NO_TRANSFORM]},
                },
            },
            _not_found_response(),
        ],
        "match": [{"host": [TENANT_APEX, TENANT_WILDCARD]}],
        "terminal": True,
    }


def _plain_http_platform_route() -> dict[str, object]:
    return {
        "handle": [
            _response_headers({"Cache-Control": [NO_STORE_NO_TRANSFORM]}),
            _not_found_response(),
        ],
        "match": [
            {
                "host": [
                    PLATFORM_APEX,
                    *PLATFORM_COMPATIBILITY_HOSTS,
                    PLATFORM_SECURE_HOST,
                    PLATFORM_WILDCARD,
                ]
            }
        ],
        "terminal": True,
    }


def _plain_http_tenant_route() -> dict[str, object]:
    return {
        "handle": [
            {"handler": "headers", "request": {"delete": ["Cookie"]}},
            _non_cacheable_response_headers(),
            _not_found_response(),
        ],
        "match": [{"host": [TENANT_APEX, TENANT_WILDCARD]}],
        "terminal": True,
    }


def _catch_all_unknown_route() -> dict[str, object]:
    return {
        "handle": [
            {"handler": "headers", "request": {"delete": ["Cookie"]}},
            _non_cacheable_response_headers(),
            _not_found_response(),
        ],
        "terminal": True,
    }


def _error_route() -> dict[str, object]:
    return {
        "handle": [
            _non_cacheable_response_headers(),
            {
                "body": GENERIC_NOT_FOUND_BODY,
                "handler": "static_response",
                "status_code": "{http.error.status_code}",
            },
        ]
    }


def _non_cacheable_response_headers() -> dict[str, object]:
    return {
        "handler": "headers",
        "response": {
            "deferred": True,
            "delete": ["Set-Cookie"],
            "set": {"Cache-Control": [NO_STORE_NO_TRANSFORM]},
        },
    }


def _response_headers(headers: dict[str, list[str]]) -> dict[str, object]:
    return {
        "handler": "headers",
        "response": {"set": headers},
    }


def _not_found_response() -> dict[str, object]:
    return {
        "body": GENERIC_NOT_FOUND_BODY,
        "handler": "static_response",
        "status_code": 404,
    }
