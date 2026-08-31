"""Allowlisted Caddy routes derived from trusted platform publication state."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Final

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
PLATFORM_CANONICAL_ORIGIN: Final = f"https://{PLATFORM_APEX}"
CADDY_ADMIN_SOCKET: Final = "/run/caddy/admin.sock"
GENERIC_NOT_FOUND_BODY: Final = "No Lower Duck Pond site has been provisioned for this name."
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


def build_platform_only_caddy_routes(
    *, origin_pull_ca_der: tuple[bytes, ...]
) -> PlatformOnlyCaddyRoutes:
    """Generate fixed platform routes with tenant publication unconditionally disabled."""

    trusted_ca_certs = _origin_pull_ca_certificates(origin_pull_ca_der)
    route_state = _route_state(origin_pull_ca_der)
    access_logger_name = "log0"
    certificate_subjects = sorted((PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD))
    http_app: dict[str, object] = {
        "metrics": {},
        "servers": {
            "http": {
                "listen": [":80"],
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
                            "mode": "require_and_verify",
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


def _route_state(origin_pull_ca_der: tuple[bytes, ...]) -> dict[str, object]:
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
