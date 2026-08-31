"""Allowlisted Caddy routes derived from trusted platform publication state."""

from __future__ import annotations

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


@dataclass(frozen=True, slots=True)
class PlatformOnlyCaddyRoutes:
    """The complete production-dark Caddy config and its semantic route state."""

    configuration: dict[str, object]
    http_app: dict[str, object]
    route_metadata: dict[str, object]


def build_platform_only_caddy_routes() -> PlatformOnlyCaddyRoutes:
    """Generate fixed platform routes with tenant publication unconditionally disabled."""

    route_state = _route_state()
    http_app: dict[str, object] = {
        "servers": {
            "production": {
                "listen": [":443"],
                "routes": [
                    _compatibility_redirect_route(),
                    _platform_apex_route(),
                    _platform_unknown_route(),
                    _tenant_namespace_dark_route(),
                    _catch_all_unknown_route(),
                ],
                "errors": {"routes": [_error_route()]},
            }
        }
    }
    return PlatformOnlyCaddyRoutes(
        configuration={
            "admin": {"listen": f"unix/{CADDY_ADMIN_SOCKET}"},
            "apps": {"http": http_app},
        },
        http_app=http_app,
        route_metadata={
            "routeState": route_state,
            "routeStateDigest": caddy_route_state_digest(route_state).to_dict(),
            "schema": CADDY_ROUTE_METADATA_SCHEMA,
        },
    )


def _route_state() -> dict[str, object]:
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
    }


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
