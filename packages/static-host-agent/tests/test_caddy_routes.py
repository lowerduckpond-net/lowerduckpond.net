from __future__ import annotations

import json

from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import (
    CADDY_ROUTE_METADATA_SCHEMA,
    GENERIC_NOT_FOUND_BODY,
    NO_STORE_NO_TRANSFORM,
    NO_TRANSFORM,
    PLATFORM_APEX,
    PLATFORM_CANONICAL_ORIGIN,
    PLATFORM_COMPATIBILITY_HOSTS,
    PLATFORM_DOMAIN,
    PLATFORM_FIXTURE_ROOT,
    PLATFORM_SECURE_HOST,
    PLATFORM_WILDCARD,
    TENANT_APEX,
    TENANT_DOMAIN,
    TENANT_WILDCARD,
    build_platform_only_caddy_routes,
    caddy_route_state_digest,
)

_PLATFORM_ONLY_ROUTE_COUNT = 5


def _routes() -> list[dict[str, object]]:
    generated = build_platform_only_caddy_routes()
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    production = servers["production"]
    assert type(production) is dict
    routes = production["routes"]
    assert type(routes) is list
    assert all(type(route) is dict for route in routes)
    return routes


def _production_server() -> dict[str, object]:
    generated = build_platform_only_caddy_routes()
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    production = servers["production"]
    assert type(production) is dict
    return production


def _route_for(host: str) -> dict[str, object]:
    matches: list[dict[str, object]] = []
    for route in _routes():
        raw_matchers = route.get("match", [])
        assert type(raw_matchers) is list
        for matcher in raw_matchers:
            assert type(matcher) is dict
            hosts = matcher.get("host", [])
            assert type(hosts) is list
            if host in hosts:
                matches.append(route)
                break
    assert len(matches) == 1
    return matches[0]


def _handlers(route: dict[str, object]) -> list[dict[str, object]]:
    handlers = route["handle"]
    assert type(handlers) is list
    assert all(type(handler) is dict for handler in handlers)
    return handlers


def test_platform_only_generation_has_one_fixed_server_and_five_terminal_routes() -> None:
    generated = build_platform_only_caddy_routes()

    assert generated.http_app.keys() == {"servers"}
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    assert servers.keys() == {"production"}
    production = servers["production"]
    assert type(production) is dict
    assert production["listen"] == [":443"]
    routes = _routes()
    assert len(routes) == _PLATFORM_ONLY_ROUTE_COUNT
    assert all(route["terminal"] is True for route in routes)


def test_platform_apex_serves_only_the_fixed_platform_fixture() -> None:
    route = _route_for(PLATFORM_APEX)
    handlers = _handlers(route)

    assert route["match"] == [{"host": [PLATFORM_APEX]}]
    assert handlers == [
        {"handler": "vars", "root": PLATFORM_FIXTURE_ROOT},
        {
            "handler": "headers",
            "response": {"set": {"Cache-Control": [NO_TRANSFORM]}},
        },
        {"handler": "file_server"},
    ]


def test_platform_compatibility_hosts_redirect_the_exact_uri_to_the_apex() -> None:
    route = _route_for(PLATFORM_COMPATIBILITY_HOSTS[0])
    handlers = _handlers(route)

    assert route["match"] == [{"host": list(PLATFORM_COMPATIBILITY_HOSTS)}]
    assert handlers[0] == {
        "handler": "headers",
        "response": {"set": {"Cache-Control": [NO_STORE_NO_TRANSFORM]}},
    }
    assert handlers[1] == {
        "handler": "static_response",
        "headers": {"Location": [f"{PLATFORM_CANONICAL_ORIGIN}{{http.request.uri}}"]},
        "status_code": 301,
    }


def test_reserved_and_unknown_platform_hosts_never_serve_tenant_bytes() -> None:
    route = _route_for(PLATFORM_SECURE_HOST)

    assert route["match"] == [{"host": [PLATFORM_SECURE_HOST, PLATFORM_WILDCARD]}]
    assert _handlers(route)[-1] == {
        "body": GENERIC_NOT_FOUND_BODY,
        "handler": "static_response",
        "status_code": 404,
    }


def test_entire_tenant_namespace_is_dark_and_scrubs_cookies() -> None:
    route = _route_for(TENANT_APEX)
    handlers = _handlers(route)

    assert route["match"] == [{"host": [TENANT_APEX, TENANT_WILDCARD]}]
    assert handlers == [
        {"handler": "headers", "request": {"delete": ["Cookie"]}},
        {
            "handler": "headers",
            "response": {
                "deferred": True,
                "delete": ["Set-Cookie"],
                "set": {"Cache-Control": [NO_STORE_NO_TRANSFORM]},
            },
        },
        {
            "body": GENERIC_NOT_FOUND_BODY,
            "handler": "static_response",
            "status_code": 404,
        },
    ]


def test_unmatched_hosts_receive_the_same_non_cacheable_cookie_scrubbed_rejection() -> None:
    route = _routes()[-1]

    assert "match" not in route
    assert _handlers(route) == [
        {"handler": "headers", "request": {"delete": ["Cookie"]}},
        {
            "handler": "headers",
            "response": {
                "deferred": True,
                "delete": ["Set-Cookie"],
                "set": {"Cache-Control": [NO_STORE_NO_TRANSFORM]},
            },
        },
        {
            "body": GENERIC_NOT_FOUND_BODY,
            "handler": "static_response",
            "status_code": 404,
        },
    ]


def test_file_server_and_other_handler_errors_are_generic_and_non_cacheable() -> None:
    errors = _production_server()["errors"]
    assert type(errors) is dict
    routes = errors["routes"]
    assert routes == [
        {
            "handle": [
                {
                    "handler": "headers",
                    "response": {
                        "deferred": True,
                        "delete": ["Set-Cookie"],
                        "set": {"Cache-Control": [NO_STORE_NO_TRANSFORM]},
                    },
                },
                {
                    "body": GENERIC_NOT_FOUND_BODY,
                    "handler": "static_response",
                    "status_code": "{http.error.status_code}",
                },
            ]
        }
    ]


def test_route_metadata_is_canonical_self_bound_and_publication_disabled() -> None:
    metadata = build_platform_only_caddy_routes().route_metadata
    assert metadata["schema"] == CADDY_ROUTE_METADATA_SCHEMA
    state = metadata["routeState"]
    assert type(state) is dict
    assert state["generationClass"] == "platform-only"
    assert state["platformDomain"] == PLATFORM_DOMAIN
    assert state["tenantDomain"] == TENANT_DOMAIN
    assert state["publicationEnabled"] is False
    assert state["tenantRouteCount"] == 0
    assert metadata["routeStateDigest"] == caddy_route_state_digest(state).to_dict()

    canonical = canonical_json_bytes(metadata)
    assert canonical_json_bytes(json.loads(canonical)) == canonical


def test_generated_routes_contain_no_tenant_content_or_redirect_input_surface() -> None:
    encoded = canonical_json_bytes(build_platform_only_caddy_routes().http_app)

    assert b"/srv/lowerduckpond/sites" not in encoded
    assert b"reverse_proxy" not in encoded
    assert b"{http.request.host}" not in encoded
    assert b"{http.request.header" not in encoded
    assert encoded.count(PLATFORM_FIXTURE_ROOT.encode()) == 1
    assert encoded.count(PLATFORM_CANONICAL_ORIGIN.encode()) == 1
