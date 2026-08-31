from __future__ import annotations

import json
from pathlib import Path

from lowerduckpond_static_contracts import canonical_json_bytes
from lowerduckpond_static_host_agent import (
    CADDY_ROUTE_METADATA_SCHEMA,
    CLOUDFLARE_PROXY_CIDRS,
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
    PlatformOnlyCaddyRoutes,
    build_platform_only_caddy_routes,
    caddy_route_state_digest,
)

_PLATFORM_ONLY_ROUTE_COUNT = 5
_PLAIN_HTTP_ROUTE_COUNT = 3
_NOT_FOUND_STATUS = 404
_REPOSITORY_ROOT = Path(__file__).parents[3]
_ORIGIN_PULL_CA_DER = b"review-only-origin-pull-ca"


def _generated(*, origin_pull_required: bool = True) -> PlatformOnlyCaddyRoutes:
    return build_platform_only_caddy_routes(
        origin_pull_ca_der=(_ORIGIN_PULL_CA_DER,),
        origin_pull_required=origin_pull_required,
    )


def _routes() -> list[dict[str, object]]:
    generated = _generated()
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    production = servers["production"]
    assert type(production) is dict
    routes = production["routes"]
    assert type(routes) is list
    assert all(type(route) is dict for route in routes)
    return routes


def _production_server() -> dict[str, object]:
    generated = _generated()
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


def test_platform_only_generation_has_explicit_http_and_https_servers() -> None:
    generated = _generated()

    assert generated.http_app.keys() == {"metrics", "servers"}
    assert generated.http_app["metrics"] == {}
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    assert servers.keys() == {"http", "production"}
    plain_http = servers["http"]
    assert type(plain_http) is dict
    assert plain_http["listen"] == [":80"]
    assert plain_http["logs"] == {
        "logger_names": {
            subject: ["log0"]
            for subject in sorted((PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD))
        }
    }
    assert len(plain_http["routes"]) == _PLAIN_HTTP_ROUTE_COUNT
    production = servers["production"]
    assert type(production) is dict
    assert production["listen"] == [":443"]
    assert production["strict_sni_host"] is True
    routes = _routes()
    assert len(routes) == _PLATFORM_ONLY_ROUTE_COUNT
    assert all(route["terminal"] is True for route in routes)


def test_https_requires_account_origin_pull_and_trusts_only_reviewed_cloudflare_peers() -> None:
    production = _production_server()

    assert production["tls_connection_policies"] == [
        {
            "client_authentication": {
                "ca": {
                    "provider": "inline",
                    "trusted_ca_certs": ["cmV2aWV3LW9ubHktb3JpZ2luLXB1bGwtY2E="],
                },
                "mode": "require_and_verify",
            }
        }
    ]
    assert production["trusted_proxies"] == {
        "ranges": list(CLOUDFLARE_PROXY_CIDRS),
        "source": "static",
    }
    assert production["trusted_proxies_strict"] == 1
    assert production["client_ip_headers"] == ["CF-Connecting-IP"]


def test_staged_origin_pull_trust_verifies_present_certificates_without_requiring_one() -> None:
    generated = _generated(origin_pull_required=False)
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    production = servers["production"]
    assert type(production) is dict
    policies = production["tls_connection_policies"]
    assert type(policies) is list
    policy = policies[0]
    assert type(policy) is dict
    authentication = policy["client_authentication"]
    assert type(authentication) is dict
    route_state = generated.route_metadata["routeState"]
    assert type(route_state) is dict

    assert authentication["mode"] == "verify_if_given"
    assert route_state["originPullRequired"] is False


def test_proxy_networks_are_the_exact_reviewed_repository_snapshot() -> None:
    snapshot = json.loads(
        (_REPOSITORY_ROOT / "platform/cloudflare-networks.json").read_text(encoding="utf-8")
    )

    assert list(CLOUDFLARE_PROXY_CIDRS) == [
        *snapshot["cloudflare_ipv4_cidrs"],
        *snapshot["cloudflare_ipv6_cidrs"],
    ]


def test_plain_http_is_explicit_host_bounded_and_never_serves_content() -> None:
    servers = _generated().http_app["servers"]
    assert type(servers) is dict
    plain_http = servers["http"]
    assert type(plain_http) is dict
    routes = plain_http["routes"]
    assert type(routes) is list

    assert routes[0]["match"] == [
        {
            "host": [
                PLATFORM_APEX,
                *PLATFORM_COMPATIBILITY_HOSTS,
                PLATFORM_SECURE_HOST,
                PLATFORM_WILDCARD,
            ]
        }
    ]
    assert routes[1]["match"] == [{"host": [TENANT_APEX, TENANT_WILDCARD]}]
    assert "match" not in routes[2]
    assert all(route["handle"][-1]["status_code"] == _NOT_FOUND_STATUS for route in routes)
    encoded = canonical_json_bytes(plain_http)
    assert b"file_server" not in encoded
    assert b"Location" not in encoded


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
    metadata = _generated().route_metadata
    assert metadata["schema"] == CADDY_ROUTE_METADATA_SCHEMA
    state = metadata["routeState"]
    assert type(state) is dict
    assert state["generationClass"] == "platform-only"
    assert state["platformDomain"] == PLATFORM_DOMAIN
    assert state["tenantDomain"] == TENANT_DOMAIN
    assert state["publicationEnabled"] is False
    assert state["tenantRouteCount"] == 0
    assert state["originPullCaSha256"] == [
        "a1f04d9d49b6cdd9bcf7c38a90e19cce4915b57798720cb98eec228153505513"
    ]
    assert state["originPullRequired"] is True
    assert metadata["routeStateDigest"] == caddy_route_state_digest(state).to_dict()

    canonical = canonical_json_bytes(metadata)
    assert canonical_json_bytes(json.loads(canonical)) == canonical


def test_complete_configuration_exposes_only_the_allowlisted_native_apps() -> None:
    generated = _generated()
    configuration = generated.configuration

    assert configuration.keys() == {"admin", "apps", "logging"}
    assert configuration["admin"] == {"listen": "unix//run/caddy/admin.sock"}
    apps = configuration["apps"]
    assert type(apps) is dict
    assert apps.keys() == {"http", "tls"}
    assert apps["http"] == generated.http_app


def test_native_tls_policy_uses_cloudflare_dns_for_both_apexes_and_wildcards() -> None:
    apps = _generated().configuration["apps"]
    assert type(apps) is dict

    assert apps["tls"] == {
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
                    "subjects": sorted(
                        (PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD)
                    ),
                }
            ]
        }
    }


def test_native_access_logging_is_structured_and_journal_bound() -> None:
    generated = _generated()

    assert generated.configuration["logging"] == {
        "logs": {
            "default": {"exclude": ["http.log.access.log0"]},
            "log0": {
                "encoder": {"format": "json"},
                "include": ["http.log.access.log0"],
                "writer": {"output": "stdout"},
            },
        }
    }
    expected_server_logs = {
        "logger_names": {
            subject: ["log0"]
            for subject in sorted((PLATFORM_APEX, PLATFORM_WILDCARD, TENANT_APEX, TENANT_WILDCARD))
        }
    }
    assert _production_server()["logs"] == expected_server_logs
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    plain_http = servers["http"]
    assert type(plain_http) is dict
    assert plain_http["logs"] == expected_server_logs
    encoded = canonical_json_bytes(generated.configuration["logging"])
    assert b'"filename"' not in encoded
    assert b'"Cookie"' not in encoded


def test_generated_routes_contain_no_tenant_content_or_redirect_input_surface() -> None:
    encoded = canonical_json_bytes(_generated().http_app)

    assert b"/srv/lowerduckpond/sites" not in encoded
    assert b"reverse_proxy" not in encoded
    assert b"{http.request.host}" not in encoded
    assert b"{http.request.header" not in encoded
    assert encoded.count(PLATFORM_FIXTURE_ROOT.encode()) == 1
    assert encoded.count(PLATFORM_CANONICAL_ORIGIN.encode()) == 1
