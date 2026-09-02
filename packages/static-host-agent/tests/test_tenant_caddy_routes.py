from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import canonical_json_bytes, manifest_digest
from lowerduckpond_static_host_agent import (
    ALIAS_REDIRECT_BODY,
    GENERIC_NOT_FOUND_BODY,
    NO_STORE_NO_TRANSFORM,
    NO_TRANSFORM,
    TENANT_DOMAIN,
    TENANT_RELEASE_ROOT,
    CaddyRouteError,
    TenantCaddyRoutes,
    TenantRouteInput,
    build_tenant_caddy_routes,
    caddy_route_state_digest,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_ACTIVE_TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2100"
_UNDEPLOYED_TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2101"
_SUSPENDED_TENANT = "0191e2c4-8f7a-7c3b-8d1e-5f62047a2102"
_ACTIVE_DEPLOYMENT = "0191e2ca-49f2-7608-8cf3-f80ab2cab151"
_SUSPENDED_DEPLOYMENT = "0191e2ca-49f2-7608-8cf3-f80ab2cab152"
_GENERATION = "0198d17f-6f4a-7000-8000-000000000004"
_CA_DER = b"review-only-origin-pull-ca"
_TENANT_COUNT = 3
_ACTIVE_ROUTE_COUNT = 2


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _origin(tenant_id: str) -> str:
    return f"t-{tenant_id.replace('-', '')}.{TENANT_DOMAIN}"


def _route_input(
    *,
    tenant_id: str,
    slug: str,
    state: str,
    deployment_id: str | None,
) -> TenantRouteInput:
    manifest = _fixture("site.json")
    metadata = manifest["metadata"]
    spec = manifest["spec"]
    assert type(metadata) is dict
    assert type(spec) is dict
    metadata.update({"id": tenant_id, "slug": slug, "canonicalOrigin": _origin(tenant_id)})
    spec["desiredState"] = state

    deployment: dict[str, object] | None = None
    if deployment_id is None:
        spec.pop("desiredDeployment", None)
    else:
        deployment = _fixture("deployment-record.json")
        deployment["id"] = deployment_id
        deployment["tenantId"] = tenant_id
        spec["desiredDeployment"] = {
            "id": deployment_id,
            "archiveSha256": deployment["archiveSha256"],
        }

    observed: dict[str, object] = {
        "apiVersion": "hosting.lowerduckpond.net/v1alpha1",
        "kind": "TenantObservedState",
        "tenantId": tenant_id,
        "desiredManifestDigest": manifest_digest(manifest).to_dict(),
        "observedState": state,
        "activeDeploymentId": deployment_id,
        "runtimeGenerationId": _GENERATION if state == "active" else None,
        "reconciledAt": "2026-09-02T13:00:00Z",
    }
    return TenantRouteInput(manifest, observed, deployment)


def _inputs() -> tuple[TenantRouteInput, ...]:
    return (
        _route_input(
            tenant_id=_ACTIVE_TENANT,
            slug="active-duck",
            state="active",
            deployment_id=_ACTIVE_DEPLOYMENT,
        ),
        _route_input(
            tenant_id=_UNDEPLOYED_TENANT,
            slug="waiting-duck",
            state="undeployed",
            deployment_id=None,
        ),
        _route_input(
            tenant_id=_SUSPENDED_TENANT,
            slug="sleeping-duck",
            state="suspended",
            deployment_id=_SUSPENDED_DEPLOYMENT,
        ),
    )


def _generated(*, tenants: tuple[TenantRouteInput, ...] | None = None) -> TenantCaddyRoutes:
    return build_tenant_caddy_routes(
        platform_namespace=_fixture("platform-namespace.json"),
        tenants=_inputs() if tenants is None else tenants,
        runtime_generation_id=_GENERATION,
        origin_pull_ca_der=(_CA_DER,),
        origin_pull_required=True,
    )


def _server(generated: TenantCaddyRoutes, name: str) -> dict[str, object]:
    servers = generated.http_app["servers"]
    assert type(servers) is dict
    server = servers[name]
    assert type(server) is dict
    return server


def _route_for(
    generated: TenantCaddyRoutes,
    *,
    server: str,
    host: str,
) -> dict[str, object]:
    routes = _server(generated, server)["routes"]
    assert type(routes) is list
    matches = [
        route
        for route in routes
        if type(route) is dict
        and any(
            host in matcher.get("host", [])
            for matcher in route.get("match", [])
            if type(matcher) is dict
        )
    ]
    assert len(matches) == 1
    assert type(matches[0]) is dict
    return matches[0]


def test_active_tenant_has_one_exact_immutable_content_route() -> None:
    generated = _generated()
    route = _route_for(generated, server="production", host=_origin(_ACTIVE_TENANT))
    expected_root = f"{TENANT_RELEASE_ROOT}/{_ACTIVE_TENANT}/releases/{_ACTIVE_DEPLOYMENT}"

    assert route["match"] == [{"host": [_origin(_ACTIVE_TENANT)]}]
    assert route["terminal"] is True
    assert route["handle"] == [
        {"handler": "headers", "request": {"delete": ["Cookie"]}},
        {"handler": "vars", "root": expected_root},
        {
            "handler": "headers",
            "response": {
                "deferred": True,
                "delete": ["Set-Cookie"],
                "set": {"Cache-Control": [NO_TRANSFORM]},
            },
        },
        {"handler": "file_server"},
    ]
    plain_http = canonical_json_bytes(_server(generated, "http"))
    assert expected_root.encode() not in plain_http
    assert b'"handler":"file_server"' not in plain_http


def test_alias_redirect_is_exact_fixed_and_identical_on_both_listeners() -> None:
    generated = _generated()
    host = f"active-duck.{TENANT_DOMAIN}"
    plain = _route_for(generated, server="http", host=host)
    secure = _route_for(generated, server="production", host=host)

    assert plain == secure
    assert plain["match"] == [
        {
            "host": [host],
            "method": ["GET", "HEAD"],
            "path": ["/"],
            "query": {},
        }
    ]
    assert plain["handle"] == [
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
            "headers": {"Location": [f"https://{_origin(_ACTIVE_TENANT)}/"]},
            "status_code": 302,
        },
    ]
    encoded = canonical_json_bytes(plain)
    assert b"{http.request" not in encoded


def test_inactive_tenants_have_no_route_and_share_the_generic_rejection() -> None:
    generated = _generated()
    encoded = canonical_json_bytes(generated.http_app)

    for tenant_id, slug in (
        (_UNDEPLOYED_TENANT, "waiting-duck"),
        (_SUSPENDED_TENANT, "sleeping-duck"),
    ):
        assert _origin(tenant_id).encode() not in encoded
        assert f"{slug}.{TENANT_DOMAIN}".encode() not in encoded
    for server in ("http", "production"):
        routes = _server(generated, server)["routes"]
        assert type(routes) is list
        tenant_fallback = next(
            route
            for route in routes
            if type(route) is dict
            and route.get("match") == [{"host": [TENANT_DOMAIN, f"*.{TENANT_DOMAIN}"]}]
        )
        handlers = tenant_fallback["handle"]
        assert type(handlers) is list
        assert handlers[-1] == {
            "body": GENERIC_NOT_FOUND_BODY,
            "handler": "static_response",
            "status_code": 404,
        }


def test_route_metadata_binds_all_authoritative_state_and_is_deterministic() -> None:
    inputs = _inputs()
    before = deepcopy(inputs)
    generated = _generated(tenants=inputs)
    reversed_generation = _generated(tenants=tuple(reversed(inputs)))
    state = generated.route_metadata["routeState"]
    assert type(state) is dict

    assert inputs == before
    assert generated.configuration == reversed_generation.configuration
    assert generated.route_metadata == reversed_generation.route_metadata
    assert state["generationClass"] == "tenant-capable"
    assert state["publicationEnabled"] is True
    assert state["tenantRouteCount"] == _ACTIVE_ROUTE_COUNT
    assert state["runtimeGenerationId"] == _GENERATION
    assert state["platformNamespace"] == _fixture("platform-namespace.json")
    tenant_states = state["tenantStates"]
    assert type(tenant_states) is list
    assert len(tenant_states) == _TENANT_COUNT
    assert [item["routeSet"] for item in tenant_states] == ["present", "absent", "absent"]
    assert generated.route_metadata["routeStateDigest"] == caddy_route_state_digest(state).to_dict()


def test_alias_and_unknown_com_logs_drop_raw_uri_and_all_headers() -> None:
    generated = _generated()
    logging = generated.configuration["logging"]
    assert type(logging) is dict
    logs = logging["logs"]
    assert type(logs) is dict
    alias_log = logs["alias"]
    assert type(alias_log) is dict
    assert alias_log["encoder"] == {
        "fields": {
            "request>headers": {"filter": "delete"},
            "request>uri": {"filter": "delete"},
        },
        "format": "filter",
        "wrap": {"format": "json"},
    }
    for server in ("http", "production"):
        server_logs = _server(generated, server)["logs"]
        assert type(server_logs) is dict
        names = server_logs["logger_names"]
        assert type(names) is dict
        assert names[f"*.{TENANT_DOMAIN}"] == ["alias"]
        assert names[f"active-duck.{TENANT_DOMAIN}"] == ["alias"]
        assert names[_origin(_ACTIVE_TENANT)] == ["log0"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("digest", "desired manifest"),
        ("deployment", "bound across"),
    ],
)
def test_route_derivation_rejects_cross_record_binding_drift(
    mutation: str,
    message: str,
) -> None:
    active = _inputs()[0]
    if mutation == "digest":
        digest = active.observed_state["desiredManifestDigest"]
        assert type(digest) is dict
        digest["value"] = "f" * 64
    else:
        assert active.deployment is not None
        active.deployment["tenantId"] = _UNDEPLOYED_TENANT

    with pytest.raises(CaddyRouteError, match=message):
        _generated(tenants=(active,))


def test_new_generation_accepts_an_active_tenant_retained_from_an_earlier_commit() -> None:
    active = _inputs()[0]
    earlier_generation = "0198d17f-6f4a-7000-8000-000000000005"
    active.observed_state["runtimeGenerationId"] = earlier_generation

    generated = _generated(tenants=(active,))
    state = generated.route_metadata["routeState"]
    assert type(state) is dict
    tenant_states = state["tenantStates"]
    assert type(tenant_states) is list
    assert tenant_states[0]["observedState"]["runtimeGenerationId"] == earlier_generation
    assert state["runtimeGenerationId"] == _GENERATION


def test_route_derivation_rejects_duplicate_live_or_reserved_slugs() -> None:
    active, undeployed, _suspended = _inputs()
    metadata = undeployed.manifest["metadata"]
    assert type(metadata) is dict
    metadata["slug"] = "active-duck"
    undeployed.observed_state["desiredManifestDigest"] = manifest_digest(
        undeployed.manifest
    ).to_dict()

    with pytest.raises(CaddyRouteError, match="duplicate slug"):
        _generated(tenants=(active, undeployed))


def test_archived_state_is_rejected_until_its_archive_binding_lands() -> None:
    archived = _route_input(
        tenant_id=_ACTIVE_TENANT,
        slug="archived-duck",
        state="suspended",
        deployment_id=_ACTIVE_DEPLOYMENT,
    )
    spec = archived.manifest["spec"]
    assert type(spec) is dict
    spec["desiredState"] = "archived"
    archived.observed_state.update(
        {
            "desiredManifestDigest": manifest_digest(archived.manifest).to_dict(),
            "observedState": "archived",
            "activeDeploymentId": None,
        }
    )

    with pytest.raises(CaddyRouteError, match=r"deferred until M3\.10"):
        _generated(tenants=(archived,))
