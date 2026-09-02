from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from lowerduckpond_static_contracts import manifest_digest
from lowerduckpond_static_host_agent import (
    CADDY_GENERATION_ROOT_MODE,
    CaddyBinarySource,
    CaddyGenerationPayload,
    CaddyGenerationStore,
    CaddyRouteError,
    TenantGenerationError,
    TenantRouteInput,
    TenantRouteSnapshot,
    build_platform_only_caddy_routes,
    configured_origin_pull_policy,
    derive_tenant_generation_payload,
)

_FIXTURE_ROOT = Path(__file__).parents[3] / "tests/static-publication/fixtures/accepted"
_SOURCE_GENERATION_ID = "0198d17f-6f4a-7000-8000-000000000001"
_CANDIDATE_GENERATION_ID = "0198d17f-6f4a-7000-8000-000000000002"
_ORIGIN_PULL_CA_DER = (b"review-only-origin-pull-ca",)


def _fixture(name: str) -> dict[str, object]:
    value = json.loads((_FIXTURE_ROOT / name).read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _snapshot() -> TenantRouteSnapshot:
    manifest = _fixture("site.json")
    observed = _fixture("tenant-observed-state.json")
    deployment = _fixture("deployment-record.json")
    observed["desiredManifestDigest"] = manifest_digest(manifest).to_dict()
    return TenantRouteSnapshot(
        _fixture("platform-namespace.json"),
        (TenantRouteInput(manifest, observed, deployment),),
    )


def _source_payload(tmp_path: Path) -> CaddyGenerationPayload:
    binary = tmp_path / "caddy"
    binary.write_bytes(b"verified-caddy-binary\n")
    binary.chmod(0o755)
    routes = build_platform_only_caddy_routes(
        origin_pull_ca_der=_ORIGIN_PULL_CA_DER,
        origin_pull_required=True,
    )
    return CaddyGenerationPayload(
        CaddyBinarySource(binary, os.geteuid(), os.getegid()),
        b"CLOUDFLARE_API_TOKEN=review-only-token\n",
        routes.configuration,
        routes.route_metadata,
    )


def _generation_store(tmp_path: Path) -> CaddyGenerationStore:
    root = tmp_path / "generations"
    root.mkdir(mode=CADDY_GENERATION_ROOT_MODE)
    root.chmod(CADDY_GENERATION_ROOT_MODE)
    return CaddyGenerationStore.open(
        root,
        expected_owner=os.geteuid(),
        expected_group=os.getegid(),
    )


def test_derives_complete_tenant_routes_from_pinned_source_policy(tmp_path: Path) -> None:
    with _generation_store(tmp_path) as store:
        store.publish(_SOURCE_GENERATION_ID, _source_payload(tmp_path))
        with store.open_verified(_SOURCE_GENERATION_ID) as source:
            payload = derive_tenant_generation_payload(
                source,
                _snapshot(),
                candidate_generation_id=_CANDIDATE_GENERATION_ID,
            )
            assert payload.source is source

    route_state = payload.route_metadata["routeState"]
    assert type(route_state) is dict
    assert route_state["generationClass"] == "tenant-capable"
    assert route_state["runtimeGenerationId"] == _CANDIDATE_GENERATION_ID
    assert len(route_state["tenantStates"]) == 1
    assert configured_origin_pull_policy(dict(payload.configuration)) == (
        _ORIGIN_PULL_CA_DER,
        True,
    )


def test_source_and_candidate_generation_ids_must_be_distinct(tmp_path: Path) -> None:
    with _generation_store(tmp_path) as store:
        store.publish(_SOURCE_GENERATION_ID, _source_payload(tmp_path))
        with (
            store.open_verified(_SOURCE_GENERATION_ID) as source,
            pytest.raises(TenantGenerationError, match="must differ"),
        ):
            derive_tenant_generation_payload(
                source,
                _snapshot(),
                candidate_generation_id=_SOURCE_GENERATION_ID,
            )


def test_source_origin_pull_policy_must_be_exactly_generated(tmp_path: Path) -> None:
    payload = _source_payload(tmp_path)
    configuration = dict(payload.configuration)
    apps = configuration["apps"]
    assert type(apps) is dict
    http = apps["http"]
    assert type(http) is dict
    servers = http["servers"]
    assert type(servers) is dict
    production = servers["production"]
    assert type(production) is dict
    policies = production["tls_connection_policies"]
    assert type(policies) is list
    policy = policies[0]
    assert type(policy) is dict
    authentication = policy["client_authentication"]
    assert type(authentication) is dict
    pool = authentication["ca"]
    assert type(pool) is dict
    pool["unreviewed"] = True

    with pytest.raises(CaddyRouteError, match="origin-pull trust"):
        configured_origin_pull_policy(configuration)


def test_rejects_closed_source_and_non_snapshot_inputs(tmp_path: Path) -> None:
    with _generation_store(tmp_path) as store:
        store.publish(_SOURCE_GENERATION_ID, _source_payload(tmp_path))
        source = store.open_verified(_SOURCE_GENERATION_ID)
        source.close()
        with pytest.raises(ValueError, match="closed"):
            derive_tenant_generation_payload(
                source,
                _snapshot(),
                candidate_generation_id=_CANDIDATE_GENERATION_ID,
            )
        with pytest.raises(TypeError, match="complete route snapshot"):
            derive_tenant_generation_payload(
                source,
                object(),  # type: ignore[arg-type]
                candidate_generation_id=_CANDIDATE_GENERATION_ID,
            )
