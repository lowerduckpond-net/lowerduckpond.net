from __future__ import annotations

import pytest
from lowerduckpond_m3_qualification.browser import BrowserOrigins, validate_browser_endpoint

ORIGIN_COUNT = 4


def valid_origins() -> BrowserOrigins:
    return BrowserOrigins(
        platform="https://m3-qualification.lowerduckpond.net",
        tenant_alias="https://m3-a.lowerduckpond.com",
        tenant_immutable=("https://t-0198d17f6f4a70008000000000000001.lowerduckpond.com"),
        tenant_unknown="https://m3-unknown.lowerduckpond.com",
    )


def test_live_browser_origins_are_exact_and_https() -> None:
    assert len(valid_origins().all_origins) == ORIGIN_COUNT


def test_local_browser_origins_are_an_exact_separate_site_pair() -> None:
    origins = BrowserOrigins(
        platform="https://platform.ldp-platform.test",
        tenant_alias="https://alias.ldp-tenant.test",
        tenant_immutable=("https://t-0198d17f6f4a70008000000000000001.ldp-tenant.test"),
        tenant_unknown="https://unknown.ldp-tenant.test",
    )

    assert origins.platform_domain == "ldp-platform.test"
    assert origins.tenant_parent_domain == "ldp-tenant.test"


@pytest.mark.parametrize(
    "endpoint",
    (
        "ws://docker:3000/",
        "wss://127.0.0.1:3000/",
        "ws://user@127.0.0.1:3000/",
        "ws://127.0.0.1:3000/?token=unsafe",
    ),
)
def test_browser_endpoint_rejects_non_loopback_or_credentialed_values(endpoint: str) -> None:
    with pytest.raises(ValueError):
        validate_browser_endpoint(endpoint)


def test_browser_endpoint_accepts_the_loopback_server() -> None:
    assert validate_browser_endpoint("ws://127.0.0.1:3000/") == "ws://127.0.0.1:3000/"


@pytest.mark.parametrize(
    "platform",
    [
        "http://m3-qualification.lowerduckpond.net",
        "https://m3-qualification.lowerduckpond.net:8443",
        "https://different.lowerduckpond.net",
        "https://m3-qualification.lowerduckpond.net/path",
        "https://user@m3-qualification.lowerduckpond.net",
    ],
)
def test_live_browser_origins_reject_nonapproved_platform_values(platform: str) -> None:
    origins = valid_origins()
    with pytest.raises(ValueError):
        BrowserOrigins(
            platform=platform,
            tenant_alias=origins.tenant_alias,
            tenant_immutable=origins.tenant_immutable,
            tenant_unknown=origins.tenant_unknown,
        )


def test_scoped_browser_origins_accept_only_exact_disposable_subjects() -> None:
    origins = (
        "https://source.platform.example",
        "https://tenant.source.tenants.example",
        "https://immutable.source.tenants.example",
        "https://unknown.source.tenants.example",
    )
    scopes = ("source.platform.example", "source.tenants.example")
    prepared = BrowserOrigins(*origins, approved_scopes=scopes)
    assert prepared.platform_domain == scopes[0]
    assert prepared.tenant_parent_domain == scopes[1]
    with pytest.raises(ValueError, match="exact approved host set"):
        BrowserOrigins(*origins)
    with pytest.raises(ValueError, match="outside the approved disposable scopes"):
        BrowserOrigins(
            origins[0],
            "https://tenant.source.tenants.example.foreign.test",
            origins[2],
            origins[3],
            approved_scopes=scopes,
        )
