"""Mandatory live dual-domain browser qualification."""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final
from urllib.parse import urlsplit

from playwright.async_api import Browser, BrowserContext, Page, async_playwright

from lowerduckpond_m3_qualification.report import CheckResult, EvidenceValue

BROWSER_ENGINES: Final = ("chromium", "firefox", "webkit")
BROWSER_CHECK_SUFFIXES: Final = (
    "domain-boundary",
    "cross-site",
    "caddy-filter",
    "sibling-parent-residual",
)
PLATFORM_HOST: Final = "m3-qualification.lowerduckpond.net"
TENANT_HOSTS: Final = (
    "m3-a.lowerduckpond.com",
    "t-0198d17f6f4a70008000000000000001.lowerduckpond.com",
    "m3-unknown.lowerduckpond.com",
)
CANONICAL_ORIGIN: Final = "https://t-0198d17f6f4a70008000000000000001.lowerduckpond.com"
PARENT_TENANT_DOMAIN: Final = "lowerduckpond.com"
PLATFORM_DOMAIN: Final = "lowerduckpond.net"
CANARY_VALUE: Final = "ldp-m3-canary-not-sensitive"
FILTERED_ROUTE_COUNT: Final = 5


@dataclass(frozen=True, slots=True)
class BrowserOrigins:
    """Exact temporary origins accepted by the live qualification harness."""

    platform: str
    tenant_alias: str
    tenant_immutable: str
    tenant_unknown: str

    def __post_init__(self) -> None:
        expected_hosts = (PLATFORM_HOST, *TENANT_HOSTS)
        for origin, expected_host in zip(self.all_origins, expected_hosts, strict=True):
            parsed = urlsplit(origin)
            if (
                parsed.scheme != "https"
                or parsed.hostname != expected_host
                or parsed.port is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("qualification origin is not the exact approved HTTPS host")

    @property
    def tenant_origins(self) -> tuple[str, str, str]:
        return (self.tenant_alias, self.tenant_immutable, self.tenant_unknown)

    @property
    def all_origins(self) -> tuple[str, str, str, str]:
        return (self.platform, *self.tenant_origins)


async def run_browser_checks(origins: BrowserOrigins) -> tuple[CheckResult, ...]:
    """Run every mandatory boundary check in all supported browser engines."""
    results: list[CheckResult] = []
    async with async_playwright() as playwright:
        for engine in BROWSER_ENGINES:
            browser_type = getattr(playwright, engine)
            try:
                browser = await browser_type.launch(headless=True)
            except Exception:
                results.extend(_failed_engine_checks(engine))
                continue
            try:
                results.extend(await _run_engine_checks(browser, engine, origins))
            finally:
                await browser.close()
    return tuple(results)


async def _run_engine_checks(
    browser: Browser,
    engine: str,
    origins: BrowserOrigins,
) -> tuple[CheckResult, ...]:
    operations: tuple[
        tuple[str, Callable[[BrowserContext, Page], Awaitable[dict[str, EvidenceValue]]]], ...
    ] = (
        ("domain-boundary", lambda context, page: _check_domain_boundary(context, page, origins)),
        ("cross-site", lambda context, page: _check_cross_site(context, page, origins)),
        ("caddy-filter", lambda context, page: _check_caddy_filter(context, page, origins)),
        (
            "sibling-parent-residual",
            lambda context, page: _check_sibling_parent_residual(context, page, origins),
        ),
    )
    results: list[CheckResult] = []
    for suffix, operation in operations:
        context = await browser.new_context()
        page = await context.new_page()
        try:
            evidence = await operation(context, page)
        except Exception:  # Reports intentionally exclude browser errors and page data.
            result = CheckResult(
                check_id=f"m3.0.browser.{engine}.{suffix}",
                status="failed",
                evidence={"engine": engine},
                error_code="probe_failed",
            )
        else:
            result = CheckResult(
                check_id=f"m3.0.browser.{engine}.{suffix}",
                status="passed",
                evidence={"engine": engine, **evidence},
            )
        finally:
            await context.close()
        results.append(result)
    return tuple(results)


def _failed_engine_checks(engine: str) -> tuple[CheckResult, ...]:
    return tuple(
        CheckResult(
            check_id=f"m3.0.browser.{engine}.{suffix}",
            status="failed",
            evidence={"engine": engine},
            error_code="probe_failed",
        )
        for suffix in BROWSER_CHECK_SUFFIXES
    )


async def _check_domain_boundary(
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    await page.goto(f"{origins.platform}/set-platform-state", wait_until="networkidle")
    platform_state = await context.cookies(origins.platform)
    if not any(item["name"] == "__Host-ldp_m3_platform" for item in platform_state):
        raise RuntimeError

    await page.goto(f"{origins.tenant_alias}/static", wait_until="networkidle")
    tenant_state = await context.cookies(origins.tenant_alias)
    if any(item["domain"].endswith(PLATFORM_DOMAIN) for item in tenant_state):
        raise RuntimeError

    await page.evaluate(
        "document.cookie = 'ldp_m3_invalid=blocked; Domain=lowerduckpond.net; Path=/; Secure'"
    )
    platform_state_after = await context.cookies(origins.platform)
    if any(item["name"] == "ldp_m3_invalid" for item in platform_state_after):
        raise RuntimeError
    return {"boundary_enforced": True}


async def _check_cross_site(
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    del context
    await page.goto(origins.platform, wait_until="networkidle")
    observed = await page.evaluate(
        """async (origin) => {
            const response = await fetch(`${origin}/probe`, {credentials: 'include'});
            return response.headers.get('x-m3-sec-fetch-site');
        }""",
        origins.tenant_immutable,
    )
    if observed != "cross-site":
        raise RuntimeError
    return {"cross_site_observed": True}


async def _check_caddy_filter(
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    await context.add_cookies(
        [
            {
                "name": "ldp_m3_parent",
                "value": CANARY_VALUE,
                "domain": f".{PARENT_TENANT_DOMAIN}",
                "path": "/",
                "secure": True,
            }
        ]
    )
    alias_response = await context.request.get(origins.tenant_alias, max_redirects=0)
    alias_headers = alias_response.headers
    if (
        alias_response.status != HTTPStatus.FOUND
        or alias_headers.get("location") != f"{CANONICAL_ORIGIN}/"
        or alias_headers.get("cache-control") != "no-store, no-transform"
        or alias_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in alias_headers
    ):
        raise RuntimeError

    alias_non_root_response = await context.request.get(
        f"{origins.tenant_alias}/static", max_redirects=0
    )
    alias_non_root_headers = alias_non_root_response.headers
    alias_non_root_body = await alias_non_root_response.body()
    if (
        alias_non_root_response.status != HTTPStatus.NOT_FOUND
        or alias_non_root_headers.get("cache-control") != "no-store, no-transform"
        or alias_non_root_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in alias_non_root_headers
    ):
        raise RuntimeError

    canonical_response = await page.goto(
        f"{origins.tenant_immutable}/probe", wait_until="networkidle"
    )
    if canonical_response is None:
        raise RuntimeError
    canonical_headers = await canonical_response.all_headers()
    canonical_body = await canonical_response.body()
    if (
        canonical_response.status != HTTPStatus.OK
        or canonical_headers.get("x-m3-upstream-saw-state") != "false"
        or canonical_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in canonical_headers
    ):
        raise RuntimeError
    stored = await context.cookies(origins.tenant_immutable)
    if any(item["name"] in {"ldp_m3_route", "ldp_m3_upstream"} for item in stored):
        raise RuntimeError

    static_response = await page.goto(
        f"{origins.tenant_immutable}/static", wait_until="networkidle"
    )
    if static_response is None:
        raise RuntimeError
    static_headers = await static_response.all_headers()
    if (
        static_response.status != HTTPStatus.OK
        or static_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in static_headers
    ):
        raise RuntimeError

    unknown_response = await page.goto(origins.tenant_unknown, wait_until="networkidle")
    if unknown_response is None:
        raise RuntimeError
    unknown_headers = await unknown_response.all_headers()
    if (
        unknown_response.status != HTTPStatus.NOT_FOUND
        or unknown_headers.get("cache-control") != "no-store, no-transform"
        or unknown_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in unknown_headers
    ):
        raise RuntimeError

    await context.clear_cookies()
    alias_non_root_clear_response = await context.request.get(
        f"{origins.tenant_alias}/static", max_redirects=0
    )
    alias_non_root_clear_headers = alias_non_root_clear_response.headers
    if (
        alias_non_root_clear_response.status != HTTPStatus.NOT_FOUND
        or alias_non_root_clear_headers.get("cache-control") != "no-store, no-transform"
        or alias_non_root_clear_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in alias_non_root_clear_headers
        or hashlib.sha256(await alias_non_root_clear_response.body()).digest()
        != hashlib.sha256(alias_non_root_body).digest()
    ):
        raise RuntimeError

    state_free_response = await page.goto(
        f"{origins.tenant_immutable}/probe", wait_until="networkidle"
    )
    if (
        state_free_response is None
        or hashlib.sha256(await state_free_response.body()).digest()
        != hashlib.sha256(canonical_body).digest()
    ):
        raise RuntimeError
    return {"independent_body": True, "routes_checked": FILTERED_ROUTE_COUNT}


async def _check_sibling_parent_residual(
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    del context
    await page.goto(f"{origins.tenant_alias}/static", wait_until="networkidle")
    await page.evaluate(
        "document.cookie = 'ldp_m3_residual=observed; Domain=lowerduckpond.com; Path=/; Secure'"
    )
    await page.goto(f"{origins.tenant_unknown}/static", wait_until="networkidle")
    names = await page.evaluate(
        "document.cookie.split(';').map((part) => part.trim().split('=', 1)[0])"
    )
    if "ldp_m3_residual" not in names:
        raise RuntimeError
    return {"residual_observed": True}
