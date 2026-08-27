"""Mandatory live dual-domain browser qualification."""

from __future__ import annotations

import hashlib
import sys
import traceback
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final
from urllib.parse import urlsplit

from playwright.async_api import Browser, BrowserContext, Page, Response, async_playwright

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
LOCAL_PLATFORM_HOST: Final = "platform.ldp-platform.test"
LOCAL_TENANT_HOSTS: Final = (
    "alias.ldp-tenant.test",
    "t-0198d17f6f4a70008000000000000001.ldp-tenant.test",
    "unknown.ldp-tenant.test",
)
CANARY_VALUE: Final = "ldp-m3-canary-not-sensitive"
CANONICAL_ROOT_BODY: Final = b"lowerduckpond-m3-canonical-root"
FILTERED_ROUTE_COUNT: Final = 6


def _diagnostic_line(error: Exception) -> int:
    local_frames = [
        frame for frame in traceback.extract_tb(error.__traceback__) if frame.filename == __file__
    ]
    return (local_frames[-1].lineno or 0) if local_frames else 0


def validate_browser_endpoint(value: str) -> str:
    """Accept only the loopback Playwright server used by the qualification harness."""
    parsed = urlsplit(value)
    if (
        parsed.scheme != "ws"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Playwright endpoint must be an uncredentialed loopback WebSocket")
    return value


@dataclass(frozen=True, slots=True)
class BrowserOrigins:
    """Exact temporary origins accepted by the live qualification harness."""

    platform: str
    tenant_alias: str
    tenant_immutable: str
    tenant_unknown: str

    def __post_init__(self) -> None:
        hosts = tuple(urlsplit(origin).hostname for origin in self.all_origins)
        if hosts not in {
            (PLATFORM_HOST, *TENANT_HOSTS),
            (LOCAL_PLATFORM_HOST, *LOCAL_TENANT_HOSTS),
        }:
            raise ValueError("qualification origins are not an exact approved host set")
        for origin, expected_host in zip(self.all_origins, hosts, strict=True):
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

    @property
    def tenant_parent_domain(self) -> str:
        hostname = urlsplit(self.tenant_alias).hostname
        if hostname is None:
            raise ValueError
        return hostname.split(".", maxsplit=1)[1]

    @property
    def platform_domain(self) -> str:
        hostname = urlsplit(self.platform).hostname
        if hostname is None:
            raise ValueError
        return hostname.split(".", maxsplit=1)[1]


async def run_browser_checks(
    origins: BrowserOrigins,
    *,
    ws_endpoint: str | None = None,
    ignore_https_errors: bool = False,
) -> tuple[CheckResult, ...]:
    """Run every mandatory boundary check in all supported browser engines."""
    results: list[CheckResult] = []
    async with async_playwright() as playwright:
        for engine in BROWSER_ENGINES:
            browser_type = getattr(playwright, engine)
            try:
                browser = (
                    await browser_type.connect(ws_endpoint)
                    if ws_endpoint is not None
                    else await browser_type.launch(headless=True)
                )
            except Exception as error:
                print(f"m3.0.browser.{engine}: FAIL ({type(error).__name__})", file=sys.stderr)
                results.extend(_failed_engine_checks(engine))
                continue
            try:
                results.extend(
                    await _run_engine_checks(
                        browser,
                        engine,
                        origins,
                        ignore_https_errors=ignore_https_errors,
                    )
                )
            finally:
                await browser.close()
    return tuple(results)


async def _run_engine_checks(
    browser: Browser,
    engine: str,
    origins: BrowserOrigins,
    *,
    ignore_https_errors: bool,
) -> tuple[CheckResult, ...]:
    operations: tuple[
        tuple[
            str,
            Callable[
                [BrowserContext, Page, BrowserOrigins],
                Awaitable[dict[str, EvidenceValue]],
            ],
        ],
        ...,
    ] = (
        ("domain-boundary", _check_domain_boundary),
        ("cross-site", _check_cross_site),
        ("caddy-filter", _check_caddy_filter),
        ("sibling-parent-residual", _check_sibling_parent_residual),
    )
    results: list[CheckResult] = []
    for suffix, operation in operations:
        context = await browser.new_context(ignore_https_errors=ignore_https_errors)
        page = await context.new_page()
        try:
            evidence = await operation(context, page, origins)
        except Exception as error:  # Reports intentionally exclude browser errors and page data.
            diagnostic_line = _diagnostic_line(error)
            print(
                f"m3.0.browser.{engine}.{suffix}: FAIL "
                f"({type(error).__name__} at browser.py:{diagnostic_line})",
                file=sys.stderr,
            )
            if urlsplit(origins.platform).hostname == LOCAL_PLATFORM_HOST:
                print(f"local-browser-detail: {error}", file=sys.stderr)
            result = CheckResult(
                check_id=f"m3.0.browser.{engine}.{suffix}",
                status="failed",
                evidence={"engine": engine},
                error_code="probe_failed",
            )
        else:
            try:
                result = CheckResult(
                    check_id=f"m3.0.browser.{engine}.{suffix}",
                    status="passed",
                    evidence={"engine": engine, **evidence},
                )
            except Exception as error:
                diagnostic_line = _diagnostic_line(error)
                print(
                    f"m3.0.browser.{engine}.{suffix}: FAIL "
                    f"({type(error).__name__} at browser.py:{diagnostic_line})",
                    file=sys.stderr,
                )
                result = CheckResult(
                    check_id=f"m3.0.browser.{engine}.{suffix}",
                    status="failed",
                    evidence={"engine": engine},
                    error_code="probe_failed",
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
    if any(item["domain"].endswith(origins.platform_domain) for item in tenant_state):
        raise RuntimeError

    await page.evaluate(
        "document.cookie = "
        f"'ldp_m3_invalid=blocked; Domain={origins.platform_domain}; Path=/; Secure'"
    )
    platform_state_after = await context.cookies(origins.platform)
    if any(item["name"] == "ldp_m3_invalid" for item in platform_state_after):
        raise RuntimeError
    return {"boundary_enforced": True}


async def _check_cross_site(
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    del context
    # Prime the exact target origin before the cross-site fetch. This keeps the
    # check focused on browser site classification rather than first-contact TLS.
    await page.goto(f"{origins.tenant_immutable}/probe", wait_until="networkidle")
    await page.goto(f"{origins.platform}/fidelity", wait_until="networkidle")
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


async def _check_caddy_filter(  # noqa: PLR0912,PLR0915
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    await context.add_cookies(
        [
            {
                "name": "ldp_m3_parent",
                "value": CANARY_VALUE,
                "domain": f".{origins.tenant_parent_domain}",
                "path": "/",
                "secure": True,
            }
        ]
    )
    responses: list[Response] = []

    def record_response(response: Response) -> None:
        responses.append(response)

    page.on("response", record_response)
    canonical_root_response = await page.goto(origins.tenant_alias, wait_until="networkidle")
    if canonical_root_response is None:
        raise RuntimeError
    alias_response = next(
        (response for response in responses if response.url.rstrip("/") == origins.tenant_alias),
        None,
    )
    if alias_response is None:
        raise RuntimeError
    alias_headers = await alias_response.all_headers()
    if (
        alias_response.status != HTTPStatus.FOUND
        or alias_headers.get("location") != f"{origins.tenant_immutable}/"
        or alias_headers.get("cache-control") != "no-store, no-transform"
        or alias_headers.get("x-m3-incoming-state", "")
        or "set-cookie" in alias_headers
    ):
        raise RuntimeError
    canonical_root_headers = await canonical_root_response.all_headers()
    if (
        canonical_root_response.url.rstrip("/") != origins.tenant_immutable
        or canonical_root_response.status != HTTPStatus.OK
        or canonical_root_headers.get("cache-control") != "no-store, no-transform"
        or canonical_root_headers.get("x-m3-incoming-state", "")
        or canonical_root_headers.get("x-m3-origin-reached") != "true"
        or "set-cookie" in canonical_root_headers
        or await canonical_root_response.body() != CANONICAL_ROOT_BODY
    ):
        raise RuntimeError(
            "canonical root contract "
            f"target={canonical_root_response.url.rstrip('/') == origins.tenant_immutable} "
            f"status={canonical_root_response.status == HTTPStatus.OK} "
            f"cache={canonical_root_headers.get('cache-control') == 'no-store, no-transform'} "
            f"incoming={not canonical_root_headers.get('x-m3-incoming-state', '')} "
            f"origin={canonical_root_headers.get('x-m3-origin-reached') == 'true'} "
            f"stateless={'set-cookie' not in canonical_root_headers} "
            f"body={await canonical_root_response.body() == CANONICAL_ROOT_BODY}"
        )

    alias_non_root_response = await page.goto(
        f"{origins.tenant_alias}/static", wait_until="networkidle"
    )
    if alias_non_root_response is None:
        raise RuntimeError
    alias_non_root_headers = await alias_non_root_response.all_headers()
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
        raise RuntimeError(
            "canonical contract "
            f"status={canonical_response.status} "
            f"upstream={canonical_headers.get('x-m3-upstream-saw-state') == 'false'} "
            f"incoming={not canonical_headers.get('x-m3-incoming-state', '')} "
            f"stateless={'set-cookie' not in canonical_headers}"
        )
    stored = await context.cookies(origins.tenant_immutable)
    hostile_names = {"ldp_m3_upstream", "__Host-ldp_m3_upstream_host"}
    if any(item["name"] in hostile_names for item in stored):
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
    alias_non_root_clear_response = await page.goto(
        f"{origins.tenant_alias}/static", wait_until="networkidle"
    )
    if alias_non_root_clear_response is None:
        raise RuntimeError
    alias_non_root_clear_headers = await alias_non_root_clear_response.all_headers()
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
    return {"routes_checked": FILTERED_ROUTE_COUNT, "state_independent": True}


async def _check_sibling_parent_residual(
    context: BrowserContext, page: Page, origins: BrowserOrigins
) -> dict[str, EvidenceValue]:
    del context
    await page.goto(f"{origins.tenant_alias}/static", wait_until="networkidle")
    await page.evaluate(
        "document.cookie = "
        f"'ldp_m3_residual=observed; Domain={origins.tenant_parent_domain}; Path=/; Secure'"
    )
    await page.goto(f"{origins.tenant_unknown}/static", wait_until="networkidle")
    names = await page.evaluate(
        "document.cookie.split(';').map((part) => part.trim().split('=', 1)[0])"
    )
    if "ldp_m3_residual" not in names:
        raise RuntimeError
    return {"residual_observed": True}
