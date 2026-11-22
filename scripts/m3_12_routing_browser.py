"""Keep disposable browser continuity distinct from restored-host response proof."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import sha256
from http import HTTPStatus
from uuid import uuid4

from playwright.async_api import Browser, Page

from scripts.m3_12_contracts import Document, digest, require
from scripts.m3_12_disposable_routing import (
    RESTORE_PHASES,
    PreparedRouting,
    RoutingEndpoint,
    require_prepared_cutover,
)
from scripts.m3_12_droplet_native import require_endpoint
from scripts.m3_12_droplet_observe import BROWSER_QUERY
from scripts.m3_12_droplet_ssh import ReadExecutor, observe_browser_request

CONTINUITY_SLOT = "ldp-m3-12-local-continuity"


@dataclass(frozen=True)
class Continuity:
    """A marker from the original Page/context, with no server authority."""

    page: Page
    origin: str
    routing_sha256: str
    marker: str


async def remember_browser(page: Page, source: PreparedRouting, tenant_id: str) -> Continuity:
    origin = source.policy.expected_origin(tenant_id)
    require(source.role == "source" and page.url == origin + "/", "droplet-browser-origin-changed")
    marker = uuid4().hex
    await page.evaluate(
        "([slot, marker]) => localStorage.setItem(slot, marker)", [CONTINUITY_SLOT, marker]
    )
    return Continuity(page, origin, source.policy.sha256, marker)


async def browser_continuity(
    before: Continuity, destination_host: RoutingEndpoint, tenant_id: str, *, cutover: Document
) -> Document:
    """Revisit in the original context without attributing its state to the server."""
    destination = destination_host.prepared
    require_prepared_cutover(destination_host.inputs, destination, cutover)
    require(
        destination.role == "restore"
        and destination.policy.sha256 == before.routing_sha256
        and destination.policy.expected_origin(tenant_id) == before.origin
        and before.page.url == before.origin + "/",
        "droplet-browser-origin-changed",
    )
    await before.page.goto(before.origin + "/", wait_until="domcontentloaded", timeout=0)
    require(before.page.url == before.origin + "/", "droplet-browser-origin-changed")
    marker = await before.page.evaluate("(slot) => localStorage.getItem(slot)", CONTINUITY_SLOT)
    return {"origin": before.origin, "sameBrowserContinuity": marker == before.marker}


async def fresh_restored_response(  # noqa: PLR0913 - live proof inputs are independently scoped
    browser: Browser,
    destination_host: RoutingEndpoint,
    tenant_id: str,
    *,
    cutover: Document,
    expected_body_sha256: str,
    execute: ReadExecutor,
) -> Document:
    """Require a fresh TLS visit and a separate restore-host observation of that request."""
    destination = destination_host.prepared
    inputs = destination_host.inputs
    policy = destination.policy
    require_prepared_cutover(inputs, destination, cutover)
    scope, intent = inputs.open(RESTORE_PHASES)
    enrolled = require_endpoint(destination_host.endpoint, scope, intent)["enrollment"]
    origin = policy.expected_origin(tenant_id)
    request = uuid4().hex
    url = f"{origin}/?{BROWSER_QUERY}={request}"
    context = await browser.new_context(
        service_workers="block",
        ignore_https_errors=False,
        extra_http_headers={"Cache-Control": "no-cache"},
    )
    try:
        page = await context.new_page()
        response = await page.goto(url, wait_until="domcontentloaded", timeout=0)
        require(
            response is not None
            and response.status == HTTPStatus.OK
            and response.url == page.url == url,
            "droplet-browser-restored-response-missing",
        )
        assert response is not None  # noqa: S101 - checked above
        body = sha256(await response.body()).hexdigest()
        require(body == expected_body_sha256, "droplet-browser-restored-body-changed")
        observed = await asyncio.to_thread(
            observe_browser_request,
            destination_host.endpoint,
            origin.removeprefix("https://"),
            request,
            executor=execute,
        )
        guest = observed["observation"]
        require(
            observed["origin"] == origin
            and observed["requestId"] == request
            and guest["bootSha256"] == destination.boot_sha256
            and guest["state"]
            == {
                "artifactSha256": scope["candidate"]["hostAgentSha256"],
                "launchPresent": True,
                "publication": "enabled",
            }
            and guest["hostIdentity"]
            == {
                key: enrolled[key] for key in ("machineSha256", "systemUuidSha256", "hostKeySha256")
            },
            "droplet-browser-restored-host-unproven",
        )
        return {
            "routingSha256": policy.sha256,
            "cutoverSha256": digest(cutover),
            "bodySha256": body,
            "nativeRequestSha256": digest(observed),
        }
    finally:
        await context.close()
