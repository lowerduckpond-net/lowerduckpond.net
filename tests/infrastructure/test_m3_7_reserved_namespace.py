from __future__ import annotations

from lowerduckpond_m3_qualification.reserved_namespace import (
    BLOCKED_RESERVED_PATHS,
    PROVIDER_TRACE_PATH,
    NamespaceResponse,
)

from scripts import check_m3_7_reserved_namespace as production_check


def test_production_check_uses_both_exact_apex_hostnames() -> None:
    observed: list[tuple[str, str]] = []

    def request(hostname: str, path: str) -> NamespaceResponse:
        observed.append((hostname, path))
        if path == PROVIDER_TRACE_PATH:
            return NamespaceResponse(
                status=200,
                fields={"server": "cloudflare", "content-type": "text/plain"},
                content=b"fl=test\ncolo=DFW\n",
            )
        return NamespaceResponse(status=403, fields={}, content=b"blocked")

    production_check.run(request=request)

    assert observed == [
        (hostname, path)
        for hostname in production_check.PRODUCTION_HOSTNAMES
        for path in (*BLOCKED_RESERVED_PATHS, PROVIDER_TRACE_PATH)
    ]
