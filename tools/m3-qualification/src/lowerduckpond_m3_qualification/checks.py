"""The exact, no-skip M3.0 qualification gate."""

from __future__ import annotations

from typing import Final

LIBRARY_CHECK_IDS: Final = frozenset(
    {
        "m3.0.python.botocore",
        "m3.0.python.hypothesis",
        "m3.0.python.jsonschema",
        "m3.0.python.playwright",
        "m3.0.python.rfc8785",
        "m3.0.python.runtime",
        "m3.0.python.safe-yaml",
    }
)
FILESYSTEM_CHECK_IDS: Final = frozenset(
    {
        "m3.0.filesystem.atomic-rename",
        "m3.0.filesystem.directory-fsync",
        "m3.0.filesystem.flock",
        "m3.0.filesystem.hardlink",
        "m3.0.filesystem.no-follow",
        "m3.0.filesystem.type",
    }
)
HOST_CHECK_IDS: Final = frozenset(
    {
        "m3.0.host.caddy-admin",
        "m3.0.host.caddy-descriptor",
        "m3.0.host.caddy-hooks",
        "m3.0.host.caddy-log-safety",
        "m3.0.host.caddy-routes",
        "m3.0.host.sudo-uuid",
        "m3.0.host.systemd-recovery",
        "m3.0.host.tmpfs-limits",
        "m3.0.host.ubuntu",
    }
)
DOMAIN_CHECK_IDS: Final = frozenset(
    {"m3.0.domain.lowerduckpond-com", "m3.0.domain.lowerduckpond-net"}
)
BROWSER_CHECK_IDS: Final = frozenset(
    f"m3.0.browser.{engine}.{suffix}"
    for engine in ("chromium", "firefox", "webkit")
    for suffix in ("caddy-filter", "cross-site", "domain-boundary", "sibling-parent-residual")
)
M3_REQUIRED_CHECK_IDS: Final = frozenset().union(
    LIBRARY_CHECK_IDS,
    FILESYSTEM_CHECK_IDS,
    HOST_CHECK_IDS,
    DOMAIN_CHECK_IDS,
    BROWSER_CHECK_IDS,
)

EVIDENCE_KEYS_BY_CHECK: Final = {
    "m3.0.python.runtime": frozenset({"version"}),
    "m3.0.python.jsonschema": frozenset({"draft", "version"}),
    "m3.0.python.rfc8785": frozenset({"version"}),
    "m3.0.python.hypothesis": frozenset({"examples", "version"}),
    "m3.0.python.botocore": frozenset({"operations", "version"}),
    "m3.0.python.safe-yaml": frozenset({"mode", "version"}),
    "m3.0.python.playwright": frozenset({"engines", "version"}),
    "m3.0.filesystem.type": frozenset({"filesystem"}),
    "m3.0.filesystem.directory-fsync": frozenset({"directory_synced", "file_synced"}),
    "m3.0.filesystem.atomic-rename": frozenset({"same_filesystem"}),
    "m3.0.filesystem.hardlink": frozenset({"initial_links", "remaining_links"}),
    "m3.0.filesystem.no-follow": frozenset({"symlink_rejected"}),
    "m3.0.filesystem.flock": frozenset({"exclusive_blocks_shared", "shared_blocks_exclusive"}),
    "m3.0.host.ubuntu": frozenset({"distribution", "release"}),
    "m3.0.host.sudo-uuid": frozenset({"accepted", "rejected"}),
    "m3.0.host.tmpfs-limits": frozenset({"inodes", "private", "size_mib"}),
    "m3.0.host.caddy-descriptor": frozenset({"generation_pinned"}),
    "m3.0.host.caddy-admin": frozenset({"access_limited", "tcp_disabled", "unix_socket"}),
    "m3.0.host.caddy-hooks": frozenset({"bounded_attempts", "invocation_hooks", "reload_pinned"}),
    "m3.0.host.caddy-routes": frozenset({"independent_body", "route_classes"}),
    "m3.0.host.caddy-log-safety": frozenset({"structured", "values_omitted"}),
    "m3.0.host.systemd-recovery": frozenset({"handoff_ms", "nonblocking", "reset_recovered"}),
    "m3.0.domain.lowerduckpond-net": frozenset(
        {"auto_renew", "cloudflare_active", "controlled", "nameservers"}
    ),
    "m3.0.domain.lowerduckpond-com": frozenset(
        {"auto_renew", "cloudflare_active", "controlled", "nameservers"}
    ),
    **{
        f"m3.0.browser.{engine}.domain-boundary": frozenset({"boundary_enforced", "engine"})
        for engine in ("chromium", "firefox", "webkit")
    },
    **{
        f"m3.0.browser.{engine}.cross-site": frozenset({"cross_site_observed", "engine"})
        for engine in ("chromium", "firefox", "webkit")
    },
    **{
        f"m3.0.browser.{engine}.caddy-filter": frozenset(
            {"engine", "independent_body", "routes_checked"}
        )
        for engine in ("chromium", "firefox", "webkit")
    },
    **{
        f"m3.0.browser.{engine}.sibling-parent-residual": frozenset({"engine", "residual_observed"})
        for engine in ("chromium", "firefox", "webkit")
    },
}
