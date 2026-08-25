# 0003: Use Caddy and Cloudflare DNS-01

- Status: superseded by [ADR 0028](0028-use-cloudflare-as-the-public-web-edge.md)
- Date: 2026-08-20

## Context

The service needs apex, wildcard, and independent-tenant HTTPS with safe,
generated routing.

## Decision

Use Caddy as the only public edge. Build and pin Caddy with the Cloudflare DNS
module, and use a narrowly scoped token for ACME DNS-01 validation.

## Consequences

Caddy configuration must be generated, validated, atomically installed, and
reloaded. The custom build and plugin are supply-chain inputs that require
explicit versioning.

ADR 0028 retains Caddy and DNS-01 for the origin certificate but replaces the
direct public-edge decision with Cloudflare proxying and an authenticated Caddy
origin.

## Alternatives considered

Manually managed certificates and per-tenant HTTP validation were rejected for
the wildcard namespace. A separate proxy and certificate daemon would add more
moving parts without a pilot benefit.
