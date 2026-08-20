# 0001: Use OpenTofu

- Status: accepted
- Date: 2026-08-20

## Context

DigitalOcean, Cloudflare, and durable storage must be reproducible from public
definitions without depending on console-only setup.

## Decision

Use OpenTofu for infrastructure resources and remote state. Keep tenant state
and host configuration outside OpenTofu.

## Consequences

Infrastructure changes receive plans and review. State and credentials remain
private, and ordinary tenant operations never invoke OpenTofu.

## Alternatives considered

Terraform was rejected to keep the core workflow community-governed and open
source. Provider-specific scripts were rejected because they obscure drift and
resource dependencies.
