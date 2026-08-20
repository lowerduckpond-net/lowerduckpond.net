# 0005: Isolate dynamic workloads with rootless Podman

- Status: accepted
- Date: 2026-08-20

## Context

Approved PHP sites execute tenant-supplied code on a shared host and need
independent identities, limits, mounts, networking, and lifecycle control.

## Decision

Run each dynamic tenant in a rootless Podman container under a dedicated
non-login account. Describe systemd lifecycle with generated Quadlet units.

## Consequences

The platform must test filesystem, network, process, metadata, and SQL
isolation. Containers reduce but do not eliminate the risk of tenant code.

## Alternatives considered

Shared PHP-FPM pools were rejected as an inadequate boundary. Kubernetes and
tenant-provided container images were rejected as unnecessary and unsafe for
the pilot.
