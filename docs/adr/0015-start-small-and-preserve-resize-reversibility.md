# 0015: Start small and preserve resize reversibility

- Status: accepted
- Date: 2026-08-20

## Context

Development and player onboarding may take longer than expected. DigitalOcean
charges for powered-off Droplets, and increasing a Droplet disk cannot be
reversed. The OpenTofu provider increases the disk by default during a resize.

## Decision

Begin Milestone 1 with the `s-1vcpu-2gb` Basic Droplet in NYC1. Explicitly set
`resize_disk = false`, and move to the `s-2vcpu-4gb-amd` class before the full
platform or initial tenants require it. Retain the reserved address and Spaces
storage independently from replaceable compute.

## Consequences

Early development costs less, and CPU/RAM-only upgrades can return to the
original size. The small development node is not the production capacity
target. If a future target cannot accept the existing root-disk size, OpenTofu
must replace and reconfigure the Droplet rather than shrink its disk.

## Alternatives considered

Starting immediately at 4 GiB was rejected as unnecessary during foundation
work. Enlarging the root disk during scaling was rejected because it removes a
useful downscale path. Merely powering off an idle Droplet was rejected because
DigitalOcean continues billing while it exists.
