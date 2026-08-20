# 0010: Serialize OpenTofu state changes

- Status: accepted
- Date: 2026-08-20

## Context

DigitalOcean Spaces is S3-compatible, but its support for OpenTofu's native
conditional-write lockfile must be verified before relying on it.

## Decision

Store encrypted, versioned remote state in a dedicated Spaces bucket. Until
lockfile behavior is proven, serialize production plans and applies through one
protected GitHub environment and concurrency group.

## Consequences

Uncoordinated local production applies are prohibited. Backend credentials stay
in CI secrets, and state bootstrap remains separate from the production stack.

## Alternatives considered

Local state was rejected as fragile and unsuitable for handoff. Assuming S3
locking compatibility without a test was rejected as unsafe.
