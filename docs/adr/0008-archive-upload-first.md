# 0008: Support archive upload before Git deployment

- Status: accepted
- Date: 2026-08-20

## Context

Community members need a deployment method that does not require Git knowledge,
while the platform needs one stable validation and rollback contract.

## Decision

Implement uploaded site archives first. Add repository integration only after
archive validation, atomic activation, and rollback behavior are stable.

## Consequences

Archive safety, quotas, and traversal checks become the initial deployment
boundary. Git integration can later produce the same internal artifact.

## Alternatives considered

Git-only deployment was rejected as an unnecessary participation barrier.
Supporting both mechanisms initially would duplicate unsettled behavior.
