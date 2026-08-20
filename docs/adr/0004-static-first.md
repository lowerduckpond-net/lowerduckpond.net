# 0004: Make static hosting the default

- Status: accepted
- Date: 2026-08-20

## Context

Static content is inexpensive and does not grant tenants server-side code
execution. PHP materially changes the isolation and operational risk.

## Decision

Launch and stabilize the complete static-site lifecycle before enabling any
dynamic runtime. Dynamic hosting requires separate approval and isolation tests.

## Consequences

Early milestones can validate infrastructure, deployment, recovery, and user
flows without accepting untrusted code. PHP compatibility is deliberately later.

## Alternatives considered

Launching static and PHP tiers together was rejected because failures would be
harder to isolate and the initial blast radius would be much larger.
