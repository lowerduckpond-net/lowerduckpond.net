# 0009: Require pilot administrative approval

- Status: accepted
- Date: 2026-08-20

## Context

Open automated signup would expose a free service and community identity to
abuse before policy and resource limits have operational evidence.

## Decision

Require administrator approval for every site during the pilot. Record policy
acceptance and the approval decision in the audit history.

## Consequences

Signup is not instant, but abuse and support load remain bounded. The identity
verification method is deliberately deferred until the Milestone 4 user-flow
design.

## Alternatives considered

Immediate self-service provisioning was rejected for the pilot. Invitation-only
access remains a possible operating policy but is not required by the platform.
