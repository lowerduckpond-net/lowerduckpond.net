# 0006: Separate the control plane and provisioner

- Status: accepted
- Date: 2026-08-20

## Context

The public application needs authentication and metadata access, while tenant
reconciliation requires narrowly privileged filesystem and service operations.

## Decision

Package and run the control plane and provisioner separately. Communicate
through idempotent, recorded jobs rather than executing privileged operations in
web requests. The authenticated control plane is the job authority; the
provisioner may execute an immutable authorized job but cannot originate or
alter one. Before the control plane exists, ADR 0020's trusted SSH adapter
creates the same root-owned authorization envelope.

## Consequences

Each component receives only its required credentials and host permissions.
Job schemas, correlation IDs, retries, and convergence become first-class
interfaces. Compromise of a provisioner can delay or deny work but cannot mint
a tenant mutation, export, or destructive lifecycle transition.

## Alternatives considered

A single privileged web process was rejected because a web vulnerability would
immediately inherit host-level tenant-management authority.
