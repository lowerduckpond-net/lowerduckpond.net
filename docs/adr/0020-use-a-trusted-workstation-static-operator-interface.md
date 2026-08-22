# 0020: Use a trusted-workstation static operator interface

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 must demonstrate the complete static lifecycle before Milestone 4
provides authentication, a portal, or a production job queue. Building a
temporary web administration surface would enlarge the public attack surface
and couple tenant operations to a transport that will soon be replaced.

## Decision

Provide a trusted-workstation CLI, exposed through documented `just` recipes,
for `create`, `deploy`, `rollback`, `suspend`, `resume`, `rename`, `export`,
`archive`, `restore`, `delete`, and `reconcile`.

The client connects through the existing restricted administrative SSH path and
transfers manifests and archives into a dedicated non-public intake boundary.
It never edits live host files. Host-side commands accept structured inputs,
return machine-readable results, and require a caller-supplied UUIDv7
correlation ID. Reusing a correlation ID and request converges on the same
result rather than duplicating releases or audit events.

Keep manifest validation, archive validation, lifecycle orchestration, and
privileged activation behind transport-independent Python interfaces. The SSH
client is a Milestone 3 adapter; Milestone 4 can enqueue the same operations
without inheriting SSH or trusted-workstation assumptions.

Do not add FastAPI endpoints, public authentication, or a production queue in
Milestone 3. The unprivileged provisioner receives only the exact privileged
activation capability defined by ADR 0017, not general sudo or Caddy access.

## Consequences

An administrator can exercise every lifecycle operation without manual host
editing, while the public service remains only Caddy. The operator must use the
trusted workstation and administrative network until Milestone 4 is complete.

The command contract and result model become compatibility surfaces. Tests must
prove that local, SSH-adapted, and later queued invocation cannot change core
semantics.

## Alternatives considered

A temporary administrative web UI was rejected because it would require early
authentication and authorization work. An Ansible role per tenant was rejected
because tenant lifecycle is application state, not durable host configuration.
Manual SSH editing was rejected because it cannot satisfy the milestone's
idempotence or audit requirements.

## References

- [0002: Use Ansible for durable host configuration](0002-use-ansible.md)
- [0006: Separate the control plane and provisioner](0006-separate-control-plane-provisioner.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
