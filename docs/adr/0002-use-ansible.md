# 0002: Use Ansible for durable host configuration

- Status: accepted
- Date: 2026-08-20

## Context

Droplets must be rebuildable, testable, and idempotently configured after a
minimal first boot.

## Decision

Use Ansible roles and playbooks for durable operating-system and service
configuration. Limit cloud-init to establishing Ansible access and boot-critical
prerequisites.

## Consequences

Configuration can be reapplied and acceptance-tested independently of resource
creation. Roles must remain small, idempotent, and free of tenant lifecycle
state.

## Alternatives considered

Large cloud-init scripts and image-only configuration were rejected because
they make iteration, drift repair, and component testing harder.
