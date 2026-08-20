# 0014: Use Ubuntu 26.04 LTS initially

- Status: accepted
- Date: 2026-08-20

## Context

Ansible roles, package versions, rootless Podman behavior, and host acceptance
tests require a concrete operating-system baseline available on DigitalOcean.

## Decision

Use DigitalOcean's Ubuntu 26.04 LTS image and its distribution-maintained Podman
5.7 package for the first hosting node.

## Consequences

Molecule and host tests target this baseline. Package updates remain pinned or
bounded through Ansible, and changing distributions requires an ADR and a full
acceptance run.

## Alternatives considered

Ubuntu 24.04 LTS carries a much older Podman release. Debian 13 is credible but
would split initial documentation and testing without a demonstrated benefit.
