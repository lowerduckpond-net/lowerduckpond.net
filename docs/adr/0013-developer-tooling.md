# 0013: Standardize the developer workflow

- Status: accepted
- Date: 2026-08-20

## Context

Contributors and CI need the same pinned tools and commands across Python,
OpenTofu, Ansible, documentation, and security checks.

## Decision

Use `mise` for executable versions, `just` for documented commands, and
pre-commit for fast local checks. Use Dependabot for controlled updates to
supported dependency ecosystems. Retain Renovate only for the custom Caddy
release reference in `platform/versions.yml`, which is outside Dependabot's
manifest support. Use one `just check` command as the local acceptance gate.
Pre-commit may apply safe hygiene fixes and then fail so the contributor can
review and rerun it.

## Consequences

The repository must pin a patched `mise` version, lock Python dependencies, pin
CI actions by commit, and keep narrow `just` recipes callable independently.
Dependabot and Renovate must have non-overlapping ownership so a dependency has
only one update source.

## Alternatives considered

Make was rejected because this repository does not build a single traditional
artifact. Unpinned system tools and CI-only validation were rejected because
they make failures difficult to reproduce.
