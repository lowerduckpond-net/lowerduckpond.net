# 0012: Use FastAPI, SQLAlchemy, and uv

- Status: accepted
- Date: 2026-08-20

## Context

The control plane needs explicit composition, typed request boundaries, and a
maintainable relational model without adopting a batteries-included framework
or active-record style ORM.

## Decision

Use FastAPI for HTTP services, SQLAlchemy 2 typed declarative mapping for
persistence, and `uv` for Python environments and lockfiles. Package the
provisioner independently with no FastAPI dependency.

## Consequences

Authentication, administration, migrations, and job processing will be chosen
explicitly. Python aligns with Ansible tooling, while component boundaries must
prevent the web process from acquiring provisioner privileges.

## Alternatives considered

Django's framework and ORM style were rejected. Go would simplify deployment
but provide less leverage from existing FastAPI experience. TypeScript and
Laravel would add another primary application toolchain.
