# 0007: Use MariaDB for tenant SQL

- Status: accepted
- Date: 2026-08-20

## Context

Period-style PHP applications commonly expect MySQL-compatible behavior. The
pilot should avoid supporting multiple tenant database engines.

## Decision

Use MariaDB for tenant SQL. Allocate one database and least-privilege user per
tenant, with independently tested dumps and credential revocation.

## Consequences

Quotas and isolation tests target MariaDB. SQLAlchemy keeps the control plane
portable; its final database session and driver configuration is decided with
the Milestone 4 data model.

## Alternatives considered

PostgreSQL is a strong control-plane database but is less compatible with the
intended PHP tenant ecosystem. SQLite cannot provide the required tenant SQL
service.
