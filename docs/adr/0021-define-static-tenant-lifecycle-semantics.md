# 0021: Define static tenant lifecycle semantics

- Status: accepted
- Date: 2026-08-22

## Context

Create, deployment, rollback, suspension, archival, restoration, and deletion
must have stable meanings before they are automated. Ambiguous destructive
operations or retries could lose content, publish the wrong release, or produce
state that the Milestone 4 scheduler cannot safely adopt.

## Decision

Create establishes an `undeployed` tenant with no deployment or public route.
The first successful deploy installs an immutable release and moves it to
`active`; creation and deployment remain independently idempotent operations.

Retain the active immutable release and its two immediately preceding releases.
A successful activation triggers garbage collection only after the new route is
serving and its state is durably recorded.

Suspension removes the tenant route and therefore returns the same generic 404
as an unknown tenant hostname; it preserves manifests, releases, and the last
active deployment. Resume republishes that deployment. Rename atomically
replaces the derived route while preserving the tenant ID.

Rollback evaluates lifecycle state again while holding the publication lock.
For an active tenant, it selects and publishes the retained release through the
ordinary activation transaction. For a suspended tenant, it changes only the
remembered deployment that a later `resume` will publish; it does not create a
route or leave `suspended`. Rollback is invalid for `undeployed` or `archived`
tenants. Consequently, a delayed rollback queued before suspension cannot
republish the tenant, and only an explicit `resume` can leave the suspended
state. Export produces a portable bundle without changing lifecycle state.

Archive first creates and verifies a portable bundle in durable archive storage,
then removes the public route. Restore validates that bundle and creates a new
deployment while preserving the tenant ID; it does not mutate a historical
release. Delete refuses to remove desired state or live releases unless a
verified archive record exists. The provisioner's ordinary activation
capability cannot bypass that prerequisite.

An emergency deletion without archive evidence uses a separate root-only
operator command that is absent from the provisioner's sudo allowlist and
transport-independent worker interface. It is available only through the
authenticated administrative SSH and sudo boundary and records the operator
identity, correlation ID, and mandatory reason before deletion begins. A reason
or correlation ID supplied through the provisioner is never authorization for
this path.

Every transition is idempotent and appends an audit event. Retrying the same
correlation ID and request returns the established result. Automated notices,
grace periods, retention expiry, and scheduled deletion remain Milestone 4
policy rather than Milestone 3 host behavior.

## Consequences

Suspended sites do not disclose whether a hostname exists, and rollback remains
cheap because releases are immutable. A suspended tenant can select its next
release safely without becoming public. Retaining three releases uses bounded
additional storage that must be included in disk monitoring and release garbage
collection.

Archive storage and audit records become prerequisites for ordinary deletion.
The separately authenticated emergency command is deliberately conspicuous and
must be covered by tests and operational documentation.

## Alternatives considered

A branded suspension page was rejected because it reveals tenant status and
requires another public template. In-place rollback was rejected because it
destroys immutable evidence. Treating `deleted` as an ordinary manifest state
was rejected because deletion removes desired state and must retain only an
audit tombstone. Immediate unarchived deletion was rejected as too easy to
invoke accidentally. Requiring an archive during `create` was rejected because
it would collapse two accepted operator operations and prevent reserving a slug
before its first deployment.

## References

- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [0019: Constrain static archives and exports](0019-constrain-static-archives-and-exports.md)
- [0020: Use a trusted-workstation static operator interface](0020-use-a-trusted-workstation-static-operator-interface.md)
