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

Archive derives the proposed canonical `archived` manifest from the current
manifest and selected deployment, creates and verifies a portable bundle for
that exact manifest and release in durable archive storage, then commits the
archived state and removes the public route through one lifecycle transaction.
Its root-owned archive record binds the tenant ID, selected deployment ID and
content digest, canonical archived-manifest digest, portable-bundle digest and
size, and durable object identity. Restore validates that bundle and creates a
new deployment while preserving the tenant ID; it does not mutate a historical
release.

After the bundle is durable, archive acquires publication and exclusive
tenant-state in the global order and proves the captured source manifest,
deployment, and release are still current. It then prepares and syncs the
proposed `archived` manifest and a complete Caddy runtime generation without the
tenant. Its write-ahead intent names the preceding active manifest and runtime
generation, the proposed archived manifest, the verified archive record, and
the proposed no-route runtime generation. The activator then selects and reloads
the no-route generation, durably commits desired and observed archived state
plus the audit event, and only then clears intent. Reconciliation must inspect
archive intent before ordinary desired-state reconciliation and converge on
either the complete preceding active generation or the complete archived
generation; it may never republish merely because an interrupted transaction
left the old active manifest on disk. This is the ADR 0017 durability protocol
applied to the manifest and route transition, rather than an assumption that
two filesystem renames are literally atomic together.

For a tenant that has ever been deployed, ordinary delete requires
`desiredState: archived` and revalidates immediately before mutation that a
durable archive record and object match the current canonical manifest and its
desired deployment. An older verified archive never authorizes deletion after
restore, deployment, rename, or any other manifest change; the operator must
archive the current generation. Delete refuses to remove desired state or live
releases when any bound digest, identity, size, or object check differs. The
provisioner's ordinary activation capability cannot bypass that prerequisite.

There is one ordinary archive-free deletion transition: an `undeployed` tenant
whose root-owned deployment, release, archive, and audit history proves that it
has never had a deployment. While holding the exclusive tenant-state and
publication locks, the activator checks that complete authoritative history,
durably appends the deletion tombstone, and only then removes the empty desired
manifest and releases its slug. Missing, inconsistent, or previously deployed
history fails closed and requires a verified archive through the ordinary path.
The never-deployed exception is idempotent by correlation ID, fully audited,
and does not invoke or grant the emergency-deletion authority.

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

The complete ordinary transition matrix is:

| Operation | Allowed source | Result |
| --- | --- | --- |
| `create` | absent | `undeployed`; an existing tenant or slug follows conflict/idempotency rules rather than creating another identity. |
| `deploy` | `undeployed`, `active` | Installs a new deployment and becomes or remains `active`. |
| `deploy` | `suspended` | Installs and remembers the new deployment but remains unrouted and `suspended`. |
| `rollback` | `active` | Selects and publishes a retained prior deployment; remains `active`. |
| `rollback` | `suspended` | Selects only the remembered deployment; remains unrouted and `suspended`. |
| `suspend` | `active`, `suspended` | Removes the route and becomes or remains `suspended`. |
| `resume` | `suspended`, `active` | Publishes the remembered deployment and becomes or remains `active`; no other operation may leave `suspended`. |
| `rename` | `undeployed`, `active`, `suspended` | Changes the slug without changing lifecycle state; only `active` receives a replacement route. |
| `export` | `active`, `suspended` | Snapshots the selected deployment without changing state. |
| `export` | `archived` | Revalidates and returns the bound durable bundle without changing state. |
| `archive` | `active`, `suspended` | Captures and verifies the selected deployment, removes any route, and becomes `archived`. |
| `archive` | `archived` | Revalidates the existing bound durable bundle and remains `archived`. |
| `restore` | `archived` | Validates the bound bundle as a new deployment and becomes `active`. |
| `delete` | never-deployed `undeployed`, current-evidence `archived` | Applies the corresponding audited ordinary deletion rule and removes desired state. |
| `reconcile` | every persisted state | Repairs observed state to the same valid desired state; it does not select a new desired transition. |

Every unlisted source/operation pair fails closed without changing desired or
observed state. In particular, archived tenants cannot deploy, roll back,
suspend, resume, or rename; they must restore first, preventing a manifest
change from silently detaching the archive evidence. Undeployed tenants cannot
export, archive, roll back, suspend, or resume because no deployment exists.
The separately authenticated emergency deletion remains outside this ordinary
matrix.

## Consequences

Suspended sites do not disclose whether a hostname exists, and rollback remains
cheap because releases are immutable. A suspended tenant can select its next
release safely without becoming public. Retaining three releases uses bounded
additional storage that must be included in disk monitoring and release garbage
collection.

Archive storage and audit records become prerequisites for ordinary deletion of
any tenant that has ever been deployed. The separately authenticated emergency
command is deliberately conspicuous and must be covered by tests and
operational documentation.

Archive evidence is generation-specific rather than a permanent tenant flag.
Any later manifest or deployment generation needs a newly verified archive
before ordinary deletion.

Archival has no intermediate durable lifecycle state: after reconciliation the
tenant is either active with its preceding route or archived with no route.

Unused slug reservations can be removed without manufacturing an empty archive,
while authoritative history—not caller-supplied lifecycle state—keeps the
exception unavailable to any tenant that has ever stored content.

## Alternatives considered

A branded suspension page was rejected because it reveals tenant status and
requires another public template. In-place rollback was rejected because it
destroys immutable evidence. Treating `deleted` as an ordinary manifest state
was rejected because deletion removes desired state and must retain only an
audit tombstone. Immediate unarchived deletion was rejected as too easy to
invoke accidentally for a tenant that has ever been deployed. Requiring an
archive for a provably never-deployed reservation was rejected because it adds
no recoverable content. Requiring an archive during `create` was rejected
because it would collapse two accepted operator operations and prevent
reserving a slug before its first deployment.

## References

- [0018: Version the static tenant manifest contract](0018-version-static-tenant-manifests.md)
- [0019: Constrain static archives and exports](0019-constrain-static-archives-and-exports.md)
- [0020: Use a trusted-workstation static operator interface](0020-use-a-trusted-workstation-static-operator-interface.md)
