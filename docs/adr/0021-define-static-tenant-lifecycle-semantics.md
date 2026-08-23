# 0021: Define static tenant lifecycle semantics

- Status: accepted
- Date: 2026-08-22

## Context

Create, deployment, rollback, suspension, archival, restoration, and deletion
must have stable meanings before they are automated. Ambiguous destructive
operations or retries could lose content, publish the wrong release, or produce
state that the Milestone 4 scheduler cannot safely adopt.

## Decision

Create establishes an `undeployed` tenant with a root-generated immutable ID,
a reserved mutable slug, and no deployment or public route. The first
successful deploy installs an immutable release and moves it to `active`;
creation and deployment remain independently idempotent operations.

Retain the selected deployment's immutable release and its two immediately
preceding releases in tenant deployment chronology. Every successful deploy or
rollback triggers garbage collection only after its lifecycle transaction is
durably committed. For an active tenant that means the selected route is
serving and desired and observed state agree. For a suspended tenant it means
the remembered deployment is committed while desired and observed state still
prove both routes absent. Cleanup takes exclusive tenant-state, preserves any
release pinned by an export snapshot or transaction intent, and runs during
startup reconciliation as well as after either kind of successful commit.

Suspension removes both the canonical content route and platform slug alias and
therefore returns the same generic response as an unknown hostname; it
preserves manifests, releases, the immutable tenant origin, and the last active
deployment. Resume republishes that deployment and both routes. Rename
atomically replaces only the platform alias while preserving the tenant ID and
canonical content origin. After commit, the previous slug is available for
another tenant.

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
archived state and removes both public routes through one lifecycle
transaction.
The snapshot retains the active or suspended source manifest separately for
final compare-and-swap revalidation; the bundle's `manifest.json` is always the
proposed archived manifest, not that source manifest.
Its root-owned archive record binds the tenant ID, selected deployment ID and
versioned `lowerduckpond-release-tree-v1` content digest, versioned
`lowerduckpond-manifest-v1` canonical archived-manifest digest, exact-byte
portable-bundle SHA-256 and size, and durable bucket, key, and Spaces version
ID. Restore recomputes those representations from that exact version and
creates a new deployment while preserving the tenant ID; it does not mutate a
historical release.

After the bundle is durable, archive acquires publication and exclusive
tenant-state in the global order and proves the captured source manifest,
deployment, and release are still current. Archive requires observed state to
be reconciled to that source manifest before it prepares the transition. It
then prepares and syncs the proposed `archived` manifest and a complete Caddy
runtime generation without the tenant.

Its write-ahead intent binds the exact preceding desired manifest and digest,
`active` or `suspended` lifecycle state, observed state, remembered deployment,
complete runtime generation, and presence or absence of both tenant routes. It
also binds the proposed archived manifest, verified archive record, and
proposed no-route runtime generation. The activator then selects and reloads
the generation containing neither the canonical content route nor its slug
alias, durably commits desired and observed archived state plus the audit event,
and only then clears intent.

Reconciliation inspects archive intent before ordinary desired-state
reconciliation and converges on either the exact preceding state and runtime
generation or the complete archived state and generation. Rolling back an
archive whose source was `suspended` restores that suspended manifest,
remembered deployment, observed state, and no-route generation; it cannot
publish either tenant route. Rolling back an `active` source restores its
active manifest, observed deployment, and both routes. Reconciliation never
infers `active` from the existence of a retained release or from an old
manifest left on disk. This is the ADR 0017 durability protocol applied to the
manifest, lifecycle, and route-set transition, rather than an assumption that
multiple filesystem renames are literally atomic together.

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
has never had a deployment. While holding publication and then exclusive
tenant-state, the activator checks that complete authoritative history,
durably appends the deletion tombstone, and only then removes the empty desired
manifest and releases its slug. Missing, inconsistent, or previously deployed
history fails closed and requires a verified archive through the ordinary path.
The never-deployed exception is idempotent by correlation ID, fully audited,
and does not invoke or grant the emergency-deletion authority.

The ordinary archived deletion path also releases the slug after its archive
checks and deletion audit commit. Neither deletion path makes the immutable
tenant ID or canonical hostname available to a new tenant. The audit tombstone
records released slugs as history but does not participate in future slug
availability checks.

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
policy rather than Milestone 3 host behavior. Until that coordinated policy is
implemented, every durable object bound by an authoritative archived tenant
record is retained without current-object age expiration. Milestone 3 must
remove the existing current-object expiration from the `archives/` storage
prefix before enabling archive operations. Storage lifecycle rules may still
abort incomplete uploads and expire unreferenced or superseded objects, but
must not independently delete a bundle that live tenant state requires for
export, restore, or ordinary deletion. Version-aware cleanup permanently purges
every version and delete marker of an unreferenced unique key and confirms none
remain; lifecycle expiration is only a backstop and does not reclaim charged
capacity or reopen archive admission.

The complete ordinary transition matrix is:

| Operation | Allowed source | Result |
| --- | --- | --- |
| `create` | absent | Generates a tenant ID and becomes `undeployed`; an existing live slug follows conflict/idempotency rules rather than creating another identity. |
| `deploy` | `undeployed`, `active` | Installs a new deployment, publishes both routes, and becomes or remains `active`. |
| `deploy` | `suspended` | Installs and remembers the new deployment but remains unrouted and `suspended`. |
| `rollback` | `active` | Selects and publishes a retained prior deployment; remains `active`. |
| `rollback` | `suspended` | Selects only the remembered deployment; remains unrouted and `suspended`. |
| `suspend` | `active`, `suspended` | Removes both routes and becomes or remains `suspended`. |
| `resume` | `suspended`, `active` | Publishes the remembered deployment and both routes and becomes or remains `active`; no other operation may leave `suspended`. |
| `rename` | `undeployed`, `active`, `suspended` | Changes the reusable alias without changing tenant ID, canonical origin, or lifecycle state; only `active` receives a replacement alias route, and the old slug is released after commit. |
| `export` | `active`, `suspended` | Snapshots the selected deployment without changing state. |
| `export` | `archived` | Revalidates and returns the bound durable bundle without changing state. |
| `archive` | `active`, `suspended` | Captures and verifies the selected deployment, removes both routes, and becomes `archived`. |
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

Suspended sites do not disclose whether an alias or canonical hostname exists,
and rollback remains cheap because releases are immutable. A suspended tenant
can select its next release safely without becoming public. Applying the same
three-release retention rule to active and remembered deployments keeps that
storage bounded and must be included in disk monitoring and release garbage
collection.

Archive storage and audit records become prerequisites for ordinary deletion of
any tenant that has ever been deployed. The separately authenticated emergency
command is deliberately conspicuous and must be covered by tests and
operational documentation.

Bound archive retention is therefore controlled by the tenant lifecycle rather
than by an uncoordinated object-age timer. Milestone 4 may remove a bound bundle
only as part of a scheduled, audited tenant-deletion transition; a storage
lifecycle rule may provide later cleanup for objects that authoritative state
already proves are unreferenced.

Archive evidence is generation-specific rather than a permanent tenant flag.
Any later manifest or deployment generation needs a newly verified archive
before ordinary deletion.

Archival has no intermediate durable lifecycle state: after reconciliation the
tenant is in its exact preceding `active` or `suspended` state and route set, or
it is `archived` with neither route.

Unused slug reservations can be removed without manufacturing an empty archive,
while authoritative history—not caller-supplied lifecycle state—keeps the
exception unavailable to any tenant that has ever stored content.

Published slugs are also reusable after a committed rename or deletion because
they never served tenant-controlled content. Browser state remains bound to the
old tenant's UUID-derived canonical origin, which is not reassigned.

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
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
