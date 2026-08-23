# 0018: Version the static tenant manifest contract

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 needs a durable desired-state contract before the portal and control
plane exist. That contract must support idempotent operator commands now and
queued reconciliation later without changing tenant identity or treating host
paths as application state.

## Decision

Commit a strict JSON Schema for `hosting.lowerduckpond.net/v1alpha1` static site
manifests. Accept safe YAML as the human-authored representation and persist a
canonical JSON form. Before YAML composition, the root transport enforces the
64-KiB raw manifest ceiling and decode deadline in ADR 0017; no YAML parser sees
an unbounded stream. The parser rejects duplicate mapping keys before schema
validation or canonicalization; a safe loader alone is not sufficient because
common loaders silently retain one duplicate value. Reject unknown fields so
misspellings do not silently weaken policy. The resulting canonical JSON must
fit the 16-KiB manifest ceiling.

The root activator generates UUIDv7 values for immutable tenant and deployment
IDs; a `create` caller cannot select a tenant ID. Restrict slugs to 1–63 ASCII
bytes matching
`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?![\s\S])`, whose final negative
lookahead is an absolute-end assertion in both the JSON Schema ECMA-262 pattern
dialect and Python. Do not use `$`, which can match before a final newline.
Independently enforce the same grammar in the root validator with an ASCII
`fullmatch` plus the encoded byte-length check; schema success alone is not the
privileged boundary. Maintain a committed reserved-name list. Because the
alphabet is ASCII, the byte and character counts are equal. Validate the
complete `<slug>.lowerduckpond.net` alias length before persistence. Separately
validate the normalized tenant-origin suffix so the UUID-derived canonical
hostname remains within the DNS limit. Derive both hostnames from root-owned
state; do not accept an arbitrary domain or redirect target in this version.

The tenant-origin namespace must isolate mutually untrusted tenants from
`lowerduckpond.net` and from one another at the browser cookie boundary. Each
canonical `t-<tenant-uuid-without-hyphens>.<tenant-origin-suffix>` hostname must
therefore be a distinct registrable domain according to the browser Public
Suffix List, either beneath a project-controlled private suffix recognized by
supported browsers or through another mechanism that assigns a distinct
registrable domain per tenant. A separate shared registrable domain without a
public-suffix boundary is not sufficient for cross-tenant isolation.

Reserve `lowerduckpond.net` for platform-controlled responses, including the
reusable slug aliases in ADR 0023. Those aliases return only a fixed non-cached
redirect from an active tenant's bare alias root to its UUID-derived canonical
origin. They never serve or proxy uploaded content, accept a tenant redirect
target, forward paths or queries, set cookies, or register a service worker.

Selecting, provisioning, and browser-testing that namespace is an external
Milestone 3 prerequisite. The existing `*.lowerduckpond.net` DNS and certificate
foundation is used only for platform-controlled slug aliases and must not be
used for tenant-controlled content.

After that prerequisite is verified and before the first tenant is created, an
explicit root-owned initialization operation persists and syncs a versioned
platform namespace record containing the normalized tenant-origin suffix. It
may initialize only when desired state, deployment and archive records, tenant
audit history, and deletion tombstones are all empty. Once any tenant identity
has been created, the record and suffix are immutable even after every tenant
is deleted. The record is authoritative control-plane state covered by backup
and disaster recovery, not a value that Ansible may replace from current
configuration.

Host convergence, startup, and reconciliation require the configured suffix to
exactly match the platform namespace record before changing a Caddy generation.
A missing record alongside tenant history, a configuration mismatch, or an
invalid record fails closed without removing old origins or publishing new
ones. Changing the suffix requires a separately designed origin-migration
operation that preserves or deliberately retires browser origins; Milestone 3
provides no such operation.

The desired manifest records the tenant ID, complete canonical origin, slug,
`runtime: static`, desired lifecycle state, and quotas. The `create` request
supplies the desired slug and quotas but omits both `metadata.id` and
`metadata.canonicalOrigin`; its root-owned result and persisted canonical
manifest contain the generated tenant ID and the origin derived from that ID
and the pinned suffix. Every later validation and reconciliation recomputes the
origin from the tenant ID and platform namespace record and requires an exact
match with `metadata.canonicalOrigin`. `create` persists that manifest with
`desiredState: undeployed` and no `desiredDeployment`. The deployment reference,
containing a deployment UUIDv7 and archive SHA-256, becomes required when the
state changes to `active`, `suspended`, or `archived`. An immutable deployment
record carries its creation time and correlation ID. Keep observed activation
status, including the active release, separate from desired state so
reconciliation can detect and repair drift.

Persist desired and observed state, deployment and archive records, and audit
history in root-owned stores. The root activator validates and commits desired
state, changes observed state, and appends audit events. The provisioner may
read only the records required to construct or reconcile work and cannot write,
replace, or remove authoritative state or audit history.

The initial platform ceilings are 100 MiB of extracted content and 5,000 total
archive entries, counting both regular files and directories.
They operate beneath the host-wide 25-tenant, 10-GiB, and 500,000-inode
admission ceilings in ADR 0017; a schema-valid per-tenant quota never reserves
capacity the host admission transaction cannot provide.
The desired lifecycle states are `undeployed`, `active`, `suspended`, and
`archived`. Schema conditionals reject a deployment reference in an undeployed
manifest and require one in every other state. Deletion removes desired state
only through an audited operation and retains a tombstone audit event rather
than representing ordinary mutable state as `deleted`.

Schema-version changes require explicit migration code and fixtures. A stable
tenant ID and its persisted, independently rederived canonical origin do not
change when the slug or active deployment changes, and a deleted tenant ID is
never assigned to a new tenant.

## Consequences

Milestone 4 can store or enqueue the same contract without importing the
operator transport. Canonical JSON makes hashing and comparison deterministic,
while YAML remains approachable for an operator. Custom domains require a later
schema version and ownership-verification design.

The tenant-origin prerequisite adds DNS, certificate, Cloudflare credential,
and possibly domain or public-suffix coordination before the production canary.
It prevents tenant JavaScript from poisoning platform authentication cookies or
the cookies of another tenant.

The explicit DNS-label bound means every persisted slug can be used as a
platform alias later; creation cannot reserve a name that deployment must reject
for length or hidden trailing characters. Because aliases are not tenant
origins, rename and deletion may release them for deterministic reprovisioning
without transferring browser storage between tenants.

Desired and observed state require separate root-owned storage and
reconciliation logic. The platform namespace record is an additional
authoritative backup and recovery input; losing or changing it cannot be
treated as ordinary configuration convergence.
UUIDv7 avoids another identifier dependency on Python 3.14 but changes the
illustrative ULID-shaped identifier in the original roadmap.

## Alternatives considered

ULID was rejected because Python 3.14 provides UUIDv7 directly. Caller-supplied
hostnames were rejected because the operator-owned tenant namespace is the only
approved Milestone 3 routing scope. Tenant-controlled subdomains directly below
`lowerduckpond.net` were rejected because they share its cookie scope. Serving
tenant content from a mutable slug hostname was rejected because safely
reprovisioning the slug would also transfer its browser origin. A separate
shared registrable domain without a browser-recognized public-suffix boundary
was rejected because tenants would still share cookies with one another.
Permissive schemas were rejected because ignored or misspelled security fields
are unsafe at a privileged boundary. Combining initial creation and deployment
was rejected because the accepted operator interface exposes them as separate
idempotent operations.

## References

- [0004: Make static hosting the default](0004-static-first.md)
- [0008: Support archive upload before Git deployment](0008-archive-upload-first.md)
- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [Public Suffix List format and private domains](https://github.com/publicsuffix/list/wiki/Format)
- [Public Suffix List submission guidelines](https://github.com/publicsuffix/list/wiki/Guidelines)
