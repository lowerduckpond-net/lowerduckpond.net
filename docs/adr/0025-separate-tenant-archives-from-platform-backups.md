# 0025: Separate tenant archives from platform backups

- Status: accepted
- Date: 2026-08-23
- Amends archive placement and expiration in: [ADR 0021](0021-define-static-tenant-lifecycle-semantics.md)

## Context

Milestone 2 created one versioned DigitalOcean Space and one bucket-scoped key
for encrypted Restic backups. Earlier Milestone 3 design placed durable tenant
archive bundles beneath an `archives/` prefix in that same Space.

Backups and tenant archives have different trust and lifecycle requirements.
Restic owns encrypted repository objects and retention. The static activator
must list, write, read, verify, and permanently delete exact archive object
versions as part of tenant lifecycle transactions. Sharing a key or bucket
would let an archive implementation defect or compromised archive credential
damage the backup repository, while a compromised backup credential could
damage authoritative tenant archive evidence.

DigitalOcean Spaces keys can be scoped to buckets but not to the narrower
operation and prefix boundaries required to make shared-bucket access safe.

## Decision

Provision a second private, versioned production Space dedicated to tenant
archives. Give the root-owned static archive component a dedicated Spaces key
whose grant covers only that archive Space. Keep the existing backup Space and
Restic key dedicated to backups.

The archive Space has:

- versioning enabled;
- `force_destroy = false` and an OpenTofu destroy guard;
- no current-object or noncurrent-version age expiration;
- an incomplete-multipart abort rule only as defense in depth for non-platform
  clients; and
- project assignment and policy checks equivalent to the backup Space.

Managed archive code continues to use unique keys beneath `archives/`, exactly
one known-length `PutObject`, exact version binding, version-aware accounting,
and explicit permanent deletion from ADR 0019. It does not depend on lifecycle
expiration for correctness or reclamation.

The archive credential is installed only for the root-owned archive boundary.
It is not readable by Caddy, the provisioner, the operator account, Restic, or
tenant workloads. The backup credential cannot access the archive Space, and
the archive credential cannot access the backup Space. OpenTofu marks generated
credential outputs sensitive; the trusted configuration workstation transports
them without committing a secret inventory or variables file.

Archive metadata remains part of the authoritative root-owned state protected
by Restic. The archive bundles themselves are not copied into Restic. Restore
therefore requires both a consistent authoritative-state snapshot and the exact
Space object version bound by that state.

## Consequences

Archive lifecycle operations cannot damage the Restic repository using their
ordinary credential, and backup maintenance cannot expire or prune tenant
archive objects. Remote capacity accounting becomes simpler because every
object and version in the managed archive prefix belongs to one subsystem.

The production stack gains a second globally unique bucket name, credential,
secret handoff, health check, and recovery dependency. A root compromise can
still reach both credentials on the host while their services run; this
decision reduces component and mistake blast radius rather than claiming to
contain root.

The existing backup Space's `archives/` lifecycle rule becomes obsolete and is
removed without deleting any objects. It is currently empty; migration must
fail if discovery finds an unexpected archive object or version.

## Alternatives considered

A shared bucket with separate prefixes was rejected because Spaces credentials
cannot enforce the required prefix boundary and both components would retain
destructive access to the other's objects. A write-only archive credential was
rejected because reconciliation, restore, accounting, and permanent retirement
require version listing, reads, and deletes. Copying every archive into Restic
was rejected because exact version-aware lifecycle authority would be obscured
inside a second retention system.

## References

- [0019: Constrain static archives and exports](0019-constrain-static-archives-and-exports.md)
- [0021: Define static tenant lifecycle semantics](0021-define-static-tenant-lifecycle-semantics.md)
- [DigitalOcean Spaces API reference](https://docs.digitalocean.com/reference/api/spaces/)
