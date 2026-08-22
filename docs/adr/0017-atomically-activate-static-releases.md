# 0017: Atomically activate immutable static releases

- Status: accepted
- Date: 2026-08-22

## Context

Static publication crosses a privilege boundary and changes both tenant content
and public routing. A validation-then-reload sequence is unsafe when another
process can alter a route or content path between validation and use. Updating a
content pointer and route separately also creates ambiguous recovery after a
crash or failed reload.

## Decision

Install static releases below
`/srv/lowerduckpond/sites/<tenant-id>/releases/<deployment-id>/`. The root
activator revalidates and extracts the accepted archive into a new root-owned
temporary release, normalizes its attributes, and makes the final release
immutable to both the provisioner and Caddy. Caddy receives read-only access.

Generate complete, immutable, root-owned route-set generations below
`/etc/caddy`. Each tenant route is derived only from validated tenant ID, slug,
state, and deployment ID and points directly to an immutable release; it never
follows a provisioner-controlled `current` link. Validate the complete candidate
route set, atomically replace the root-owned active-route reference, and reload
Caddy. If reload fails, restore the preceding reference and reload the last
known-good route set.

Every process that changes live Caddy inputs or reloads the service uses the
same global publication lock. Before tenant publication is enabled, refactor the
Ansible Caddy role to render candidate base configuration, environment, binary
and unit selection, and route-root changes outside live paths, then apply and
reload them through a root-owned host-configuration transaction under that
lock. Ansible no longer writes a live Caddy input or invokes an independent
reload. The provisioner's sudo capability cannot invoke this broader
host-configuration transaction.

An undeployed tenant has authoritative desired state but no deployment record,
release, or route. Its first successful `deploy` operation creates those
artifacts and changes desired state to `active` through the ordinary activation
transaction.

Serialize activation, rollback, rename, suspension, archival, restoration,
deletion, and reconciliation with one root-owned publication lock. Record intent
before changing the active reference so reconciliation can finish or reverse an
interrupted operation. Backups take a shared tenant-state lock while publication
and reconciliation take it exclusively, preventing a snapshot from combining
incompatible content and manifest generations.

Atomic rename is not a durability barrier. While holding the locks, apply this
ordered persistence protocol:

1. Normalize and `fsync` every completed release and route-set file, `fsync`
   their directories from leaves upward, rename each temporary generation to
   its final immutable name, and `fsync` each parent directory. The Ansible
   Caddy transaction applies the same ordering to its candidate inputs.
2. Write the transaction intent, including previous and proposed generations,
   to a temporary file; `fsync` it, rename it into place, and `fsync` the state
   directory.
3. Create a temporary active-route reference, atomically rename it over the old
   reference, and `fsync` its containing directory. A reference is never
   selected before its release and route-set targets are durable.
4. Reload Caddy. On success, write desired and observed state through
   write-`fsync`-rename-directory-`fsync`, append and `fsync` the audit event,
   then remove the intent and `fsync` its directory.
5. On validation or reload failure, atomically restore and durably persist the
   prior reference before reloading the last-known-good generation. Persist the
   failure result and audit event before removing intent.

On startup and before any later mutation, reconciliation inspects durable
intent, references, and state. It completes a transaction whose selected
generation and targets are durable, or restores the durable prior generation;
it never infers completion from observed state alone.

The root activator accepts structured identifiers and an artifact from the
fixed intake boundary. It does not accept arbitrary destination paths, commands,
or Caddy directives. It performs every security-critical check itself even when
the unprivileged provisioner already performed a preflight validation.

The activator is also the only ordinary writer of root-owned desired manifests,
observed state, deployment and archive records, and append-only audit events.
The provisioner never receives directory write permission for those stores.
Only its transient intake and job workspace remains provisioner-writable.

## Consequences

The active route-set reference becomes the publication commit point. Releases
can be prepared without affecting traffic, retries can reuse an already verified
immutable release, and rollback selects a prior release without rewriting its
content. Route-set generations and write-ahead state consume small amounts of
extra disk and need bounded garbage collection. Durably syncing every file and
directory adds deployment latency, bounded by the archive limits, in exchange
for a recoverable commit after process termination or power loss.

The backup service, root activator, and Ansible Caddy transaction must share
their respective state and publication lock contracts. Caddy route generation
becomes intentionally limited; adding a new route capability requires changing
reviewed root-owned code and its tests.

## Alternatives considered

A provisioner-writable `current` symlink was rejected because it could be
retargeted after validation. Per-tenant route-file replacement without a
complete candidate set was rejected because Caddy validates and loads the
combined configuration. Updating content and routes independently was rejected
because neither operation alone is a safe public state.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [Static-publication threat model](../threat-model/static-publication.md)
