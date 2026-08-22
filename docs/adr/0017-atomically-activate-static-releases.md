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
extra disk and need bounded garbage collection.

The backup service and root activator must share a lock contract. Caddy route
generation becomes intentionally limited; adding a new route capability
requires changing reviewed root-owned code and its tests.

## Alternatives considered

A provisioner-writable `current` symlink was rejected because it could be
retargeted after validation. Per-tenant route-file replacement without a
complete candidate set was rejected because Caddy validates and loads the
combined configuration. Updating content and routes independently was rejected
because neither operation alone is a safe public state.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [Static-publication threat model](../threat-model/static-publication.md)
