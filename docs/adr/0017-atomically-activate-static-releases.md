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

Generate complete, immutable, root-owned Caddy runtime generations below
`/etc/caddy/generations/<generation-id>/`. Each generation contains a manifest
of exact file digests, the pinned Caddy binary, Caddy-only environment, complete
adapted base-and-tenant configuration, and route metadata. Each tenant route is
derived only from validated tenant ID, slug, state, and deployment ID and points
directly to an immutable release; it never follows a provisioner-controlled
`current` link. Unchanged host payloads may be root-created hard links to the
same immutable inodes, but every generation is independently manifest-verified.
Validate the complete candidate with its own binary and environment, atomically
replace one root-owned active-generation reference, and reload or restart Caddy
as the transaction declares. If activation fails, restore the preceding
reference and the complete last-known-good runtime generation.

Every process that changes live Caddy inputs or reloads or restarts the service
uses the same global publication lock. Before tenant publication is enabled,
refactor the Ansible Caddy role to render a complete candidate runtime
generation outside live paths, combining its proposed base configuration,
environment, and binary with the current validated tenant routes. Apply it
through a root-owned host-configuration transaction under that lock. Ansible no
longer writes an independently consumed live Caddy input or invokes an
independent reload. The provisioner's sudo capability cannot invoke this
broader host-configuration transaction.

Keep the systemd unit and a small generation launcher as a frozen root-owned
bootstrap, not members selected independently with each runtime generation.
The Milestone 3 migration stops and masks Caddy, installs that bootstrap and the
first complete generation, reloads systemd, runs reconciliation, and only then
unmasks and starts Caddy. Any later bootstrap change is a conspicuous maintenance
transaction with the service stopped and masked until its unit, launcher,
recovery gate, and runtime compatibility have been installed and verified; a
crash leaves Caddy unavailable rather than starting a mixed generation.

Before every start and automatic restart, a privileged `ExecStartPre` recovery
gate acquires the publication lock and reconciles any intent. The unprivileged
launcher then holds the lock while it reads the active reference once, opens
that immutable generation directory, verifies its manifest, and opens every
binary, environment, and configuration input relative to the pinned directory
descriptor without following links. It loads the environment, passes the open
configuration to Caddy, releases the lock after all inputs are pinned, and
executes the already-open binary; it never resolves the active reference once
per input, and it does not retain the lock for Caddy's lifetime. The reload
helper uses the same pinned-directory-descriptor rule and sends the already-open
complete configuration to the running matching binary. Host transactions that
change binary or environment always restart rather than reload. Thus systemd
`Restart=` cannot observe a partially selected set of paths.

An undeployed tenant has authoritative desired state but no deployment record,
release, or route. Its first successful `deploy` operation creates those
artifacts and changes desired state to `active` through the ordinary activation
transaction.

Serialize creation, activation, rollback, rename, suspension, archival,
restoration, deletion, and reconciliation with one root-owned publication lock.
Creation and rename acquire the exclusive tenant-state lock before checking
tenant ID and slug uniqueness and hold it through the durable manifest commit.
The uniqueness decision is therefore part of the root-owned state transaction,
not an advisory provisioner check; no second create or rename can reserve the
same slug between validation and commit. Record intent before changing the
active reference so reconciliation can finish or reverse an interrupted
operation. Backups take a shared tenant-state lock while publication and
reconciliation take it exclusively, preventing a snapshot from combining
incompatible content and manifest generations.

Atomic rename is not a durability barrier. While holding the locks, apply this
ordered persistence protocol:

1. Normalize and `fsync` every completed release and complete Caddy-generation
   file, `fsync` their directories from leaves upward, rename each temporary
   generation to its final immutable name, and `fsync` each parent directory.
   The Ansible Caddy transaction applies the same ordering to its candidate.
2. Write the transaction intent, including previous and proposed generations,
   to a temporary file; `fsync` it, rename it into place, and `fsync` the state
   directory.
3. Create a temporary active-Caddy-generation reference, atomically rename it
   over the old reference, and `fsync` its containing directory. A reference is
   never selected before its release and complete runtime generation are
   durable.
4. Reload or restart Caddy according to the declared transaction. On success,
   write desired and observed state through
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
fixed intake boundary. It opens and claims that artifact without following
links, then streams its bytes exactly once into an exclusively created,
root-owned snapshot while enforcing the compressed-size limit and computing
the digest. After syncing and closing the snapshot, the activator verifies the
request digest and performs every security-critical parse, validation, and
extraction against the snapshot. It never validates or extracts from the
provisioner-writable inode, so an already-open provisioner file descriptor
cannot change the privileged input. It does not accept arbitrary destination
paths, commands, or Caddy directives, and it repeats every security-critical
check even when the unprivileged provisioner already performed a preflight.

The activator is also the only ordinary writer of root-owned desired manifests,
observed state, deployment and archive records, and append-only audit events.
The provisioner never receives directory write permission for those stores.
Milestone 3 also removes the provisioner's ownership of the persistent home,
intake, job, manifest, and audit directories installed by the Milestone 2 empty
host baseline. The trusted SSH adapter creates root-owned intake artifacts and
job records; the provisioner receives only the read access needed for advisory
preflight and submits its structured request without making a writable copy.

The provisioner's only general-purpose writable filesystem is a private
ephemeral workspace mounted in its service namespace. Its initial hard limits
are 64 MiB and 4,096 inodes in aggregate, independent of the per-archive
limits, and the workspace is discarded whenever the unit stops or restarts.
The service gets no persistent writable home. Root-owned intake snapshots and
activation staging are not exposed in that namespace: the activator permits at
most one snapshot for a serialized operation, removes it on every terminal
path, cleans abandoned snapshots during reconciliation, and rejects work that
would cross the configured host free-space reserve.

## Consequences

The active Caddy-generation reference becomes the publication commit point.
Releases can be prepared without affecting traffic, retries can reuse an already
verified immutable release, and rollback selects a prior release without
rewriting its content. Complete Caddy generations duplicate some metadata and
retain Caddy-only secret environment files, so they need strict ownership,
backup exclusion, bounded garbage collection, and retention of every generation
named by active or pending intent. Durably syncing every file and directory
adds deployment latency, bounded by the archive limits, in exchange for a
recoverable commit after process termination or power loss.

The backup service, root activator, and Ansible Caddy transaction must share
their respective state and publication lock contracts. Caddy route generation
becomes intentionally limited; adding a new route capability requires changing
reviewed root-owned code and its tests.

The private workspace limits must be monitored and tested at both their byte
and inode boundaries. Increasing either limit requires another host-capacity
review; application cleanup is not the security boundary that prevents a
compromised provisioner from filling the host filesystem.

## Alternatives considered

A provisioner-writable `current` symlink was rejected because it could be
retargeted after validation. Per-tenant route-file replacement without a
complete candidate set was rejected because Caddy validates and loads the
combined configuration. Updating content and routes independently was rejected
because neither operation alone is a safe public state.
Selecting binary, environment, base configuration, unit, and routes through
separate live paths was rejected because systemd could restart between their
individual commits. Versioning the systemd bootstrap with ordinary runtime
generations was rejected because the manager has already loaded its unit;
freezing it and requiring a stopped-and-masked maintenance transaction fails
closed on interruption.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [Static-publication threat model](../threat-model/static-publication.md)
