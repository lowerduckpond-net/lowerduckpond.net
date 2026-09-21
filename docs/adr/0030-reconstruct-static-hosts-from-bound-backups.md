# 0030: Reconstruct static hosts from bound backups

- Status: proposed; acceptance occurs with the M3.11 plan PR
- Date: 2026-09-21
- Amends: [ADR 0017](0017-atomically-activate-static-releases.md)
- Implementation and qualification: [M3.11 plan](../plans/milestone-3.11.md)

## Context

ADR 0017 says backup takes only shared tenant-state, but installed backup code
already takes shared publication followed by shared tenant-state and rejects
nonempty release staging. Publication-only writers change Caddy selection and
startup intent; tenant-state alone cannot capture those consistently. The
existing backup set omits those external Caddy records and deliberately excludes
secret-bearing runtime generations. The smoke restore checks file presence,
not reconstruction of a tenant-bearing host.

A new host cannot replay an old systemd invocation or start a generation whose
binary/environment/configuration were intentionally excluded. Likewise, a
pending deployment can outlive intake bytes excluded from backup. The normal
in-place recovery contracts must not be weakened globally to handle this
different, explicitly authorized administrative operation.

Audit entries also authorize result replay, deletion and history projection.
Removing a local segment without preserving those queries would change ordinary
lifecycle semantics even if its remote bytes were perfectly retained.

## Decision

### Coherent backup capture

Amend the backup-only lock statement in ADR 0017: backup takes shared
publication, then shared tenant-state, through snapshot completion. It continues
to exclude mutation and refuses unclassifiable release staging. Other existing
host lock order and contention rules remain unchanged. Backup-side operations
take repository serialization outside the host locks; ordinary workers never
take that repository lock. Do not wait synchronously for a systemd job while
holding publication.

Capture a versioned, bounded, non-secret recovery descriptor under those locks.
It binds the exact state/release/audit snapshot, installed artifact, source
policy, repository, namespace/launch authority and Caddy selection/start-intent
evidence. It may contain generation manifest and route-state digests, never
adapted configuration or environment bytes. The M3.11 plan defines its exact
identity and validation bounds. Transient inputs remain excluded; tenant
archive bundles remain exclusively in their separate Space under ADR 0025.

### Audit consumers after rotation

Retain a bounded local lookup witness for each archived segment, generated from
its restore-verified bytes and cryptographically bound by its protected
descriptor/index. Its fixed-order rows reconstruct the original canonical audit
entries needed by every existing lifecycle query. Constant schema fields are
defined by its version; no audit authority is inferred from a lossy summary.
Remote snapshots remain the complete archival evidence. Ordinary workers gain
neither backup credentials nor a network capability.

Local witness/index allocation counts within the existing ordinary audit
allowance, with a stricter metadata sublimit. It cannot consume the administrator
reserve. Reaching a bound closes admission/rotation, rather than deleting
history or growing an unbounded alternate store. Indexes and witnesses are
backed up and validated; missing witnesses can be rebuilt only from verified
protected bytes. All correlation, result, deletion and sequence semantics
remain unchanged. Protected snapshots, including equivalent duplicates, remain
outside ordinary retention indefinitely during M3.

### Explicit restored-host transaction

Introduce an administrator-only restored-host transaction, distinct from
ordinary Caddy startup and tenant `restore`. It requires a fenced source host,
a fresh or explicitly prepared destination, an exact coherent platform snapshot,
verified original provenance, trusted current host inputs, and all exact tenant
archive versions required by recovered state. Install a durable startup gate
and keep Caddy, ordinary ingress and mutation/maintenance schedules stopped
through validation and reconciliation. Reboot cannot bypass this gate.

Resolve each lifecycle intent using its captured selection, complete source/
candidate authority, release digests and the operation-specific rules. Preserve
immutable results and historical audit entries. An incomplete or ambiguous
proof leaves the entire restored host unavailable; it does not authorize a
guess, partial serving, an emergency deletion, or a new namespace.

For an accepted deploy/import whose transient input is absent and which has no
committed lifecycle intent or result, validated preserved source state permits
one terminal `restore_input_unavailable` failure for the original job. This
failure is audited through the same result-first failure-repair discipline;
it does not recreate the artifact, refund admission, or permit another success
under that correlation. If an intent and durable release exist, use their
recovery authority instead. A successful export's missing transient delivery
copy may be durably marked retired without changing its immutable result or
extending its lifetime. Neither exception applies to ordinary live execution.

After state reconciliation, build new complete Caddy generations from trusted
host configuration and recovered tenant state. The root restore journal binds
the snapshot, old generation references, exact reconstructed route state and
new verified generations. It permits only those runtime observation-reference
updates; tenant manifests, deployment identity, audit timestamps and immutable
results are preserved. Existing-result validation must independently verify
this mapping; a generic generation mismatch is still corruption.

Old startup intents, invocation IDs, counters and failed attempts remain
preserved evidence. They are never rebound to a new host or erased to refund
attempts. A new explicit host-restore transaction owns the new generation and
uses the ordinary bounded invocation-fenced start/verification path. This is
not a new fallback for ordinary startup, a publication gate override, or
permission to recover an inconsistent live host by resetting its counters.

### Restored state versus later remote history

An old backup may reference a tenant archive version legitimately retired by a
later restore/deletion. This decision preserves ADRs 0019 and 0025: both exact
state and exact archive-version evidence are required. Missing, corrupt,
inaccessible or ambiguous versions block restored service. Do not substitute
the current object, manufacture a replacement version, pin every retired
version, or use a deletion tombstone as content authority.

Protected audit descriptors created after a backup can recover its archived
prefix when their bytes agree with its exact chain boundary. If discovery
proves audit events beyond that boundary, preserve them and stop automated
restoration. Do not extend the old prefix into a competing history, replay
future audit events into old state, or automatically create a new lineage.
Choose a newer coherent backup or review an explicit recovery/data-loss decision.
Unknown newer tenant objects likewise grant no cleanup authority to an older
intent. Fence writers and reconcile the complete inventory before mutation.

### Rollout and evidence

Install protection and readers before enabling local removal. Take and
restore-verify a new coherent backup before rollout; legacy smoke snapshots
lacking the descriptor do not pass the new automated gate. After removal, an
old reader cannot safely be selected without a separately qualified restoration.
Disabling rotation preserves the new readers, index and protected snapshots.

The plan's independent and cross-feature cases qualify every durable boundary,
privilege, capacity and negative recovery outcome. Production publication stays
disabled; convergence is a separate operator step. ADR 0029 governs final
input/artifact/target identity, original evidence bytes and records-only closeout.

## Consequences

Backups may hold publication longer, but that is already the installed behavior
and now has explicit bounds and concurrency evidence. Reconstruction has a
conspicuous administrative boundary and can fail when a previously retired
version or newer audit history makes an older snapshot unsuitable. This is a
reported recovery limitation, not silent loss.

The local audit index remains finite and preserves online authorization without
giving workers storage credentials. It is not an unlimited-history scalability
solution; changing its bounds or retention later requires a reviewed migration.

## Alternatives considered

- Drop publication locking to match the old sentence: leaves publication-only
  state and release staging outside the coherent boundary.
- Back up and replay complete Caddy generations: violates the exclusion of
  generated secret-bearing inputs and cannot transplant a systemd invocation.
- Treat restored desired state alone as authority: loses unfinished operations,
  immutable results, audit continuity and archive retirement evidence.
- Fetch archived audit during each worker operation: adds credential/network
  dependencies and lock interactions to ordinary execution.
- Automatically drop missing archived tenants or resurrect retired versions:
  changes accepted lifecycle and storage contracts without administrator review.
