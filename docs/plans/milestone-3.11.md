# Milestone 3.11: backup, audit archival, and restored-host recovery

- Status: accepted design; implementation starts only after this plan and its ADR merge
- Baseline: `f4c9911824c0037f366fda6da738f3904f17d08e`
- Parent: [Milestone 3](milestone-3.md#m311-complete-backup-audit-and-restored-state-recovery)
- Prerequisite: [accepted sustainability closeout](../records/2026-09-20-sustainability-exit.md)
- Outcome: coherent platform backups, indefinitely protected audit snapshots,
  interruption-safe rotation, and a verified reconstruction before service

## 1. Scope, authority, and delivery gate

M3.10 qualification and production convergence are complete. PR #162 closes
operational sustainability. Their original reports remain historical evidence;
their age does not reopen either milestone. The deployed M3.10 artifact and the
qualified sustainability artifact differ, as the closeout records. M3.11
qualifies its own final inputs and records deployment separately.

ADRs [0017](../adr/0017-atomically-activate-static-releases.md),
[0019](../adr/0019-constrain-static-archives-and-exports.md),
[0022](../adr/0022-test-static-publication-as-a-security-boundary.md),
[0025](../adr/0025-separate-tenant-archives-from-platform-backups.md),
[0027](../adr/0027-gate-production-static-publication.md), and
[0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md)
remain authoritative. [ADR 0030](../adr/0030-reconstruct-static-hosts-from-bound-backups.md)
is the explicit amendment reviewed with this plan. Implementation cannot
silently amend an ADR.

This phase includes component tests, independent installed cases, complete
disposable reconstruction, live storage qualification, usable operator tooling,
a dark-production handoff, and a records-only closeout. It does not enable
production publication, perform the M3.12 canary, requalify the public-edge/browser
matrix solely because time passed, introduce a public API, or change tenant
archive retirement. M3.12 retains its full acceptance gate and remains unstarted.

One M3.11 PR is open at a time. The plan is the first commit and first PR.
After its acceptance and merge, each implementation PR carries its meaningful
component and independently runnable installed coverage. Squash-merge only the
exact current head after required checks and configured automatic review finish,
with applicable findings resolved. Do not request reviews or post PR progress
comments. Technical replies explain findings resolved without code changes.

## 2. Existing implementation and remaining gaps

| Boundary | Present at baseline | M3.11 change and acceptance |
| --- | --- | --- |
| Backup | `roles/backup` supplies root-only configuration, repository serialization, 7/5/12 retention, source/exclusion fingerprints, and smoke restore. `backup-static-snapshot` validates lock inodes, takes shared publication then tenant-state, and refuses nonempty release staging. | Capture every authoritative store and a non-secret recovery descriptor. Prove coherent old/new state across all mutations, including state outside the current source set; distinguish smoke restore from reconstruction. |
| Audit | `audit.py` validates canonical hash-chained entries and deterministic 8-MiB segments, bounded ordinary allocation and the administrator reserve. Every existing reader expects a local contiguous chain beginning at zero. | Add strict archive descriptors, protected index and historical lookup witnesses; teach every reader to combine archived and local history. Never reset sequence, predecessor, correlation, deletion, or supersession authority. |
| Retention | Maintenance calls `forget --tag scheduled ... --prune`; it does not inspect audit archives. | Verify protected descriptors and content before either destructive phase; select an explicit ordinary-only deletion set. A scheduled tag alone must not make an audit snapshot eligible. |
| Recovery | Lifecycle/source-candidate recovery, archive construction/retirement, authorization repair, Caddy invocation fencing, release measurement and bootstrap are implemented. | Reconstruct a different host without backed-up Caddy runtime generations or transient inputs; reconcile from preserved authority before starting services. Existing in-place recovery cannot simply be pointed at a restored tree. |
| Qualification | Thirteen fresh installed groups, conservative selection, timing, bounded diagnostics and live Spaces evidence exist. | Add independent backup/audit/reconstruction cases through that registry and retain the complete cross-feature and live workflow. |

Code review starts with `audit.py`, `repository.py`, `execution.py`,
`intents.py`, `job_runtime.py`, `entrypoints.py`, `caddy_startup.py`,
`archive_recover.py`, the lifecycle recovery modules, and their component tests.
Installed foundations are `molecule/default/tests/test_host.py`, the M3.8
archive/transport/reboot tests, and the backup role. In particular, existing
audit lookup participates in result validation, failed-result repair,
never-deployed deletion, creation history and later-tenant inventory projection;
rotation is incomplete until all these consumers work across an archived prefix.

## 3. Backup authority and locking

### Sources and exclusions

Scheduled snapshots retain these sources, under the existing encrypted Restic
repository and backup credential, separate from the tenant archive Space:

| Source | Included authority and recovery treatment |
| --- | --- |
| `/srv/lowerduckpond` | Platform fixture and every retained immutable tenant release. Remeasure each restored release against its deployment record; reject extra releases except staging explicitly authorized by an intent. |
| `/var/lib/lowerduckpond/static` | Namespace and launch records; tenant desired/observed state, deployment/archive records; complete authorization/correlation/result/phase and emergency evidence; lifecycle/construction/retirement intents and quarantine; local audit, protected index/witnesses and recovery cursor. |
| `/var/lib/lowerduckpond/recovery` | Restore journal, original backup descriptor and immutable generation-mapping receipts. This root is outside the trees it installs and is included in subsequent backups as recovery provenance. |
| Staged `mariadb.sql.gz` | Existing consistent logical database dump. M3 tenant authority is filesystem state; no cross-database transaction is claimed. |
| Staged `static-recovery.json` | New versioned, canonical recovery descriptor captured under both static locks. Includes non-secret Caddy selection/start-intent evidence that lives outside the static tree. |

Exclude intake artifacts, authenticated-delivery exports, release `.staging`,
audit verification workspace, restore workspace, sockets, parser workspace,
caches, and abandoned temporary files. Exclude `/etc/caddy/generations`, adapted
configuration, `/var/lib/caddy`, Caddy environment files, archive/backup
credential files and generated secret-bearing host inputs. Tenant archive bundles stay exclusively
in the archive Space; Restic stores their authoritative records, not copies of
their bytes. The descriptor cannot contain environment or adapted-config bytes.
Audit metadata and root-owned restore journals are authoritative, not caches.

Caddy certificate/ACME storage is reconstructible and is removed from the M3.11
source set, not declared coherent under locks that Caddy does not take. Routine
backup therefore does not stop Caddy or race a live copy of that store. Restore
starts with an empty, correctly owned Caddy data directory and obtains origin
certificates using trusted host configuration and DNS-01 credentials before
opening public web ingress. Section 6 defines that gate and its failure cases.
The separately backed-up workstation origin-pull CA remains an operator input;
this decision does not discard it or replace Cloudflare's origin-pull identity.
ADR 0030 records the source-policy change explicitly. Preserve existing production
sources until the cold-storage reconstruction drill qualifies the replacement;
do not delete earlier snapshots merely because their source policy differs.

Expand excludes explicitly as new transient paths are introduced. A fixed
source manifest in code/Ansible and assertions on actual Restic trees prove
inclusion and exclusion, including secret canaries. Do not use a broad filesystem
root source or silently substitute a path selected by a caller. Lock files may
be present as inert backup files; a new host creates and validates fresh kernel
lock inodes before workers start and never replaces locks under live processes.

The recovery descriptor is `lowerduckpond-static-backup-v1`, at most 256 KiB.
It binds a root-generated capture UUIDv7, UTC capture time, source-policy digest,
selected host-agent artifact, repository binding, audit lineage and exact audit
terminal sequence/hash, namespace/launch digests, a streamed canonical digest
of authoritative relative paths/modes/bytes, and the bounded tenant/deployment/
release digest inventory. It embeds exact non-secret Caddy start intent and
active/previous/candidate generation identities, manifest and route-state
digests, plus the selected target. Absence is explicit, never inferred from a
failed read. Each supplied digest has a named format and SHA-256 algorithm.
The Restic snapshot ID is obtained after capture and therefore is not embedded
self-referentially. A capture UUID tag connects descriptor and snapshot.

### Lock contract and amendment

Retain the **implemented** shared publication then shared tenant-state capture.
ADR 0017's statement that backup takes only tenant-state is insufficient for
Caddy state writers that take only publication and for release staging guarded
by publication. Amend it explicitly in the plan PR; do not remove the existing
protection to match that sentence. No lifecycle lock order changes.

For backup-side commands, acquire the existing repository lock first, then any
host-agent selection lease, then publication, then tenant-state. Intake/export,
when needed by a restore coordinator, precede publication/state in their existing
order. Ordinary workers never acquire the repository lock. The installer never
calls a repository operation while holding selection exclusive. Backup never
acquires intake/export or upgrades a shared lock.

Snapshot capture holds both shared static locks through Restic's successful
completion, with validated inherited descriptors. Missing/unsafe/replaced lock
inodes, dirty release staging or unclassifiable authority fail without reporting
backup success. An interrupted lifecycle with complete final release objects and
durable intent is capturable; its outcome must be reconstructed by section 6.
Existing writers that affect any included authoritative path must hold the
appropriate exclusive lock; inventory each writer and fix any uncovered path
before the coherent-backup gate passes. Caddy-state readers hold publication.

Rotation and maintenance hold repository serialization, capture their local
authority under exclusive tenant-state, then release tenant-state for network
I/O. Rotation reacquires state only to compare-and-swap the same closed segment,
index head and intent before committing. It never waits for a worker that needs
its repository lock. No command waits synchronously for systemd while holding
publication. Root waits are bounded by their service runtime; ordinary lifecycle
contention remains retryable busy without allocating staging or unbounded waiters.

## 4. Audit formats, identity, and online lookup

All new formats reject unknown fields/versions, duplicate JSON keys, coercion,
noncanonical bytes, unsafe inode metadata and unsupported digest formats. Use
the existing canonical JSON plus LF and durable directory primitives. Integers
are nonnegative and bounded before allocation. UUIDs use the existing canonical
UUIDv7 grammar; snapshot/config IDs are complete 64-character lowercase hex,
never Restic's display abbreviations or `latest`.

Define `H(format, bytes)` as SHA-256 of ASCII format, one NUL, an unsigned
64-bit big-endian byte length, then the exact bytes. New descriptor, index,
witness and restore-journal digests use distinct `lowerduckpond-...-v1` domains.
Segment byte SHA-256 and the existing audit-entry digest retain their existing
formats; neither is substituted for the other.

### Repository and lineage identity

P2 persists a root-generated audit lineage UUIDv7 before its first recovery
descriptor, initialized only after validating the entire pre-migration local
chain and discovering that the bound repository has no protected history
requiring an existing lineage. Its root record binds the namespace digest
and repository binding; preserve it through host reconstruction. A host name
alone is not chain identity. An empty new installation may initialize a new
lineage; an index, archived history or tenant history cannot authorize reset.

Repository binding is a versioned digest over canonical JSON containing the
Restic config ID, configured node identity, and canonical repository locator.
For S3 the locator includes endpoint, bucket and repository prefix; for local
tests it is the canonical absolute path. Credentials, cache path and retention
counts are excluded. The binding is distinct from the mutable source/exclusion
scope and ADR 0029's region/archive-bucket/backup-bucket target digest. Changing
credentials does not change identity. A different repository ID/location/node
requires an explicit reviewed migration; do not rebind historical descriptors.
Private descriptors may contain locators; shareable reports contain only digests.

### Descriptor and protected snapshot

Each `lowerduckpond-audit-rotation-v1` descriptor is at most 16 KiB and contains:

- `schema`, `rotationId`, `lineageId`, `repositoryBinding`, `createdAt`;
- `segmentNumber`, `segmentName`, `firstSequence`, `lastSequence`, `entryCount`,
  `segmentBytes`, `segmentSha256`;
- `predecessorEntryDigest` (null only at sequence zero), `terminalEntryDigest`;
- `previousDescriptorDigest` (null only for the first archived segment);
- `witnessFormat`, `witnessBytes`, `witnessDigest`.

`segmentName` is derived from its zero-based 20-digit segment number, never a
free path. Ranges and counts must agree with the restored segment, and archived
segments form a contiguous prefix. A closed segment has a durable successor;
never force-close or remove the current tail to manufacture rotation capacity.

Create one dedicated snapshot of an isolated, sealed directory containing only
`descriptor.json` and `segment.jsonl`, at the fixed source
`/var/cache/lowerduckpond-backup/audit/snapshot`. Restic's structural parent
directories are permitted; extra payloads are not. Its required tags are
`lowerduckpond-audit-archive`, `lineage-<uuid>`, `rotation-<uuid>`, and
`repository-<binding digest>`, with the bound node host. It must not have
`scheduled`. Verify the complete snapshot tree, paths, safe types, byte lengths,
canonical descriptor, descriptor digest, entry schemas and full hash chain by
restoring both files into a fresh bounded workspace. Snapshot existence or a
successful backup exit alone never permits local removal.

### Durable index and bounded historical witnesses

Store archive metadata below `static/audit/archive/`; local `segment-*.jsonl`
remain at their current paths. A versioned `head.json` binds lineage, repository,
last indexed segment/sequence/terminal digest and the preceding immutable index
record digest. An immutable record for each segment embeds its descriptor and
adds the full `snapshotId`, exact required tag set, descriptor digest, witness
digest and previous index digest. One fixed `rotation-intent.json` records the
root attempt, expected index head, exact source identity/digest, phase and
discovered snapshot IDs. All live-to-archive overlap must agree byte-for-byte.

Online workers continue to have no backup credentials or network. For each
archived segment, keep a root-generated immutable **lookup witness** beside its
index record. This is a canonical JSON array of fixed-order rows containing
sequence, predecessor digest, timestamp, principal, operation, tenant ID,
correlation ID, result digest/status and deletion evidence (explicit null when
absent). Constant API version/kind are supplied by the witness format. Thus a
row reconstructs the exact original canonical audit entry and digest without
dropping any authority used by existing readers. This deliberately retains
bounded local authorization evidence after removing the segment file; it is
not a second independently authored audit history.

Before sealing the descriptor or creating a snapshot, deterministically build
a provisional witness from the validated closed local segment and bind its
exact length/digest in the descriptor. This provisional copy has no lookup or
removal authority. After restoring and verifying the snapshotted segment and
descriptor, independently regenerate the witness from those restored bytes and
require exact agreement with the descriptor binding and any surviving
provisional bytes. If interrupted staging is absent, regenerate it from the
unchanged closed local segment when present and compare again; the immutable
descriptor and restored bytes remain sufficient when recovering an already
indexed removal. Absence of a transient provisional copy cannot reset identity.
Only that verified witness may be installed with the immutable index before
head commit; never modify a descriptor after it has been snapshotted. All ordinary
audit APIs merge witnesses and the local suffix in sequence order, verifying
continuity and duplicate-correlation rules across the join. Preserve creation,
deployment, deletion, result replay, failed-audit repair and supersession
semantics. No witness is trusted if its immutable index binding is absent or
disagrees. During recovery, regenerate a missing witness only from the exact
verified protected snapshot; do not accept a digest without its entries.

Witnesses plus index metadata have a 32-MiB/8,192-inode sublimit, at most 4,096
archived segments and 65,536 witnessed entries. These are additional limits,
not an expansion: count their allocated blocks, directories and temporary
replacements within the existing 128-MiB ordinary audit allowance. The separate
8-MiB administrator reserve remains unavailable to ordinary work and rotation.
Reserve worst-case metadata/witness allocation before starting. Exhaustion
closes rotation/new ordinary admission; it does not evict witnesses, reset
history or expire remote evidence. M3's existing permanent correlation ceiling
also remains. A later index expansion/compaction requires reviewed migration.

## 5. Durable rotation, discovery, retention, and health

Rotation defaults off until retention protection and restored-state consumers
are installed and qualified. Process at most one closed segment per invocation.
Once enabled, an hourly timer rotates the oldest eligible closed segment;
ordinary audit usage at 64 MiB raises a warning before the 128-MiB ceiling.
Admission reserves witness/index headroom, so reaching the ordinary ceiling
cannot authorize borrowing the administrator reserve for rotation.
At every durable write use file sync, rename and parent sync; removals require
parent sync. Compare revisions before each transition. Tests inject termination
on both sides of every primitive, not just at named phase boundaries.

| Durable boundary / interruption | Required recovery outcome |
| --- | --- |
| Before prepared intent | Local segment remains authority; safe abandoned private staging is removable. No remote request has authority. |
| Prepared intent and sealed descriptor synced | Revalidate exact segment and expected index head. Enumerate protected descriptors for the attempt before any new snapshot request. |
| Snapshot committed, response lost or ID not synced | Discover by full repository/lineage/rotation/descriptor binding, restore-verify the candidate, then persist its full ID. Never blindly create another snapshot. |
| Snapshot ID recorded, restore verification partial | Discard only private verification output and repeat exact-ID restore/validation. Preserve local segment and snapshot. |
| Verified bytes, witness/index file synced but head not committed | Validate the immutable pending files and finish only the same expected-head compare-and-swap. Local segment stays present. |
| Index head renamed, parent sync uncertain | Re-read old/new head and immutable chain; finish a provable old/new state. Restore verification repeats before first removal after restart. |
| Index durable, local unlink not done | Require the indexed snapshot, descriptor, witness and segment equality again; unlink that segment only. |
| Local unlink done, directory sync or intent removal interrupted | The verified index supplies history; finish directory sync and intent cleanup without appending or renumbering an entry. |
| Any missing, corrupt, conflicting or unclassifiable evidence | Preserve every remaining file/snapshot, mark critical, close rotation and ordinary admission. No best-effort deletion or new genesis. |

Enumerate protected tags during startup reconciliation, before rotation and
before maintenance. A valid unindexed descriptor is recovered only when its
prefix position, lineage, predecessor and bytes uniquely agree with local
authority. Byte-identical duplicate snapshots for the *same* descriptor/attempt
are equivalent copies: retain all, select the lexicographically smallest full ID
when no index already selects one, and durably list the other IDs as protected
duplicates. Preserve an already indexed ID. Different descriptors for the same
position, different attempts without matching durable authority, a fork, gap,
wrong repository, or ambiguous discovery fail closed. Do not delete duplicates
in M3 or use an arbitrary newest snapshot to resolve a conflict.

### Retention protocol

Maintenance first inventories the complete repository snapshot metadata and
protected descriptors, reconciling unindexed attempts. Verify every indexed
and duplicate protected snapshot by exact ID/tag/binding and restore its
descriptor and segment; compare witnesses. Unknown protected data or an indexed
snapshot whose tag was removed is critical. A simultaneous `scheduled` tag is
an invalid protected snapshot, never an ordinary retention candidate.

Compute 7/5/12 retention only over the ordinary `scheduled` set for the bound
node, grouped by host and source paths as today. Use Restic's bounded JSON
dry-run selection, then independently reject any proposed ID in the protected
inventory or referenced by any index/intent. Persist a maintenance intent with
the exact remove IDs and protected inventory digest. Run `forget` on those full
ordinary IDs, without a combined `--prune`. Re-enumerate and reverify protected
evidence before running `prune`; then run `check` and verify protection again
before recording success. Keep protected snapshots outside ordinary counts
indefinitely, including snapshots older than every daily/weekly/monthly window.

After interruption during forget, reconcile the fixed ID set with present
snapshots; already absent ordinary IDs are completed work. Before any resumed
prune repeat the protected proof. After interrupted prune require Restic
integrity and protected-content validation; failure leaves maintenance critical
and needs operator investigation. Never automatically unlock/repair a repository
or call `forget` to eliminate a failed proof. The supported Restic 0.18.x
[retention semantics](https://restic.readthedocs.io/en/v0.18.1/060_forget.html)
separate snapshot removal and data pruning; tests exercise both independently.

The repository lock serializes all supported backup-side operations and
configuration activation; Restic's own locks remain enabled. Out-of-band root
retagging/deletion is not made safe by this lock and is detected by subsequent
verification. During M3 there is no protected-snapshot expiry command or
provisioner capability to forget, prune, retag, truncate, rotate or use reserve.

### Bounds, privileges, and failures

New audit verifier/rotator services run as root with only the backup environment,
fixed commands, private workspace, no archive credential/socket, no interactive
shell input, metadata endpoint denial, and the existing backup hardening.
Ordinary executors read only local witnesses; Caddy and both ordinary accounts
cannot read them. Install root commands at `0700`, without a sudo rule for the
provisioner or forced-command operator. Artifact selection leases prevent mixed
schema implementations during backup/recovery.

Use one 32-MiB/128-inode verification workspace and stream at most one 8-MiB
segment at a time; descriptor output is 16 KiB, inventory metadata 16 MiB and
8,192 snapshots. Oversized listings fail before unrestricted allocation. The
verifier/rotation unit has `MemoryMax=256M`, no swap, `TasksMax=32`,
`LimitNOFILE=256`, one CPU and a 5-minute runtime. Backup and maintenance each
have `MemoryMax=512M`, no swap, 32 tasks, 1,024 descriptors, one CPU and a
30-minute runtime. These are new explicit bounds, subject to qualification;
timeout is failure, never permission to weaken validation or extend a deadline
to force success. Existing parser/worker limits remain unchanged.

All staging accounts actual blocks/inodes and preserves the greater of
5 GiB/10% blocks and 100,000/10% inodes through worst-case allocation. Snapshot
count or service-budget exhaustion leaves local evidence and a fixed diagnostic.
M3 retains protected remote data indefinitely and reports count/bytes; an
operator must provision storage or review a later migration when capacity is
exhausted, not age out protected evidence.

Extend existing health/textfile reporting with fixed categories for protection,
rotation pending, index corruption, archive unavailability, restore phase and
resource exhaustion. Durable status binds repository/lineage/index head and
verification time, never raw object names or content. Missing, stale (>24 hours),
future-dated or wrong-scope proof closes ordinary admission and rotation. Run
protected verification at boot and at least daily; maintenance/rotation always
perform fresh proof. With no archived prefix, validate the local chain and empty
protected inventory. Status is an admission cache, not deletion authority.
Existing healthy traffic need not stop solely because remote backup health is
critical; restored-host startup remains closed until its full gate passes.
Administrator diagnosis and evidence-preserving recovery remain available.

## 6. Restored-host protocol and unavailable remote versions

### Bootstrap and authority

Add a root-only `restore-static-host` command and an Ansible recovery-bootstrap
mode. The workstation supplies a full scheduled snapshot ID and a private,
validated target configuration, not arbitrary shell commands. Production
reconstruction is an explicit administrator maintenance action; qualification
uses newly created disposable hosts. Reuse the private environment-file and
disposable-shell workflow; no credential values enter this workspace.

Before restoring bytes, durably close public HTTP/HTTPS ingress while preserving
administrative SSH, and stop/mask Caddy, operator ingress, lifecycle workers,
reconcilers, rotation and retention. Install verified immutable code, frozen
Caddy unit/launcher, recovery gate, filesystem layout and fresh locks. A durable
root restore marker and startup checks enforce the mask after reboot. A plain
converge must detect that marker and refuse ordinary bootstrap/enablement.
Never start an empty platform-only generation over restored tenant history.

Restore to a private target on the intended filesystems. Verify full snapshot
identity, source policy and recovery descriptor; safe paths/types/ownership;
namespace and launch policy; every record schema/digest; complete authorization
and result relations; all retained release digests and resource bounds. Unknown
inputs fail before installation. Historical snapshots lacking the M3.11 recovery
descriptor remain available for private inspection, but do not pass the new
automated recovery gate. Obtain a new coherent snapshot before rotation rollout.

Discover protected audit descriptors independently of the recovered index.
Reconstruct its unique ordered prefix and validate the local suffix through
the scheduled snapshot's exact terminal sequence/hash. Remote descriptors can
postdate the backup: use only the identical prefix through that boundary,
including an identical overlap with a locally backed-up segment. Preserve later
evidence separately; never replay a future audit entry into old tenant state.
A descriptor crossing the snapshot terminal requires exact prefix verification
for diagnosis, but its future suffix proves a later timeline and blocks automated
restoration. The same applies to a wholly later descriptor. Preserve all that
evidence and select a newer coherent backup or obtain a separately reviewed
recovery decision; never extend the old prefix into a competing history under
the same lineage. A fork, unknown lineage, missing required segment or unequal
overlap also blocks service.

The restore journal `lowerduckpond-host-restore-v1` is canonical, root-owned and
at most 256 KiB, at `/var/lib/lowerduckpond/recovery/host-restore.json`.
The fixed coordinator lock and restore gate also live outside replaced roots;
restored journals are inspected as prior provenance, never installed over the
current coordinator's journal or gate. It binds restore UUIDv7,
snapshot/capture/repository/lineage IDs,
original artifact and input digests, destination identity, trusted new input
digest, phase, exact inventory digests, chosen lifecycle recovery outcomes,
old-to-new Caddy generation bindings, and verification receipts. Each phase
compare-and-swaps the prior journal digest; preserve the original immutable
backup evidence. It is separate administrator provenance, not a fabricated
ordinary tenant job or a rewrite of historical audit entries/results.

### Recovery decisions

| Restored condition | Required decision |
| --- | --- |
| Valid settled active/suspended/undeployed/archived tenant | Preserve identity, lifecycle, slug, manifest and retained deployment history. Only active state gains routes after the final gate; archived state remains archived. |
| Lifecycle intent with captured candidate selected and complete candidate authority/content | Complete only that intent's candidate using existing operation-specific transformations, result and audit rules. Validate every required exact remote version first. |
| Captured source/prior selection with complete source authority | Restore the exact intent-authorized source, preserving suspension and absent routes; produce only the existing authorized failure outcome. |
| Mixed records recoverable by the existing intent | Finish the same old/new choice under locks, independently verifying records, releases and terminal result. Selection alone never substitutes for those proofs. |
| Missing selection proof, unrelated records, absent required release or contradictory terminal result/audit | Stop; preserve evidence. Do not guess from timestamps or observed state alone. |
| Pending deploy/import with excluded input, no committed lifecycle intent/result | Bind an explicit terminal `restore_input_unavailable` failure to the original job and preserved source after validation. No upload recreation or success. A new authenticated request can supply the artifact after recovery. |
| Claimed deploy/import with intent and durable release | Reconcile from intent and release; do not require already-consumed intake bytes. If neither source nor candidate can be proved, stop. |
| Committed export with absent transient delivery file | Retain immutable result/digest and mark delivery retired through durable recovery evidence; replay cannot regenerate a different export or extend its lifetime. |
| Archive construction/retirement intent | Reconcile its related lifecycle first. Preserve still-bound versions. Classify unbound objects before any exact-key retirement; ambiguity stays charged and closed. |
| Interrupted Caddy ordinary/transactional start | Preserve old invocation/attempt evidence. Reconstruct state first, then create a new explicit host-restore transaction; never reuse another host's systemd invocation or pretend its old generation started. |

The new missing-input terminal outcome and explicit disaster-recovery Caddy
transaction need the reviewed ADR amendment in the plan PR. The latter permits
regeneration under new trusted host inputs, not in-place startup fallback or an
attempt refund. Existing live restart limits and immutable results stay intact.

Reconstruction does not invoke ordinary tenant `restore` merely to verify an
archived tenant: that operation creates a new deployment and retires the source
version. Instead use the existing exact-version reader and bounded parser to
validate the archive record, archived manifest, bundle and release-tree digests,
then discard private verification bytes. Keep that tenant archived and its
object bound. Archive and backup credentials remain in separate helpers.

### Remote state newer than the backup

ADR 0025 explicitly requires both platform state and its referenced exact tenant
archive versions. ADR 0019 retires those versions after successful restore or
deletion. Consequently, an older ordinary backup is **not a guarantee** that
every referenced archive still exists. M3.11 does not pin retired versions,
reupload content under new version IDs, copy bundles into Restic, substitute
current-key reads, or treat audit tombstones as content authority.

If any required exact version is absent, unreadable, corrupt or ambiguous,
leave the entire restored host gated and emit the specific fixed category plus
private diagnostic identity. Operator options are a newer coherent backup whose
required versions verify, independently recovered *identical* version evidence
through a reviewed storage recovery, or a separately reviewed data-loss/lifecycle
decision. There is no automatic tenant drop, suspension, emergency deletion or
partial serving escape hatch. Retention of tenant archives would require a
separate ADR amendment; it is not implied by this plan.

A restored old retirement/construction intent cannot authorize deletion of
objects belonging to the later live timeline. Fence the source host before any
destination mutation. Compare the complete remote version/marker/multipart
inventory with the recovered authority. Unknown/newer objects are preserved,
reported privately and keep recovery closed; the operator selects the correct
snapshot or explicitly reconciles the timeline. Disposable drills use an owned
storage fixture and prove source/destination exclusion. Production recovery
never mutates archive storage while another host may still write it.

### Installation, publication, and interrupted restore

Persist phases `prepared`, `restored`, `validated`, `reconciled`,
`runtime-prepared`, `installed`, `verified`, `complete`. Before `installed`,
only private restored trees may change. Journaled same-filesystem renames install
each validated state/release root; interruption between roots leaves the restore
gate closed. Record old/new root identities before each rename, sync parents,
and resume only that transaction. Never merge unknown destination files into the
restored tree. Preserve the original snapshot and prior destination until the
new host passes verification; do not double-count available free capacity.
No ordinary worker may hold a state lock during installation. The coordinator
holds its separate fixed lock, discards restored kernel-lock files as inert
input, creates/validates fresh static lock inodes after installing the roots,
and only then permits a service to acquire them. Preserve the validated durable
recovery cursor separately from those recreated lock files.

Build complete Caddy generations from trusted reviewed binary/base/credentials
and reconciled tenant state. Record old-to-new runtime IDs and route-state
digests in restore provenance; update only the runtime observation references
authorized by that mapping, preserving tenant manifests, deployment identities,
historical audit timestamps and immutable operation results. Terminal replay
must validate those mappings rather than accept arbitrary generation drift.
No old adapted configuration/environment is installed from backup.

Only after all state, audit, release, exact-version, quiescence, capacity,
namespace/launch and trusted-configuration checks pass may the coordinator
unmask/start Caddy through the normal invocation-fenced verifier, with public
web ingress still closed by the durable restore firewall gate. The gate drops
non-loopback HTTP/HTTPS before the ordinary ingress allowlist; SSH and DNS-01
outbound traffic retain their existing policy. Boot ordering installs that gate
before Caddy or any ordinary firewall reapply can admit traffic.

Caddy starts with empty certificate/ACME storage and regenerates it using the
reviewed DNS-01 policy and configured issuer. Preserve acquired state across an
interrupted recovery attempt rather than repeatedly registering new accounts
or requesting certificates. Require valid certificate/key pairs for every
trusted configured apex/wildcard subject, matching names, issuer/trust chain,
validity at the current time, and the selected Caddy generation's TLS policy.
Verify the certificates actually presented on loopback against that evidence;
do not interpret an ACME request, Caddy process start or admin health alone as
certificate readiness. The loopback probe does not relax authenticated origin
pulls or make an unauthenticated application request. Caddy's
[automatic HTTPS](https://caddyserver.com/docs/automatic-https) provides issuance;
the restore coordinator supplies the explicit readiness and public-ingress gate.

Unavailable DNS credentials, CA/network failure, issuance rate limits, missing
or invalid certificates, or an exhausted existing service/coordinator deadline
leave public ingress closed and a fixed diagnostic. Do not extend timeouts,
reset Caddy attempts or switch to internal/self-signed TLS on production.
The operator resolves the cause and resumes the same journaled restore.
Workstation origin-pull trust and Cloudflare configuration are verified trusted
inputs; fresh origin certificates do not replace them.

Keep operator ingress and mutation/maintenance timers stopped until the selected
runtime, TLS and routes match verified state. A failed start retains the restore
marker and ordinary bounded attempt evidence; interruption after unmask cannot
bypass the pre-start or firewall gate. Reboot with the gate closed and exact
old-result replay are final acceptance steps. Mark `complete` durably before
idempotently removing the restore-only firewall rule and restoring schedules/
ingress. This restores the reviewed ordinary firewall; it never admits a broader
source set. A crash after completion but before opening remains safely closed.

The recovery coordinator has a 30-minute runtime, 512 MiB, no swap, 32 tasks and
one CPU; helper/parser ceilings remain unchanged. Restore space is reserved
from the snapshot inventory before allocation, with the ordinary free floors
remaining after both private candidate and retained destination. Oversize or
unfinished work fails closed for operator diagnosis, not automatic timeout
extension. Tests cover each write/sync/rename/mask/unmask/start/marker boundary.

## 7. Qualification, CI, and evidence

Add the following fixed installed registry cases. Every case creates its own
owned fixture through sustainability tooling, declares exact no-skip receipts,
uses production admission/resource policy, records timings, and obtains fresh
local and independent remote accounting before teardown. Fixture builders may
share code; assertions cannot depend on another group's leftover tenants.

| Group | Independent setup and required invariants |
| --- | --- |
| `backup-coherence` | Supported active/suspended/archived/undeployed fixtures; snapshot versus create/deploy/import/rollback/rename/suspend/resume/archive/restore/delete/emergency/reconcile, authorization repair, release cleanup and Caddy/Ansible overlap. Restored descriptor/state/releases are one recoverable boundary; excludes contain no canary secrets. |
| `audit-protection` | Own Restic repository and closed-segment fixture; descriptor/schema/repository/tag failures, wrong full ID, aged ordinary snapshots, duplicate/orphan discovery, missing witness/index, real restore verification, interrupted forget/prune and indefinite protection. Rotation still disabled during the first implementation slice. |
| `audit-rotation` | Supported tenant history spanning a closed segment; interrupt every snapshot/index/witness/head/unlink/sync phase, retry and reboot. Original correlations/results, deletion and later-transition authority survive local removal; ordinary cap/admin reserve/provisioner denial are enforced. |
| `restore-reconstruction` | Fresh source and second fresh host, exact scheduled snapshot and archive versions; all four tenant states, retained release digests, archived prefix/local tail, excluded intake/export outcomes, intent recovery and trusted Caddy regeneration. Start fails at every inconsistent intermediate state; reboot and result replay pass. |
| `restore-tls-bootstrap` | Own restored fixture with empty Caddy storage; cold certificate generation, readiness versus process health, interrupted issuance, reboot and durable web-ingress gating. Local controlled issuance covers deterministic faults; the final live drill separately proves public-CA DNS-01 on owned disposable names. |
| `restore-negative` | Fresh source/destination; retired exact version, inaccessible/corrupt version, unknown later remote objects, wrong namespace/launch/repository/artifact, forked audit, mixed roots, unavailable trusted inputs and source fencing failures. No routes, destructive cleanup or success report. |

Component/process tests cover every durability primitive with exception and
process-exit injection, schema golden/hostile vectors, byte/count/inode/free-space
boundaries, real lock schedules, snapshot IDs, digest separation, complete
historical-reader equivalence, restored-job decisions, provenance mapping and
report rejection. Installed tests prove the actual Restic/systemd/identity/
filesystem/credential boundaries, not only mocks. Use at least two real 8-MiB
segment transitions in installed rotation qualification; do not add a production
limit override to shorten tests. A deterministic root fixture may supply extra
canonical audit entries only in a test-owned audit lineage, while ordinary
operator-driven history proves authorization behavior in its own fixture.

Shared backup/audit/recovery/schema/Ansible/selector changes select the complete
installed matrix until a narrower dependency map is reviewed and proved. The
existing stable `Ansible`/`Gate` requires every selected receipt. Documentation
selection may skip installed groups without changing ADR 0029's input identity.
Keep all existing thirteen groups and the original complete journey; add a
cross-feature sequence covering backup, protected rotation, tenant mutation,
reconstruction and reboot. Weekly/manual full runs retain all groups and the
complete journey, and a scheduled regression blocks release.

Targets remain five minutes for focused components, fifteen for fast lanes and
thirty including setup for each installed case. Split a case at independent
fixture boundaries if measured scope needs it; do not loosen production limits,
broaden retries or increase CI timeouts to obtain a pass. Collect measurements
from normal validations, including failures, setup, pacing, wall time and total
runner minutes. The complete live run retains the existing 330-minute safeguard;
record its measured cost. A budget exception requires explicit review before
closing the milestone. Avoid repeated expensive runs without changed inputs or
an unresolved failure. When only a long lane remains, record head/run links and
resume from durable task state after the operator reports the result.

Final qualification includes the original complete installed/live Spaces
workflow plus the new combined reconstruction cases on disposable supported
Ubuntu/ext4/systemd hosts. Extend the secure-workstation wrapper and report
validator, not a parallel bypass. Test real Restic in a dedicated qualification
repository/prefix in the backup Space and exact versions in the archive Space;
do not run retention against the production backup repository. Preserve the
existing whole-bucket and mutual-denial rules. Local/MinIO evidence establishes
local behavior only. Live-provider proof is a separate mandatory operator step.

The final wrapper also requires a cold-certificate recovery receipt using the
pinned Caddy build, public CA and existing DNS-01 credential on run-owned
disposable apex/wildcard names in both configured zones. Bind those names privately
to the run and report their digest; never use production serving names or replace
production certificates. Prove the ingress gate stays closed before readiness,
survives interruption/reboot, and opens only after TLS verification; confirm
challenge cleanup during owned-fixture teardown. A local internal CA cannot
satisfy this receipt. This validates the changed recovery dependency and does
not reopen the complete M3.12 production edge/browser/renewal gate.

Protected snapshots in a disposable qualification repository have no production
retention authority: after the successful drill and fresh independent accounting,
retire the entire owned fixture through the explicitly authorized qualification
teardown. This cannot expose a runtime command to expire individual protected
production snapshots. A failed proof retains the fixture and original failure.

Publish an M3.11 invariant-to-test/evidence map and a new versioned report envelope
that retains the original source, exact artifact, ADR 0029 input policy/digest,
storage-target digest, source/destination fixture identities, phase times,
snapshot/descriptor/index digests, counts, final accounting and check outcomes.
Raw snapshots, object coordinates, audit events and logs stay private. Require
every declared phase and teardown; missing, skipped, failed, future-dated or
diagnostic reports cannot qualify. Preserve seven-day oldest-observation
consumption and 24-hour packaging bounds; no timestamp refresh. Capture target
identity before provider proof and verify it again at packaging/convergence.

## 8. Migration, operator handoff, and rollback

Install in this order: P2 repository/lineage schema support and validated lineage
initialization, then coherent backup descriptors; P3 index/witness readers and
retention guard; rotation machinery (off);
restored-host gate and qualification; then reviewed dark-production convergence.
Migration validates the old complete local chain and records its exact head
before initializing an empty archived prefix. It never renumbers entries or
turns a normal scheduled snapshot into a protected snapshot by retagging.
Existing input/source fingerprints change when sources/exclusions/policy change;
take and restore-verify a new matching backup. Keep old snapshots/sources until
the new reconstruction drill passes. No implementation PR enables production
rotation or publication automatically.

Before requesting operator action, deliver exact commands in
`docs/operations/m3-11-backup-recovery.md` with prerequisites, expected receipts,
bounded diagnostic collection and resumable phase rules. Required interfaces
to implement and qualify are:

1. `just m3-11-spaces-qualification` in the existing private environment shell:
   final clean merged inputs, disposable reconstruction and live storage proof;
   return only the documented report/checksum and optional timing/failure JSON.
2. `just preflight-m3-11-production`: read-only predecessor/artifact/completion,
   dark publication, empty production tenant history, backup repository,
   archive accounting, fresh credentials/edge/firewall and free-space checks.
3. `M3_11_QUALIFICATION_REPORT=/absolute/private/run/qualification.json just configure-production`:
   separately authorized operator execution, two converges, acceptance,
   matching backup and disposable reconstruction proof. Preserve
   `static_publication_enabled: false`. Default rotation remains off until the
   protected verification/recovery gate passes, then enable it through the
   reviewed M3.11 configuration transaction, never a direct file edit.
4. Root `restore-static-host --snapshot FULL_ID` on a prepared fenced recovery
   target, plus `--status` for read-only phase inspection. Repository and paths
   come only from trusted installed configuration. This is documented disaster
   recovery, not an instruction to reconstruct production during M3.11 rollout.

These names are planned interfaces, not commands available at the baseline.
Qualification alone does not deploy. Production credentials/live execution stay
on the secure workstation, using its existing private environment-file launcher
and pinned Mise tools. An operator runs production convergence explicitly;
the coder task prepares everything independently possible before that handoff.

Before any local segment removal, rollback can disable rotation and use the
preceding implementation only after proving it understands the current layout
or restoring the preserved pre-migration state on a fenced target. After index
use/local removal, never select an old reader unaware of archived history.
Disable rotation and maintenance, preserve the working new readers, and deliver
a forward repair, or perform the qualified gated restoration. Do not delete
indexes/snapshots, rewrite audit history or silently hydrate beyond local caps
to make downgrade pass. Runtime rollback retains the existing Caddy/tenant
authority safeguards. Publication false is not a later tenant shutdown switch.

## 9. Ordered PRs and completion evidence

| PR | Prerequisite and reviewable result |
| --- | --- |
| P1: plan and explicit ADR amendment | This document is the first commit. Settle locking, reconstruction authority, formats, failure cases and scope; merge before implementation. |
| P2: coherent backup and recovery descriptor | P1. Complete source/writer inventory, repository binding and lineage schema/validated initialization before the first descriptor, exact capture authority, bounded units and `backup-coherence` coverage. No rotation. |
| P3: protected audit verification and maintenance | P2. Descriptor/index/witness schemas and readers, empty-index initialization against the existing P2 lineage, orphan discovery, retention guard, health and `audit-protection`. Rotation remains off. |
| P4: durable rotation and historical consumers | P3. Snapshot/verify/index/remove state machine, all lookup consumers, resource/reserve boundaries and `audit-rotation`. Keep production feature off. |
| P5: restored-host reconstruction | P4. Gated bootstrap including cold TLS storage, exact-version and timeline checks, missing-input decisions, generation mappings, independently runnable positive/negative/TLS recovery groups and operator restore instructions. |
| P6: combined qualification and production handoff | P5. Cross-feature journey, final live wrapper/report validation, evidence map, reviewed rollout/rollback commands, timings and complete local/CI proof. Complete live qualification and explicit operator convergence after this final input-changing PR merges. |
| P7: records-only closeout | Passing P6 qualification and recorded operator handoff/execution outcome. Original byte-for-byte shareable reports/checksums, source/artifact/input/target identities, actual deployed identity, acceptance and remaining limitations. No requirement/runbook edits. |

Split a boundary only when review size or fixture independence warrants it;
seven is an estimate. A contract change discovered later gets a reviewed plan/
ADR amendment before dependent implementation. Each slice includes its tests
and operator behavior; P6 integrates them rather than postponing correctness
testing. Keep durable private task notes with current PR/head, checks/review,
completed decisions, next slice and required operator actions.

Completion requires all five implementation objectives to have passing mapped
evidence, the final complete secure-workstation qualification, usable and
reviewed production instructions, the explicit operator production outcome,
and accepted records-only closeout. If the operator has not executed the handoff,
state that blocker and the actual deployed predecessor; do not call merged code
deployed or declare M3.11 complete. Record-only descendants retain the original
qualification identity under ADR 0029 and must not force another deployment.
M3.12 remains unstarted throughout.
