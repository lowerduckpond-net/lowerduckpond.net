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
immutable to both the provisioner and Caddy. It records the versioned canonical
release-tree digest defined by ADR 0019; the admitted ZIP-byte SHA-256 remains a
separate artifact digest. Caddy receives read-only access.

Generate complete, immutable, root-owned Caddy runtime generations below
`/etc/caddy/generations/<generation-id>/`. Each generation contains a manifest
of exact file digests, the pinned Caddy binary, Caddy-only environment, complete
adapted base-and-tenant configuration, and route metadata. Each canonical
tenant route is derived only from validated tenant ID, state, and deployment ID
and points directly to an immutable release; it never follows a
provisioner-controlled `current` link. A separate alias route is derived from
the validated slug and tenant ID and can return only the fixed platform
redirect defined by ADR 0023. It cannot serve or proxy the release. Unchanged
host payloads may be root-created hard links to the same immutable inodes, but
every generation is independently manifest-verified.
Validate the complete candidate with its own binary and environment, atomically
replace one root-owned active-generation reference, and commit it through the
synchronous reload path or durable restart state machine described below. If
activation fails, restore the preceding reference and the complete
last-known-good runtime generation.

Every process that changes live Caddy inputs or advances a reload or restart
uses the same global publication lock for each state transition. No process
holds it while synchronously waiting for a systemd job whose `ExecStartPre`,
launcher, or `ExecStartPost` must acquire it. Before tenant publication is
enabled, refactor the Ansible Caddy role to stage only its proposed base
configuration, environment, and binary outside live paths. A root-owned
host-configuration transaction then acquires the publication lock, reconciles
earlier intent, rereads authoritative tenant desired and observed state, and
derives the complete current route set. While still holding the lock it combines
those routes with the staged host inputs, validates and durably installs the
final complete candidate generation, and only then records intent and selects
it. A candidate assembled from tenant routes before lock acquisition is never
eligible for selection. Ansible no longer writes an independently consumed
live Caddy input or invokes an independent reload. The provisioner's sudo
capability cannot invoke this broader host-configuration transaction.

Keep the systemd unit and a small generation launcher as a frozen root-owned
bootstrap, not members selected independently with each runtime generation.
The Milestone 3 migration stops and masks Caddy, installs that bootstrap and the
first complete generation, reloads systemd, runs reconciliation, and only then
unmasks and starts Caddy. Any later bootstrap change is a conspicuous maintenance
transaction with the service stopped and masked until its unit, launcher,
recovery gate, and runtime compatibility have been installed and verified; a
crash leaves Caddy unavailable rather than starting a mixed generation.

Pin `Restart=on-failure`, `RestartSec=5s`, `StartLimitBurst=3`, and
`StartLimitIntervalSec=60s` in the frozen unit rather than relying on systemd
defaults. Before every start and automatic restart, a privileged `ExecStartPre`
recovery gate acquires the publication lock and reconciles any intent. A
transactional restart intent contains a selected start target (`candidate` or
`previous`), a separate attempt counter for each target, and the systemd
invocation ID bound to the current attempt. The first start for a target durably
advances its phase to `candidate-starting` or `recovery-starting`, sets its
counter to one, and binds the current invocation ID.

A start with no existing intent is an ordinary startup, including the first
post-migration start, a normal boot, an explicit service start, or an automatic
restart after a previously successful transaction cleared its intent. Under
the publication lock, `ExecStartPre` reads the active reference once, opens and
manifest-verifies that immutable generation, and proves its captured route
state still matches current authoritative tenant state. It then creates and
syncs a distinct root-owned `ordinary-starting` intent that binds that exact
generation and manifest, expected running inputs, an attempt counter of one,
and the current invocation ID before allowing the launcher to run. It never
changes the active reference, chooses the last-known-good generation, or
creates an operation result on this path. A missing, malformed, unreferenced,
or authoritative-state-inconsistent active generation fails closed before
Caddy starts and requires root reconciliation or operator repair.

An automatic retry receives a different invocation ID. The gate may durably
rebind only when the intent remains in the same starting phase, the active
reference and manifest still select the same target, no prior invocation owns
the running main process, and its counter is below three. It records the prior
attempt as failed, increments the target's counter, binds the new invocation,
and syncs intent before releasing the lock. Any mismatch, exhausted counter,
duplicate invocation, or attempt to return to a prior target fails closed. The
unprivileged launcher then reacquires the lock while it reads the active
reference once, opens that immutable generation directory, verifies its
manifest, and opens every binary, environment, and configuration input relative
to the pinned directory descriptor without following links. It loads the
environment, passes the open configuration to Caddy, releases the lock after
all inputs are pinned, and executes the already-open binary; it never resolves
the active reference once per input, and it does not retain the lock for
Caddy's lifetime.

The reload helper uses the same pinned-directory-descriptor rule and sends the
already-open complete configuration to the running matching binary. A
configuration-only tenant transaction may reload and commit synchronously while
holding the publication lock because it does not traverse systemd's start
hooks. A host transaction that changes the binary or environment always uses
the restart state machine rather than reload.

For a restart, the host transaction may stage host-only inputs before acquiring
the publication lock. Under the lock it reconciles any earlier intent, captures
and hashes the authoritative tenant route state, constructs and validates the
final candidate, and durably records a root-owned restart intent. The intent
binds the operation and correlation IDs, previous and candidate generation IDs
and manifests, captured authoritative route-state digest, expected running
inputs, prior observed state, and a compare-and-swap phase. Under that same lock
acquisition it selects and syncs the candidate active reference and advances
intent to `restart-required`. It then releases the lock before idempotently queuing
`systemctl --no-block restart caddy`; a crash before or after queuing is
indistinguishable and recovery may queue it again while the nonterminal intent
remains authoritative.

After Caddy starts, a privileged `ExecStartPost` verifier acquires the
publication lock, proves that the systemd invocation, running executable,
loaded configuration, active reference, and healthy admin response all match
the intent's selected target, current attempt number, and current invocation
ID. A delayed verifier for an earlier attempt cannot advance state. Only the
matching verifier commits observed state and audit before clearing intent. It
also commits the immutable operation result for a transactional restart, or
bounded startup-health evidence for an ordinary start. The originating host
transaction waits for its result without holding any host lock. A bounded client
timeout does not clear intent or independently roll back; the post-start
verifier or reconciler owns the terminal transition.

If candidate start or verification fails, a separate privileged recovery unit
triggered through `OnFailure=` acquires the publication lock, selects and syncs
the preceding complete generation, and advances the same intent to
`rollback-restart-required`. It releases the lock before idempotently queuing
the non-blocking recovery start. Because the service retains
`Restart=on-failure`, the recovery helper must first run the fixed
`systemctl reset-failed caddy.service` operation after the prior reference and
`rollback-restart-required` phase are durable, and only then run
`systemctl --no-block start caddy.service`. This resets the failed state and
start-rate counter that exhausted the three candidate attempts without
weakening the unit's ordinary automatic-restart limit. It also resets only the
recovery attempt counter before selecting the preceding generation's first
invocation; the recorded candidate attempts remain immutable evidence. Both
commands are idempotent; a crash between them leaves intent authoritative, and
reconciliation repeats the reset and start without another recovery transition.

The same pre-start, launcher, and post-start path pins and verifies the prior
generation, records the failed operation result and audit event, and clears
intent only after the last-known-good generation is healthy. One intent admits
one candidate target transition and one last-known-good recovery target
transition, each with at most three durably fenced invocation attempts. An
`OnFailure=` callback that encounters `recovery-starting` cannot select another
target or reset its counter. Exhausted recovery attempts leave Caddy unavailable
with intent and attempt evidence intact for operator recovery instead of
entering an unbounded restart loop.

An `ordinary-starting` intent uses the same invocation fencing and permits at
most three attempts at its one bound active generation. A successful matching
`ExecStartPost` durably records the observed running generation and startup
health evidence before clearing the intent; it does not invent a tenant or host
operation result. If all attempts fail, `OnFailure=` preserves the intent and
evidence and leaves Caddy unavailable. It must not select the last-known-good
generation, reset the counter, or enter transactional rollback because no
uncommitted generation transaction authorized that change. Root reconciliation
may resume only the same bound target; selecting a different generation
requires an explicit host transaction.

Every later mutation that encounters a nonterminal start intent returns a
retryable busy result before staging. Startup reconciliation resumes the only
valid next phase; only a transactional candidate failure may select its durable
prior generation. Reconciliation never refunds an attempt, reuses an invocation
binding, or queues another start when the same systemd job is already pending.
Thus systemd `Restart=` cannot observe a mixed set of paths, and no transaction
can wait for a lock callback while retaining the publication lock itself.

Retain at most three complete runtime generations: active, immediate
last-known-good, and one candidate named by current intent. Before staging a
candidate, the root transaction reconciles intent, removes every unreferenced
temporary or failed generation, and accounts existing unique `(device, inode)`
objects so hard-linked payloads are not double-counted. It enforces aggregate
ceilings of 256 MiB and 4,096 inodes for runtime generations plus the configured
host free-space reserve. Selection cannot begin unless the complete worst-case
candidate fits. On success, garbage collection runs only after Caddy and
observed state commit; on failure or startup, it preserves every active,
last-known-good, intent, and still-running pinned generation and removes other
staging. Exceeding a bound fails before live state changes.

Every generation directory and manifest is root-owned; only the Caddy account
can read the environment and adapted configuration, and neither is included in
backup, audit, logs, or diagnostic artifacts. Garbage collection limits the
number of retired copies of secret-bearing inputs as well as disk consumption.

An undeployed tenant has authoritative desired state but no deployment record,
release, canonical content route, or slug alias route. Its first successful
`deploy` operation creates those artifacts and changes desired state to
`active` through the ordinary activation transaction.

Serialize creation, activation, rollback, rename, suspension, archival,
restoration, deletion, and reconciliation with one root-owned publication lock.
Creation allocates the root-generated tenant ID and both creation and rename
acquire the exclusive tenant-state lock before checking slug uniqueness. They
hold it through the durable manifest commit. The uniqueness decision is
therefore part of the root-owned state transaction, not an advisory provisioner
check; no second create or rename can reserve the same slug between validation
and commit. Record intent before changing the active reference so
reconciliation can finish or reverse an interrupted operation. Backups take a
shared tenant-state lock while publication and reconciliation take it
exclusively, preventing a snapshot from combining incompatible content and
manifest generations.

Whenever an operation needs more than one host lock, acquire them only in this
global order: export lock, publication lock, then tenant-state lock. Ordinary
exports take the export lock and then shared tenant-state; archive and every
restore or deletion that retires a bound archive take the export lock before
their later publication transaction; other lifecycle mutations take
publication and then exclusive tenant-state; backup takes only shared
tenant-state; Ansible and the Caddy recovery/launcher paths take only
publication. Never upgrade a shared lock or acquire an earlier lock while
holding a later one. Contention returns a retryable busy result before creating
a parser worker or staging artifact rather than accumulating unbounded lock
waiters; the same correlation ID can retry. Root recovery may wait with its
service runtime bound, but a timeout fails Caddy startup closed.

Atomic rename is not a durability barrier. While holding the locks, apply this
ordered persistence protocol:

1. Normalize and `fsync` every completed release and complete Caddy-generation
   file, `fsync` their directories from leaves upward, rename each temporary
   generation to its final immutable name, and `fsync` each parent directory.
   The Ansible Caddy transaction applies the same ordering to its candidate.
2. Write the transaction intent, including the exact previous source manifest
   and proposed candidate manifest plus their canonical digests, to a temporary
   file; `fsync` it, rename it into place, and `fsync` the state directory. The
   candidate must be the exact operation-specific transformation of that source;
   recovery rejects any unrelated field change before dispatch.
   A host-agent artifact upgrade may install its immutable candidate, but it
   must not select a new schema implementation while any lifecycle intent is
   active. The prior selected agent retains recovery authority; after it clears
   the intent, convergence may atomically select the verified upgrade. The
   unversioned executor and reconciler wrappers acquire the root-owned
   host-agent selection lock in shared mode before resolving `current` and hold
   it through execution. The installer holds the same lock exclusively across
   its active-intent scan and selector replacement. During adoption, Ansible
   replaces the wrappers and waits for every pre-lock worker and reconciler to
   exit before invoking that installer, so an old implementation cannot create
   recovery evidence in the scan-to-selection interval.
3. Create a temporary active-Caddy-generation reference, atomically rename it
   over the old reference, and `fsync` its containing directory. A reference is
   never selected before its release and complete runtime generation are
   durable.
4. For a configuration-only reload, reload Caddy while holding the lock. On
   success, write desired and observed state through
   write-`fsync`-rename-directory-`fsync`, append and `fsync` the audit event,
   then remove the intent and `fsync` its directory. For a restart, persist the
   `restart-required` phase and release the lock before idempotently queuing the
   non-blocking systemd job; the pre-start and post-start helpers advance and
   commit the remaining phases under separate lock acquisitions.
5. On validation or reload failure, atomically restore and durably persist the
   prior reference before reloading the last-known-good generation as
   appropriate. On restart failure, persist
   `rollback-restart-required`, release the lock, and queue the recovery restart;
   only its post-start verifier persists the failure result and audit event and
   removes intent after the preceding generation is healthy.

On startup and before any later mutation, reconciliation inspects durable
intent, references, and state. It completes a transaction whose selected
generation and targets are durable, or restores the durable prior generation;
it never infers completion from observed state alone.

The root activator accepts from the provisioner only a root-generated
authorization-job ID. The trusted SSH issuer's privileged transport reader
never gives stdin, a pipe, socket, or file directly to a structured parser. It
reads at most the configured raw ceiling plus one byte into a fixed bounded
buffer under a 15-second monotonic read deadline and requires EOF at or below
the ceiling. An extra byte, timeout, invalid UTF-8, or incomplete document
produces a fixed bounded error without authorization, correlation lookup,
staging, or payload logging. A regular file size check is only an early
rejection; the same bounded read remains authoritative.

Only a raw-size-compliant buffer enters the structured decoder. Run that
decoder in a resource-limited helper, reject duplicate keys and unsupported
syntax, canonicalize its result, and enforce the smaller canonical limit before
authorization. The helper receives no host path or credential and can return
only a bounded canonical value or fixed error. The issuer commits that value
and its digest, authenticated operator, exact operation and target, correlation
ID, artifact binding, and expected source-state digests in the root-owned job.
Idempotent retries and externally requested root-only operations traverse the
same byte gate; an established correlation ID never bypasses it.

The activator opens the named job as a root-owned, mode-`0600`, single-link
regular file beneath the fixed job directory without following links. Before
path derivation it requires the one canonical lowercase UUIDv7 grammar with an
ASCII `fullmatch`. It accepts only the versioned allowlisted schema, verifies
the canonical request and artifact bindings, and compares the
job's expected lifecycle, manifest, deployment, and archive-record digests with
current authoritative state before it admits or stages work. It then durably
claims the pending job. The executor records terminal validation only after the
complete durable tenant state and selected runtime match a successful result,
or the intent-authorized source state and runtime have both been restored for a
failed transition. Create recovery retains the complete candidate generation,
route-set, and observed-state authority through terminal validation. A terminal
retry revalidates current durable state and runtime before returning its
immutable result. Immutable job, result, and audit bindings preserve the
authority needed after intent cleanup: each current job retains its exact
source manifest and any source archive record, and a successful archive result
retains its exact new archive record. An executor-produced failure carries an
immutable publisher discriminator, so a result-first crash can complete only
that trusted failure's missing audit and terminal phase; lifecycle-handler
failures without their own audit remain rejected. If a newer successful tenant
transition commits before that missing failure audit is repaired, the repaired
entry's original acceptance timestamp preserves the supersession relationship;
replay does not mistake its later chain position for current tenant authority.
An older preexisting transition does not suppress source-state validation. A
nonterminal retry reconciles its phase; a changed binding, state drift, unknown
job ID, or provisioner-supplied raw request fails without mutation. The sudo
rule exposes only this job-ID execution entry point and cannot invoke the
root-only issuer.

Before dispatch, a current authorization job also records the complete bounded
sets of that tenant's retained deployment- and archive-record identities. A
failed lifecycle handler is terminally valid only when both sets remain exact
after rollback; a candidate record cannot silently consume retention or block
a later archive or delete. Operations that are not allowed to create or retire
history (`create`, `export`, `rename`, `reconcile`, `resume`, and `suspend`)
must leave both sets exact even when their handler reports success. For deploy
and import, root independently derives the normalized release-tree digest
directly from the admitted ZIP and binds it to the job before invoking the
handler; the committed deployment record must match both that digest and the
artifact-byte digest. A handler-authored pair of internally consistent but
unrelated digests is not release authority. A successful delete is terminally
valid only after
the complete tenant publication directory is absent and the selected Caddy
generation contains no tenant route. The production executor separately
enumerates the bounded release directory while holding publication and
tenant-state locks, requires it to match the complete retained
deployment-record identity set, and remeasures every retained release tree
against its durable deployment-record digest. It performs that check for every
relevant successful selection and restored failure before recording terminal
execution validation, independently of whether a lifecycle intent
still exists.

Artifact transfer has an earlier root-owned byte gate. The restricted SSH
adapter serializes intake before reading, permits one in-progress or admitted
regular artifact, streams no more than the operation-specific 100-MiB deploy or
120-MiB import ceiling, and checks the aggregate intake allocation and host
free-space reserve during the write. It publishes the artifact within intake
only after file and directory sync. Bounded idle and total deadlines, terminal
cleanup, and startup reconciliation prevent partial or abandoned uploads from
accumulating before the activator runs. Intake admission remains closed if an
unknown artifact cannot be reconciled.

The activator opens and claims the artifact without following links, then
streams its bytes exactly once into an exclusively created, root-owned snapshot
while enforcing the compressed-size limit and computing the digest. After
syncing and closing the snapshot, the activator verifies the job's artifact
size and digest and the canonical request digest, then performs every
security-critical parse, validation, and extraction against the snapshot. It
never validates or extracts from an intake inode still controlled by the
transport or caller. It does not accept arbitrary destination paths, commands,
or Caddy directives, and it repeats every security-critical check even when the
unprivileged provisioner already performed a preflight.

The activator is also the only ordinary writer of the root-owned platform
namespace record, desired manifests, observed state, deployment and archive
records, and append-only audit events. The provisioner never receives directory
write permission for those stores.
Milestone 3 also removes the provisioner's ownership of the persistent home,
intake, job, manifest, and audit directories installed by the Milestone 2 empty
host baseline. The trusted SSH adapter creates root-owned intake artifacts and
authorization jobs; the provisioner receives neither directory access nor
tenant export results. It can perform advisory preflight in its private
workspace and submit only a root-generated job ID for execution.

The provisioner's only general-purpose writable filesystem is a private
ephemeral workspace mounted in its service namespace. Its initial hard limits
are 64 MiB and 4,096 inodes in aggregate, independent of the per-archive
limits, and the workspace is discarded whenever the unit stops or restarts.
The service gets no persistent writable home. Root-owned intake snapshots and
activation staging are not exposed in that namespace: the activator permits at
most one snapshot for a serialized operation, removes it on every terminal
path, cleans abandoned snapshots during reconciliation, and rejects work that
would cross the configured host free-space reserve.

Root-side admission also bounds growth from authorized work, bugs, and replayed
execution. The Milestone 3 host initially permits:

- at most 25 persisted tenants;
- at most 10 GiB and 500,000 unique inodes across static releases and release
  staging, including the worst-case candidate before garbage collection;
- at most 10,000 immutable authorization/correlation request-result records,
  including job envelopes and phases, occupying at most 64 MiB; and
- at most 128 MiB of local ordinary audit segments, with a separate 8-MiB
  root-administrator reserve that the provisioner entry point cannot consume.

ADR 0019 separately limits the versioned `archives/` prefix to 25 unique keys,
25 total stored data versions or delete markers, and 3,000 MiB across all data
versions. The one serialized upload reserves a key, version, and 120 MiB before
it begins. Bound, constructing, retiring, and quarantined objects all consume
that same allowance; successful retirement is not treated as free capacity
until a version-aware listing proves the key absent.

A raw structured operation request is at most 32 KiB before decoding; its
canonical request and result are each at most 16 KiB. A canonical desired
manifest is also at most 16 KiB, but root constructs it from the validated
operation and authoritative source state; no raw desired manifest enters the
transport or privileged decoder. The initial structured-request decoder helper
limits are
`MemoryMax=64M`, `MemorySwapMax=0`, `TasksMax=8`, `LimitNOFILE=64`,
`LimitCPU=5`, `RuntimeMaxSec=15s`, and one CPU through `CPUQuota=100%`.

Each operator reason is at most 512 UTF-8 bytes with control characters
rejected. The authenticated job issuer admits at most 60 new correlation IDs
per rolling hour with a burst of five; an idempotent retry of an established ID
does not consume another slot. Provisioner calls with unknown or malformed job
IDs cannot allocate a correlation or job record. Raw-size, parser-limit,
lock-busy, rate-limited, and capacity-rejected calls fail before staging and
cannot force an attacker-controlled audit payload. Their aggregate counters and
sanitized, rate-limited diagnostic events use the already bounded monitoring
and journald stores.

The activator serializes storage-changing admission, counts actual unique
inodes and allocated blocks, reserves worst-case staging and retention, and
applies the host free-space floor. After the worst-case allocation, every
affected filesystem must retain the greater of 5 GiB or 10% of filesystem
blocks as ordinarily available space and the greater of 100,000 or 10% of
filesystem inodes as ordinarily available inodes; root-reserved blocks do not
satisfy the floor. It refuses a new tenant, deployment, or correlation ID before
mutation if any ceiling would be crossed. Audit is written in root-owned
hash-chained segments of at most 8 MiB. An ordinary scheduled Restic snapshot
does not authorize local segment removal because its normal retention policy
eventually expires it. Before audit rotation is enabled, backup maintenance
must preserve every root-created snapshot tagged
`lowerduckpond-audit-archive` outside its daily, weekly, and monthly counts.

For each closed segment, a root-only rotation operation creates such a snapshot
containing the segment and a versioned rotation descriptor that binds its
sequence, predecessor and terminal hashes, byte digest, repository scope, and
root-generated rotation ID. It restores and verifies both files, then durably
records the Restic snapshot ID, tag, repository scope, descriptor digest, and
terminal hash in the local chain index before removing and syncing the local
segment. If the process stops after snapshot creation but before index commit,
startup reconciliation enumerates the protected tag and validates descriptors
to recover or remove the duplicate attempt without losing chain position.

Every backup-maintenance run verifies that each chain-index snapshot still
exists under the protected tag before `forget` or `prune`, and restore discovers
tagged descriptors as well as consulting the recovered local index. A missing,
ambiguous, unverified, or ordinarily expiring archive snapshot makes backup
health critical and closes rotation and ordinary admission before local
evidence is removed. Milestone 3 retains these audit snapshots indefinitely;
later expiration requires an explicit audited retention policy. The
provisioner cannot rotate, truncate, retag, or consume the administrator
reserve. Correlation records are not pruned in Milestone 3,
preserving idempotency; reaching their cap closes new-ID admission until an
explicit later migration expands the durable store.

Admission state is not an in-memory resettable counter. Tenant, content,
correlation, and audit usage are derived from reconciled root-owned stores; the
rolling rate window is rebuilt from durable accepted-correlation timestamps.
Counter updates use the same write-`fsync`-rename-directory-`fsync` protocol as
other state. Process or host restart, wall-clock rollback, and deletion of
untrusted staging cannot restore spent capacity; an invalid time window fails
new-ID admission closed until root reconciliation repairs it.

## Consequences

The active Caddy-generation reference is the atomic runtime-selection point;
the terminal publication commit also requires successful reload or post-start
verification plus durable observed state and audit while intent is present.
Releases can be prepared without affecting traffic, retries can reuse an
already verified immutable release, and rollback selects a prior release
without rewriting its content. Complete Caddy generations duplicate some
metadata and retain Caddy-only secret environment files. Their three-generation
and aggregate resource bounds add admission and garbage-collection work but
keep that duplication finite. Durably syncing every file and directory adds
deployment latency, bounded by the archive limits, in exchange for a
recoverable commit after process termination or power loss.

The backup service, root activator, and Ansible Caddy transaction must share
their respective state and publication lock contracts. Caddy route generation
becomes intentionally limited; adding a new route capability requires changing
reviewed root-owned code and its tests.

The private workspace limits must be monitored and tested at both their byte
and inode boundaries. Increasing either limit requires another host-capacity
review; application cleanup is not the security boundary that prevents a
compromised provisioner from filling the host filesystem.

The global tenant, content, authorization/correlation, audit, and admission-rate
ceilings keep authorized operations and implementation failures from becoming
unbounded host storage consumption. A compromised provisioner can delay or
replay existing jobs but cannot spend a new correlation ID or storage allowance
without a root-owned authorization. Capacity exhaustion is conspicuous, fails
closed, and requires authenticated operator recovery rather than automatic
evidence deletion.

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
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [Static-publication threat model](../threat-model/static-publication.md)
