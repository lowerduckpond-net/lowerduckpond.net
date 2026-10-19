# Frozen fixture archive retirement

This exception removes one explicitly approved archive VersionId while retaining
the failed qualification fixture and its original history. Implementation, tests,
preservation and green CI do not authorize execution. A private execution proposal
must bind exact source, existing consumer/producer, lease/manifest, stopped actors,
original evidence, preserved bytes, bucket/key/VersionId/size/hash and reviewed
caller/program files. No private production identities belong in this document.

**Current status: staged implementation under final validation, not execution-ready.**
The source hard gate remains. The driver rejects execution before
creating its output directory, reserving an exec or gathering proofs. The native
entry and native owner's pre-marker check independently reject it as well. There
is no approval field, CLI option or environment flag that enables execution.
Read-only reconciliation remains distinct and cannot submit DELETE. Historical
seals that promised permanent disposal exclusion are superseded; they must not
be relabeled as approval for this narrower contract.

## Irreversible effects and recovery

The tested transaction primitive creates `frozen-archive-retirement/` before the
single DELETE in the producing
qualification directory. Its presence permanently excludes that fixture from
supported restart, reapply, reconstruction, debug recovery and report repair.
Partial/malformed markers also exclude it even if no DELETE was submitted.
There is no unretire operation. The owner must explicitly approve this permanent
execution restriction and the requirement for a separate verified closeout.
Permanent disposal prohibition is not part of the revised contract.

Original tenant/job/result, admission correlation and audit records remain
history. No tenant deletion job or replacement archive authority is manufactured.
Original failure, containers, state, backup prefix and verified private copies
remain retained. Read-only native observation and offline inspection remain
available; credential cleanup continues independently. The per-fixture marker
neither retires the shared lease nor proves its closure.

Deleting the original provider VersionId is irreversible: reuploading identical
bytes creates a different identity. Preserved bundle, state, canonical and audit
bytes are evidence and data, not provider rollback. Native restore still requires
its bound original version. **No automatic tested recovery route into a separately
authorized new fixture is established.** Import/rebinding would need supported
implementation, validation and separate authority. A workspace copy outside run
cleanup does not establish backup or survival of workspace deletion.

Alternatives are retaining the object (whole-bucket-empty admission still rejects
reuse), or separately authorizing another empty bucket and its configuration.
Ordinary archived-tenant delete changes tenant/runtime authority and purges all
versions for a key; it is broader than this exception. The old reconstruction-only
retirement gate and its resumable deletion branch must not be bypassed or reused.

## Staged closeout

Ordinary closeout currently uses the same execution guard, so it cannot remove
a retired run's backup prefix, stopped containers and anonymous volumes, image
tag, or original qualification directory. It would also remove local failure
logs and retirement copies. This prevents accidental evidence loss, but it is
not a reason to prohibit verified disposal forever. The narrow staged adapters
provide their own ownership and evidence checks; ordinary closeout gains no
generic bypass.

The implementation has two separately authorized stages:

1. Separately authorized remote cleanup reuses the existing exact owned-backup
   removal and independent archive/DNS observations while existing scoped
   credentials remain valid. It retains every original actor and identity record:
   active lease reuse explicitly requires those actors to be present, stopped and
   unchanged. It cannot delete another archive, replay a consumed DELETE, revoke
   credentials, dispose actors or release the lease.
2. Separately authorized local-only disposal requires authenticated complete
   terminal lease evidence, native release/drain conditions, fresh actor identity
   and quiescence checks, and a full private evidence export with fsync and an
   independent reread. A persistent external identity fence and shared operation
   lock must survive deletion/restoration of the original directory. Exact local
   disposal must work without child credentials or provider calls. Original
   failure, tenant/job/audit history and uncertain submission identities remain
   preserved outside its deletion scope.

Terminal evidence must bind the exact manifest and issuer-stopped fact plus all
seven original created/removed/denied obligations. A compact `closed` status row,
expired credential or missing secret does not suffice. Failed qualification
`closure` remains unresolved by design; that field cannot be the terminal lease
gate. The active 13-hour credential admission floor and 5,400-second proof age do
not apply to authenticated immutable terminal facts. Local identity checks remain
fresh; the earlier remote absence proof retains its actual observation timestamp.

This ordering avoids requiring revoked credentials to finish local disposal.
It does not require immediate credential cancellation, postpone scheduled cleanup,
or require waiting for credential expiry before bucket reuse. If remote cleanup
has not completed before access ends, that is a concrete remaining obligation and
authority gap; new credentials are not implied. Missing or uncertain retirement
completion must not permanently prevent independently verified resource cleanup,
and cleanup must not manufacture retirement success.

Final combined validation and independent review remain prerequisites **before
any live retirement**. The source gate cannot be overridden by an approval flag.
Later execution needs separate exact remote and local disposal scope; neither is
included in the one-VersionId plan. Read-only inspection and independent
credential cleanup remain available.

`m3_11_frozen_remote` preserves and independently rereads every owned backup
version, including empty objects; multipart data cannot be preserved through this
route and blocks entry. It never sends an archive DELETE. Its receipt truthfully
distinguishes an absent archive from the still-present original version after a
pre-DELETE failure. Global empty-bucket acceptance remains unchanged.

`m3_11_frozen_disposal` uses no provider factories or child credentials. Before
local removal it verifies the exact terminal capture, original use/release/drain
records, all current native actor identities, full remote absence proof and all
retained copies. It exports the complete original directory with metadata and
symlink targets, plus stopped actor root filesystems, logs and inspect records.
Persistent mounts, mapped devices, hardlinks, special entries, xattrs and ACLs
that the narrow exporter cannot preserve stop the operation. No volume-removal
flag or broad Docker cleanup is available. Only the named actors, original owned
image reference and original subtree can be removed. Shared controller/evidence
volumes, lease records and other fixtures remain outside this scope.

External path and immutable-identity tombstones survive disposal. A complete
intent atomically precedes both; partial publication cannot reopen execution.
Ordinary archive execution rejects an existing intent. Only a separately
authorized remote stage may complete the matching exclusion metadata, without
entering the archive transaction. Unpublished metadata and partial evidence
copies remain retained; conflicting authoritative bytes stop for investigation.

Every resource has its own fsynced submission identity. Lost acknowledgments
remain missing; independent absence does not manufacture them. Read-only
reconciliation reports actual state without journal writes. An explicit
continuation may submit only remaining identities that were never submitted,
or finish a completion/certificate publication after removal. A previously
submitted effect that remains visible is unresolved and cannot be replayed.
Terminal certificates revalidate full original proof and export bytes, exact
intents, native ID/name/label/image absence, and the persistent fence. They do
not recursively accept another consumer's certificate as their evidence.

## Concurrent ownership

Retirement takes nonblocking locks in this order: current consumer controller,
lease runtime-use, storage target, producing run, exclusive
`fixture-operation.lock`, then persistent path and immutable-identity locks.
Run leases hold shared operation ownership. Direct
command/phase, reconstruction Fixture methods, attached debugging commands and
directory disposal hold shared ownership through the complete action. Copied
diagnostic workspaces resolve the original's lock. Parent and child processes
can hold shared ownership without borrowing a non-reentrant run lease.

An earlier mutation prevents exclusive retirement until it finishes. A later
mutation checks the marker after shared acquisition and rejects before its
action. A late check alone is insufficient. Managed finalization/debug access
also holds the same runtime-use ownership throughout. All acquisitions are
nonblocking; conflicts stop rather than queue a mutation. The global credential
cleanup lock is held only for the single bounded provider request.

These are reviewed-source guards, not OS-level denial of raw Docker/admin commands
or obsolete binaries. Immutable retained controllers remain observation/cleanup
actors. The retirement program overlays reviewed Python scripts in memory and
requires an unchanged clean retained checkout and identical native dependencies.
The small bootstrap binds the complete bounded stdin bundle by checksum; no
required module is dropped to fit an exec argument. It installs no packages,
restarts no fixture and grants no bypass through old code.

## Proofs, submission and clocks

All seven roles require original private delivery, live read-only authentication,
policy, ownership and journal checks. The inherited validator requires at least
13 hours of remaining credential validity: an unchanged conservative admission
gate, **not an owner reply deadline**. Actual expiry and cleanup limits remain.

Adopt fresh outputs of the complete reviewed host and scheduled native GitHub
verifiers: ZIP digests, job/run identity, authentication, installed helper, exact
lease and historical obligations must pass. Workflow head and installed helper
are separate bindings; drift needs reviewed verification, not metadata inference.
No dispatch/restart is included. Freshness remains 5,400 seconds from native run
creation and host receipt observation, rechecked at execution. Owner waiting does
not renew proof clocks or itself expire substantive approval.

The local proof child gets 600 seconds for full archive/state rereads, native
bundle/manifest/release-tree, clean ext4, correlation/result/audit validation.
The cumulative parser limit stays 300 seconds. Nonce/evidence-bound exchanges
bound both reading and writing complete frames; the exchange allows 720 seconds
for the full 600-second local child plus transport and evidence overhead. Caller
wall allowance remains
6,000 seconds; bootstrap/import/first approval frame gets 180 seconds and native
helper gets a nonrenewing 3,600 seconds for ownership, role verification,
inventory, copy exchanges, one mutation and reporting. Before exec, reserve the
whole startup/helper plus 120 seconds. Before the permanent marker and again before DELETE, require 2,400 seconds
for post-effect proof/reporting. A known-insufficient budget must not commit the
marker. These provisional ceilings are not completed live
retirement measurements and must not be mechanically multiplied. Connect/read
limits stay 10/30 seconds, no SDK retry. A final prepared-request check runs after
signing to revalidate ownership and freshness immediately before transport.

Two principals must independently see exactly the approved sole version, with no
other versions, markers, multipart uploads or truncation. An exclusive fsynced
`delete-submitted.json` consumes the one mutation identity before final checks.
Lost response, interruption, failed final check or torn reservation never allows
automatic replay, even if the version remains visible. A separately selected
read-only reconciliation program can observe presence/absence and validate an
already-recorded completion, but cannot DELETE, create a marker, or append
authoritative absence/completion records. Absence alone never manufactures a
completed retirement receipt. Both modes repeat the dual-principal inventory
after the final potentially slow guard, and timestamp that actual final
observation. Execute success requires exactly one integer DELETE count;
reconciliation requires zero. The driver validates the checksum-bound program
and decoded payload operation and plan before any exec or reservation, so an
observation label cannot submit an execute payload.

The added final inventory performs eight bounded GET requests (four per
principal). Their nominal request allowances total 320 seconds under the shared
nonrenewing helper deadline, not an extra independent 320-second allowance.
There is no completed live retirement measurement; budget sufficiency must be
reassessed with the final adapter before enabling native execution. Existing
budgets have not been reduced or extended to hide this incomplete readiness.
Independent empty inventories and a closed bound terminal receipt
are required. Qualification remains failed; release/cleanup closure is not implied.

The private proposal records comparable timing samples, counts, revisions and
variability under the owner's minimum 1.5 times observed-window policy. Preserve
safe budgets. Incomplete work is a lower bound, never a successful baseline.
There is no completed live retirement sample. Full-size archive/restore timing
qualification remains a separate later requirement.

## Staged timing and proof collection

The [changed-path timing audit](frozen-fixture-timing.md) separates completed
constituent observations from provisional composed ceilings. Remote and terminal
local helpers each have a nonrenewing six-hour allowance; the staged caller has
seven hours from its original entry, including prelude, proof work, startup and
reporting. Per-call admission reserves a complete inner operation; it never clips
an inner timeout to the remaining outer time. Those ceilings are unmeasured
provisional budgets, not expected runtimes or new performance requirements.

Long remote preservation uses `m3_11_frozen_refresh.Refresh`. Each refresh selects
a completed scheduled run through GET, invokes the separately reviewed full
native collector and host observer, binds all their files, then runs the isolated
600-second full-byte validator. The complete exchange gets 3,600 seconds,
including the existing 1,800/600/600-second children. Reusing the same receipt
does not change its 5,400-second native origin. No suitable proof means stop,
without dispatch, queued mutation, short polling, or a new human reply deadline.
Refresh occurs outside the revocation-exclusion lock. The check immediately
before sending a provider mutation is check-only and still requires current
proof and genuine credential validity.

Terminal local disposal instead uses immutable terminal facts, after all child
credentials have been removed and independently denied. The read-only terminal
collector brackets six authenticated native GitHub GETs with two authenticated
original-controller inventory snapshots. It binds controller/daemon/image/source,
original request/use, native run/job/steps, both artifact ZIP digests, full signed
authentication policy, historical uncertainty and every original obligation.
Each raw response and per-call receipt is retained as it arrives, including when
a later read fails. Selection and transfer require the original response bytes;
projection-only receipts cannot authorize disposal. Terminal facts have no
artificial active-proof expiry, but local resource checks stay fresh under locks.
