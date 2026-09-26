# M3.11 failed-fixture archive retirement

- Status: retirement boundary accepted in PR #179; evidence correction proposed
  below, requiring merge before dependent implementation
- Parent: [M3.11](milestone-3.11.md#7-qualification-ci-and-evidence)
- Decision: [ADR 0030 amendment](../adr/0030-reconstruct-static-hosts-from-bound-backups.md#failed-disposable-qualification)
- Scope: an explicit secure-workstation action for a failed disposable combined
  reconstruction, before public-CA verification begins

## Problem and boundary

The retained live attempt at `bfd2f5bb03710560e3168cccaf4be88dbbc9ec31`
failed restored-state validation of a legacy executor rejection. Its source
and destination remain gated, Caddy is inactive, and the destination restore
unit failed at `validated`. The source still has pending local work and the
archive bucket contains one version or delete marker. Those observations do
not establish the object's identity or authorize deletion.

PR #177 fixes newly dispatched jobs without inventing missing audit boundaries
for historical records. Updating the workstation cannot repair the original
artifact or make this failed attempt pass. The existing successful-test teardown
requires completed assertions and paired accounting, which this attempt lacks.
The M3.10 ordinary-recovery instructions therefore do not supply a usable
retirement path for this particular legacy failure.

Add a separate, explicitly approved retirement of exact disposable **archive
versions**. Keep the failed hosts stopped, their local state, the original run
directory, and the entire owned backup prefix, including protected snapshots.
Keeping those resources avoids introducing backup retention or container deletion
authority just to release the archive starting gate. The operator acknowledges
that retained state will no longer resolve its old remote archive version IDs;
private copies preserve diagnostic bytes, not automatic recovery authority.

The original run remains failed. Retirement never supplies lifecycle success,
settled accounting, a passing qualification report, or production authority.
Fresh qualification must independently pass its unchanged whole-bucket-empty
guard with a new run identity and backup prefix on final merged inputs.

## Correction to the original evidence prerequisites

PR #179 required two historical records that the retained live format does not
capture. The [public-input capture](../../scripts/m3_11_public_inputs.py) saves
the fresh source's resolver, hosts and trust files, not provider DNS records.
The [DNS witness](../../scripts/m3_11_dns_witness.py) captures its baseline only
when [public-CA recovery](../../config/ansible/molecule/m3_8/tests/public_ca_recovery.py)
starts, after reconstruction and reboot. A failure during reconstruction therefore
has no pre-attempt provider DNS baseline. Retirement must use a new, explicitly
dated absence observation and must never describe it as historical evidence.

The [live fixture manifest](../../scripts/m3_11_combined_inputs.py) records an
unused MinIO name and owner, but no container ID. The live wrapper does not write
the independent local case's `case-containers.json`. Source, destination and
controlled-ACME IDs are saved separately. Do not infer the missing MinIO identity
from its current label, image or creation time. Leave that local service untouched;
exclude it from the Spaces writer set only under the checks below. This correction
reduces container mutation authority and does not permit replacement hosts.

## Eligibility and ownership

The initial implementation accepts only the following bounded case. Unsupported
or ambiguous cases retain all resources and require a further reviewed decision.

1. Validate the original private live manifest, combined context, original
   artifact digest, source revision, storage target, unique backup owner version,
   and saved source/destination/controlled-ACME container identities. Derive
   coordinates from those records; accept no caller-selected bucket, prefix,
   object key, container name, or replacement artifact. All three IDs must be
   original saved IDs. The unused local MinIO service is outside this stop
   authorization. Confirm from the original Spaces configuration that it is not
   a live archive or backup endpoint and receives no Spaces credentials. A
   read-only inspection of the saved local name must match the original fixture
   recipe and local-server launch configuration; reject unexpected environment,
   executable, command, privileges or host mounts. Record its current ID and
   configuration digest only as a fresh observation, require them unchanged
   through retirement, and never stop, restart, delete or adopt it as an original
   bound container. Missing or ambiguous exclusion evidence prevents retirement.
2. Require the original nonzero failure and interrupted reconstruction receipt;
   reject a completed reconstruction, any started public-CA phase, successful
   combined assertions/report, or existing successful teardown authorization.
   Require both ingress gates, inactive Caddy, and the destination's failed
   restore at `validated`. A diagnostic report alone cannot satisfy these checks.
3. Read canonical archive and tenant records from the bound source and
   destination. Require matching archive identities and exact ownership through
   the original tenant/deployment records and reconstruction descriptor. Validate
   their existing schemas and path/tenant/deployment/digest relationships. Do not
   require the known-broken legacy settled-state replay to declare success, and
   do not change or ignore its result. Record unresolved local obligations.
4. Independently list the entire archive bucket through the archive runtime
   principal and operator principal. Require agreement on current objects and
   exact version identities, with every object accounted for by those records.
   Reject delete markers, multipart uploads, duplicate/extra/missing versions,
   unknown objects, and missing or conflicting ownership. Never infer ownership
   from an empty starting bucket, a fixture label, a prefix, or a count alone.
5. Reject any public-CA phase intent or `public-dns` observation directory,
   including partial progress. Derive the exact disposable subjects and
   challenge names from the original bound context and name record. Using the
   operator credential, verify both zone identities and collect a new bounded
   all-record-type absence observation for those names. Persist its real time,
   context/name digests and zone bindings under the separate retirement
   transaction. Recheck absence before approval and each deletion; any record,
   changed binding or failed observation stops progress. Do not create a
   replacement `public-dns/0000.json`, backdate evidence or infer historical
   absence. This path performs no DNS changes and cannot handle an interrupted
   public-CA attempt.

Use the existing 25-tenant, 120-MiB-per-bundle and 3,000-MiB aggregate archive
bounds. Reject oversized inventories before allocation. Fixed command and
provider deadlines, capped pagination, streaming reads and bounded diagnostics
apply; no unbounded retries or new production timeout apply.

## Operator transaction

Implementation supplies a dedicated command with `prepare`, `retire` and
`inspect` actions. These interfaces are requirements, not commands available
from this amendment. Provider credentials remain in the existing private shell.
No production host is mutated. The operator must exclude other archive writers
and other live qualification attempts for the duration; a bucket listing cannot
prove that exclusion. Document and enforce a workstation storage-target lease
in both this command and the live qualification entry point. Another workstation
or manual provider writer remains an explicit operator exclusion prerequisite.

### Prepare: stop writers and preserve evidence

Take that lease and the original run lease. Validate eligibility before changing
anything. Write an immutable preparation intent binding the original inputs,
container incarnations, observed gates, fresh DNS/unused-MinIO observations and
the hashes of existing failure and phase evidence. Stop only the three recorded
disposable source, destination and controlled-ACME containers. Require
their original identities, unchanged incarnations, stopped state and disabled
restart policies; never un-fence, restart or replace a container. Resuming an
interrupted stop uses this same intent and rejects a restart or replacement.

After shutdown, preserve private copies of the fixed state ext4 backing images
used by the source and destination fixtures, with their metadata and digests.
Read authoritative records and recovery journals from those copies using an
offline read-only filesystem reader. Docker's now-unmounted state paths are not
evidence of an empty filesystem. Require clean ext4 images; do not repair them
or replay their journals. Capacity checks include the backing-image copies.
Revalidate eligibility and archive ownership against this frozen capture;
live unit status remains the preceding recorded observation, not an assertion
that a stopped unit is currently readable. Recheck both provider inventories and
current DNS absence and the unchanged exclusion of the untouched local MinIO
service. Stream each exact archive version to an exclusively created
private file; enforce its recorded
length and SHA-256, then fsync and reread it to verify preservation. A changed,
missing or unreadable version prevents authorization. Check sufficient local
capacity before copying; a partial copy never counts as preserved evidence.

Create a canonical, immutable private plan binding original inputs, container
incarnations, frozen evidence hashes, exact versions, verified private copies,
unresolved obligations and provider/DNS observations. Print a shareable summary
with counts and the plan digest, omitting private coordinates. Preparation stops
writers and writes private evidence; it deletes no provider bytes and does not
change the original qualification records. A failed preparation leaves stopped
resources stopped and reports its incomplete stage.

### Retire: explicit approval of the exact plan

Require the original plan digest and explicit acknowledgement of failed-run
archive data loss as command arguments. This is separate from approval of the
software PR. Reacquire both leases, validate all original bindings and retained
evidence, and require all recorded writers still stopped with the same
incarnations and restart policies. Revalidate the preserved copies, backup owner,
current DNS absence, the untouched local MinIO exclusion and both exact archive
inventories before accepting approval.

Persist that authorization before the first deletion. Delete only the listed
`Key` plus `VersionId`, never an unversioned key or bucket-wide purge. Before each
deletion, recheck writer fencing and provider inventories against the immutable
plan minus already authorized removals. Journal the pending exact deletion
durably before sending it. After a lost response, two-principal absence of that
pending version may complete its journal entry; absence without a preceding
durable deletion authorization is an error. Newly appearing objects, restarted
writers, changed private evidence or lost ownership stop all further deletion.

Independent final current-object, version/delete-marker and multipart absence
is mandatory. A durable receipt records original failure, plan and authorization
digests, exact removal progress, final proof times, and the resources retained.
Its format is `lowerduckpond-m3-11-failed-fixture-archive-retirement-v1`, with
outcome `archives-retired-fixture-retained`. All qualification and production
validators reject it. `inspect` reports progress without restarting workers,
deleting bytes or rewriting original evidence. Interrupted retirement resumes
only the same approved plan; it cannot refresh or expand its authority.

The three stopped containers, untouched local MinIO service, original logs/state,
private archive copies and backup prefix remain retained for diagnosis. This
workflow neither removes them nor provides a procedure for restarting them.
Their later disposal requires its own
explicitly reviewed authority. Any future claim about their recovery must
acknowledge that the original remote archive versions were retired.

## Required validation and delivery

Merge this plan and ADR amendment first. The next implementation PR must provide
the operator tool, exact runbook commands and the following evidence before any
secure-workstation retirement is requested:

- Component cases reject wrong runs, artifacts, endpoints, production hosts or
  backup prefixes,
  container replacements/restarts, changed evidence, public-CA progress, ambiguous
  archive records and provider inventories, malformed/oversized input, symlinks,
  unavailable copies and inadequate local capacity.
- Tests cover interrupted preparation, partial copies, interruption immediately
  before/after every delete, lost responses, changed inventory, and concurrent
  local attempts. Approval of one digest cannot authorize a modified plan.
- A failed reconstruction without provider DNS history can prepare only after
  fresh absence checks. Existing public-CA progress, a nonempty name, wrong zone,
  failed provider read or later DNS change prevents authorization or further
  deletion. Original public-input bytes remain unchanged and no public-CA
  baseline is fabricated.
- A live-format fixture without a saved MinIO ID leaves that service untouched.
  Unexpected launch settings, a changed current ID/configuration or ambiguous
  exclusion from Spaces writers blocks retirement. A matching name, image or
  creation time never permits stopping a container without its original ID.
- An independent installed MinIO case uses real source/destination fixtures with
  gated failed restoration and unresolved work, real versioned objects and
  separate runtime/operator credentials. It proves exact retirement and retains
  every original failure, job/result/audit byte, stopped container, protected
  backup object and private evidence copy. Negative cases preserve foreign
  objects and reject missing/ambiguous authority.
- Passing qualification and production validators reject retirement receipts;
  the old combined attempt remains non-resumable. Fresh qualification still
  requires the original complete lifecycle, public-CA proof and success teardown.
- Registry, conservative selection, diagnostic privacy, runtime targets and
  timeout margins follow the sustainability contract. Local/MinIO evidence does
  not establish live Spaces deletion behavior. The explicit workstation action
  supplies its own original retirement receipt, separately from qualification.

After implementation merges, prepare the retained run, review its concrete
summary, obtain explicit operator approval of that plan, and retire only its
proved archive versions. Then run fresh live qualification and the separately
authorized production handoff. P7 retains the original failed attempt and this
retirement limitation alongside the later passing evidence; M3.12 stays unstarted.
