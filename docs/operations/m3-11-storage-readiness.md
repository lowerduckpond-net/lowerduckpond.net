# M3.11 retained-lease storage readiness

A failed qualification can leave an owned archive version even after its runtime
has stopped. Releasing its credential lease establishes runtime quiescence; it
does not establish an empty archive bucket. Reusing such a lease previously
allocated another attempt before the worker discovered the retained version.

The unattended `start` path now validates readiness and durably reserves reuse in
one native helper operation. It holds the existing daemon admission reservation
and invokes the exact prepared helper. The helper rechecks its committed source,
artifact, daemon, retained lease manifest, stopped issuer, credential lifetime
and every prior consumer's released state. The original runtime-use and
storage-target locks remain held through allocation. Neither lock is created
by this check. Resumed or replaced consumers, changed ownership, closing
credentials and insufficient time block admission.

All seven roles must have their original private delivery and immutable creation
fact. The existing credential validator checks each live identity, name,
creation window, active status, scope, authentication and expiry. The cleanup
bootstrap must retain its original principal. Native journal records are read
again before allocation to catch a close or changed ownership fact. Reads cannot
make remote state immutable: fresh worker credential validation remains mandatory.
The helper uses no provisioning or journal publication operation.

The retained operator credential also undergoes the existing private ACL, absent
bucket policy and lifecycle rule, enabled versioning, and **whole-bucket** empty
checks. At most 35 bucket-policy requests run with automatic retries disabled.
The three Spaces role-authentication probes use the same one-attempt policy
client and their respective archive/backup buckets. Control-plane and journal
exchanges permit only GET with no body. Native inventory/pagination bounds and
the shared deadline apply without an arbitrary extra journal-size limit.
The worker's provider preflight and full storage acceptance remain mandatory.
An isolated-prefix credential check cannot substitute for the empty baseline.

Only after all checks pass does `reuse-admission` acquire the local cleanup lock
for the short commit. It records immutable `admission-<candidate>.json` first,
then the request, initial status, private configuration and exact lease-use
reservation, all while runtime/storage ownership is held. The run directory and
its parent are synced. Unlike the observation-only `storage-admission` operation,
this operation deliberately mounts evidence/configuration/cleanup writable;
source, storage-lock volume and container root remain read-only. It creates no
credentials, deletes no objects and releases no lease.

Interrupted writes and lost replies retain the candidate for read-only
reconciliation and block another admission. No absent controller or elapsed
wait silently releases that reservation. The watchdog preserves an exact,
unstarted reservation while still honoring explicit cancellation and original
credential expiry. A worker may adopt only its exact request and configuration;
all other consumers must still pass fresh release checks. Launch uncertainty
reports the known candidate ID instead of suggesting a second submission.

Provider failures retain a closed diagnostic document on stderr and, where a
qualification timing directory exists, the first private
`failure-provider-preflight.json`. This includes the phase, monotonic elapsed
time, invocation count, bounded exception relationships and allowlisted source
coordinates, storage reasons and numeric provider metadata. Invocation count is
not a guessed HTTP attempt count. SDK retry metadata is included only when
present. Exception messages, URLs, bodies, headers, bucket/object identifiers and
unknown class names are omitted. A strict validator checks helper diagnostics
before they cross the native CLI boundary. Missing diagnostics preserve failure;
they cannot establish success or recover a previously discarded exception.

## Timing audit for the new composed path

The applicable policy is at least 1.5 times the longest comparable completed
window. Existing safe budgets are not reduced to that floor. There are **zero
completed observations of this new full readiness helper**; its first production
use must record a complete window and trigger a new audit. Offline tests verify
ordering, completion and admission of complete inner allowances without sleeps
or exact-duration assertions.

The closest retained observation on source `2b57ed4734a30e8dbc37695b19e637c1de258806`
is a single successful, separately bound four-request inventory: 0.873244 seconds
inside its reader, 1.112831 seconds inside Docker exec, and 1.192744 seconds for
the caller. Their respective 1.5-times floors are 1.309866, 1.669247 and 1.789116
seconds. This probe omitted the new helper's source/artifact verification,
all-seven-role authentication, policy reads, complete released-consumer checks
and durable allocation. It is **not a comparable
completed baseline** for that helper; variability is unknown with one sample.
No per-request or per-daemon-command completed timing is available from it.

| Clock, start through stop | Old allowance | New allowance | Evidence and reason |
| --- | --- | --- | --- |
| Each Docker read subprocess, invocation through collected exit | 1,200 s | Unchanged 1,200 s | No comparable complete sample; retain the existing safe allowance. Includes daemon response and local process overhead. |
| Each source Git read, invocation through collected exit | No finite per-call bound | 60 s provisional | Four local read-only commands, no comparable full sample. Shared helper clock also applies; optional writes and fsmonitor are disabled. |
| Each Spaces policy/authentication read | Policy client: 10 s connect, 30 s read, one attempt | Same policy client for both | No comparable completed per-request sample. Reuse the existing bounded policy client instead of the worker probe client that permits retries. These socket limits are not a complete DNS/request wall-time bound. |
| Each provider-control/Connect exchange, child invocation through collected exit | 30 s | Unchanged 30 s | No comparable complete request sample. Connect permits up to three read-only DNS attempts within this same process deadline; no mutation replay or additional outer retry is added. |
| Entire helper, before source/daemon checks through result assembly | New path | 3,600 s provisional | Includes source/artifact reads, lock acquisition, released-consumer checks, all role/control/provider calls, validation and the lock-held local commit. A nonrenewing real-time ceiling covers stalls outside transport timers. |
| Native Docker utility call, before container start through result collection | 1,200 s for existing operations | 3,720 s for this operation only | Encloses the helper plus 120 s for container startup, result transfer and teardown. Existing utility operations retain their bounds. |

Every daemon read must have its **full requested timeout plus 60 seconds**
remaining on the shared helper clock before it starts. Source reads require
60 + 60 seconds, Spaces reads require 10 + 30 + 60 seconds, and control/Connect
exchanges require 30 + 60 seconds. The local commit starts only with its
60-second conservative work reserve plus the 60-second reporting reserve. The helper
rejects a late read instead of shortening its allowance or renewing the outer
deadline. These reserves are conservative operational allowances, not measured
work or additional human response deadlines. The one-hour helper cap limits the
composition; it is not the sum or product of every worst-case inner timeout.
Bucket reads and Spaces probes have no retries or backoff. Existing Connect DNS
retry handling is included in its 30-second exchange and the enclosing clock.
`provider_read_count` counts only whole-bucket policy reads; separate
`control_read_count` and `credential_probe_read_count` report helper-level
exchanges, not inferred lower-level HTTP attempts. Queue/startup time belongs to
the enclosing caller; external observation time and active work must be recorded
separately. The local tests are synthetic execution evidence, not a production
runtime sample. No existing safe allowance is reduced because they finish fast.

The previous private launch adapter's 3,600-second native-start ceiling cannot
enclose the new 3,720-second storage call plus the rest of launch readiness. That
adapter must not execute this revision until its complete outer envelope and
remaining credential validity have been reviewed. Do not clip the new readiness
check or silently extend an approval to make it fit. The original approval's
expiry is checked before committing allocation and again before launch; credential deadlines, cleanup
reserve, main qualification deadlines and full-size archive service limits are
unchanged. A preflight failure supplies no full-size archive/restore timing
validation.

## Retained archive disposition

Nonempty storage requires a separate, explicitly authorized disposition. Neither
a successful inventory nor this source correction grants deletion authority.
Preservation must use the exact recorded version, byte count and whole-file
SHA-256; validate the portable bundle against its complete archive record and
manifest, durably publish outside the run's cleanup tree, and independently reopen
and reread the preserved bytes before any removal.

A completed construction can still be named by authoritative archive state.
Its job success and absent construction intent do not make that version unbound.
Inspect desired/observed/deployment/archive records, job/result/audit bindings and
pending intent/quarantine state before selecting an eligible retirement path.
The existing failed-fixture retirement CLI has its own eligibility requirements;
its copy and journal patterns do not authorize bypassing those requirements.
An exact-version disposition must preserve ownership bookkeeping and original
failed-run evidence, durably record intent, and reconcile uncertain responses
without replaying deletion. Ordinary archived-tenant deletion is an authoritative transition only when its
claimed authorization job, desired/observed archived state, manifest/platform/
archive digests and prepared `static-retirement-v2` journal match. The journal
binds job, operator, tenant and correlation; execution also holds export
exclusion. Its purge enumerates and removes every version of the key and can
change tenant/runtime state. It is broader than one identified VersionId.
Neither ordinary deletion nor low-level exact deletion is eligible or authorized
here without retained-state capture and scope review. Do not bypass those
checks with an ad hoc adapter. None of these changes closes the
seven retained credential obligations or authorizes another qualification.
