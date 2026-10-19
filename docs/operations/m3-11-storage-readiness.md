# M3.11 retained-lease storage readiness

A failed qualification can leave an owned archive version even after its runtime
has stopped. Releasing its credential lease establishes runtime quiescence; it
does not establish an empty archive bucket. Reusing such a lease previously
allocated another attempt before the worker discovered the retained version.

The unattended `start` path now checks storage before allocating an attempt ID,
writing its initial state or launching its controller. It holds the existing
daemon admission reservation and invokes the exact prepared helper. The helper
rechecks its committed source, artifact, daemon, retained lease manifest, stopped
issuer, credential lifetime and every prior consumer's released state. It holds
the original runtime-use and storage-target locks through read-only mounts.
Neither lock is created by the check. Resumed or replaced consumers, changed
ownership, closing credentials and insufficient time all block admission.

The helper uses the retained operator credential with the existing read-only
policy client: private ACL, absent bucket policy and lifecycle rule, enabled
versioning, and no current objects, versions, delete markers or multipart uploads
in the **whole bucket**. It issues at most 35 requests with automatic retries
disabled. It never creates credentials, deletes objects or releases a lease.
The worker's provider preflight and full storage acceptance remain mandatory.
An isolated-prefix credential check cannot substitute for this empty baseline.

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
policy reads and complete released-consumer checks. It is **not a comparable
completed baseline** for that helper; variability is unknown with one sample.
No per-request or per-daemon-command completed timing is available from it.

| Clock, start through stop | Old allowance | New allowance | Evidence and reason |
| --- | --- | --- | --- |
| Each Docker read subprocess, invocation through collected exit | 1,200 s | Unchanged 1,200 s | No comparable complete sample; retain the existing safe allowance. Includes daemon response and local process overhead. |
| Each source Git read, invocation through collected exit | No finite per-call bound | 60 s provisional | Four local read-only commands, no comparable full sample. Shared helper clock also applies; optional writes and fsmonitor are disabled. |
| Each provider connect/read | 10 s connect, 30 s read; one attempt | Unchanged | No per-call completed sample. These are existing transport bounds, not a wall-time bound on DNS resolution or the complete helper. |
| Entire helper, before source/daemon checks through result assembly | New path | 3,600 s provisional | Includes source/artifact reads, lock acquisition, released-consumer checks, provider calls and validation. A nonrenewing real-time ceiling covers stalls outside transport timers. |
| Native Docker utility call, before container start through result collection | 1,200 s for existing operations | 3,720 s for this operation only | Encloses the helper plus 120 s for container startup, result transfer and teardown. Existing utility operations retain their bounds. |

Every daemon read must have its **full requested timeout plus 60 seconds**
remaining on the shared helper clock before it starts. Source reads require
60 + 60 seconds, and provider reads require 10 + 30 + 60 seconds. The helper
rejects a late read instead of shortening its allowance or renewing the outer
deadline. These reserves are conservative operational allowances, not measured
work or additional human response deadlines. The one-hour helper cap limits the
composition; it is not the sum or product of every worst-case inner timeout.
Retries and backoff remain zero. Queue/startup time belongs to the enclosing
caller; observation time and active work must be recorded separately.

The previous private launch adapter's 3,600-second native-start ceiling cannot
enclose the new 3,720-second storage call plus the rest of launch readiness. That
adapter must not execute this revision until its complete outer envelope and
remaining credential validity have been reviewed. Do not clip the new readiness
check or silently extend an approval to make it fit. The original approval's
expiry is rechecked after storage observation; credential deadlines, cleanup
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
without replaying deletion. The general purge path can remove multiple versions
and is not an exact-version-only substitute. None of these changes closes the
seven retained credential obligations or authorizes another qualification.
