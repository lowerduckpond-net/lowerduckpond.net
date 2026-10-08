# 0029: Bind qualification to inputs and live observations

- Status: accepted
- Date: 2026-09-18

## Context

M3.10 proved the installed lifecycle against production Spaces and completed
production convergence. Its report binds a source commit and artifact; all
supporting evidence expires after 24 hours. A completion marker similarly binds
an exact source. Recording completion advances Git even when the qualified
inputs do not change. Treating that new commit as a new installation causes
repeated qualification and creates pressure to deploy merely to record a deploy.

A host-agent digest alone cannot solve this: Ansible, service configuration,
verification code, dependencies, and requirements can change without changing
that archive. Provider behavior and deployed configuration can also change
without a repository commit. These are different reasons to invalidate evidence.

## Decision

### Candidate identity and closeout records

A versioned SHA-256 fingerprint binds every tracked input's repository path,
Git file mode, and content digest. It includes code, dependencies, toolchain
specifications, Ansible and service policy, configuration, tests, scripts,
requirements, and unknown/new paths by default. Git symlinks and submodules are
unsupported and fail closed. Both commits must be available, the evidence
source must be an ancestor of the candidate, and the candidate checkout must be
clean and complete. Git replacement objects cannot substitute another source.

Only non-executable `.md`, `.json`, and `.sha256` files in `docs/records/` and
`docs/threat-model/evidence/` are excluded. These directories are reserved for
historical records, not runtime, build, test, configuration, or requirements
inputs. Introducing such a dependency requires changing this policy first.
All other documentation remains an input, including plans, ADRs, runbooks, and
threat-model requirements. We deliberately avoid a blanket Markdown exemption.

Closeout-only commits go in those record directories. They reference the
original source, artifact, evidence digest, and actual acceptance results.
They do not edit requirements merely to advance milestone status. Updating a
record does not require production convergence. If an operator intentionally
reconfigures an equivalent completed installation, the runner retains its
original accepted source in the completion marker and repeats the live gates.

The artifact must still match independently. A SHA-256 digest of the Spaces
region, archive bucket, and backup bucket binds the storage target without
putting bucket names or credentials into the public report. Runtime credentials
remain subject to fresh capability checks. The completion marker records this
target too; an older marker or changed target cannot authorize qualification
reuse. Changing deployment inputs still requires a new qualified candidate.

### Validity and invalidation

| Evidence | Validity | Invalidation or required fresh proof |
| --- | --- | --- |
| Immutable candidate behavior and installation tests | Historical proof for the original input fingerprint and artifact; no calendar expiry as a historical fact | Changed input content/mode/path, changed artifact, changed requirements or policy, unavailable provenance, or a known regression |
| Full installed interaction with live Spaces, before accepting a new installation | At most seven days from the **oldest** supporting evidence | Expiry, changed candidate or storage target, known provider/OS regression, or failure of any fresh gate |
| Previously accepted, equivalent installation | Completion remains valid without periodic redeployment | Missing/untrusted completion, changed selection or inputs/target, failed live checks, or revocation |
| Host integrity, history/accounting, quiescence, and selected generation | Read anew in the same configuration invocation before host mutation | Any drift or unfinished work stops that invocation |
| Bucket controls, exact remote accounting, edge policy, firewall | Read anew in the same invocation before host mutation | Unknown, missing, foreign, or unsafe state stops that invocation |
| Current archive and backup runtime keys | Fresh disposable-prefix capability proof in that invocation | Failed version/read/delete, pagination, multipart, mutual-denial, or cleanup proof stops that invocation |
| Failed runs, diagnostics, or partial reports | Diagnostic evidence only | Never authorize installation, cleanup, or report promotion |

The seven-day limit is an explicit operating budget, not a measured provider
reliability guarantee. It accommodates one weekly deployment window, including
CI/review delays and a weekend, while bounding the age of full provider behavior
observed before accepting a new installation. Existing fresh probes cover
version reads, delete markers, forced pagination, multipart create/abort, mutual
bucket denial, and cleanup. They do not cover the complete installed full-size
archive path or injected recovery behavior. Spaces can change those semantics
without a visible configuration change; Ubuntu package repositories and base
images also contain mutable inputs within the declared platform bounds.

We accept up to seven days of residual uncertainty for those unobserved changes,
with fresh controls and exact candidate checks immediately before mutation.
A known regression revokes evidence immediately regardless of age. There is no
claim that either 24 hours or seven days eliminates that risk. Compared with the
previous blanket day-long window, this avoids repeating a multi-hour run just
because an otherwise unchanged review spans days. It does not schedule weekly
full runs or redeployments for an already accepted equivalent installation.
S3's independent installed case may later support a cheaper, separately reviewed
refresh of provider-specific proof; it does not replace the full gate here.

`scripts/qualification-revocations.json` records revoked sources, artifacts,
report digests, and input digests. A known regression must be recorded there as
part of its correction. The policy file itself is an input, so changing it also
invalidates earlier candidate fingerprints. An unavailable/malformed policy
fails closed. Revocation never authorizes repair or destruction of live state.

### Report lifecycle and migration

New CLI-created reports use `lowerduckpond-m3-10-installed-spaces-v2`, retaining
the original source, artifact, timestamps, storage evidence digest, six passing
phases, and exact zero final accounting. They add input-policy, input-fingerprint,
and storage-target digests. Verification recomputes both source trees; it does
not trust a caller-supplied equivalence assertion. The report is not rewritten
when a later record-only commit consumes it.

The live wrapper captures source, input fingerprint, and storage target before
the first provider proof. Packaging must match that original capture. Loading
a different bucket pair later cannot bind the old run's proof to the new target;
missing capture or unsuitable Git provenance fails before the long lifecycle.

Report **creation** retains the 24-hour input/phase packaging bound and existing
final-proof chronology checks. This is a bound on assembling one completed run,
not the lifetime of an already-created v2 report. Packaging stale partial work
cannot produce newly dated evidence. Future timestamps remain rejected outside
the existing five-minute clock tolerance. A newer envelope timestamp cannot
hide expired oldest evidence.

Existing v1 reports keep their exact-source, 24-hour consumption policy; they
are not relabelled or silently promoted to wider scope. Existing two-field
completion records remain readable as completed predecessors, but lack storage
target provenance and cannot authorize the new reuse path. The next deliberately
qualified and accepted installation records the new target-bound completion.
The already completed M3.10 deployment remains complete throughout this
migration; it needs no repeat deployment to record this policy's merge.

The replacement live workflow must pass complete secure-workstation
qualification before it is used as release authority. During sustainability
implementation, collect that proof with the final changed harness rather than
performing redundant intermediate production deployments. Local tests and CI
validate the policy machinery; they do not manufacture live-provider evidence.

## Consequences

### Managed M3.11 credentials

The dedicated unattended controller adds the
`lowerduckpond-m3-11-installed-spaces-managed-v1` envelope. It preserves the
original source, input fingerprint, artifact, storage target, combined recovery,
chronology and freshness requirements. It additionally binds its managed run
and trusted lifecycle-helper revision to **separate** production and fixture
credential receipts. The production receipt proves the actual non-expiring
exact-policy Caddy token and the existing short production storage capability
check. Fixture credentials cannot substitute for that proof. Packaging incorporates
both receipts into oldest-evidence time and rejects missing, stale, mismatched,
unknown-field or overlapping-identity receipts. Legacy accepted formats keep
their previous contracts; production deployment gates remain active.

An approved dedicated Docker host may hold these inputs. It is a trusted
credential-processing host, not a container security boundary. Durable external
creation intents, exact ownership reconciliation, terminal/watchdog/GitHub
revocation and a separate unresolved-cleanup outcome are required before closing
an unattended attempt. Their deletion authority covers newly issued credentials
only. It introduces no production rotation, data retirement or deployment
authority. Native Cloudflare expiry and Spaces deletion deadlines are distinct;
scheduler/provider availability precludes an exact-time Spaces expiry guarantee.

Service-account cleanup also depends on 1Password's shared account request quota. Admission
requires observed request headroom; it cannot reserve that quota. Local death
checks remain independent of hourly remote polling. Terminal cleanup is immediate;
persistent failures back off from a five-minute first retry to hourly retries.
Encrypted immutable journal read caches reduce repeated reads, but every sweep
requires live vault inventory
and exact metadata/content-hash agreement, followed by fresh provider readback.
Neither a cached receipt nor exhausted quota resolves an outstanding obligation.
Invalid cache inputs require a cold live read; cache write failures or size bounds
do not prevent credential reconciliation. Only newly validated encrypted cache
output may be saved for reuse, including after a provider revocation failure.

The explicit Connect backend keeps the same vault separation, credential policy,
production checks and report bindings. A shared cache is not independent durable
storage. Before provider creation, a separate cleanup-only Connect identity on
GitHub must acknowledge the exact run and intent after retaining the complete
journal in encrypted artifacts with an append-only commit-status registry. Both
servers' immutable native authors are demonstrated during activation, including
attempted author impersonation. The approved genesis binds the full inventory,
manifest, full provider targets, server identities and trusted helper. A reviewed
helper upgrade preserves that genesis and all historical obligations, and requires
fresh independent readiness at the successor helper. It never reinitializes an
existing journal or revives an old attempt's provisioning window.

Checkpoint lineage follows the append-only registry's publication order, never
the numeric magnitude of opaque GitHub artifact IDs. Exact genesis, predecessor,
logical sequence and retained-history extension are required before independent
acknowledgement. Controllers verify the native independent author and exact
genesis binding without receiving GitHub cleanup authority.

Connect cache inventory is established by two stable unfiltered item lists,
native metadata and all retained event hashes, not equality with its aggregate
vault count. Accepted writes can precede that stable inventory. The same ledger
used by activation, controllers and independent cleanup therefore polls only
readback for a bounded period after POST, preserving the original intent and
returned ID across interruption. It never retries POST, accepts an incomplete
snapshot, or treats cache visibility as independent persistence.
A Connect GET may repeat hostname resolution twice within its original process
deadline; the retry does not apply to HTTP errors, invalid responses or POSTs.
This preserves the single-submission boundary during intermittent resolver failures.
A reviewed pre-discovery helper correction preserves the original initializing marker's
bindings, probe identities, spool and inventory in an immutable private upgrade
record; any started discovery or credential intent prevents that migration.
After discovery starts, a reviewed successor coordinator may recover the original
ceremony using its original merged helper, immutable requests and dispatches.
It records both revisions and the retained evidence hashes before proceeding.
That recovery publishes the successor active helper only after the original
genesis completes; fresh independent readiness is still required.

A separate explicit replacement is permitted for failed genesis whose
original executable cannot complete, only while its authoritative registry has
no entries and both complete journal views contain no credential creation or
cleanup activity. An empty attempt's exact terminal-path revocation request may
remain when its full hash is already bound in the original initial history;
any intent, created, cleanup or resolved event still blocks replacement globally.
The retained request is not revocation evidence. It requires unchanged bootstrap
bindings, both helpers merged, retained
original evidence and a separate private attempt directory. An immutable transition
links old and new epochs, executable revisions, failed execution and orphan
artifacts before mutation. A non-admitting protected marker fences old genesis
requests, then all pending cleanup executions are drained and the complete old
registry is checked again. Missing, ambiguous or changed evidence blocks progress.
Discovery is frozen against the original revocation allowlist before initialization
is published, so later requests cannot enter the new initial history on retry.
The new attempt retains every prior logical record and repeats full independent
discovery, provenance, genesis and readiness. Interrupted replacement resumes its
recorded epoch. It preserves the original failure and artifacts, cannot replace an
active or registered genesis, and never replays a qualification attempt.

GitHub receipt acceptance binds
the successful current attempt and Connect job to its native artifact metadata,
digest and observation interval. Legacy same-name artifacts require an
unambiguous upload within that job; earlier failed artifacts remain retained.

The launcher binds a running GitHub witness to the exact approved attempt before
detaching the controller. Creation acknowledgements require current deletion
authority and a bounded capacity reservation; cleanup remains available after
that window closes. GitHub artifact reads and checkpoint status writes require
explicit additional access approval. Missing/expired artifacts, incomplete
registry history, insufficient capacity or stale readiness block new starts and
remain visible independently of the qualification result. Connect avoids native
service-account quota on this path but introduces these recovery dependencies;
the live independent path must be demonstrated before issuing child credentials.

Initial run-reservation confirmation consumes the original ten-minute creation
window, bounded also by the controller deadline. Its fixed deadline covers
canonicalization, staging and complete native readback; a retained run cannot
receive a renewed window. Typed snapshot-budget expiry may retry observation
only, retaining the sixty-second bound on each complete snapshot. Credential
events keep their separate 120-second confirmation budgets. No acknowledgement
extends provider submission, credential lifetime or qualification deadlines.

A completed cleanup sweep may service an already reserved attempt before publishing
its informational heartbeat. This ordering preserves all provider, authority,
restoration and checkpoint checks. ACK publication revalidates completed cleanup
coverage against its newly retained snapshot; earlier readiness cannot override
new adverse obligations. The exact active run's unexpired intent may enter the
not-due frontier, while foreign or invalidated obligations remain blocking. This
does not create a reservation, renew a deadline or turn local timing evidence into
a successful live lifecycle.

The independent witness's initial twelve-minute wait includes controller
preparation, so it must not substitute for the admitted creation window. After
the exact native reservation is durable, the witness arms once from that
reservation's immutable cutoff plus a five-minute acknowledgement drain. It
never renews the creation cutoff or an event's confirmation budget. Creation
witnessing is capped at 27 minutes from reconciliation entry within the existing
30-minute job ceiling, including bootstrap; slow operations can still require
later cleanup sweeps. Ordinary reconciliation does not gain a creation wait.

Restart is reconciliation of one immutable attempt, not a retry of qualification.
Changed executable inputs require a new correctly bound attempt. Complete live
Spaces/public-CA qualification, a demonstrated credential rehearsal and verified
revocation remain operational acceptance requirements beyond component tests.

On October 6, 2026 the operator authorized one immediate historical exception for
the missing creation outcome of Page Rules intent
`ccdc7926243530cf6dd6615745f8520440d29531f28869a226f432b31a64b574`.
Repeated provider/UI absence and a successfully observed, independently revoked
comparison token support accepting this uncertainty. The helper pins the exact
intent and failed attempt; fresh inventory and an independent GitHub observation
remain required. This permits new admission and aggregate operational acceptance
without calling the historical credential revoked, expired, or never created.
The original failed result remains unchanged, late discovery still triggers
ordinary revocation, and all subsequent credentials retain the original verified
cleanup requirement. The [operations runbook](../operations/m3-11-backup-recovery.md)
describes its separate, visible acceptance receipt. This is not a general waiver.

Administrative records can advance independently of qualification. Production
still requires reviewed current main, exact artifacts, verified history, fresh
live controls, and successful convergence/idempotence/acceptance. Input equivalence
introduces no production data cleanup, qualification retry, credential rotation,
or publication authority.

Broad input inclusion may conservatively require qualification for changes that
ultimately prove irrelevant. Narrowing the input map is a reviewed policy change,
not a PR label or an operator override. Mutable realized OS/image versions are
not claimed to be reproducible merely because their declared versions match;
S1 records environment/timing detail and existing installed/host acceptance
continues to enforce the supported platform boundaries.

## Alternatives considered

- Keep exact Git identity and 24-hour expiry for everything: preserves the
  documented repeated-closeout problem and does not distinguish actual drift.
- Use only the artifact digest: misses installation, harness, policy, and
  requirements changes.
- Exempt all documentation: silently ignores changes to normative requirements.
- Make full live-provider evidence valid indefinitely: leaves unobserved provider
  and platform changes unbounded before a newly accepted installation.
- Extend expiry without identity and live checks: does not establish that the
  old proof applies to the candidate or current operating conditions.

## References

- [Sustainability plan](../plans/m3-operational-sustainability.md)
- [Convergence runbook](../operations/m3-10-convergence-preparation.md)
- [Security-boundary qualification](0022-test-static-publication-as-a-security-boundary.md)
