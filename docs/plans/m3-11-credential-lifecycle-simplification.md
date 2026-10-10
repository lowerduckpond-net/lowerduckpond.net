# M3.11 credential lifecycle simplification

- Status: design choices accepted as recorded below; final implementation approval pending
- Plan version: r3
- Prepared: 2026-10-10
- Inspected baseline: `0b5b198bf06443e61f01b1f7259fea827f79fc23`
- Parent: [M3.11 qualification plan](milestone-3.11.md)
- Related decision: [ADR 0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md)
- Current authorization: create this plan document only. The previous unattended
  qualification goal remains cancelled. No implementation, credential operations,
  infrastructure changes, live runs, commits, pushes or merges follow from this draft.

The user has authorized independent read-only review of this plan against current
code. Implementation may proceed only after both that reviewer and the parent
coordinator approve the same final plan. This document's author cannot supply the
independent approval. Live credential actions and cutover remain separately gated.
The parent's design acceptance below does not release the current no-code hold.
After independent review of r3, the parent must review that exact version and
verdict and explicitly authorize bounded local implementation and tests.

## 1. Requirements, design acceptance and pending live policy

The user's requirements are:

1. Access 1Password through Connect without consuming the Families service-account
   request quota for routine retrieval, while protecting credentials.
2. Rotate upstream provider credentials monthly for one logical LDP authority;
   automatically issue appropriately scoped milestone credentials as needed.
   Monthly manual supply of runtime credentials is not the requested model.
3. Preserve useful issuance and Connect capabilities for future milestones and
   another project, without creating a general credential framework now.
4. Preserve actual qualification checks, production/fixture separation, private
   evidence and all existing cleanup obligations. A failed attempt stays failed.

The parent has accepted the following implementation-design choices under the
user's conditional authorization. These are design decisions, not newly inferred
user requirements or live operational approval:

| Decision | Accepted implementation design | Pending live policy or retained limit |
| --- | --- | --- |
| D1: architecture | Parent accepted compact inventory in the existing private 1Password journal vault and independent GitHub Connect cleanup | Configuration delivery, permission configuration and workflow activation remain separately gated. Section 2 retains the alternatives comparison. |
| D2: persistence prerequisite | Parent accepted one independent confirmation of the complete credential-set manifest before any CREATE | Local Connect readback alone has no verified off-host durability guarantee. Live confirmation/cutover is separately gated. |
| D3: child lifetime | Parent accepted seven days as the design default | This is no live credential authorization or fallback for missing approved policy. Actual lifetime and start window require explicit approval. |
| D4: reuse after failure | Parent accepted a milestone lease with exclusive runtime-use ownership and verified quiescence before reuse | Live retention/reuse requires approved policy. Cancel-lease still revokes; stop-attempt remains a distinct operation. |
| D5: rotation and reserve | Calendar-month generation mechanics and configurable fail-closed coverage checks may be implemented after final plan approval | Issuance cutoff, cleanup reserve and provider expiry remain pending, with no operational defaults. No invented 60-day cap; the existing two-day reserve is not an approved default for the replacement. |
| D6: unavailable writer | Parent accepted no terminal closure while an issuance writer can still resume | Revoke discoverable children, retain unresolved status and require an exact decision for any exception; a heartbeat timeout is not fencing. |

D5's pending runtime values do not block local implementation of its mechanics.
They must be explicit, approved inputs: missing or unapproved issuance cutoff,
cleanup reserve or provider expiry rejects live preparation. Do not inherit old
constants or synthetic test values as operational defaults. Local tests use
explicit synthetic policies and confer no live approval.

Actual lifetimes, scopes, authority generations, provider-expiry verification,
Connect permission configuration, credential creation, existing-container stops
or restart-policy changes, remote workflow activation, cutover and live runs
remain separately gated. Implementation must not broaden persistent access.
Later live approval must bind concrete targets, policies and cleanup readiness;
design acceptance alone must not activate them.

Non-goals: new providers, buckets, datastore, public secret endpoint, deployment,
production credential rotation, destructive failed-fixture retirement, high
availability issuance, or a second supported lifecycle mode. Do not implement the
held 20/50-minute changes as an implied part of this plan.

## 2. Architecture and alternatives

Reuse the shared Connect server, dedicated provisioning/cleanup/production
vaults, private evidence volume and existing protected GitHub cleanup environment.
The GitHub job already starts an independent Connect server through
[connect_host.py](../../scripts/m3_11_unattended/connect_host.py); it reads the
cleanup and journal vaults without reaching Unraid's Connect endpoint.

The existing LDP GitHub repository was verified public. No existing private
operational repository was identified. This design needs neither a new repository
nor direct copies of provider secrets in GitHub environment secrets.

Keep one configured issuance host and one active credential set for these targets.
Use existing local process/storage locks. Do not add distributed writer election,
automatic host takeover, or restoration of an old volume into active issuance.

Replace the live event protocol with a bounded inventory:

- One immutable lease manifest containing a unique lease identity, approved
  policy and target digests, authority generation, creation-helper revision,
  all planned role names/scopes, ownership baselines, issuance cutoff and expiry.
- Separately written issuance outcomes and returned provider IDs. Child values
  stay in private local files, never in the inventory or GitHub receipts.
- Monotonic finish/cancel requests, cleanup observations and terminal results.
  Separate writers do not overwrite one shared mutable document. Repeated
  identical observations do not generate an unlimited event history.

Before issuance, the independent GitHub job reads the exact complete manifest
through its own Connect server, verifies cleanup access, and returns one receipt
binding the manifest digest. Waiting cannot create credentials. A timeout can
fail preparation or retry observation of the same manifest; it does not authorize
CREATE. Remove per-event acknowledgement, genesis, anti-rollback checkpoint and
creation-reservation choreography after migration.

After this confirmation, the inventory already names every possible child.
Returned IDs improve cleanup, but an interrupted post-CREATE inventory write does
not erase the pre-existing obligation. Independent cleanup can reconcile exact
names, scope, creation interval and baseline against provider inventory.

| Alternative | What changes | What remains unproven |
| --- | --- | --- |
| Smallest current-controller patch | Correct demonstrated aggregate creation-window and terminal cleanup publication/locking failures | Successful complete rehearsal and full qualification; does not provide the clarified rotation/lease model. |
| Adapt current controller | Add authority generations, longer children and reusable fresh receipts; retain coordination | Those adaptations and the complete distributed lifecycle. |
| Proposed simplification | Make those policy changes and replace coordination in place with the compact inventory and one pre-issuance confirmation | Inventory failure handling, migration and the same original qualification stages. |

The first alternative has the smallest immediate diff. No measured evidence
establishes which alternative reaches qualification fastest. The recommendation
reduces ongoing dependencies; it is not a claim that replacement work is free.

## 3. Trust boundaries and exposure

Retain [Connect transport](../../scripts/m3_11_unattended/connect_api.py),
[provider transport](../../scripts/m3_11_unattended/http.py) and
[private file handling](../../scripts/m3_11_private_inputs.py). Secrets cross
private pipes/files, not command arguments. Export only constructed sanitized
results. Connect clients authorize vault access, not individual field access.

The trusted preparation process receives management credentials. Qualification
receives only its child credentials. The fixture receives the required runtime
keys; the account-wide Spaces operator key stays controller-side. DNS Write
still reaches both whole zones; bucket-scoped keys reach whole buckets.

Keep [production.bootstrap/validate](../../scripts/m3_11_unattended/production.py)
as the short separate process for actual production Caddy and storage checks.
Production-state credentials and passphrase never enter qualification. The
production Caddy validator remains exact-policy and non-expiring. Temporary
fixture success cannot substitute for production success.

The host and Docker administrators can inspect process memory, environment and
private volumes. Container separation is not a hard boundary against them.
Retained failed fixtures and private logs may contain credential values. Unlinking
delivery files is not secure erasure; revocation ends provider access. A longer
lease therefore increases exposure duration. No new external secret cache is
part of this plan.

The simplified inventory trusts authorized vault writers and 1Password storage.
It does not preserve the current independent anti-rollback proof against malicious
authorized rewriting. Private delivery, exact ownership and provider readback
remain mandatory; accepting this reduced threat model is part of D1-D2.

## 4. Lifecycle, interruption and reconciliation

Lease states are prepared, confirmed, issuing, active, closing and closed.
Unresolved reasons remain attached to issuing/closing; they are not successful
terminal states. Attempt outcomes are separate from lease cleanup outcomes.

### Preparation and issuance

1. Verify policy, targets, authority coverage and absence of conflicting active
   issuance or unresolved ordinary obligations. Preserve the one historical
   exception described in section 7.
2. Create the complete immutable manifest locally and in the existing journal
   vault. Confirm it independently once. Lost manifest-write responses reconcile
   the original lease identity; do not create competing inventories.
3. Under the local single-writer lock, durably record each role as submitting
   before its one provider CREATE. Immediately save a returned ID and available
   secret privately, then publish the ID and outcome. Verify actual policy,
   identity, activity and expiry before delivery.
4. Only the original, uninterrupted issuance process may submit its remaining
   planned roles. Restarted processes reconcile; they never replay issuance for
   an existing manifest. Lost local state does not authorize adoption or replay.

A lost CREATE response is an uncertain outcome, not a retryable mutation.
Reconcile complete provider inventory against the recorded identity conditions.
Record a recovered ID before deletion. If the secret was lost, revoke that child;
provider secrets are not assumed recoverable. A new set needs a new manifest and
clearance of the original obligations. Failed/partial inventory and repeated
absence alone do not manufacture proof that an uncertain CREATE never occurred.
Ambiguous matches, scope mismatches without a known ID, or missing ownership stay
unresolved for a specific operator decision.

### Qualification and credential reuse

Under D4's accepted design and separately approved live policy, a new attempt can
use a valid active set without issuing another one. Recheck provider policy/activity, target and identity
separation, remaining lifetime and lease status. Bind new production and fixture
receipts to that attempt's source, artifact and input fingerprint. Issuance time
is distinct from current validation time. A changed executable revision requires
a new correctly bound attempt, not promotion of diagnostic continuation.

The lease has one runtime-use owner: either the active attempt or its explicitly
attached diagnostic session. Record that ownership before delivery. No second
attempt or diagnostic session may use the set concurrently. The current
[worker drain](../../scripts/m3_11_unattended/worker.py) stops host process groups,
while the runner preserves failed Docker fixtures and
[diagnostic attachment](../../scripts/m3_11_debug_fixture.py) expects them running.
Draining the controller therefore does not establish runtime quiescence.

Before transferring use to another attempt, drain the owned host/guest commands
and verify the exact retained source, destination, ACME and other credential-using
container identities. Stop those containers and prevent their automatic restart,
without removing containers, volumes, data or evidence. Verify stopped state and
restart behavior, then release the previous use owner. Interrupted or unverifiable
quiescence blocks transfer; restarting an old fixture requires reacquiring the
same exclusive use ownership. A resumed old controller must not reattach it
automatically. Existing storage leases, fixture ownership and failed-data gates
still apply: quiescence alone does not authorize a new run over retained resources
or destructive retirement. If these gates cannot be met, reuse remains blocked.

An ordinary qualification failure stops that attempt and preserves its evidence;
it retains an active milestone lease only if live retention is approved.
Scope/delivery failure or suspected disclosure closes the set. Explicit milestone finish,
lease cancellation or expiry initiates revocation. A successful qualification
initiates finish; overall completion still requires verified cleanup.

Keep cancellation unambiguous: cancel the lease means stop its active attempt and
issuance, then revoke. An explicitly named stop-attempt operation may retain the
lease for diagnosis. Do not silently change the existing cancellation command
into a credential-retention action.

### Cancellation, stale writers and host loss

Cancellation during issuance stops new submissions and drains or terminates the
owned request process. Any mutation whose outcome was lost becomes uncertain.
All possibly submitted roles remain cleanup obligations.

A local closing record and fresh status checks prevent ordinary late submissions,
but cannot fence a process suspended after its last check and before an API call.
Neither provider offers a fencing primitive demonstrated by this implementation.
Therefore provider absence alone must not close a lease while such a writer can
still resume.

On a reachable host, stop and verify the exact owned issuance process/container
and its restart behavior before terminal closure. Preserve fixtures and evidence.
On an unreachable host, independent cleanup revokes discoverable children and
keeps reconciling; report writer fencing and closure as unresolved. Resolve that
condition only after the old writer is verifiably stopped, or its creation
authority is disabled and outstanding requests are reconciled. Native child
expiry alone cannot fence a still-authorized creator. Do not automatically revoke
shared upstream authority to solve this exception.

No automatic second-host takeover is permitted. A restored host starts in
reconciliation mode, not issuance mode. A paused writer resuming during cleanup,
a duplicate start, and an old-volume restore are explicit acceptance cases.

### Cleanup completion

Retain immediate requested cleanup, local watchdog recovery and independently
scheduled GitHub cleanup. Delete exact owned provider IDs; never delete failed-run
containers, evidence, backups, DNS records or remote data as credential cleanup.

Publish finish/cancel intent before acquiring the provider-cleanup lock. Lock
contention cannot hide the request from independent cleanup. Publication failure
must not suppress immediate provider deletion, and must remain an unresolved
durability result. This preserves the demonstrated terminal-path failure case
without adopting the held timer changes.

Successful DELETE is insufficient. Require authenticated provider readback and
negative authentication where the secret remains available. If the host and
secret are lost, report the negative probe unavailable; never claim it passed.
Interrupted cleanup retries deletion/readback idempotently. Failed verification,
unknown issuance, an unfenced writer or failed result persistence leaves closure
unresolved and prevents replacing the credential set without a specific decision.

Cloudflare expiry is native. Spaces deletion is scheduled, with overdue status;
GitHub scheduling and provider availability preclude exact-time removal promises.
Elapsed time, a failed list request or a stale success receipt cannot discharge
an obligation.

## 5. Rotation, provider policy and time bounds

Keep the existing upstream credential types and separated identities initially:
DigitalOcean PATs, Cloudflare account-owned management tokens, and Cloudflare
user-owned management tokens. One logical LDP authority encompasses them.

| Capability | Minimum provider permissions |
| --- | --- |
| Spaces issuance | `spaces_key:create_credentials` plus `spaces_key:read`, `spaces:read`, `regions:read`, `sizes:read`, `actions:read` |
| Spaces cleanup | `spaces_key:delete` plus those reads; no creation required |
| Cloudflare account token management | Account API Tokens Write on the approved account |
| Cloudflare user token management | API Tokens Write on the approved user; Page Rules remains user-owned |

The existing DigitalOcean issuer configuration additionally requires deletion.
Do not expand permissions; reduction is optional at the approved rotation.
Cloudflare cleanup tokens can also create tokens because the required management
permission covers both. Code limiting their use is not provider-enforced
deletion-only access.

Rotate by staging a replacement generation in the existing dedicated vaults,
verifying it, making it active for new leases, and retaining old cleanup access
until its obligations close or a verified handover covers them. Record the old
and new generation IDs and evidence. Do not retain old generations indefinitely
or revoke one while it is the only usable cleanup authority.

Logical authority binds approved provider principal and resources. Secret
fingerprints identify credential versions, not authority equivalence. Cloudflare
verification compares actual account/user resource IDs, complete management
policy, activity and expiry. DigitalOcean's current
[attestation writer](../../scripts/m3_11_unattended/setup.py) and
[validator](../../scripts/m3_11_unattended/config.py) bind token hash, scopes,
expiry and attester; they do not record team identity. Add a non-secret
`digitalocean_principal` attestation from the operator's approved provider team
context, bound to each generation's token fingerprint and to the lease manifest.
Record the operator, observation time and supporting team context. This is a new
setup input, not an existing native verification capability.

Both setup and cleanup must compare that principal with the approved logical
authority and previous generation. A different or unestablished principal refuses
handover, even when the replacement authenticates and lists no credentials. Before
transferring known outstanding IDs, require the replacement to positively read
those exact owned IDs and verify their metadata while the old generation remains
available. Lost-response obligations without a known ID retain their original
cleanup generation until resolved or separately approved for a concrete handover.
If no trustworthy principal comparison or capability check is possible, retain
old cleanup; do not turn an empty inventory into removal proof.

Independent native verification of all DigitalOcean PAT metadata was not
established; operator attestation remains a trust dependency. Do not silently add
`account:read`. Cross-generation deletion and any effect of parent revocation on
children remain live validation gates before old access is removed.

Necessary constraints are explicit expiry, enough child validity to finish an
attempt, bounded individual operations, and usable cleanup authority beyond every
outstanding deadline. Preserve the 600-minute runner ceiling and currently
twelve-hour minimum remaining validity unless separately amended. The latter
contains a two-hour reserve; its exact value is policy, not a provider limit.

The fourteen-hour child lifetime, eight-day audit ceiling, ninety-one-day Page
Rules ceiling, seven-day Connect-client cap, five-minute creation interval and
ten-minute aggregate creation window are local choices. Seven-day children fit
the existing audit ceiling but are not mandated by it. Update only fixture/lease
and bootstrap lifetime handling required by approved decisions; do not weaken
production validators or original report freshness rules.

Do not replace the creation/witness race with another tight aggregate performance
gate. Record an explicit lease issuance cutoff; bound each request and cancellation
drain, and surface failures. Choose the cutoff, upstream expiry dates and cleanup
reserve during policy review. No automatic extension is permitted. Current public
documentation does not establish the exact DigitalOcean expiry choices available
to this account; setup must verify them before dependent live authorization.

Provider references:
[DigitalOcean issuance scopes](https://docs.digitalocean.com/reference/api/scopes/spaces_key/create_credentials/),
[cleanup scopes](https://docs.digitalocean.com/reference/api/scopes/spaces_key/delete/),
[PAT expiry](https://docs.digitalocean.com/reference/api/create-personal-access-token/),
[Spaces key API](https://docs.digitalocean.com/products/spaces/reference/api/spaces-keys/),
[Cloudflare token creation](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/),
[native expiry](https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/),
[account-token compatibility](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/),
[Connect token duration](https://www.1password.dev/cli/reference/management-commands/connect#connect-token-create).

## 6. Bounded code changes

All paths below are under `scripts/m3_11_unattended/` unless stated otherwise.
Names define the implementation boundary, not permission to rewrite whole files.

| Area | Retain or change |
| --- | --- |
| Private access | Retain `connect_api.py`, `http.py`, `connect_host.py`, and `scripts/m3_11_private_inputs.py`; separate reader configuration from journal/witness requirements in `connect_configuration.py`. Keep a small reusable reader boundary, no new package. |
| Inventory and lifecycle | Replace live `connect_journal.py` / `connect_ledger.py` behavior with one compact `inventory.py` adapter; update `model.py`, `lifecycle.py`, `creation_outcome.py`, `state.py`, `approval.py`, `config.py` for sets, attempts and authority generations. |
| Execution and cleanup | Adapt `__main__.py`, `worker.py`, `docker.py`, `watchdog.py`, `cleanup.py`, `connect_action.py`, `evidence.py`; preserve detached host networking, restart reconciliation, cancellation and sanitized evidence. |
| Validation and setup | Adapt `inputs.py`, `cloudflare.py`, `connect_auth.py`, `connect_setup.py`, `connect_renewal.py`, `connect_renewal_setup.py`, and `setup.py`; retain `spaces.py` capability/ownership checks and `production.py` isolation. Change `scripts/m3_11_fixture_tokens.py` and managed report handling only for approved lifetime and fresh lease/attempt bindings. |
| Private configuration delivery | Adapt `connect_delivery.py` and its receiver to the single versioned bundle and authority generations; retain private stdin, owner/mode checks and destination identity checks. Remove renewal/checkpoint coupling only after its legacy obligations and keys are accounted for. |
| Workflow and documentation | Simplify `.github/workflows/m3-11-credential-cleanup.yml` and `.github/actions/m3-11-connect/` (`index.js`, `action.yml`) to confirmation and cleanup operations. Retain private stdin and sanitized output; remove obsolete run-digest/checkpoint/artifact-runtime inputs. Update the existing backup-recovery runbook and relevant ADR text only to describe accepted behavior. |

`setup.py` retains useful schema/protection checks and gains the bound DigitalOcean
principal attestation; replace its service-account retrieval with the existing
Connect reader or authenticated operator setup, and remove obsolete service-account
setup commands. Preserve `journal.py` record parsing/validation only for migration
and historical obligations; retire `OnePassword`/`OpJournal` runtime access and
`journal_cache.py` quota caching after import. Keep old encrypted records and keys
privately for the obligation reader; do not make them an alternative live inventory.

`audit_policy_recovery.py` and `cleanup_expiry.py` are migration-only for previously
authorized records. Preserve their exact identity/policy checks until the import
proves no pending restoration or uncertain expiry update remains. Disable their
new grant/update commands; this plan does not authorize renewing old grants.

Adapt the tests under `tests/infrastructure/` for unattended lifecycle, controller,
inputs, delivery, providers, Docker and creation identities, plus Connect setup,
delivery, authentication, configuration, action, host and launcher readiness.
Replace journal/ledger tests with compact-inventory tests. Remove tests exclusive
to quota, admission choreography, settling, checkpoints and genesis after those
paths disappear; retain any ownership, private-delivery or migration cases they
also cover. Update control/activation/recovery tests to the surviving single path,
and retain original production/report/fixture coverage. Update `pyproject.toml`
test-file/mypy selections and installed-group selection where these file changes
require it. The parent accepted this bounded tracked-test scope for implementation;
edits still await final r3 review and explicit local implementation authorization.

After migration, remove unused `connect_admission.py`, `connect_provisioning.py`,
`connect_genesis.py`, `connect_checkpoint.py`, `connect_checkpoint_key.py`,
`github_checkpoint.py`, `checkpoint_audit.py`, service-account/quota branches and
their exclusive tests. Reduce or remove `connect_control.py`, `connect_activate.py`
and `connect_recovery.py` according to the single manifest-confirmation path.
Retain shared parsing/transport and any legacy obligation reader still required;
do not blindly delete modules by filename. Remove obsolete expiry-extension
commands only after active obligations no longer depend on them.

No changes to the original provider/storage checks, Molecule phases, combined
recovery, public certificate issuance or report acceptance are authorized merely
to make a new test pass. Page Rules issuance and complete policy validation stay.

## 7. Migration, historical exception and rollback

Keep old cleanup active during preparation. Inventory every old obligation and
private retained secret file without deleting them. Produce a reviewable import
mapping with original record digests, statuses, provider IDs and authority
generations. Import is not a new success receipt.

Include historical audit-policy restoration records and local cleanup-expiry
intent/result files, not only child-creation records. Reconcile any lost update
response against the exact approved token identity and policy before retiring the
old helper. A pending restoration/expiry update blocks cutover unless the
replacement cleanup-only path can reconcile it with the same authority and
constraints. Do not infer completion from an absent receipt or obsolete command.

Preserve exactly the exception in
[historical_absence.py](../../scripts/m3_11_unattended/historical_absence.py):
attempt `01a11021-76d1-775a-adb1-fe00b6fd6152`, Cloudflare user Page Rules intent
`ccdc7926243530cf6dd6615745f8520440d29531f28869a226f432b31a64b574`.
Its creation outcome and negative authentication are unavailable. The operator
accepted proceeding on 2026-10-06 after API/UI absence observations and a separate
positive-control token's verified deletion, without waiting for the requested
expiry. Preserve the original failure and continued reconciliation. This is not
verified revocation and grants no exception to later credentials.

The latest retained rehearsal-20 evidence records six issued credentials removed
with denied authentication and the seventh never submitted. Revalidate old
obligations during separately authorized cutover; this planning record is not a
fresh provider observation.

Use one versioned configuration bundle binding the replacement helper and inventory
format. Validate it before activation. Stop old issuance permanently, verify the
replacement can read all old obligations, then switch the single active cleanup
path without an unprotected gap. Only afterward enable new issuance. Delete
obsolete active paths in the cutover change or its explicitly scoped removal
commit; archive evidence and pinned historical source, not a second supported mode.

Before any new-format credential exists, rollback may restore old cleanup only;
old issuance stays disabled. After new-format issuance, rollback must retain a
cleanup-only helper that understands those obligations. Never revert to an older
issuer, discard the inventory, or roll back a provider deletion. If no reviewed
helper can safely reconcile, stop issuance and use a separately authorized exact-ID
cleanup procedure while retaining unresolved status and evidence.

The pinned rollback entry point is `python -m scripts.m3_11_unattended.cleanup`
with its private `--config` and `--actor` selection; GitHub reaches it through the
retained `connect_action.py` wrapper and independent Connect bootstrap. Its
versioned configuration is cleanup-only and contains no provisioning reader.
`__main__.py start`, worker issuance and old grant/update routes reject that mode.
Before activation, stop old issuer containers, disable restart/start routes and
retire their active provisioning configuration. Archived source and private
historical evidence remain available; automatic rollback cannot reactivate them.

## 8. Ordered implementation and acceptance gates

No step below is execution authorization. Complete each gate before its dependent
step; record failures and remaining unknowns rather than broadening the project.

1. **Plan review and local authorization.** Record the parent's design acceptance
   of D1/D2/D3/D4/D6, cancellation semantics and section 6's bounded test scope.
   D5 monthly-generation mechanics and fail-closed configurable checks are locally
   implementable without activating unresolved runtime values. Obtain the same
   independent reviewer's verdict on exact r3, then the parent's explicit approval
   for bounded local implementation and tests. D5 operational values and all live
   actions remain pending under section 1; do not create or resume a goal.
2. **Local lifecycle implementation.** Implement inventory/schema, one manifest
   confirmation, authority generations and lease/attempt separation using doubles.
   Preserve provider transports and the original runner. Evidence: deterministic
   state-transition and transport results with explicit synthetic policies, no
   live bootstrap access and no expansion of persistent permissions.
3. **Local integration and failure matrix.** Exercise the actual entry points
   with local providers and isolated test containers/volumes. Cover every row
   below, then run relevant repository checks and inspect committed installed-group
   selection. Evidence: results tied to the candidate revision, canary scan and
   retained failure outputs. Do not modify real containers or credentials.
4. **Review and CI.** Present one coherent implementation/cutover change with the
   plan, module removals, validation and unresolved live gates. Obtain exact-head
   review and required CI. Use GitHub review first and bounded isolated fallback
   if needed. No merge, push or cutover is authorized by this document alone.
5. **Separately approved setup and cutover.** Present exact revisions, migration
   mapping, actual authority/expiry metadata, targets and rollback helper.
   Verify independent access and activate one cleanup path before issuance.
   Provider credential replacement, workflow activation and configuration delivery
   require explicit authorization for these concrete operations.
6. **Separately approved live lifecycle validation.** Issue all original seven
   roles, verify actual policies including user-owned Page Rules, deliver and
   perform bounded probes. Exercise cancellation/revocation and authority handover.
   Test host-independent cleanup without host shutdown: the GitHub job has no
   workspace mounts or local secret files and cannot use Unraid's Connect endpoint;
   it uses its own existing independent Connect bootstrap. Record provider readback
   and negative probes where available. Failures remain diagnostic; diagnose and
   batch demonstrated corrections before another attempt.
7. **Separately approved full qualification and closeout.** Execute the unchanged
   complete M3.11 runner at the final approved revision. Verify production and
   fixture receipts separately, finish the lease, verify revocation, and retain
   exact source/artifact/target identities and sanitized/private evidence locations.

| Finite local acceptance case | Required result |
| --- | --- |
| Delayed/lost Connect writes and confirmation | No CREATE without exact independent manifest visibility; no competing lease after ambiguous preparation. |
| Partial provisioning, lost CREATE response, wrong scope/lifetime, lost ID publication | No mutation replay; exact ownership reconciliation; known wrong credentials revoked; uncertainty stays explicit. |
| Duplicate starts, controller death, volume loss/restore, suspended writer resuming after cancellation | One issuer; no automatic replay/takeover; no closed lease while a writer can still create. |
| Cancellation during each issuance boundary and interrupted cleanup | Pending calls accounted for; deletion/readback resumes; failed reads never erase obligations. |
| Finish/cancel during cleanup-lock contention and failed intent publication | Request publication needs no provider-cleanup lock; publication failure does not suppress deletion or falsely close durability. |
| Host unavailable and cleanup authority expired or replaced | Independent cleanup needs no Unraid endpoint; authority gaps refuse issuance; handover checks principal/scope, not only fingerprint. |
| Replacement DigitalOcean token authenticates for a different team | Setup and cleanup reject principal mismatch; authenticated empty inventory cannot discharge the old team's obligations. |
| Reused child with fresh attempt, changed source/target, stale receipt | Revalidation creates new bound evidence; mismatches and stale receipts fail; old failure is immutable. |
| Lingering guest command, interrupted quiescence or retained fixture restart | Exclusive runtime-use owner remains held; no new attempt until exact prior writers and restart behavior are verified quiescent; evidence/data remain. |
| Real private delivery/export and retained fixtures with secret canaries | No bootstrap in qualification, no secret argv/export, strict private permissions; retained-secret limitations reported accurately. |
| Complete report packaging and production checks | Expiring fixture accepted only in fixture validation; expiring production Caddy rejected; original storage and recovery checks preserved. |
| Migration and rollback with the historical exception | Every obligation accounted for; one exact exception retained; rollback cannot re-enable obsolete issuance. |

## 9. Definition of done and scope-change rule

Implementation completion requires reviewed code, required CI, the finite local
acceptance evidence, one active lifecycle path and removal of abandoned paths
without losing obligations. Operational completion additionally requires the
authorized live lifecycle/rotation evidence, complete M3.11 qualification, verified
revocation, and explicit reporting of the one historical accepted uncertainty.
Component tests, a lifecycle rehearsal or a diagnostic continuation alone are not
full qualification. No new goal is created or old goal resumed by completing a step.

Return for review if implementation needs a new datastore/provider/permission,
public endpoint, additional secret copy, automated takeover, renewed witness
protocol, broader scope/lifetime, weaker ownership or qualification checks,
destructive retirement, or an exception beyond the exact historical one. Likewise
return if the proposed inventory cannot handle the stale-writer or host-loss cases
without materially different machinery. Do not convert an unresolved provider
behavior or policy choice into assumed live authority.

## 10. Recorded local implementation authorization

This appendix records authorization received after r3 review; it supersedes the
earlier pending-approval statements only for bounded local implementation. The
first 37660 bytes above remain the exact approved r3 document, SHA256
`21d3adad04c2fb531a5bf053ee6b964c230d90fc19da0e57b077c755fd4eebfb`.

- Independent reviewer: `/root/review_credential_plan`; APPROVE exact r3.
- Parent approval: coordinator thread `01a123a3-bb08-7749-af68-d451fe6db0c5`
  approved that same hash and authorized sections 6/8's bounded local code,
  documentation and tests.
- Implementation turn: `01a1253b-f0a1-7132-a139-dda55c08af18`.
- Branch: `codex/credential-lease-inventory`.
- Base: `0b5b198bf06443e61f01b1f7259fea827f79fc23`.

Use explicit synthetic policy and provider doubles. No live bootstrap access,
credential operations, persistent-access expansion, configuration delivery,
existing-container changes, remote workflow activation, cutover, live runs,
pushes or merges are authorized. The cancelled goal remains cancelled. The four
held drafts in the creation-batch checkout remain untouched. Final local code
requires independent review against r3 before reporting local completion.

Implementation checklist:

- [x] Verify approved baseline, isolate checkout and record dual approval.
- [ ] Implement explicit policy, compact inventory and generation/lease lifecycle.
- [ ] Adapt private setup, controller, cleanup, evidence and migration entry points.
- [ ] Exercise the finite local acceptance matrix and repository checks.
- [ ] Obtain independent final-code review and resolve in-scope findings.
- [ ] Report local result and separately gated live work; do not activate it.
