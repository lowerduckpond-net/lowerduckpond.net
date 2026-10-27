# 0032: Retire migrated custody after terminal lease cleanup

Status: proposed; execution requires a separately reviewed and sealed caller.

## Context

The frozen retirement route requires its original active lease, controller,
daemon and actors. A migrated custody copy with seven revoked credentials
cannot satisfy that route. Starting the source or relabelling history would
not repair those bindings. An occupied archive bucket also blocks the next
qualification's whole-bucket readiness check.

## Decision

Add a separate, narrow adapter for one exact archive version. Keep the existing
active-lease retirement route unchanged. Do not create a new bucket, change
targets, revive an old credential or convert preserved history into runtime
identity. The adapter creates no credentials and never contacts the old source.

The new plan separates three authorities:

- Historical custody binds the original fixture UUID, source workspace,
  original lease/manifest, preserved archive and clean state image. A new local
  index binds unchanged original files and migration provenance by byte hashes.
  `verify_preserved` rechecks the native tenant/job/result/audit/archive chain.
- Authenticated current journal reads must prove the old lease's seven exact
  created/removed/denied identities and original stopped issuer. A compact
  `closed` summary or expired token alone is insufficient.
- A separately approved, already issued native seven-role lease supplies live
  authority. It must have no runtime users, its original issuer must be stopped,
  its complete manifest independently confirmed, its native scopes verified and
  both current host and independent cleanup proofs bound to the new helper.

Only the fresh archive key may DELETE. The distinct fresh operator key is an
observer, restricted by the adapter's SDK hooks to exact bounded inventory
operations. Both must independently observe the entire approved bucket: exactly
the single planned version, no markers, no multipart uploads and no truncation.
No backup-bucket objects, original files or source resources are mutated.

## Exclusion and one submission

Hold daemon-wide native admission, the current lease runtime-use lock and the
existing target storage lock. Verify the running helper's full container ID,
approved daemon/image, read-only helper/config mounts and actual shared native
evidence/storage volumes. Pin evidence-volume creation time to reject replacement
lock domains. A copied workspace path is insufficient. Hold the cleanup lock only
for the bounded submission and its final native close-intent read.

Before the final inventory and DELETE, durably consume a local exclusive
reservation and publish an exclusion keyed by historical fixture UUID into the
existing external Connect journal. Require exact readback through the provision
and cleanup principals. This is application-enforced append-only storage, not
provider-enforced immutability or a distributed compare-and-swap lock. Shared
native admission/volume ownership supplies exclusion; journal conflict checks
are additional guards, not an election protocol.

The separate title/tag namespace is ignored by current lease and legacy-obligation
readers. The obsolete strict import bridge does not support it. Execution therefore
requires the current native watchdog and independent helper, never that bridge.
There is a maximum of eight custody facts per bounded inventory; excess or any
malformed/conflicting/duplicate fixture fact fails closed.

Every future migrated-retirement invocation consults the external fixture key,
independent of path, current lease or plan. A matching fact permits observation
only after loss of crow and all local files. An interrupted invocation never
adopts a pending publication or prior reservation as renewed deletion authority.
The old route still requires its actual original active lease, which this
terminal historical lease cannot supply. No execution/import of this retired
custody is supported. The external note must remain with the retained journal
after workspace disposal.

After any consumed reservation or uncertain SDK outcome, there is no automatic
retry. Observation may report present or absent; it cannot manufacture a
completion receipt. Completion requires two fresh whole-bucket empty observations,
the retained external exclusion and unchanged historical proof. It truthfully
reports the old lease closed and cleanup of the current lease still owed.

## Continuing qualification

After verified completion, record a digest-bound index on the same unused fresh
lease. The existing storage-admission route may then allocate its real first
runtime consumer, after rechecking the external fact, current credentials,
approval and whole-bucket emptiness. It does not invent a failed/released consumer,
waive readiness or mint a second credential set. Existing leases with consumers
retain their original admission rules.

The standard `start` command accepts `--custody-manifest-sha256` with an existing
explicit qualification-lease approval. It preserves all start gates and sends an
explicit first-use request to native admission. That request must prove zero
prior users and completed retirement in the same actual daemon/evidence domain;
it cannot substitute for an ordinary retained-lease controller or receipt.

## Publication and execution gates

This code and a passing unit suite do not constitute execution approval or a
caller seal. A concrete private caller must authenticate the native preservation,
host-watchdog and scheduled GitHub collectors; run the complete offline verifier;
pin its source/runtime/transitive dependencies; verify Coder's exact workspace;
hold native admission throughout; launch only the fixed helper with the approved
image and mounts; exchange nonce-bound proof frames; validate exact terminal
receipts; and retain uncertainty without automatic re-execution.

Native `LeaseLifecycle.prepare/issue` remains the creation boundary. Do not use
`worker._provision` as an issuance-only shortcut, fabricate a runtime consumer or
read passive custody credentials. Exact current issuance scope and exact live
VersionId inventory must be bound to action-time approval before those actions.

Publishing/merging this new change needs its own authorization and required CI.
After publication, regenerate the operator delivery package, controller/helper
images, cleanup bindings, caller seal and executable plan against the exact new
revision. A setup package or plan pinned to an earlier helper must not activate.
Preserve all historical packages and existing approvals as history; never rewrite
them to claim they named a later revision.
