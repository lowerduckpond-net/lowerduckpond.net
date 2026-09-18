# Milestone 3.10 implementation plan

- Status: completed; live qualification and production convergence passed 2026-09-18
- Date: 2026-09-12
- Base: `8d9adc1` on current `main`
- Branch: `feat/m3.10-archive-restore-deletion`
- Parent: [Milestone 3, M3.10](milestone-3.md#m310-implement-remote-archive-restore-and-deletion)
- Outcome: complete remote archive, restore, deletion, and archived export;
  prepare the reviewed production convergence starting gate while publication
  remains disabled

## Current implementation checkpoint

The plan is the first branch commit (`a70f107`). Coherent subsequent commits
implement the remote boundary, private services, durable journals, archive,
restore, ordinary deletion, and a separate root administrator emergency path.
The [evidence map](../threat-model/m3-10-evidence.md) records the tested revisions
and distinguishes component, installed-host, and live-provider qualification.

Archive preserves the complete active or suspended rollback source, binds one
verified remote version, and removes both route classes transactionally. It
retains the bounded local release history. Restore validates the exact bound
bundle, creates a fresh deployment, and applies selected-plus-two-predecessors
retention. Ordinary deletion requires a separate post-archive job, except when
complete verified history proves the tenant was never deployed. Tombstones
precede namespace and release removal; historical results remain replayable.

Construction and retirement journals preserve durable authority across remote
failures. A prepared upload is never repeated after interruption. Remote cleanup
independently verifies audited terminal state, preserves every bound version,
and confirms exact-key absence before removing retirement evidence. Whole-bucket
inventory includes unknown keys, versions, markers, and multipart uploads.
Quarantine resolution verifies all remaining bound bytes and inventories before
and after verification; it grants no deletion authority.

The installed root-only emergency command requires the administrator identity,
a correlation ID, and a reason. Its strict durable intent and permanent result
carry distinct administrator provenance, without inventing an ordinary job.
A dedicated bounded service and timer recover interrupted emergency deletion.
Ordinary transport and provisioner sudo cannot invoke this command.

The earlier component suite at `bd47ac8` passed 2,441 tests, with two separately
scheduled MinIO skips and one inapplicable filesystem-fault parameter skip.
Four repeated private archive/restore cycles and final deletion passed,
including historical result replay and bounded release retention.
The complete installed archive group also passed at `00f3f1a`, including
full-size suspended archive/restore and deferred snapshot/Caddy/Ansible races.
Both installed emergency deletion tests passed after fixture and service-policy
corrections. Exact persisted state and served routes survived reboot with
automatic recovery. The complete transport/recovery group passed, including
all six idempotent configuration overlaps and competing requests. Installed
quarantine recovery passed at `36aa88e`. That qualification run ended with no pending
intents, intake, exports, staging, quarantine, remote versions/markers, or
multipart uploads. Those development checkpoints preceded the final live Spaces
qualification and production convergence, which completed on 2026-09-18 for
merged source `22147a64e9b39e7965201cf2d96e07aeaa6d3ca1`. The
[production checkpoint](../threat-model/m3-10-evidence.md#production-checkpoint-2026-09-18)
records the exact artifact, sanitized report, required CI, final preflight,
credential-backup confirmation, and successful production runner exit.
Production publication remains disabled. The
[operational sustainability phase](m3-operational-sustainability.md) is next,
before M3.11 implementation.

## Installed execution boundary

The parser worker and ordinary reconciler remain network-isolated. Three
root-only private services provide job-bound archived export, fresh-session
construction, and cleanup with independent source/terminal proof. Requests
carry opaque durable authority and verified descriptors; they cannot choose
URLs, credentials, object names, or arbitrary filesystem paths. Only the root
network boundary receives `/etc/lowerduckpond/archive/credentials.json`.

Export exclusion survives descriptor transfer, worker death, queued descriptors,
and provider stream closure. Lending while an inner publication/state lock is
held is rejected. Construction requires a session established before intent
creation, independently derives the exact source/proposed manifest and unique
key, uploads once, and verifies the exact returned version. Cleanup derives its
authority from permanent audit/result evidence and current bindings.

The qualified systemd filesystem policy uses a read-only empty tmpfs root plus
explicit mounts. `ProtectSystem=false` is intentional: on the tested Ubuntu
26.04 systemd, `ProtectSystem=strict` overlays that empty root with the host root
and defeats path isolation. Complete installed-unit probes verify the effective
policy. The emergency service preserves the user/group switches needed by Caddy
validation through sandbox setup with
`AmbientCapabilities=CAP_SETGID CAP_SETUID`, while retaining
`NoNewPrivileges=true` and the bounded `CAP_CHOWN CAP_SETGID CAP_SETUID` set.

The SDK uses the fixed regional HTTPS endpoint and root-administered system CA
bundle; ambient endpoint, proxy, credential, and CA settings cannot replace
those inputs. Disposable installed storage qualification uses a private CA and
pinned MinIO container with separate archive and backup identities. It does not
replace the live Spaces gate.

For live checks, use the existing
[qualification wrapper](../../scripts/m3-archive-qualification), which retrieves
separate archive and backup credentials from encrypted production state.
Production credentials intentionally remain on the secure workstation. The
M3.10 wrapper now runs the installed lifecycle against live Spaces there and
produces sanitized evidence for the coder task; no credentials are transferred.

## Accepted boundaries

Follow ADRs [0019](../adr/0019-constrain-static-archives-and-exports.md),
[0021](../adr/0021-define-static-tenant-lifecycle-semantics.md), and
[0025](../adr/0025-separate-tenant-archives-from-platform-backups.md), together
with the existing authorization, transaction, publication, and lock contracts.
Reuse the host-agent, strict contracts, portable bundles, export spool,
immutable releases, audit, and complete Caddy generation machinery. The
provisioner continues to execute only root-issued opaque authorization jobs.

The dedicated private, versioned archive Space already exists. Only the
root-owned archive component receives its bucket-only credential. Never use
the Restic credential or ambient SDK credential discovery. Use the regional
endpoint, one known-length `PutObject`, exact returned version reads, and
fully paginated version/marker accounting; prohibit multipart and high-level
transfer APIs. Unexpected multipart uploads close admission.

Reserve one unique key, one version, and the full 120-MiB bundle ceiling before
upload. Count all versions and markers against 25 keys, 25 versions/markers,
and 3,000 MiB. Construction and retirement intents and quarantine retain
charges until an exact listing proves absence. Unknown or ambiguous objects
close archive admission while allowing recovery and cleanup.

## Coherent implementation commits

1. **Plan (this commit).** Record scope, ordering, evidence, and rollout gates
   before implementation changes.
2. **Remote storage boundary.** Add strict low-level client operations,
   explicit credential/configuration loading, bounded exact-version streaming,
   accounting and reservations, and fake-client protocol tests. Reuse the
   existing local versioned-storage qualification where appropriate without
   making privileged runtime code depend on qualification tools.
3. **Durable remote recovery.** Implement construction and retirement
   journaling, unknown-object quarantine, exact-key version/marker purge and
   absence confirmation. Reconcile lifecycle authority before remote cleanup;
   preserve every key still bound by any authoritative tenant record. Cover
   lost upload responses and interrupted discovery, purge, and journal updates.
4. **Archive transaction.** Capture source and proposed archived manifests
   separately, build and verify the proposed bundle under export exclusion,
   sync intent before the first remote request, and verify the returned version.
   Revalidate the source under publication and exclusive tenant-state before
   committing archived state, archive record, route removal, audit, and result.
   Recovery preserves the exact active or suspended source on rollback. A
   separate archive request for archived state independently verifies its record.
5. **Archived export and restore.** Deliver the exact bound remote bundle
   through the authenticated spool/result path. Restore independently validates
   that bundle and its record, creates a fresh deployment preserving tenant
   identity, journals retirement before unbinding, publishes transactionally,
   and retires the remote key after durable commit. Retain ordinary local
   release cleanup and enforce remote evidence on terminal result replay.
6. **Deletion.** Require a separate post-archive delete authorization and
   current exact object evidence for previously deployed tenants. Prove complete
   never-deployed history for the archive-free exception. Durably record the
   tombstone before removing state and releasing the slug; never reuse the
   tenant ID. Keep emergency deletion separately authenticated, root-only,
   reasoned, audited, and outside provisioner sudo and the ordinary transport.
7. **Installed boundary and qualification.** Install only the dedicated
   archive credential with root-only access, package required runtime
   dependencies, and extend local/installed tests and CI selection. Exercise
   real versioned storage, capacity, restore/rearchive, archived export/import,
   interrupted workers, and deferred snapshot and Caddy/systemd/Ansible races.
8. **Evidence and convergence starting gate.** Record precise passed and
   outstanding checks, add an operational preflight/runbook, and update the
   parent milestone status only to the level demonstrated. Keep live
   qualification, merge, and production convergence separately identifiable.

Split or combine adjacent implementation commits only when doing so improves
the completeness of their proof obligation; keep all work on this branch.

## Required evidence

- Fake-client assertions prove regional, exact-key/version operations, one
  explicit-length upload, no implicit retry that creates additional versions,
  no multipart/transfer manager, closed streams, bounded reads and listings,
  and fail-closed malformed or ambiguous responses.
- Durable-state and interruption tests cover every remote commit boundary,
  unreturned version discovery, unknown versions and delete markers, quota
  ceilings, quarantine persistence, and preservation of bound remote bytes.
- Lifecycle tests cover active and suspended archival, stale source rejection,
  fresh restore deployments, repeated restore/rearchive, distinct deletion
  jobs, never-deployed history, tombstone recovery, exact retries, and
  independent terminal object-presence or retired-key-absence checks.
- Archived export must preserve exact bundle bytes and round-trip through
  portable import into a newly created undeployed target with its own identity.
- Complete the M3.9 archive/restore/deletion snapshot races and the M3.8
  restoration/deletion Caddy, systemd, and Ansible overlap cases under the
  installed worker limits. Exercise reboot and autonomous recovery.
- Run focused tests first, then the relevant packaged-wheel checks and the
  repository's `just check` validation lanes. Distinguish unavailable live
  dependencies from implementation failures and retain sanitized evidence only.
- Live expendable-prefix tests must prove Spaces behavior and mutual archive/
  backup credential denial. Local substitutes do not satisfy that live gate.

## Production convergence starting gate

The [preparation runbook](../operations/m3-10-convergence-preparation.md)
records the existing workstation input workflow and the evidence needed to
reach this gate. The gate passed on 2026-09-18 for the recorded production
release. The requirements below remain the basis of that checkpoint; historical
evidence does not authorize a different source or artifact.

The requested stopping point is readiness for convergence, with no production
tenant creation or publication enablement. Before declaring the gate passed:

1. Complete implementation and all applicable local and installed acceptance
   checks, with a reviewable evidence map and rollback/recovery instructions.
2. Identify the exact reviewed source and reproducible host-agent artifact.
   Production convergence itself still requires clean, current `main`; a
   feature-branch artifact is not evidence of a merged production release.
3. Read-only preflight must prove the current dark host identity and artifact,
   empty live tenant history, unchanged edge controls, the archive Space's
   private/versioned/no-expiration policy, accounted remote contents, absence
   of multipart uploads, and separate bucket-only credentials retained in the
   established trusted-workstation secret store.
4. Finish and record the necessary live expendable-prefix qualification using
   the established guarded workflow and backed-up dedicated credential.
5. Stop before production host convergence. Publication remains
   `static_publication_enabled: false`; M3.11 backup/audit recovery and M3.12
   production qualification/enablement remain later gates.

Missing live credentials, unavailable provider access, unresolved integrity
failures, or absent merged-release evidence block their dependent gate only;
continue independent implementation and hermetic qualification where possible.

## Recovery and rollback

Preserve a still-bound archive version. Reconcile related lifecycle intents
before deciding whether an uploaded or retiring object is unreferenced. Purge
every data version and marker of an unreferenced unique key and independently
confirm absence before retiring its journal or capacity charge. Ambiguity
retains durable evidence and closes archive admission. Never restore routes
from an inferred active state, discard evidence to pass a check, or reclaim
storage based on an unversioned delete or object-age policy.
