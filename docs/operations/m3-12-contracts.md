# M3.12 publication contracts

P1 defines [version 1 record shapes](../../schemas/m3-12/v1/contracts.schema.json),
their [semantic validators](../../scripts/m3_12_contracts.py), and the
[proof inventory](../threat-model/m3-12-evidence.md). P2 implements diagnostics
and P3 implements the shared writer, enforcement and successor controller.

## Canonical records and independent authority

Use strict UTF-8 JSON, RFC 8785 plus a single LF, and lowercase SHA-256 of those
bytes for references. Reject duplicate members, unknown fields, unknown
formats, invalid timestamps and oversized records. Record timestamps use
UTC to second precision. An independent receipt reader authenticates the
immutable original bytes and their observation provenance before making them
available by digest. A digest identifies bytes. Authenticity comes from the
appropriate protected journal, run owner or verified evidence producer.
Transport arguments, imported reports by themselves, raw diagnostics and
self-authored successes cannot populate that trusted store. Failed, partial,
diagnostically mutated or revoked runs are ineligible for completion.

Each binding contains the closed kind/purpose pair, run ID, exact target
digest, candidate digest and platform digest. The candidate identifies the
reviewed clean Git revision, ADR 0029 input policy and full fingerprint,
host-agent artifact, toolchain and dependency identity, and requirements
inventory. Tracked content and modes follow ADR 0029, including plans,
runbooks and future paths. The ADR's historical record exclusions apply.
The platform digest binds the namespace, exact storage target and backend,
reviewed Cloudflare network set, platform domain, origin/alias suffixes,
and edge and cookie policy versions. The selected storage digest binds
provider/region and the admitted archive and backup targets. Runtime keys
and their use are observed separately through their authorized role checks.

The controller establishes target kind and purpose by independent
allocation/provisioning observations and root-owned enrollment on the
connected host. Reread on initial activation and every resumed mutation,
including the lease and operation fence, current scope, transport and
revocation. Before either disposable path may progress, compare all known
addresses and aliases, inventory, state, lease, enrollment and transaction
namespace against the enrolled production set. An unavailable or incomplete
production exclusion set closes disposable admission. The address-set
digest binds the selected inventory. Also compare individual addresses to
catch partial overlap. Pass the observed and reserved identity sets
independently of the bundle.

| Target kind and purpose | Required enrollment and identity |
| --- | --- |
| `installed-fixture` / `installed-test` | Use the existing owned Docker machinery and original private allocation/run manifest. Bind actual endpoint and the daemon's observed ID, Name, DockerRootDir and ServerVersion, drained allocation and exact host/archive full container and image IDs, run labels, MinIO, fixture-operation lock domain and run lease. Verify the selected container transport or SSH peer and host key; use the daemon only outside the guest. Reject replacement, extra roles, uncertain allocation, frozen/disposed ownership and changes to the transport. |
| `disposable-droplet` / `disposable-qualification` | Bind the exact owned OpenTofu state, run/project/Droplet, independent provider/metadata/SSH identities, admitted address and inventory, provisioning and leased operation scope, and exact disposable Spaces targets. |
| `production-host` / `production` | Bind the enrolled provider/metadata/SSH identity, real inventory and state, original accepted M3.11 completion and selection, reviewed successor proposal, distinct successor journal and lease, reserved address and exact production Spaces targets. The successor proposal digest identifies the original proposal before it is cross-linked from the successor journal. |

The immutable admission bundle contains that binding and the target, candidate
and platform documents it hashes. The current invocation, authority and
fence must independently match. Require absence of tenant history,
tenant-bearing active generation and unfinished lifecycle work. Current
tenant count alone cannot decide first launch.

## Prerequisites, launch and later completion

- Installed and Droplet admissions require passing component and
  transport/bootstrap receipts, actual dark staging and repeat converge, and
  current target safety after dark repeat. The target safety receipt belongs
  to the activation invocation. That invocation rechecks provider/ownership
  facts where applicable. A disposable prerequisite backup may use its dark
  platform state entirely before activation.
- Production also requires the exact complete-disposable report for the
  same candidate and reviewed disposable platform, same-invocation live
  preflight before the first host mutation, the accepted predecessor and successor
  lease, and the final restore-verified platform backup taken after dark
  repeat. After an interrupted caller, read back the earlier dark stage and
  run fresh preflight before the resumed invocation mutates the host. The earlier disposable platform has its own approved storage
  identity. Match the reviewed Cloudflare network set, domains and policies.
- Every direct prerequisite receipt binds the admission's original run,
  target, candidate and platform, exact expected receipt kind and an
  authenticated observation digest. Include original observation start,
  finish and oldest supporting time. The only prerequisite that can refer
  to downstream work is production's earlier, distinct disposable report.
  Its own admission accepts only the pre-launch prerequisite kinds.
- A production backup/restore prerequisite binds the exact protected
  backup identity, restored platform contents and observed compatible
  generation. The independent reader verifies exact version, backup
  completion, restore isolation and successful smoke checks before making
  the receipt trusted.
- The same future initializer uses the same durable publication path in all
  three environments. Its invocation cannot select a more permissive kind or
  treat a caller's claim as enrollment. Under the global lock order, reread
  enrollment, history, namespace, policy and receipt identities on the
  selected bound target. Persist and sync the intent before record creation.
  Write the existing root-owned `platform/launch.json` at mode `0600` using
  descriptor-relative atomic replacement safeguards. Sync the file and
  parent before opening issuance. The existing
  `lowerduckpond-m3-acceptance-v1` digest is SHA-256 of the immutable
  pre-enablement admission. Bind the receipt to the exact intent and launch
  bytes and preserve the first intent's launch timestamp.
- A crash before intent allows a fresh preparation under current authority.
  With a durable intent and missing record, keep issuance closed and
  compare the original reviewed bytes after draining uncertain work and
  repeating current safety checks. An exact authorized retry finishes the
  same intent. A launch record observed before the durability boundary must
  be verified and synced before opening issuance. After durable launch,
  return the original bytes and timestamp. Conflicting, missing or forked
  authority at any boundary stops mutation and stays available for diagnosis.
  A resumed caller can hold a new fence and invocation while validating and
  preserving the immutable original admission and launch intent.
- Issuance requires valid durable launch before the first external tenant
  job. Once tenant history exists, require compatible launch for
  reconciliation and route mutation even when no current tenants remain.
  Restored state retains launch and namespace identity and follows separately
  scoped, fenced restore authority. Ordinary startup and autonomously
  scheduled reconciliation continue under their existing documented authority.

## Production stages and configuration

The future reviewed candidate already contains the final production
`static_publication_enabled: true` selection. Apply stage differences only
through the reviewed transaction and leased controller. Keep platform recovery
and audit rotation enabled throughout. Unspecified environments remain
closed. Direct production converge and arbitrary extra variables cannot select
a stage. Read-only preparation exposes the candidate, actual host,
predecessor, stage values, proof and proposed effects before approval.

| Phase | Effective configuration and commit evidence |
| --- | --- |
| Preparation | Observe selection, exact accepted predecessor, ingress, keys/capability, integrity and quiescence in the same invocation. Pin the reviewed proposal and prove original authority and lease. |
| Dark staging | Apply the reviewed candidate with publication false. Verify healthy platform generation, no tenant work or issuance, and stage-effective inputs. |
| Dark repeat | Repeat the same dark view. Record converged health and no unexpected changes across the agreed idempotence boundary. |
| Final backup verification | Stay dark. Capture final platform backup and restore-verify the same immutable backup on the separately authorized target. |
| Activation preparation | Stay dark. Validate original pre-launch receipts, freshness, current ownership and enrolled target. Reveal only allowed effects. |
| Durable launch | Stay dark until the exact intent and launch record are durable. Read back the record and its parent boundary. |
| Enabled convergence | Use the final reviewed enabled view with matching launch and restart/reconciliation authority. Verify publication, health and policy. |
| Enabled repeat | Repeat that exact enabled view and verify idempotence. |
| Canary | Keep enabled. Use ordinary audited operations on the two synthetic tenants. |
| Accounting | Keep enabled. Verify route absence, archive retirement, audit continuity and settled work. |
| Acceptance | Keep enabled. Join the original evidence, canary and accounting. Record one terminal result. |

The distinct successor journal stores the immutable transaction and
hash-linked phase receipts in order. Bind the applicable stage view and
reviewed effective configuration digest to each phase. Replicate original proposals, record
the start/intent before effects, independently read the postcondition, and
only then commit. An uncommitted start means outcome unknown until the
current owner reads remote state. Drain the original process before
committing a verified effect or proving it had no effect. Only a verified
`not-applied` receipt with original preconditions allows a fresh attempt at
the same phase. Reuse committed receipts. Conflicts, uncertain state or a
changed lease/target block progress. A lost caller cannot prove failed
submission. Resize, provisioning, credentials, inventory changes and
restore-target allocation require separately approved scopes and receipts.

Before tenant history, separately record a rollback decision bound to the
current journal head, original platform-only predecessor and independently
verified absence of tenant state/work. Close issuance, restore only that
compatible generation and retain all intent and launch bytes and decisions.
The journal reader treats the latest rollback disposition as a closed
overlay on the normal phase machine. Resume requires explicitly guarded
same-policy reactivation with fresh checks and the original launch identity
if present. P3 implements the durable rollback disposition and gating.
When history exists, keep the enabled contract and use tested lifecycle,
forward repair, or separately authorized emergency operations or fenced
restore. Zero current tenants after deletion does not reopen rollback.

## Reports, provenance and time

A report wraps a durable seal for one completed target. The seal binds
the same admission and launch receipt plus the original functional,
accounting and teardown receipts for installed/disposable runs. The
production seal binds canary, accounting and acceptance instead. Its
original proof includes the earlier disposable qualification.
`installed-diagnostic` may support a reviewed component/installed slot.
Live slots require the original disposable/production proof with their
own binding. `complete-disposable` is the only report kind consumable by
production admission. Production acceptance follows the production launch.

The trusted producer verifies [exact requirement coverage](../threat-model/m3-12-evidence.md)
and final observations before certifying the functional/acceptance receipt
and authenticating the seal. Record the oldest real observation used
by each receipt. Preserve original chronology and exact accounting and
teardown facts, including independent cleanup/ownership disposition.
A finalized envelope may be assembled later from the same sealed bytes.
Keep the original five-minute future-clock tolerance and the seven-day
consumption rule measured from the oldest supporting evidence through
production admission. Preserve original expiry, withdrawal, revocation,
cleanup reserve and exact scope. An attended pause has no inherent
whole-session deadline. Every active action still has its applicable
operational and credential limits. Existing M3.10/M3.11 reports, approvals,
historical records, and their validators retain their existing limits.

## Diagnostic and artifact exclusions

Allocate a private run before setup and preserve append-only allowlisted
checkpoints through guest helper, systemd, SSH/Docker, Ansible and the detached
caller. The bounded diagnostic record carries operation and stage, correlation
IDs, UTC/monotonic timing, safe source/helper and artifact digests, permitted
numeric statuses and pinned source symbol/line frames. Use structured systemd,
Ansible or provider status and typed errors. Keep the primary failure and
independent collection, transfer, cleanup, lease-release and finalization
failures. Emit additional checkpoint records when one bounded record is full.
A missing terminal record distinguishes interruption or uncertainty from a
known result. Expose missing or omitted output explicitly. Public summaries
use the separate projection of identifiers, safe categories, outcome and
checkpoint/omission counts. Derive private location, summary location and next
inspection command from the trusted run ID and operation; never copy paths
or commands from an exception.

Apply exclusions **before** observation, transport, processing or persistence
in every layer. Forbidden content includes Caddy-only environment, adapted
Caddy configuration, credentials and keys, signed URLs, sensitive arguments,
locals, bulk service or Docker inspect output, raw streams/exception text,
request/response payloads and tenant bytes. This applies to private spools,
scratch files, journals, backups, audit, crash dumps, transcripts, diffs,
diagnostics and exported records. Do not read forbidden bytes for hashing,
redaction or later filtering. Use pre-existing trusted manifest digests and
metadata probes. Constrain each boundary to the same field and source
allowlist. Keep private records and secret-free repair materials outside
ordinary tenant backup authority. Diagnostic artifacts cannot confer
admission, cleanup, restoration or production authority.
