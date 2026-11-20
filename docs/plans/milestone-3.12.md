# Milestone 3.12: deliver, qualify, and enable static production

- Status: draft implementation plan for review; no implementation or live operation authorized by this document.
- Assessed: November 4, 2026, against `main` at `ecb3c2be3212d54209f1ed34b8c3a6961f6c850a`.
- Scope: the complete [M3.12 definition](milestone-3.md#m312-qualify-and-enable-production), its production gate, and final Milestone 3 evidence.
- Execution policy: evidence and dependencies determine readiness; there is no delivery deadline, fixed number of debugging attempts, or human response timer.

## 0. First: resolve the current Dependabot updates

The operator explicitly requested that Dependabot updates be front-loaded.
Complete this dependency work before M3.12 feature implementation and before
selecting its qualification candidate. The inventory below was checked on
November 4, 2026; `main` still resolved to the assessed `ecb3c2b` revision.
All seven open PRs were authored by `dependabot[bot]`. This is an inventory and
implementation sequence, not authorization to rebase, edit, close or merge them
during this planning task.

### 0.1 Current PRs, CI and overlap

| PR and inspected head | Proposed change | Observed checks and disposition to prepare |
| --- | --- | --- |
| [#190](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/190), `34ca5ecd94aa` | `urllib3` 2.7.0 → 2.8.0 in `uv.lock`. | Historical Gate passed. Oldest of this set; automatic rebases are disabled. Refresh against current main and test actual HTTP/TLS/proxy, streaming and pinned Botocore paths before accepting its new lock. |
| [#257](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/257), `0d0edfdb6e6b` | `certifi` 2026.7.22 → 2026.10.18; lockfile revision 3 → 5. | Historical Gate passed. Shares `uv.lock` with the other Python PRs; verify the trust-store change and its resolved compatibility with the updated HTTP/SDK stack. |
| [#255](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/255), `537f4c22ac92` | `filelock` 3.32.3 → 4.2.1, plus `virtualenv` 21.7.4 → 21.14.13 and `python-discovery` 1.5.2 → 1.6.4; adds virtualenv's packaging dependency and lock revision 5. | Historical Gate passed. Major filelock change needs compatibility review. Its actual diff already contains the entire virtualenv/discovery change proposed by #254; treat them as one overlapping dependency set. |
| [#254](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/254), `903a0a834d40` | `virtualenv` 21.7.4 → 21.14.13, `python-discovery` 1.5.2 → 1.6.4 and associated lock metadata. | Historical Gate passed. Prefer #255 as the coherent combined update if it remains compatible after refresh; then prepare #254's superseded disposition. Do not blindly merge both stale lockfiles. |
| [#264](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/264), `4da5be4f9feb` | Six grouped Actions updates: `mise-action` 4.3.0 → 5.2.3; Docker login 4.6.0 → 4.7.0; upload 7.0.1 → 7.0.2; download 8.0.1 → 8.0.2; CodeQL init/analyze 4.37.9 → 4.39.1. Changes six workflows, including credential/public-CA cleanup. | Gate/Python/aggregate Ansible failed; installed matrix did not run. Actions, CodeQL and static checks passed. Investigate the observed baseline test failure, review the major mise-action migration and artifact/cleanup contracts, then run checks on the refreshed head. |
| [#194](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/194), `a0b1e29624f2` | Pinned pre-commit `markdownlint-cli2` 0.23.2 → 0.24.0. | Gate/Python/aggregate Ansible failed; installed matrix did not run. Its Pre-commit check passed. Refresh and validate the whole documentation set under the new hook before writing M3.12 documents against that baseline. |
| [#265](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/265), `0616bfe11f92` | DigitalOcean provider 2.100.0 → 2.106.0 and Cloudflare provider 5.24.0 → 5.28.1 across bootstrap-state, production, qualification and the edge module; three lockfiles plus provider declarations. | Gate/Python/aggregate Ansible failed; installed matrix did not run. OpenTofu and the speculative PR plan passed. Review provider schema/state effects and exact lock consistency before the M3.12 infrastructure work. Production plan/apply were skipped, which is expected and is not live compatibility proof. |

The four green Python-update heads predate current main; their passing checks
are useful history, not acceptance of their combination with PR 267. The
separate complete journey was skipped in all seven inspected PR runs. On a
fresh read at **2026-11-04 09:44 UTC**, GitHub returned `mergeable: true` and
`mergeable_state: behind` for all seven unchanged heads. The earlier unknown
response was transient. Mergeability does not establish required CI success or
compatibility of the combined dependency graph; refresh this snapshot when
preparing actual changes.

The failed Python job logs for
[#264](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/41280706379/job/124771880852),
[#194](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/41281558942/job/124774342051),
and [#265](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/41282267162/job/124776413458)
show the same generation-handover tests rejecting a replacement that was not
newer than the original in `connect_renewal.py`. They establish that shared
failure, not causation by any dependency update. The current fixture uses
second-truncated `datetime.now()` for the replacement generation, making
deterministic clock/order investigation appropriate. Do not waive the production
newer-generation rule or add sleeps to make it pass. Reproduce on current main
and the refreshed heads; if needed, front-load a minimal deterministic fixture
correction as part of P0, retaining the real cleanup/rotation assertions.

### 0.2 Dependency-first execution order

1. Refresh this inventory and inspect the exact diffs/release or migration notes
   on current main. Preserve PR attribution, original heads and observed failures.
   Prepare any minimal deterministic baseline-test correction needed to obtain
   meaningful CI; do not bundle unrelated M3.12 feature changes into it.
2. Resolve #264's CI-tooling and #194's hook updates early so subsequent changes
   are validated using the intended tooling. Check full-SHA pins, supported
   runner/tool installation, artifact upload/download identity and failure
   behavior, CodeQL, secret exposure and scheduled cleanup contracts. Their
   static/PR checks cannot prove a live scheduled cleanup execution; preserve
   that future live-proof requirement without issuing credentials now.
3. Resolve the Python lockfile set on that baseline: prioritize #190 and #257's
   network/trust changes, then the coherent #255/#254 tooling dependency set.
   Regenerate or refresh targeted resolutions using the repository's pinned uv
   rather than concatenating stale lockfile hunks or updating every package.
   Validate the final combined graph, hashes and supported Python 3.14 install.
   The solver must settle any lockfile-format revision difference; do not
   hand-label a revision bump as compatible. Review the major filelock change
   through its actual pre-commit/virtualenv/discovery consumers. If #255 covers
   the accepted #254 update, record and later close/supersede the duplicate
   rather than doing a second update for its own sake.
4. Resolve #265 across every consuming root/module and lockfile. Regenerate
   consistent lock metadata without unreviewed provider drift. Inspect changes
   affecting reserved-IP assignment/retry/readback, host creation/resize,
   firewall and Cloudflare policy/association semantics. The inspected repository
   does use reserved-IP assignment; the release-note GradientAI resource rename
   is not a used resource family here. Validate actual usage rather than inventing
   a state migration. Prepare a read-only production plan separately under the
   trusted-workstation boundary when authorized; a provider update does not
   authorize apply, state mutation or production resource replacement.
5. Finish required review/CI for each accepted logical update, then validate the
   combined post-update main baseline before P1 feature work. Record exact
   accepted versions, commit/lock digests, duplicate disposition and any real
   incompatibility still unresolved. Do not silently defer a requested update
   or call a failing update accepted. A demonstrated incompatibility gets a
   concrete correction or explicit disposition, not an endless update chase.

Actions/hook/provider work has no semantic dependency on a particular Python PR;
the order above establishes a useful validation baseline, not artificial new
approval gates. Overlapping Python PRs do depend on one final consistent solver
result. Newly appearing bot PRs should be assessed for security/compatibility,
not automatically expand P0 into a perpetual requirement to use the latest
release. The existing bot cooldowns/schedules are not new human waiting periods.

### 0.3 Validation before M3.12 implementation and qualification

For the refreshed Python graph run frozen full-workspace sync, focused real SDK
and HTTP/TLS/proxy/error-transport tests, pre-commit environment creation and
the full Python checks. Use the existing real Botocore parsing/encoding tests,
MinIO integration and ownership/cleanup regressions; a pure fake-provider pass
cannot stand in for the updated transport behavior. Check urllib3/botocore
compatibility and certificate trust with the pinned dependency versions rather
than inferring it from an unchanged direct-dependency declaration.

For #194 run the upgraded hook over the whole repository and check links;
subsequent M3.12 plan/runbook validation must use that accepted hook. For #264
run actionlint/workflow contract regressions, exercise diagnostic/artifact
failure paths and inspect required CI/CodeQL. For #265 run formatting, isolated
backend-disabled init with locked provider selection, validate/lint/security
checks for all roots, edge-module tests and plan assertions. Investigate
unexpected replacement, drift, permission or schema changes; never fix them by
loosening the production edge/security policy.

Use the existing installed-selection policy for each committed update and the
combined dependency baseline. Run required installed groups and the complete
journey once for the final combined graph before starting M3.12 features; do not
repeat full live qualification after every dependency-only PR. Retain failed
logs, root causes and corrections under the same diagnostic principles below.
After M3.12 code lands, repeat the required final checks and perform one complete
live qualification against the final combined candidate.

All dependency/hook/workflow/provider changes are ADR 0029 inputs. Recompute the
candidate fingerprint and rebuild affected artifacts/controller/helper images.
Keep the accepted dark-production deployment historical; do not deploy merely
to record P0 completion. Changed default-branch workflow identity can invalidate
private cleanup/caller seals even when their code is otherwise compatible.
Before later live use, reconcile and regenerate affected delivery/seal bindings
against the exact accepted revision, preserving older packages and approvals as
history. Never silently rewrite a sealed package or reuse old qualification as
authority for the new dependencies.

## 1. Intended result and scope

Deliver the missing activation, orchestration, diagnostics, and acceptance tooling;
qualify the final candidate on real disposable infrastructure; then separately
authorize its installation and activation on the existing production host. Prove
the ordinary two-tenant production canary, retire its tenant archive objects,
preserve audit and backup evidence, and close Milestone 3 through records.

This milestone requires code changes. It is not simply another invocation of
the current deployment command against a fresh Droplet. Reuse the static
lifecycle, backup, archive, and recovery engines. Change them only for uncovered
requirements or failures demonstrated by tests and investigation. Do not add
Milestone 4 control-plane features, dynamic hosting, custom domains, cache
enablement, or real customer onboarding; the latter remains Milestone 7.

There are three distinct environments:

| Environment | Purpose and permitted work |
| --- | --- |
| Local CI and disposable installed fixtures | Fast component regressions, deterministic failures, real Unix/SSH/systemd and SDK tests, and the complete existing installed journey. Enroll an actual owned Docker target as `installed-fixture` and use the same launch initializer; its receipts are diagnostic installed evidence only. Synthetic logs may use the established CI output policy. |
| OpenTofu-owned NYC1 qualification Droplet and separately fenced restore target | Production-equivalent deployment, full boundary and failure qualification, public-edge/browser proof, resource measurement, actual reboot, backup/restore, and interactive investigation. Destructive faults stay here. |
| Existing production host | Fresh inspection, separately approved resize if needed, qualified dark staging, final verified backup, reviewed activation, two-tenant canary and actual reboot. No hostile isolation drill, injected origin outage, or disposable teardown against production. |

The restore target is expendable infrastructure; the production host is not.
Production Restic snapshots and the service-lifetime archive bucket are not
disposable qualification resources. A disposable host using the real `.net` and
`.com` DNS zones still has a production shared-service boundary: ownership must
constrain every DNS record, certificate association, ruleset, object and credential.

## 2. Verified baseline and remaining gaps

The [M3.11 closeout](../records/2026-11-02-m3-11-closeout.md) records the accepted
dark deployment of source `a3d35834ac8a0a28bc7723be017407b58bf4a73e`, with
publication false, recovery enabled, and audit rotation enabled. Its original
qualification, production journal, interventions and limits remain historical
facts. Its earlier source does not qualify a later changed candidate.

[PR 267](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/267) is merged
at the assessed revision. It already implements the 90-day audit-reader policy
and orders bootstrap dependencies before their use. It also removes candidate
pre-seeding from the M3.10 predecessor fixture and adds acknowledged-copy
interruption/resume regressions. Retain and exercise those fixes; do not recreate
them as missing features. The PR's own local validation did not claim its full
real-SSH/systemd rollout proof. Subsequent inspection of the final PR head
`689ccedcc3744e9adf8a5ebc50b9dd93e9bdc896` confirmed that
[CI run 41702597563](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/41702597563)
passed all 24 installed groups, including `production-rollout`, the aggregate
Ansible check and Gate. That PR-triggered run skipped the separate complete
journey. These results support the fixes; they are not live Spaces/Droplet
qualification or evidence for the future M3.12 candidate. Recheck its required
CI before release.

| Existing implementation | M3.12 work required |
| --- | --- |
| `scripts/m3_11_production_gate.py`, production journal/controller and `config/ansible/tasks/m3-11-production-guard.yml` require dark publication and deny convergence from an accepted transaction. | A separately bound successor transaction, preserving the accepted M3.11 records and ownership fence, must authorize dark staging and first activation. Do not weaken M3.11's completed-transaction semantics. |
| `enable-publication.yml` verifies the authoritative Caddy selection and opens the configuration gate at the end of `site.yml`. | Bind opening to explicit M3.12 acceptance authority and durable first-launch state; make interruption and retry safe. |
| The `LaunchRecord` schema, repository path, backup capture and restore bindings already exist. No first-enablement writer was found in the inspected host-agent, Ansible or scripts paths. | Implement initialization and enforcement, including issuance/reconciliation and backup/restore tests. A valid schema fixture is not live launch authority. |
| `scripts/m3-qualification`, the qualification OpenTofu root and `m3-qualification.yml` provide M3.0 primitive/edge/browser proof. The playbook sets `caddy_generation_enabled: false` and installs only base, firewall, Caddy and qualification roles. | Add a full-stack real-host qualification path. Do not relabel the old M3.0 host drill as installed lifecycle/backup/recovery acceptance. |
| `scripts/qualification_groups.py` declares 24 installed groups, and the complete journey remains separate. Much fixture transport assumes Docker. | Preserve those tests and the complete journey; provide real-SSH/Droplet adapters and an explicit coverage inventory for the final environment. Docker restart is not a Droplet reboot. |
| M3.11 has retained-fixture debugging, native helper traces, timing, immutable failed reports, original-authority finalization and cleanup recovery. | Extend these facilities to every M3.12 entry point, real Droplets and production deployment; test the entire error path to the invoking operator. |
| Production inventory has `static_publication_enabled: false`; enabled-role compatibility checks reject changed installed artifacts/commands. | Qualify and install changed bits while dark before opening publication. An enabled converge cannot be used to bypass those compatibility guards. |

No `AGENTS.md`, repository `.agents` instruction, or repository `SKILL.md` exists
in the inspected tree. The available local Codex memory database had no
matching Lower Duck Pond/M3 record. Current source and retained repository
records therefore anchor this plan. No live host or provider state was inspected.

## 3. Design decisions to implement

### 3.1 One candidate, explicit stage configuration

Use [ADR 0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md):
bind the complete clean source, input-policy/fingerprint, host-agent artifact,
tool/dependency versions and storage target. Unknown/new paths remain inputs.
Plans and runbooks are inputs too. Only qualifying historical record files have
the existing exclusion. Do not qualify a branch and later change a normative
document or the publication flag while claiming the same candidate.

The final reviewed candidate must already contain the intended production
`static_publication_enabled: true` change before release qualification. Defaults
for unspecified environments stay false. The qualified transaction manifest
defines the only allowed stage differences: dark staging with issuance closed,
then explicit activation. These stage values are validated by the native leased
controller, not arbitrary operator `--extra-vars`. Direct `configure-production`
against that candidate must fail without the new transaction authority.

A dry/read-only preparation command must expose the exact host, predecessor,
source, artifact, input fingerprint, stage configuration, evidence and allowed
effects before a live approval. Source changes found during investigation get
new identities. Do not manufacture equivalence from a matching artifact alone.

### 3.2 Successor production transaction

Add an M3.12 transaction namespace and closed phase machine that cross-links the
original accepted M3.11 journal, completion identity and actual host selection.
Keep the old directory and accepted bytes intact. The guard must recognize a
valid successor under its own lease without treating M3.11 acceptance as new
configuration authority. Missing, conflicting, unfinished or substituted
predecessor/successor authority stops mutation and prints how to inspect it.

Reuse the established lease/action exclusion, replicated original proposals,
hash-linked receipts, retained inputs and remote process draining. Avoid a new
parallel generic workflow or a new authority ceremony for each phase. Each phase
has: preconditions, immutable start/intent, permitted effects, independently
readable postconditions, commit and resumption rules. A lost caller is not proof
that a remote action did not run.

At minimum the phase model distinguishes preparation, dark staging, dark repeat
convergence, final backup verification, activation preparation, durable launch,
enabled convergence, enabled repeat convergence, canary progress, final
accounting, and acceptance. Resize, infrastructure changes and restore-target
creation have their own approved scopes and receipts; they are not implicit
side effects of host convergence. Reuse the original phase on resume rather
than replacing the transaction or replaying a completed backup/upload.

### 3.3 Durable launch and enforced admission

Implement a narrow root-owned launch initializer using the existing canonical
contract, descriptor-relative durable I/O and global lock order. Use the **same
initializer and durable publication path** for installed Docker tests, disposable
Droplet rehearsal and production. Its common checks verify:

- a valid, closed-schema, target-bound admission bundle; exact candidate/artifact,
  input fingerprint and storage/namespace bindings; no revocation and current
  scoped authority;
- no tenant history, tenant-bearing active generation or unfinished lifecycle
  work at first launch; an empty current tenant count alone is insufficient;
- the backed-up platform namespace, trusted `.net`, alias/origin `.com` suffixes,
  cookie/edge policy versions, and reviewed Cloudflare network-set digest; and
- actual completed dark staging, health/idempotence and the pre-launch safety
  checks required for the bound target.

The admission bundle uses a closed `targetKind` enum and purpose pair. Only the
three pairs below are valid; they are non-interchangeable. Neither a
caller-selected `--disposable`/`--fixture` switch nor a test-only initializer can
choose which authority the connected target requires:

| Target kind and admission purpose | Required real evidence and authority |
| --- | --- |
| `installed-fixture` / `installed-test` | An exclusively allocated synthetic/MinIO run on its actual Docker daemon; original private owner/run manifest and operation lease; independently observed full container IDs, image IDs, run labels and role inventory; selected artifact and current dark staging/idempotence. Require only component/transport/bootstrap prerequisites that do not depend on this launch. Run the actual initializer and write the real launch record in that container, with no provider Droplet identity, completed live report or production preflight claim. Its completion receipts are permanently installed diagnostic evidence. |
| `disposable-droplet` / `disposable-qualification` | Exact owned OpenTofu qualification-state/run/Droplet identity, independent provider/metadata/SSH identity checks, an admitted disposable target and lease, reviewed candidate and passing declared component/transport/bootstrap prerequisites that do not require this launch, actual dark staging/idempotence and current fixture safety/provider checks. Explicitly authorize first activation of this owned Droplet so the complete live suite can run. It does **not** assert completed M3.12 qualification or production preflight. |
| `production-host` / `production` | Complete passing qualification of the final candidate on disposable infrastructure, same-invocation production preflight, the exact accepted M3.11 production predecessor and successor journal/lease, completed dark staging/idempotence and the final restore-verified platform backup. This pair alone can activate the enrolled production host. |

For installed targets, extend the actual repository ownership machinery rather
than inventing success responses. `qualification_local.py` resolves and retains
the Docker endpoint in `fixture.json`, rejects a live Spaces backend and filters
inherited `SPACES_`/`CLOUDFLARE_` inputs. `qualification_context.py` generates per-run
names and holds `run_lease` plus the fixture-operation ownership lock;
`qualification_case.owned_containers` rereads full IDs and the
`lowerduckpond.qualification.run` label. The managed allocation path in
`qualification_allocation.py` additionally binds the daemon's `ID`, `Name`,
`DockerRootDir`, `ServerVersion`, exact container/image/owner/role observations
and drained allocation outcome. Ordinary local runs currently lack that full
managed allocation record: add the necessary native daemon/enrollment capture
to them, without requiring live credentials or a managed cloud lease for CI.

Bind endpoint **and actual daemon identity**, original allocation/run owner,
host and archive container full IDs and image IDs, role inventory, source/
artifact and fixture lock domain into the installed admission. Read back that
ownership before launch and every resumed mutation. Names, labels, an endpoint
string, copied manifest or environment variables alone are insufficient. Reject
daemon replacement, container recreation under the same name, unowned/extra
roles, image substitution, uncertain allocation, frozen/disposed ownership or
changed transport. Use explicit metadata queries consistent with section 4.1;
do not persist bulk inspect environments. The controller observes the daemon
outside the guest and binds the root-owned enrollment transaction through the
actual selected container transport or its verified SSH endpoint/host key.
Never mount the Docker socket or give the initializer daemon control to prove
its own identity. This uses the existing real-SSH/systemd installed-rollout
pattern while preserving the new admission checks.

Installed admission and launch receipts must carry their original kind/purpose
and target binding through every nested digest and report. Mark the completion
format explicitly as installed diagnostic evidence; it may support the CI/
prerequisite evidence map but cannot satisfy a live Droplet/provider observation,
complete live qualification envelope, production preflight or production launch
authority. Live report producers and consumers must reject an installed receipt
in any required live slot, even if all test outcomes say passed. No report
repackaging, copied root state or changed outer label can promote it.

Bind target kind, purpose and complete physical/logical identity inside the immutable
bundle whose digest enters the launch record. Derive the required purpose from
the controller's independently verified allocation/provisioning chain and the
root-owned bound transaction on that target. Match these facts to actual Docker
identity or live provider metadata, as appropriate, and original inventory/state
before mutation. Droplet admission must prove the run-owned Droplet, and
installed admission must prove the exact owned Docker target. Both reject the
production host, inventory, state, reserved-address identity and production
transaction namespace even if a caller changes labels, arguments or a local
target file. Never trust a name/tag, caller-provided environment field or
self-authored success receipt as that enrollment proof. The production guard
must not expose a branch accepting installed or disposable admission on its
enrolled target. A Docker fixture cannot claim to be a real Droplet either.

The dependency chain is consequently acyclic: prerequisite checks and actual
owned-host preparation → disposable admission → real first launch → complete
disposable suite and cleanup evidence → fresh production preflight and
production admission → production launch → production canary. A disposable
backup/restore prerequisite can run on its dark platform state if required;
it cannot depend on the later tenant-bearing qualification result. Exercise the
real initializer in the installed and Droplet suites, including its durable
writes and interruption/retry behavior. The separate installed path is:
actual owned allocation and dark preparation → installed admission → native
launch → installed assertions/diagnostic receipts. It requires no prior live
qualification and produces no authority for the live chain. Do not preseed
`launch.json`, fabricate qualification completion, mock successful admission or
disable launch checks for installed tests.

Use the existing `platform/launch.json` schema and mode `0600`. Record the
original configuration version, acceptance-evidence digest and launch timestamp
once. Persist a launch intent before publication; atomically write and sync the
record and parent before opening issuance. An exact retry validates and returns
the original record, without renewing timestamps. Conflicting bytes fail and
remain available for diagnosis. Crashes before and after each durable boundary
must leave a resumable closed gate or the exact authorized launch.

The launch record's `lowerduckpond-m3-acceptance-v1` digest binds the immutable
**pre-enablement admission bundle for that exact target kind, purpose and identity**.
Installed and disposable bundles record their real admission prerequisites
rather than claiming a completed live suite; a production bundle binds completed disposable
qualification and production preflight. Later qualification/canary reports link
the original bundle and launch record. Never replace the launch digest with a
report that could only exist after that launch. Document these purpose-specific
schema/validator semantics and amend ADR 0027 as needed; do not insert a
placeholder digest or let a generic report consumer confuse installed evidence,
disposable admission, full live qualification or production acceptance.

Issuance must require valid launch authority before the first external tenant
job. Reconciliation and route mutation must require it once tenant history
exists and compare its namespace/policy bindings to current authoritative state.
Audit and reject missing, malformed, substituted or incompatible launch state;
the boolean alone cannot authorize tenants. Include backup capture, restored
launch identity, namespace locking after deletion, reboot, and historical-result
replay in these tests. Keep ordinary startup, autonomous reconciliation and
documented recovery possible under their correct existing authority.

### 3.4 Rollback boundaries

Follow [ADR 0027](../adr/0027-gate-production-static-publication.md). Before the
first tenant/history, the qualified transaction can restore the preceding
platform-only generation and set the configured gate false after rechecking
absence and compatibility. Preserve any launch intent/record and record its
pre-tenant rollback disposition; do not erase launch history. Define exact
same-policy reactivation through the successor journal and fresh checks.

After tenant history exists, including after both canaries are deleted, do not
toggle publication false, restore an empty predecessor, or use an older reader
that cannot understand audit archives. Use tested tenant suspension/lifecycle,
forward repair, separately authorized emergency operations or gated restoration
on a fenced target. A canary failure preserves evidence and stops dependent
acceptance; it is not an invitation to wipe the tenant history.

## 4. Diagnostics and interactive debugging are delivery requirements

### 4.1 Error contract through the real transport

Every entry point must establish a private persistent run/attempt location and
print its identifier/path before dependency sync, argument/provider validation,
source checks or infrastructure work. Setup failures need evidence too. Extend
the existing diagnostics instead of a second incompatible error framework.

For each expected rejection record a stable category, failed prerequisite,
stage and relevant correlation/transaction/invocation identifiers. For an
unexpected exception retain useful stack frames and the complete chain of cause
types, safe error codes and operation context, including the underlying
transport failure rather than only a generic wrapper. Capture no locals,
secret-bearing arguments, environment dumps, request/response bodies or tenant
content in diagnostic artifacts, private or shareable. Arbitrary exception
messages and source lines are not safe merely because a file is private.

Apply [ADR 0017's exclusion](../adr/0017-atomically-activate-static-releases.md)
and ADR 0022 **before collection**, including to private artifacts: Caddy-only
environment contents and adapted Caddy configuration bytes must never enter
backups, audit, logs, transcripts, crash dumps, diffs, diagnostic bundles or
collector scratch files. Credentials, private keys and secret-bearing provider
or service output are excluded too. Root-only permissions or a later sanitized
export do not make forbidden capture acceptable.

Use explicit source/property allowlists and metadata/digest observations; never
recursively copy Caddy runtime trees, dump environments, record raw terminal
streams, or invoke bulk `docker inspect`/systemd output capture that can include
secrets. Do not read forbidden files merely to hash, redact or scan them into a
diagnostic artifact; use already trusted manifest digests/selection metadata.
Filter at the emitting helper and each collection/transport boundary, so
forbidden bytes cannot first land in a private spool and only then be removed.
Known-safe numeric provider status/error codes, exception classes and pinned
module/function/line frames preserve diagnostic causes without secret values.
If output cannot be collected safely, record an explicit omission and use a
safe structured probe for the missing fact rather than broad raw capture.

Capture where applicable:

- original error, UTC and monotonic observations, source/helper/artifact digests,
  phase start/end, process exit/signal, command result and whether its outcome is
  known, uncertain, interrupted or not submitted;
- the unfinished Ansible task and recap, actual SSH/connection-plugin/helper
  safe stderr, systemd unit result/exit code/invocation ID, pinned helper code
  frames, allowlisted service-journal fields and native failure records, all
  subject to the private-artifact exclusions above;
- provider operation category, safe request identifier, HTTP status, DNS/TLS/
  socket exception class, timing and retry count; exclude authorization headers,
  signed URLs, object names/private target identity and unsafe exception text
  from public output; and
- original failure plus every collection, evidence-transfer, cleanup, lease
  release and finalization failure as separate outcomes. A cleanup error cannot
  replace the primary failure or imply functional success.

Preserve the complete **permitted diagnostic record** privately before
truncating its console view; this is not permission to spool raw output.
Byte-bounded summaries must say what is missing, why and where permitted private
evidence lives. Do not let "last eight failures" or a small output cap silently
overwrite the only first-cause trace: checkpoint helper records at each stage
and at failure. Keep permitted private journals, source-only diffs and captured
secret-free repair scripts outside public records and ordinary tenant backup
authority. Never include live Caddy environment/configuration diffs.

The operator's final output must contain the original status, failure category,
private path, shareable summary path, uncertain running work, and the next
inspection command. Test propagation from a guest helper through systemd,
SSH/Docker transport, connection plugin, Ansible, wrapper and detached caller.
Finding a trace in a helper unit test does not prove the caller can obtain it.

Diagnostic write/collection failure is itself observable and never converts
failure to success. Provide a minimal safe stderr fallback and durable remote
checkpoint. SIGKILL, machine loss and full disks can prevent a terminal traceback;
the recovery reader must show the last durable start, missing terminal evidence
and an interrupted/unknown outcome. Do not claim impossible guaranteed capture.

### 4.2 Retained-fixture investigation loop

Provide attended commands for `status`, `inspect`, `collect`, `debug`,
`resume`, `finalize`, `cancel` and `cleanup`, with a printed prerequisites and
dependency map. These names describe the required interface; expose them via
one coherent `just m3-12 ACTION ...` family rather than inventing many wrappers.
Keep existing M3.11 entry points and evidence formats readable.

On a failed disposable run:

1. Preserve source/destination identities, selected artifacts, snapshots,
   journal, original result and provider obligations. Retain hosts on failure;
   never put destructive teardown in an unconditional shell `EXIT` trap.
2. Read live state under the original exclusion/authority. Show the failed
   stage, actual running work and blocked dependencies. An observer disconnect
   does not stop a guest service or release its lock.
3. Allow interactive administrative SSH on the specifically owned disposable
   host. Record a structured private investigation transcript of safe command
   categories, permitted observations, outcomes and before/after selection or
   trusted manifest digests; do not record arbitrary shell input/output or
   forbidden file contents. The exclusion in section 4.1 applies before private
   capture, even during hands-on debugging. Allow branch instrumentation or a
   captured secret-free repair script there, preserving source reference copies
   and existing service/resource limits.
4. Continue every independent check whose live preconditions are proven. Mark
   dependent checks blocked with a concrete reason; do not stop useful browser,
   accounting, log or state investigation merely because another assertion
   failed. A mutated diagnostic fixture cannot produce clean qualification.
5. Record each hypothesis, evidence, root cause or unresolved uncertainty,
   correction, regression test and downstream observations. Continue the useful
   dependent journey after repairing its prerequisite, so later problems are
   understood before paying for another fresh run.
6. Put necessary fixes into normal code and tests. Keep the original failure
   immutable, then make one deliberate fresh qualification attempt on the final
   corrected candidate when investigation is complete. No fixed retry count,
   cooling-off delay or repeated owner approval solely because debugging took
   time.

For production, `inspect` and `collect` remain available throughout. Interactive
debugging means observing the retained transaction and invoking its supported
resume/reconcile/lifecycle paths, not a root repair shell that edits managed
state. An unforeseen production repair outside the approved effects requires a
concrete reviewed corrective proposal and separate authorization. Prepare that
proposal from the retained evidence; do not discard the transaction first.

### 4.3 Safe continuation and outcome reconciliation

| Situation | Next safe action |
| --- | --- |
| Ordinary assertion fails; ownership and state remain known | Collect it; run independent diagnostics; block only checks requiring the failed postcondition. |
| SSH/API response is lost or a controller dies | Read the durable original intent, provider IDs and service state. Reconcile whether the action committed before any repeat. |
| A mutating command times out, process ownership is uncertain, or lease is lost | Stop new dependent mutations. Identify and drain/fence the exact prior workers under original authority; collect evidence. Resume only after ownership and postconditions are known. |
| Diagnostic repair changes disposable host bytes or bypasses an injected fault | Mark all resulting observations diagnostic, with exact provenance. Continue learning; never promote the original failed run. |
| Functional checks and teardown completed durably but packaging/checksum or observer fails | Use same-run finalization from the original completion receipts. Preserve the process failure, original report bytes and chronology; do not rerun lifecycle or issue credentials again. |
| Credentials expire or a close/cancel fact exists | Suspend dependent work; keep evidence and fixture inspection available. Cleanup proceeds under its original authority. Never erase close facts or mint replacement credentials implicitly. |
| Historical/foreign archive object, unknown ownership or malformed accounting | Stop related writers and cleanup. Investigate exact bindings; obtain a separate disposition if needed. Do not empty a shared bucket to make preflight pass. |

Explicit fault-injection tests may pass when their required recovery outcomes
pass; an unplanned functional failure remains failed. A later observer can
confirm an originally completed native action, but cannot fabricate a missing
test completion or cold-start proof from logs.

### 4.4 Persistent evidence and cleanup

Use a private persistent root such as
`${XDG_DATA_HOME:-$HOME/.local/share}/lowerduckpond.net/m3-12/<run-id>/`, with
separate immutable attempt directories. Managed execution uses its persistent
named volume, with export to trusted operator custody before host disposal.
These are implementation defaults, not a requirement to reuse another run's path.

Retain original reports, checksums, completion checkpoints and failure evidence
across restart, cancellation, debugging and cleanup. `begin` creates a new run;
it must not remove old fragments as the current M3.0 wrapper does. Publish files
atomically without replacement, sync necessary parents, preserve conflicts,
validate bindings on read, and independently reopen exported bundles. Never
retime an original report or overwrite failed attempts with later passes.

Credential deletion and cleanup supervision remain independent of fixture and
evidence retention. Revoke temporary authority when required while preserving
non-secret diagnostics. Debugging has no right to extend expired credentials.
Use original durable cleanup authority for lock contention/observer loss; report
pending or uncertain cleanup distinctly. Do not spawn another issuer or erase
ownership because a finalizer lost observation. The existing scheduled-cleanup
proof remains required when using the managed-credential workflow.

After investigation, ordinary owned teardown removes only the run's infrastructure,
prefixes, DNS challenges, temporary leaves and temporary credentials. Fresh
provider absence must confirm each deletion, including all versions/markers and
multipart uploads. Unknown responses require readback, not blind recreation or
deletion. Preserve protected audit/snapshot evidence until the existing bound
retirement procedure permits removal. Frozen-fixture and migrated-custody
restrictions remain governed by ADRs 0031/0032; M3.12 grants no bypass.

## 5. Time, authority and evidence validity

Do not add a deadline to deliver this milestone, a human debugging session, a
review response, or a standing owner decision. Do not require fresh permission
for each safe observation or continuation already inside the exact approved
scope. Preserve explicit owner limits, withdrawal, credential expiry, cleanup
reserve, target ownership and separately approved production operations.

| Existing limit or gate | M3.12 treatment and reason |
| --- | --- |
| Parser, transfer, resource, worker, recovery and network-operation limits | Preserve the supported production limits. They bound resource use and unsafe overlapping work. Observer waits must cover the real operation plus shutdown/result transfer, and fail early on a known service failure. A service limit failure needs diagnosis or a reviewed policy correction, never silent enlargement. |
| M3.11 600-minute wrapper / 660-minute managed attempt and 668-minute reporting envelope | These are existing M3.11 safeguards, not measured M3.12 runtimes or human deadlines. Do not copy them as an arbitrary total for the expanded Droplet drill. Build an M3.12 phase budget from comparable complete observations, including setup, provisioning, dependency/build work, functional steps, final accounting, actual teardown, packaging and diagnostic shutdown. Count nested spans once. Any automatic outer limit must enclose its inner work and cleanup reserve. |
| Existing 1.5-times operational allowance policy | Use comparable completed measurements or clearly identified provisional estimates where the inherited policy applies. Never size from a fast partial replay or an interrupted observer interval. Record the rationale and actual durations; do not add another arbitrary multiplier or engineering-target gate. |
| 30-minute installed-group engineering target | Keep reporting cost and regressions. Historical overruns were recorded separately from functional acceptance. Do not invent a new M3.12 pass/fail deadline from that target or claim it was met without measurements. |
| M3.10/M3.11 audit-reader and Page Rules maximum remaining validity | PR 267 permits a 90-day selection plus date-based expiry allowance, bounded at 91 days. Exact read-only audit scope, role separation, active status, future-date rejection and child-identity checks remain. No age-from-original-issue requirement; M3.7 retains its separate eight-day rule. |
| M3.11 startup minimum token validity | Current code requires **13 hours**, derived from 660 minutes plus two hours cleanup, superseding earlier 12-hour text. If reusing M3.11, preserve it. Derive M3.12 startup coverage from its actual automatic work envelope and cleanup obligations; do not copy a stale 12-hour message or demand 90 days remaining. Validate before allocation/provider writes. |
| Native provider expiry and cleanup-authority reserve | Preserve actual scope/lifetime and independent cleanup coverage. Attend to upcoming expiry while debugging; expiry stops dependent calls, not evidence retention. No automatic renewal, new issuance or cleanup-authority extension. |
| ADR 0029 seven-day full live-Spaces evidence consumption | Preserve for new installation authority unless a separately reviewed ADR amendment changes it. It bounds unobserved live-provider behavior; it is not a debugging deadline or periodic redeployment requirement. Always count from the oldest supporting observation. Refresh only the proof actually invalidated, preserving other immutable evidence and original sources. |
| ADR 0029 original report creation/chronology constraints | Existing formats keep their contracts, including the 24-hour packaging bound. For the new M3.12 envelope, amend ADR 0029 to allow later packaging of durably sealed complete functional/accounting evidence without an arbitrary wall-clock packaging cutoff. Retain original observation times and consumption rules; delayed packaging cannot refresh live proof. Partial work or diagnostics cannot be sealed as completion. |
| Existing M3.11 approval/readiness formats | Keep their legacy limits. Do not silently relabel old approvals. Define the new M3.12 live proposal around actual owner scope and current execution checks, without inheriting a one-day consent/reapproval cycle or manufacturing fresh consent timestamps. |

An attended debugger can pause between actions without an automatic whole-session
kill timer. Bounded active actions, independent credential cleanup and current
authority checks still operate. Qualification can resume an explicitly resumable
phase only under its original clean bindings and preserved chronology. A changed
candidate or a diagnostically mutated fixture requires new clean qualification,
not merely a longer clock. If a genuine platform policy conflict appears, propose
the narrow ADR/test change and explain the risk rather than burying an override.

## 6. Full disposable qualification

### 6.1 Infrastructure, installation and capacity

Add an M3.12 mode/root and inventory using the existing qualification modules
where appropriate. Do not redirect the old M3.0 state or production backend to
a new target. Bind exact OpenTofu state/run ID, provider project and Droplet ID,
SSH host key/address, metadata, admin CIDRs, zones, storage endpoints/prefixes,
certificate IDs and source. Review the saved plan before apply; fail on any
production address, apex, wildcard association or foreign-resource effect.

Run on the supported Ubuntu 26.04 amd64 host, NYC1, real ext4, systemd,
OpenSSH/sudo, production Caddy/binary/plugins, both firewalls and reviewed
Cloudflare networks. Keep the actual storage region distinct from the Droplet
region. Preserve production parser/tmpfs inode/byte, service, CPU/RAM and
block/inode reserve policies. No privileged Docker container substitutes for
the required real-host proof.

Prove the actual accepted M3.11-to-M3.12 dark upgrade on a pristine predecessor
fixture, then first activation, enabled convergence/idempotence and the full
journey. Seed no candidate dependency before measuring the predecessor. The
baseline must reproduce the accepted M3.11 installation and its documented exact
bootstrap repair bytes, not an imaginary pristine deployment success. Generate
or verify baseline completion/selection through the real historical mechanism;
do not substitute a stub that always approves. Keep historical production roles,
artifact and locks exact; any fixture-only adapter must have an enumerated diff.
Retain the PR 267 real M3.10 regression as a separate compatibility test.

Also prove supported fresh installation and recovery bootstrap on fresh fixtures.
Provision a separate fenced disposable restore host for the complete backup
drill; never restore over the only source/evidence. Do not pre-converge a full
candidate onto the cold restore target and thereby hide missing prerequisites.
Test source fencing, empty certificate storage, trusted input restoration,
exact archive versions, exclusion handling, reconciliation and ingress gating.

Measure peak resident memory, swap/OOM outcomes, CPU contention, elapsed time,
disk/inode use, unique hard-link allocation and headroom during realistic
overlapping parser, Caddy, backup, archive/export and lifecycle work. Capture
realized OS/kernel/filesystem/packages and every enforced resource setting.
The default production recommendation is the accepted 2-vCPU/4-GiB class;
retain the smaller host only if measured peaks prove every configured reserve.
Do not lower limits to make a small host pass. A later qualified resize must
preserve disk reversibility and binding to the actual host.

### 6.2 Required coverage and evidence matrix

Create `docs/threat-model/m3-12-evidence.md` and a machine-readable requirement
inventory. Map **every normative invariant and required failure case in ADR 0022**
and the M3 parent completion criteria to exact test nodes, environment and
original evidence. ADR 0022 is prose, so assign stable requirement IDs with
source section/paragraph fingerprints; review the inventory against the full
document rather than claiming a broad theme covers every clause. Reject missing,
unknown, skipped, duplicated or stale evidence. Update the existing threat-model
traceability table for changed invariants.

The following groups are the minimum coverage inventory, not permission to omit
the individual limits and failure boundaries stated in ADR 0022:

| Requirement group | Required proof and location |
| --- | --- |
| Contracts, root identity and namespace | Real producer vectors; strict JSON/YAML and canonical size/slug/origin boundaries; UUIDv7 and no caller identity; suffix locking through deletion; launch record and first-enabled authority. Component + installed + real-host activation. |
| Operator/provisioner separation | Every ordinary command via real forced-command SSH; no shell/PTY/SFTP/SCP/forwarding/environment path, arbitrary sudo, principal spoofing, raw request/job substitution, export read or state/audit tamper. Both disabled and enabled cases. |
| Immutable authorization and intake | Per-field binding/compare-and-swap, correlation replay/conflict, one immutable result, lost handoff/delivery, raw/canonical request bounds, decoder sandbox, streaming 100/120-MiB boundaries, stalled/disconnected transfer, immutable snapshot and cleanup/admission. |
| Hostile ZIP and portable envelopes | Complete existing hostile corpus; method/metadata/path/normalization/structural/arithmetic/expansion/quota boundaries, reserved `cdn-cgi`, portable envelope limits, deterministic digest/ZIP golden vectors, parser process limits and continued Caddy/backup health. Destructive exhaustion stays disposable. |
| Durable generations and Caddy startup | Every fsync/rename/selection/intent/handoff/health barrier; descriptor pinning, automatic invocation binding, three-attempt target limits, ordinary starts, recovery/reset-failed ordering, bootstrap masking, concurrent writers, unique-inode and three-generation retention. Real systemd/SSH and reboot. |
| Admission and capacity | Tenant/release/job/result/audit record/count/byte/inode limits, rate/burst and clock-restart persistence, absolute/percentage free-space floors excluding root reserve, audit-administrator reserve and bounded rejection logging. |
| Lifecycle/state/slug concurrency | Every operation across absent/undeployed/active/suspended/archived states; failed and repeated operations, suspended rollback/deploy, release retention, create/rename races, archive from active and suspended, immutable origin through rename/reuse/delete, no unauthorized resurrection. |
| Export/import identity and concurrency | Full-size deterministic export; deploy/rollback/rename/suspend/GC overlap; one capture/spool/acknowledgement/expiry; ordinary allocation of separate undeployed import target; content equality with target-only ID/origin/slug/runtime/quotas and new deployment; stale target policy and untrusted embedded fields. |
| Archive construction and SDK behavior | Known-length single PutObject, no high-level/multipart upload path; faults before send/during body/after remote commit/before receipt; exact versions, forced pagination and multipart detection/abort; real SDK XML/key decoding, opaque VersionIds, TLS and mutual bucket denial. MinIO and actual Spaces. |
| Retirement/quarantine/deletion | Bound version preserved until authoritative unbinding; all versions/markers retired; interrupted deletes reconcile; ambiguous/unowned objects remain charged and close admission; stale archive cannot authorize deletion; separate authenticated archive/delete jobs and root-only emergency path. |
| Backup, audit and reconstruction | Shared-lock coherent capture under actual mutation; secret/transient exclusions; protected rotation/index/tag/replay, retention/forget/prune failure boundaries; exact-version full restore, missing/excluded inputs, wrong identity/forked history negative cases, preserved launch/namespace and audit continuity. Independent restore target. |
| Public edge and real production policy | Proxied DNS in both zones, apex and wildcard policy, Full (strict), distinct edge/origin chains, project-specific AOP, both firewalls, authentic forwarded identity, direct-origin/cross-account denial, strict unknown hosts, safe port 80; API-observed Always Online off. Disposable origin outage only on disposable target. |
| Cache, transforms and provider endpoints | Repeated platform/tenant/alias/apex/error/lifecycle responses with no cache/stale serving; origin/edge byte equality and no-transform; provider challenge classification; WAF case/unclaimed paths and exact lowercase `/cdn-cgi/trace` classification with proof no Caddy route and no visitor-specific trace publication. |
| Alias/apex semantics and privacy | Exact bare-root fixed redirect, method/path/query rejection over HTTP and HTTPS, no intermediate alias upgrade, no reflected state, no-store/no-referrer, fresh negative-to-positive transitions, immutable target designation and no path/query/cookie/auth/referrer leakage in logs or diagnostics. No municipal tenant designation in this milestone. |
| Supported browsers and cookies | Pinned Chromium/Firefox/WebKit real-edge matrix, plus the existing stock-browser smoke; hostile `.com` cannot affect/read/receive host-only `.net` state; accepted sibling Domain cookie behavior; case-sensitive host-bound `__Host-`; Caddy request Cookie and response Set-Cookie removal on every route/error, provider cookie distinction, service-worker/alias checks and recorded residual risks. |
| ACME, origin-pull rotation and cold recovery | Apex/wildcard issuance and renewal in both zones, public trust, DNS cleanup, cold store, issuance interruption, reboot before readiness, closed ingress until verified. Disposable old/replacement AOP trust rollback/forward and old-leaf denial; separately reviewed real production zone-level association/leaf validity. |
| End-to-end operations and diagnosis | Complete existing installed journey plus full real-host cross-feature chain; exact predecessor bootstrap, deterministic interruption and controller/host reboot; errors traverse actual transport; resumed ownership, original receipts, failure retention, cleanup contention and finalization/packaging recovery. |

Use existing live M3.11 complete backup/reconstruction obligations, not just a
subset convenient on the new host. Parameterize transport and owned target
fixtures; do not weaken test assertions or silently skip incompatible Docker
tests. Where a case remains deliberately component-only, explain that layer's
proof and name the real-host assertion that validates its platform assumptions.

### 6.3 Edge, certificates and browser limitations

Temporary subdomains do not prove actual production apex/wildcard configuration.
Retain disposable scoped names for destructive issuance/outage/rollover tests,
and separately repeat the complete non-destructive public matrix against the
real `.net`/`.com` apex and wildcard policy before opening production.
Parameterize the current hard-coded qualification/browser subjects and bind
each observation to its target. Do not repoint production DNS for convenience.

The production edge uses Full (strict) and account-specific origin pulls;
arbitrary Cloudflare traffic is insufficient. Confirm the reviewed production
origin-pull trust and zone-level leaves, including the parent plan's production
rotation prerequisite. If a change is necessary, prepare its exact bounded
infrastructure/association plan and separate live authorization. Offline CA
private keys and leaf private material never enter Git, OpenTofu state or a
Coder workspace. Respect existing native validity and trust-overlap rules.

Repeat supported-browser tests through the actual edge. Where the pre-enable
production platform-only routes cannot demonstrate tenant cookie behavior,
prove it on the production-equivalent disposable host first, then repeat the
tenant-specific portion as an immediate synthetic canary check before accepting
service. Any temporary browser fixture on production needs explicit scope and
ordinary managed configuration; never a manual Caddy edit or hidden gate bypass.

Issuance and renewal require executable observation, not waiting for a calendar
renewal date. Use the existing bounded controlled/public-CA proof mechanisms
and rate-limit-aware disposable subjects, then verify the real production
certificate/trust/readiness configuration. A public edge certificate cannot
substitute for evidence about Caddy's origin certificate. Record any public-CA
limitation as a blocking missing proof, not a passing boolean.

## 7. Separate production preparation, activation and canary

### 7.1 Prepare everything reviewable before requesting live execution

Prepare the final source/artifact, complete qualification and coverage map,
sanitized report/checksum, exact proposed target/effects, infrastructure diff
where applicable, rollback/recovery procedure and operator commands. No live
action is authorized by the planning task. Live qualification, credentials,
resize/edge changes, production staging/activation/canary and disposal require
their own actual scoped authorization; combine related effects into coherent
reviewable proposals rather than asking at every test step.

The private execution bundle must identify which effects are already authorized,
which are pending and which were observed. The local plan must not embed secret
values or pretend to approve a run through a self-authored receipt. Reuse
standing scope where valid, preserving authentic consent and latest direction.

### 7.2 Same-invocation production preflight

Before each mutating/resumed phase revalidate the live facts that can drift:

- actual inventory/host key/node, supported OS/filesystem, selected artifact and
  Caddy generation, original accepted predecessor, successor journal/lease and
  no unknown competing or queued work;
- trusted namespace, launch/history state appropriate to the current phase,
  protected audit lineage/index/snapshots, backup health and active required
  timers; never demand an empty history after the canary starts;
- source/input/artifact/report/revocation binding and oldest-evidence validity,
  plus fresh provider/firewall/edge policy and capability proofs;
- dedicated operator principal/public key and forced-command restrictions;
  operator confirmation that the existing passphrase-protected private key is
  backed up, with only its public half installed; no key rotation by default;
- accounted zero objects, versions, markers and multipart uploads in the
  production tenant archive bucket before the first tenant; the backup bucket
  is expected to contain protected history and must not be emptied; and
- capacity reserves and the measured resize decision, credential policy and
  remaining cleanup coverage, and actual two-zone certificate/trust readiness.

New archives belonging to the active canary are expected later. Resume validates
their exact ownership/accounting instead of reapplying the initial zero test.
Foreign/unaccounted objects stop writers and require investigation.

### 7.3 Dark staging, backup and activation sequence

1. If required, execute the separately approved reversible CPU/RAM resize using
   existing OpenTofu management, preserving disk size, identity and reserved
   address. Observe the reboot, health and reserves; do not recreate production.
2. Acquire successor authority, drain/fence the relevant workers/timers and
   stage the qualified artifact/commands while publication remains false.
   Preserve installed recovery, audit rotation, locks and accepted M3.11 state.
   Run the real dark converge twice; require the second bound recap to show
   zero changes and no failed/unreachable/rescued/ignored work.
3. Capture a final coherent platform backup after dark staging under the
   established lock/snapshot identity. Restore and verify it on a separately
   fenced disposable target with exact namespace/audit/releases/configuration
   bindings and exclusions. Retain this original proof on resume.
4. Recheck complete pre-enable authority and live controls, durably commit the
   launch record, then change only the reviewed publication stage/configuration
   to true through the controller. Do not rotate keys, change storage, edge
   settings or deploy unrelated code during the activation step.
5. Converge twice enabled, verify job issuance/launch/namespace consistency,
   Caddy selection, required timers, host health and HTTPS. The second converge
   must be idempotent with the full accepted recap. On failure, inspect and
   resume the exact transaction; apply the history-aware rollback rule.

### 7.4 Ordinary two-tenant canary

Use synthetic content and reserved slugs, never a real customer identity. Every
ordinary mutation uses `ldp-static-operator` over the dedicated forced-command
key, with durable job/correlation/request/result/audit links. Administrative
deployment authority must not become tenant job authority.

1. Create source A; deploy known content; replace; rollback; suspend; resume;
   rename; prove old/new alias behavior and A's unchanged canonical origin.
   Exercise ordinary slug allocation/reuse and prove aliases never transfer A's
   canonical browser identity. If B consumes a released slug, allocate it
   through ordinary `create`, with its own tenant ID and policy.
2. Export A and verify the captured bundle. Separately create undeployed B if
   not already allocated, import A's bundle into B, and prove byte equality
   with B's own ID, canonical origin, slug, runtime, quotas and new deployment.
   Do not import into A, create B by writing state, or adopt embedded identity.
3. Check canonical and alias HTTP/HTTPS, cache/forwarding/origin behavior and
   the live browser/cookie boundary for both tenants. Perform planned backup
   overlap, capture both tenants coherently, restore to the fenced disposable
   target, reconcile and verify routes/content/audit/launch there. Fence source
   and destination writers as required; do not allow cloned authorities to
   race on shared objects or public names.
4. Reboot actual production under the approved canary scope. Verify services,
   launch/selection, historical results, audit continuity and both tenant route
   classes/HTTPS after boot. Disposable restore/reboot proof does not replace
   this actual production observation.
5. Archive A, verify both routes absent; restore A as a new deployment; verify
   routes and exact archive retirement; rearchive A with evidence bound to the
   restored generation; ordinarily delete A. Separately archive and ordinarily
   delete B. Use fresh immutable authorization for destructive transitions.
6. Independently verify no canonical or alias route for either tenant, all bound
   archive versions/markers retired, no multipart uploads/intents/quarantine/
   orphan staging or unfinished jobs, and intact audit and protected backups.
   Do not delete audit, protected platform backups or the service-lifetime
   archive bucket to achieve zero archive accounting.

Record expected and actual postconditions after each step. A failed canary
continues through safe diagnosis and independent checks, then its original
state determines resumable ordinary lifecycle cleanup. It cannot be accepted
through a manual edit or relabelled by a later observation.

## 8. Implementation slices, dependencies and concrete deliverables

These are dependency-ordered review units, not calendar commitments. Combine
small inseparable edits; avoid speculative generic refactors. Implementation
and local validation precede any live handoff.

| Slice | Depends on | Deliverables and completion evidence |
| --- | --- | --- |
| P0: current Dependabot updates first | This plan's review; actual update work separately authorized | Resolve the seven-PR inventory in section 0, shared baseline-test failure and overlapping Python lockfiles; accept validated CI/hook/Python/provider updates and duplicate disposition; verify the combined baseline and complete installed journey. No production apply or repeated live qualification for each update. |
| P1: contracts and reconciled requirements | P0 accepted dependency baseline | Resolve the installed-fixture/disposable-droplet/production-host target kinds and admission purposes through the same initializer, launch-evidence semantics and all-artifact exclusions; requirement inventory and ADR 0027/0029 amendments for activation/report lifecycle as needed; M3.12 error/report/transaction schemas, stage/configuration matrix, scope and rollback contracts. Keep old reports/approvals readable. |
| P2: persistent diagnostics and debugging | P1 contracts | Early run allocation, private error/transport capture, durable stage checkpoints, independent-error aggregation, status/inspect/collect and retained real-host debugger; public allowlist/export validator; failure retention and safe continuation rules. End-to-end diagnostics tests must pass before expensive new live trials. |
| P3: launch and successor deployment | P1; use P2 diagnostics | Root launch writer/enforcement, M3.12 journal/lease/phase controller, predecessor handoff, guarded dark staging/activation, history-aware rollback/resume, final-backup binding; CLI/Ansible integration and actual predecessor installed regression. |
| P4: full Droplet and restore qualification | P1/P2; exercise P3 | Owned infrastructure/inventory and real-SSH fixture adapters, complete suite and real reboots, public-edge/browser/ACME matrix, resource sampler, real Spaces/SDK coverage, cleanup and interrupted-owner reconciliation. No Docker-only claim for Droplet facts. |
| P5: canary and evidence composition | P3/P4 contracts | Resumable ordinary two-tenant canary runner, production preflight, persistent aggregate report/checksum and exact invariant map, same-run finalization, sanitized export and closeout templates. Add entry points to `justfile` and operator runbooks. |
| P6: complete local and installed verification | P0–P5 | Focused tests plus affected installed groups, full journey, all required checks and review of current CI. Make the final input-changing revision the release candidate, including accepted dependency updates, production true configuration and final normative docs. |
| P7: separately authorized live qualification | P6 | Exact-source complete real-Droplet qualification and restoration, edge/browser/ACME/capacity proof, original reports, owned teardown and credential closure. Retain failed fixtures for complete investigation before another attempt. |
| P8: separately authorized production operation and closeout | Passing P7 and fresh production readiness | Approved resize/edge work if needed; dark stage/backup/activation and full canary; independent final accounting; immutable accepted receipts; records-only closeout PR prepared from original evidence. No M3 completion claim before these pass. |

Expected code homes are `scripts/m3_12_*`, a narrow launcher/`just` family,
existing `packages/static-host-agent` durable state/entry points,
`config/ansible` guard/activation/acceptance tasks, and a clearly separated
`infra/opentofu` qualification mode/root. Reuse existing `tools/m3-qualification`
edge/browser checks and `qualification_*` test definitions. Keep modules narrow
and explicit rather than copying the entire M3.11 controller tree.

Required documents are `docs/operations/m3-12-qualification.md`,
`docs/operations/m3-12-production.md`, the invariant evidence map and schemas,
updated diagnostics/input examples/command help, and a records-only closeout
under `docs/records/`. Example secrets are fake. Private reports/transcripts and
execution proposals remain outside Git; sanitized original evidence and digests
may enter the existing records locations after review.

## 9. Test strategy and acceptance criteria

Add tests at meaningful boundaries rather than snapshots of implementation:

- Launch: missing/foreign/malformed/mismatched authority; every durable-write
  interruption; concurrent initializers; exact retry/conflict; no tenant before
  launch; post-history disable denial; deletion does not reset namespace/launch;
  restored launch and policy bindings; real installed-container and disposable
  Droplet first launch through the same initializer without preseeded state,
  mocked admission or fabricated suite completion. Swap actual Docker daemons,
  recreate a same-name container, alter full IDs/images/owner labels/roles or
  lock domain, and copy the enrollment; every mismatch must fail. Replay
  installed and disposable bundles, launch records and partial/completed reports
  into the other target kinds and production; substitute host IDs, state,
  inventory, labels, kind, purpose and transaction namespace. Every crossover
  must fail before launch write or issuance. Reject installed receipts in live
  report slots, including nested evidence repackaged under a live outer label.
  Verify that the installed negative tests need no provider credentials and no
  Docker socket in the guest. A positive production
  path requires full disposable qualification and its own preflight/authority;
  this preserves an acyclic dependency graph with no production bypass.
- Deployment: real accepted M3.11 predecessor and unchanged historical M3.10
  regression; no candidate pre-seeding; guard precedence; dark artifact staging;
  deterministic acknowledged-task/phase barriers, not `sleep` races; controller
  disconnect/reboot, lease loss, delayed callbacks and original proposal replay;
  both dark/enabled idempotence and before/after-history rollback.
- Error transport: injected early setup failure, parser/helper exception,
  Ansible failure/unreachable, DNS/TLS/HTTP failure, stderr transfer failure,
  timeout with guest still alive, worker restart, SIGTERM/SIGKILL, disk-full/log
  cap, corrupt summary and failed collector. Assert original category/status,
  private cause chain, invocation binding and caller-visible paths. Seed unique
  secrets into Caddy environment/adapted config and unsafe exception/stdout/
  stderr/provider fields; verify they never enter **any** private or public
  artifact, local/remote spool, collector scratch file, transcript, diff, audit,
  log or CI/terminal output. Test interrupted/failed collectors and alternate
  path/link attempts too. Assert permitted cause types/codes/frame locations
  still reach the caller. Tests use fixture secrets and inspect captured outputs;
  the production collector never reads forbidden files to perform this check.
- Debugging: independent stages continue, prerequisites block dependent work,
  uncertain mutation blocks overlap, live ownership changes are detected,
  repair provenance persists and permanently excludes diagnostic promotion.
  Production debugging cannot invoke disposable repair/disposal capability.
- Storage/provider fidelity: real pinned Botocore HTTP preparation/XML parsing
  and automatic URL decoding, opaque version IDs, spaces/plus/percent/Unicode
  keys, pagination/markers/multipart, mutual denial and uncertain commits;
  MinIO and real Spaces acceptance remain separate. Preserve
  `test_m3_11_custody_sdk.py` behavior rather than replacing it with a fake map.
- Evidence/finalization/cleanup: boot persistence; no-replace publication;
  timestamp/digest/revocation/target mismatch; no skipped/unknown requirements;
  functional-complete recovery without re-running lifecycle or reissuing
  credentials; cleanup-lock contention and observer loss under original durable
  authority; closed lease cannot be reused; foreign target cannot be destroyed.
- Browser/edge/capacity/backup: the complete matrix in section 6, including
  negative and failure cases, actual SSH/systemd/Droplet reboots and the
  production two-tenant observations in section 7.

Use the repository's actual entry points: focused `uv run --frozen pytest`,
`just check-python`, `just check-m3-contract-spine`, `just check-m3-qualification`,
`just check-m3-stock-browsers`, `just check-m3-archive-storage`,
`just check-installed-group CASE`, `just check-ansible-m3-8`,
`just plan-installed-checks BASE HEAD`, `just check-opentofu`, Ansible syntax/
lint, `just check-links` and relevant hygiene/secret/Actions checks. Run the
complete installed journey and required CI before release. New live entry
points must fail explicitly if prerequisites are absent; never silently skip.
The parent plan's suggested `acceptance-static-*` names are not existing proof
and need not become redundant aliases.

M3.12 is delivered and qualified only when all of these are true:

1. The current Dependabot update set is resolved first on a validated combined
   baseline, including duplicate disposition; the final candidate includes its
   accepted versions. It contains reviewed activation, tracing/debugging and
   qualification code, all required checks pass, and every requirement has
   evidence at the correct layer. Actual predecessor and error-transport tests
   pass without hidden setup or synthetic success responses.
2. A complete passing real-host report binds the exact candidate/artifact/inputs,
   realized environment/tool versions, target and original observations; all
   required failure recovery, public edge, browser, ACME, restore/reboot and
   capacity checks pass. Required teardown and credential cleanup are verified,
   or explicitly remain a blocking pending/uncertain obligation.
3. Separately approved production work completes with fresh preflight, sufficient
   reserves, final restore-verified backup, original durable launch and accepted
   successor journal. The two enabled converges complete with the required
   repeat idempotence and no failed/unreachable/rescued/ignored tasks.
4. Both ordinary canary tenants complete the specified lifecycle, import,
   backup/restore/reconciliation and actual production reboot/HTTPS checks.
   Both route classes and every bound archive object are absent afterward,
   while audit/launch/namespace/protected backups remain valid.
5. Sanitized reports map every ADR 0022 invariant to passing evidence; retained
   failures, diagnostics and process failures remain honestly labelled. Raw
   secrets/logs/tenant bytes and private configuration are not published.
6. Original receipts and evidence are independently reopenable in trusted
   persistent custody. A reviewed records-only closeout marks Milestone 3
   complete without forcing another deployment. Milestone 4 may then depend on
   the accepted host contract; real onboarding still waits for Milestone 7.

## 10. Decisions and execution prerequisites still to resolve

These do not block writing or reviewing this plan. Resolve them at their actual
dependency before implementation or live execution, without prematurely asking
for credentials or a production window:

| Decision or fact | Resolution point |
| --- | --- |
| Refreshed Dependabot mergeability, shared generation-test failure and the #255/#254 overlap | P0; inspect current main/heads and exact solver graph, then validate the dependency baseline before M3.12 feature work. No update is applied by this planning task. |
| Kind/purpose/target-bound admission, launch acceptance-bundle representation and crash/rollback semantics | P1 ADR/schema review, using the acyclic same-initializer design for owned Docker, real Droplet and production targets, with mandatory receipt/target crossover rejection tests in section 3.3. |
| New M3.12 packaging/attended-session policy versus legacy report/approval limits | P1 narrow ADR 0029/operations amendment; leave old validators unchanged and test both formats. |
| Exact full-stack Droplet inventory/transport adapters, names and restore-target layout | P4 review against every installed test's real requirements; enumerate shared-zone and storage ownership. |
| Final automatic execution budgets and startup credential coverage | P4/P6 from comparable whole-path measurements and actual credential/cleanup policy; do not invent a number in this plan. |
| Present production selection, integrity, resources, journals and archive emptiness | Read-only trusted-workstation preparation immediately before the future live operation; source records alone cannot establish current state. |
| Production AOP leaf/trust/association status and whether rotation is still due | Read-only inspection and exact reviewed edge plan before production activation; use the parent plan and ADR 0028 requirements. |
| Operator private-key backup confirmation and available provider/cleanup roles | Future trusted-workstation preparation. Reuse existing correct material; request new material only for a demonstrated missing requirement. |
| Small-host capacity exception versus reversible 2-vCPU/4-GiB resize | Disposable peak measurements plus current production reserve check; separately approve any infrastructure change. |
| Any failed or frozen historical fixture still occupying shared storage/authority | Investigate original ownership and approved disposition before allocation; apply ADRs 0031/0032 and existing cleanup tools. |

This assessment intentionally did not inspect credentials, operate providers,
start qualification, alter production, push, merge or create a live approval.
The implementation plan is the sole working-tree change.
