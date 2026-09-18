# M3.10 implementation evidence and production checkpoint

Archive, restore, ordinary deletion, and separate root emergency deletion are
implemented. Live Spaces qualification and production convergence completed on
2026-09-18 for merged source `22147a64e9b39e7965201cf2d96e07aeaa6d3ca1`.
The [production checkpoint](#production-checkpoint-2026-09-18) records the final
source, artifact, sanitized report, required CI, and operator acceptance.
Production publication remains disabled. The
[plan](../plans/milestone-3.10.md) and
[preparation runbook](../operations/m3-10-convergence-preparation.md) define the
release requirements and the established encrypted-state credential workflow.

## Invariant traceability

| Proof obligation | Evidence | Scope and limitations |
| --- | --- | --- |
| One known-length upload, no hidden retry, fixed regional HTTPS and dedicated credentials | [Remote tests](../../packages/static-host-agent/tests/test_archive_remote.py) | Real SDK request-pipeline tests reject redirects, implicit HeadBucket, second transmissions, multipart/high-level operations, ambient endpoint/proxy/CA configuration, and malformed responses. |
| Exact version and bytes, bounded whole-bucket inventory, capacity, marker and multipart accounting | [Remote tests](../../packages/static-host-agent/tests/test_archive_remote.py), [verification tests](../../packages/static-host-agent/tests/test_archive_verification.py) | Reserve the full 120-MiB ceiling; count unknown keys outside the managed namespace. Unknown, missing, or ambiguous inventory closes admission. |
| Construction precedes remote I/O; lost responses cannot repeat an upload | [Journal tests](../../packages/static-host-agent/tests/test_archive_journal.py), [construction service tests](../../packages/static-host-agent/tests/test_archive_construction_service.py) | Fresh sessions precede local preparation. Exact receipts bind the whole intent; interrupted prepared work discovers/purges its unique unbound key and retains evidence until audited failure. |
| Remote retirement follows durable unbinding and preserves bound objects | [Journal tests](../../packages/static-host-agent/tests/test_archive_journal.py), [cleanup service tests](../../packages/static-host-agent/tests/test_archive_cleanup_service.py) | Independent source/terminal verification, version/marker purge, repeated absence checks, quarantine, and failed-cleanup recovery. Quarantine resolution verifies complete inventories and every retained version; it grants no deletion authority. |
| Descriptor transfer preserves exclusion across process death and connection loss | [Lock tests](../../packages/static-host-agent/tests/test_locks.py), [transport tests](../../packages/static-host-agent/tests/test_archive_transport.py) | Borrowed descriptors retain the same open-file description and already-held flock, including queued descriptors. Inner-lock lending, replaced inodes, hostile peers, and invalid frames fail closed. |
| A worker cannot select credentials, storage locations, or arbitrary paths | [Read service tests](../../packages/static-host-agent/tests/test_archive_service.py), [configuration tests](../../packages/static-host-agent/tests/test_archive_configuration.py) | Root-only service derives authority from durable jobs and exact descriptors. Parser worker and ordinary reconciler retain network isolation. |
| Archive preserves active/suspended rollback source and commits absent routes with exact evidence | [Handler tests](../../packages/static-host-agent/tests/test_archive_handler.py), [commit tests](../../packages/static-host-agent/tests/test_archive_commit.py), [recovery tests](../../packages/static-host-agent/tests/test_archive_recover.py) | Source/proposed manifests, independent remote proof, stale source, every durable boundary, interrupted publication, archived revalidation, and retained bounded local history. |
| Restore creates a fresh deployment and retires the old bound archive | [Restore handler tests](../../packages/static-host-agent/tests/test_restore_handler.py), [commit tests](../../packages/static-host-agent/tests/test_restore_commit.py), [staging tests](../../packages/static-host-agent/tests/test_restore_staging.py) | Exact bundle inspection, retirement before unbinding, transactional route activation, source rollback/forward recovery, retention, and absence before execution validation. |
| Repeated archive/restore cannot accumulate releases or retired objects | [Cycle test](../../packages/static-host-agent/tests/test_archive_cycles.py) | Four private-service cycles, unique archive keys and fresh deployments, selected-plus-two-predecessors retention, final deletion, and replay of every earlier result. Uses a fake provider behind the real private protocol. |
| Ordinary deletion requires a distinct post-archive job or complete never-deployed proof | [Delete handler tests](../../packages/static-host-agent/tests/test_delete_handler.py), [commit tests](../../packages/static-host-agent/tests/test_delete_commit.py) | Exact remote evidence is rechecked before tombstoning. Verified complete audit/history and namespace prechecks precede descriptor-relative removal. Faults cover audit, unlink/rmdir, parent fsync, result/job, and journal boundaries. |
| Emergency deletion remains distinct administrator authority | [Emergency tests](../../packages/static-host-agent/tests/test_emergency_delete.py), [entry-point tests](../../packages/static-host-agent/tests/test_emergency_entrypoint.py) | Strict separate intent/result provenance, root and sudo-administrator checks, mandatory reason, no ordinary job, tombstone-before-removal, recovery, remote retirement, and historical ordinary result replay. |
| Archived export delivers exact bytes and import preserves target identity/policy | [Export tests](../../packages/static-host-agent/tests/test_export_handler.py), [installed lifecycle](../../config/ansible/molecule/m3_8/tests/test_archive_lifecycle.py) | Private exact-version delivery and commit/retry faults are covered locally. Installed TLS archived-export/import qualification is tracked separately below. |
| Actual SDK/XML behavior from the packaged artifact | [MinIO test](../../packages/static-host-agent/tests/test_archive_remote_minio.py), [runner](../../scripts/check-m3-archive-storage) | Exact upload/read, marker-hidden reads, forced pagination, bound-object denial, permanent purge, and multipart detection against pinned MinIO. Local storage does not substitute for Spaces. |
| Effective installed sandbox and recovery command | [Default host tests](../../config/ansible/molecule/default/tests/test_host.py) | Clone complete installed unit policy to verify path/credential denial and positive operation. Emergency helper permission/sudo denial and actual recovery-service invocation are included. |
| Deferred archive/restore/delete snapshot and activation races | [Installed capture support](../../config/ansible/molecule/m3_8/tests/archive_capture_support.py), [installed lifecycle](../../config/ansible/molecule/m3_8/tests/test_archive_lifecycle.py) | Actual worker waits on verified export-lock inode; source remains unchanged until capture completes. Restore/delete Caddy-fault recovery and Ansible overlap passed in the installed archive group at `00f3f1a`. |

## Recorded qualification

The plan is first commit `a70f107`, based on current `main` at `8d9adc1`.
All identities below are development checkpoints on
`feat/m3.10-archive-restore-deletion`, not reviewed merged production releases.

| Revision | Check and result |
| --- | --- |
| `36aa88e` | Final installed quarantine recovery passed in 315.44 seconds. Final disposable inventory confirmed terminal jobs, empty pending directories, absent quarantine, and empty version/marker/multipart inventory. |
| `ea4d44a` | Ordinary/active/never-deployed emergency test passed in 294.70 seconds. Exact reboot-state and complete installed transport/recovery checks passed, including all six idempotent Ansible overlaps. |
| `4849b70` | Corrected emergency unit converged; its strengthened complete-policy check passed in 3.44 seconds. All 33 artifact/CI-selection tests passed in 216.18 seconds, and actual archived emergency recovery passed. |
| `00f3f1a` | Complete installed archive lifecycle passed in 1,293.90 seconds: four restore/rearchive cycles, exact archived export/import, capture exclusion, Caddy failure/recovery, Ansible overlap, ordinary deletion, full-size suspended archive/restore, resource limits, bounded retention, remote retirement, and historical replay. |
| `bd47ac8` | Final complete Python lane: 2,441 passed, three explicit skips in 540.82 seconds; formatting, lint, and strict typing passed. Includes both tracing regressions and archived-result history after emergency deletion. |
| `f88614e` | Both operational wrappers disable inherited tracing before credential-input checks. Fake canaries reproduced the convergence-wrapper leak; all 39 focused wrapper/production-gate tests, formatting, lint, and shell syntax checks passed after correction. |
| `6df7ec0` | Complete Python lane: 2,439 passed, three explicit skips in 569.22 seconds; formatting, lint, and strict type checking passed. |
| `1267afb` | Quarantine retry regression first reproduced both failures; the fix passed 42 focused lifecycle tests, then the full Python lane with 2,438 passed and three explicit skips in 576.22 seconds. |
| `e348706` | Packaged MinIO lane: two tests passed, including real committed-upload/deletion response loss and the 25-key capacity ceiling; strict type checking passed. |
| `050d715` | Python checkpoint: 2,436 passed, the same three explicit skips, 615.88 seconds; formatting, lint, and strict type checking passed. |
| `0f4e804` | Fixed system trust bundle: 41 remote tests passed; strict type checking passed for 226 files. |
| `fb69cd8` | Default convergence and idempotence passed; all 45 installed checks passed in 90.53 seconds, including complete emergency unit policy. Disposable host destruction passed. |
| `434331e` | Four repeated private archive/restore cycles, retention, final deletion, and every historical result replay passed. |
| `f084475` | Complete Python suite: 2,435 passed, three skips in 570.05 seconds. Skips are two separately scheduled MinIO checks and one inapplicable never-deployed archives-directory fsync parameter. Includes integrated ordinary/emergency lifecycle, strict contracts, recovery, and historical replay. |
| `470c575` | Complete Python suite: 2,280 passed, two dedicated MinIO skips. Default convergence/idempotence and all 44 installed tests passed. Packaged local storage: two passed. |
| `57f0a81` | Full installed M3.8/M3.9 core lifecycle, large export/import, snapshot races, exact reboot-state, transport/recovery, and Caddy/systemd/Ansible overlap passed. Disposable host was destroyed. This predates M3.10 lifecycle integration. |

Artifact at the `470c575` installed checkpoint:
`a079e9fde6f5cf9f8ae1bdbb464870168f6848e880690b845610369d0eb67e1d`.
It does not qualify later restore/delete/emergency code.

The `fb69cd8` installed artifact has SHA-256
`e74efe5ddcc3cea83314452a0fcf9ef6f3741ba8dc9d96c998f8408c675f6eb4`.
All three wheel checks, local qualification and browser-boundary checks, both
packaged MinIO checks, 222 infrastructure
checks, Ansible lint (137 files), workflow lint, and secret scans passed.
OpenTofu validation/tests/security scanning, Cloudflare range verification,
repository-wide pre-commit checks, and documentation links also passed. The full
installed M3.8–M3.10 lane includes pinned private TLS MinIO, distinct test bucket
credentials, four restore/rearchive cycles, exact archived export/import,
final deletion, deferred races, full-size suspended archive/restore, and
administrator recovery. The scenario passed convergence, idempotence, the
installed core lifecycle, and the M3.9 large export/import, delivery recovery,
and snapshot-race group
against artifact
`5b2cee9128f156e22699fd73e3d78bee5443cb901ecaa79c297d97fb05463899`.
After the final quarantine fix, a fresh installation passed convergence,
idempotence, mutual bucket-credential denial with complete fixture cleanup,
the installed core lifecycle, and the complete M3.9 export/import, delivery,
and snapshot-race group against artifact
`e68d9ca026f636d51bf5b67fecddf791c8dc4ef9d8c65f66f152a9aa1041ac9d`.
The complete installed archive lifecycle subsequently passed at `00f3f1a`.
Both installed deletion tests passed after the fixture and unit corrections
below. Active and never-deployed emergency deletion, exact archived emergency
retirement, durable interruption recovery, and historical result replay are
qualified. Exact reboot-state capture/restart/verification also passed at
`ea4d44a`, including automatic Caddy/startup reconciliation and identical served
routes. The complete installed transport/recovery group passed, including
lost handoff, replaced payloads, disconnection, killed workers, the Caddy fault
matrix, all six idempotent Ansible overlaps, and competing requests. Installed
quarantine recovery passed at `36aa88e` in 315.44 seconds, preserving the unknown
object until its fixture owner removed that exact version and verifying the
retained archive before reopening admission and restoring the tenant.

The completed matrix combines a fresh installation with resumed groups after
fixture and emergency-unit corrections. The runtime artifact remained
`e68d9ca0…`; the corrected emergency unit was reapplied through the role and its
complete policy was tested. All six subsequent configuration overlaps reported
zero changes. Disposable credentials are public fixture values; production
credentials are never used in this lane.

The final 2026-09-12 disposable inventory confirmed 119 terminal ordinary jobs
(110 completed and nine intentional failure cases) and four permanent emergency
results. Lifecycle/Caddy intents, intake, exports, and release staging were
empty. Quarantine was absent; whole-bucket inventory contained no versions,
delete markers, or incomplete multipart uploads. The owned disposable host and
pinned storage container were destroyed after recording this inventory.

A fresh build at `00f3f1a` from the original checkout reproduced the installed
`e68d9ca0…` artifact exactly. A build from the separate development worktree
had identical runtime files and dependency lock, but a different digest because
`uv` embeds the local interpreter path in two dependency launchers and their
package records. This proves repeatability at the recorded build location, not
independence from workstation paths. Build and record the actual reviewed
release artifact before production preparation.

## Installed defects found and corrected

- `ProtectSystem=strict` overlaid the intended empty tmpfs root with the host
  root on the tested Ubuntu 26.04 systemd. Full-unit probes demonstrated exposed
  paths. The corrected explicit-mount policy uses `ProtectSystem=false` with the
  read-only empty root. Fresh default and full M3.8/M3.9 checks passed after the
  correction at `57f0a81`.
- The SDK's one-attempt setting still allowed a second PUT on an S3 region
  redirect. The request-creation guard refuses the second transmission and any
  implicit operation; real SDK pipeline regression tests reproduce this case.
- The first emergency installed run passed convergence/idempotence and 44 of 45
  tests. Its full sandbox lost effective `CAP_SETUID` despite the bounding set,
  preventing the controlled Caddy socket-owner switch. `fb69cd8` retains it with
  `AmbientCapabilities=CAP_SETUID`, preserving `NoNewPrivileges=true` and the
  bounded capability set. A full-policy disposable probe verified identity
  switch and restoration; the fresh complete installed rerun passed all 45 checks.
- The pinned MinIO fixture requires `s3:DeleteObject` in addition to the
  version action for exact-version deletion, as its
  [authorization implementation](https://github.com/minio/minio/blob/RELEASE.2025-09-07T16-13-09Z/cmd/auth-handler.go#L430-L457)
  demonstrates. `6df7ec0` adds that permission only to the disposable archive
  policy. The initial failure retained the known credential-proof objects and
  closed archive admission; those exact fixture versions were verified and
  removed using their fixture owners. Production Spaces policy and its live
  credential-denial gate remain separate.
- The first archived-capture race requested an exclusive-only inventory API
  while holding shared tenant-state. The helper was corrected at `00f3f1a` to
  hold exclusive tenant-state while capturing the record, then release it before
  remote I/O. The interrupted test's authorized restore completed through the
  ordinary reconciler. This test-only correction leaves the installed artifact
  unchanged. The complete archive lifecycle rerun passed on the retained
  disposable host.
- The emergency lifecycle fixture initially omitted the `ldp-admin` account
  created by production cloud-init. `530ac62` adds the locked disposable account
  and equivalent administrator sudo rule, with a check before paced tests.
- Actual archived emergency recovery then exposed a missing `CAP_SETGID` during
  Caddy candidate validation. The prior UID-only probe did not exercise clearing
  supplementary groups. `4849b70` retains both identity switches through sandbox
  setup; the complete-policy probe recovered the preserved archived deletion
  and retired its exact remote key. The installed unit regression now invokes
  the same user/group/supplementary-group drop used by Caddy validation.
  Configuration reapply passed with the two expected unit/timer changes. The
  strengthened installed policy check passed, 33 artifact/CI-selection tests
  passed, and the actual archived emergency recovery test passed at `4849b70`.
- The shared namespace fixture used a nonblocking read and could collide with
  periodic reconciliation before a test began. `ea4d44a` makes fixture setup
  wait for tenant-state ownership; ordinary operator admission remains unchanged.
  The complete ordinary/active/never-deployed emergency test subsequently passed
  in 294.70 seconds.
- Quarantine fixture creation also met normal tenant-state contention immediately
  after archive completion. `36aa88e` retries that setup within a fixed attempt
  limit, waits for the export lease during fixture reads, and bounds retries of
  post-resolution terminal verification. The failed attempt removed only its
  independently created unknown version; its bound archive was subsequently
  restored through an ordinary authorized job before the isolated rerun.

A terminal retry now completes quarantine resolution even when the preceding
cleanup already removed its journal. Unknown objects keep the result retryable;
resolution requires exact whole-bucket inventory and verification of every
retained version. The component regression covers both persistent unknown
inventory and independently resolved data, without granting deletion authority.
The [installed quarantine check](../../config/ansible/molecule/m3_8/tests/test_quarantine_recovery.py)
passed through the actual private service at `36aa88e`, including unknown-object
preservation, independently resolved inventory, retained-byte verification,
quarantine removal, ordinary restore, and final remote absence.

## Review and secure-workstation preparation

Delivery is split into the [archive boundary PR](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/137),
[lifecycle PR](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/138), and
[convergence PR](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/139). Each slice requires reviewer acceptance
and passing required CI before release. The original integration branch retains
the plan-only first commit. No production credentials are present in the coder
workspace; live checks run on the operator's secure workstation.

Review found and corrected five recovery defects. An ambiguous construction
response now preserves its journal until a subsequent invocation acquires a fresh
export lease, after the private service finishes its in-flight upload. Restore
replay reserves only remaining durable writes and permits journal-only completion
without a new capacity reservation. The same correction also applies to archive
revalidation and failed-construction replay. Root emergency recovery also resolves a
remaining quarantine after its retirement intent has already disappeared, using
independent full inventory and retained-byte verification without remote deletion
authority. Regressions cover the actual service disconnect race, six restore
commit boundaries, and both interruption and inventory failure after emergency
retirement. All 82 focused lifecycle tests passed, followed by the full revised host-agent
suite: 1,741 passed and two documented skips. The follow-up capacity corrections
passed 93 related lifecycle tests with one documented skip, including exact
remaining-write assertions at every revalidation and failed-construction durable
boundary. Strict typing also passed.

The build now pins dependency launcher interpreters to `/usr/bin/python3`, removing
checkout paths from the host artifact. Before the review recovery changes, two
independent checkout builds produced the same SHA-256
`3d34b4425aaf5336d92a1d37a5ef2191943d4413b0277b082b46d3e155daf082`;
the build/install regression passed. That historical digest is not a release pin:
the secure workstation must build and qualify the actual merged source.

The guarded read-only preflight checks the exact preceding M3.9 artifact,
quiescent disabled-publication host, enforced edge state, active host firewall,
Cloudflare DNS/TLS/origin-pull/WAF configuration, and private versioned empty
archive storage with no lifecycle expiration or multipart uploads. The installed
Spaces wrapper uses separate state-derived archive and backup credentials, first
proves mutual denial, then runs the complete installed M3.8/M3.10 scenario with
publication disabled. It accepts only a local Docker daemon, preserves failed
hosts and private diagnostics, and produces a sanitized exact-source/artifact
report only after all phases and independent final accounting pass. Production
configuration verifies that report and repeats preflight before its first host
mutation. Reports expire after 24 hours.

New complete-unit credential-boundary, post-retirement emergency recovery, and
completion/accounting checks passed against the disposable MinIO host (9 tests).
The reinstalled artifact including all three review fixes was
`0c79e838713b706cd9ee43937032595cfd8ff5ac0cd2246bb4652ffea71a698f`.
The infrastructure suite passed 292 tests on its first run; four Ansible tests
failed because the invocation omitted the project tool path, then all four
passed through the repository workflow. The strengthened host preflight passed
all 34 focused checks. Documentation links, lint, format, typing, and Ansible
validation passed. A fresh fixture installation exposed
an automatically allocated subordinate-ID range for `ldp-admin` overlapping the
runtime range. The disposable fixture now removes only that unused administrator
allocation; fresh preparation, convergence, and idempotence passed. Production
allocation rules remain strict. The live-configuration Ansible path also passed
convergence with the existing disposable MinIO credential supplied through the
private environment handoff. This checks the handoff mechanism and is not live
Spaces provider evidence.

The final provider-client and interrupted-convergence review fixes passed all
129 M3.10 infrastructure tests and strict typing across 239 source files. Real
SDK request construction now proves that every policy/accounting read can reach
the transport while writes, object reads, other buckets, and redirects are
refused. Completion is recorded only after successful host acceptance and is
invalidated before each new convergence attempt. The completion helper also
passed record, exact-artifact check, and invalidation against the disposable
host's actual root-owned directory policy. These are local checks, not live
Spaces or production evidence.

The next convergence review fixes passed all 133 M3.10 infrastructure tests,
the production Ansible lint profile (141 files), and the complete OpenTofu
checks. Freshly loaded runtime keys must pass bounded storage acceptance before
host mutation; regressions cover both an initial candidate and a previously
completed candidate when either acceptance or report verification fails.
Archive bucket names are rejected during infrastructure validation unless they
match the same lowercase-letter, digit, and dash contract used at runtime.
Credential installation now loads backup isolation and drains older invocations
before publishing the archive credential, including an interrupted first-install
retry whose isolation file was already written.
All four installed backup-process drain cases passed against the disposable
systemd host, covering both backup units and both first-install/retry paths.

Further gate review binds report age to the recorded final independent proof
and the oldest supporting evidence; stale storage reports and phase markers
cannot become fresh through later packaging. After completed convergence,
current-key validation uses a unique probe prefix and preserves existing
versions, delete markers, and multipart uploads. It cannot create an
empty-baseline qualification report. The combined infrastructure/storage/report
suite passed 177 tests, including the scoped command's success and failure paths.

Credential withdrawal now closes activation, removes the file, and stops every
active archive service instance that may retain loaded key material. Seven
installed cases passed against the actual service templates: idle withdrawal
and all three instance types, both before and after interrupted file removal.
The tests retain credential bytes only inside a disposable service process,
prove that its process exits, and restore the fixture's credential and sockets.

Completed convergence now binds the full clean source revision alongside the
artifact digest. Ansible, systemd, or runner changes cannot reuse artifact-only
completion to bypass qualification. Old completion markers fail closed. All
23 ordering and completion tests passed, including source-only changes with
missing/expired evidence or a failed preceding-host preflight.

Completed-candidate reconfiguration also revalidates mutable provider and
firewall controls. Its read-only storage mode permits existing tenant objects
while requiring private ACL, enabled versioning, and absent bucket policy and
lifecycle configuration; both edge zones and the live firewall remain mandatory.
All 189 current gate/storage tests passed, including unsafe provider controls,
either edge zone failing, and refusal before any convergence mutation.

The following provider/rollback regressions bring the current gate/storage suite
to 197 passing tests. Completed checks reject whole-bucket multipart uploads
without cleanup while permitting existing object versions. One or two bounded
public CA inputs are individually validated and copied into temporary trust;
real OpenSSL chain tests accept active leaves from either rotation anchor and
reject a replacement leaf with only the old anchor. Unsafe overlap inputs fail
closed. The evaluated production inventory now passes empty archive
configuration for the legacy artifact even when archive keys remain in the
workstation environment, selecting the already-qualified withdrawal path.
Production-profile Ansible lint passed for 141 files; typing and formatting passed.

The completed-host preflight now runs after source/artifact completion is
identified, allowing permanent tenant and audit history while retaining the
initial empty-host gate. It checks bounded canonical authorization and audit
records, exact artifact identity, authoritative enforced Caddy state, and
quiescence. Interrupted publication files are rejected before readers that
normally retire abandoned copies, so the gate preserves diagnostic evidence.
The updated gate/storage suite passed 235 tests, with one separately configured
MinIO test skipped; strict typing passed for 240 files. The actual production
worker template also omits archive socket binds for the legacy rollback, and
both edge zones must return their exact IDs and a common valid account identity.

All nine installed credential-withdrawal cases passed against the selected
`71947349c9d5452f39cce6b0ad22916950869c76a629dd4bbecf9c68168f4c27`
artifact, including managed emergency recovery before and after credential
unlink. Fresh installation, zero-change reapplication, installed source-bound
completion, and full-size export/import passed for this artifact. A subsequent
archive run exposed a timing race in the capture test helper: the worker can
already be active while waiting for the export lock. The helper now identifies
the exact worker's lock waiter; the failed deletion recovered through normal
authority and succeeded. This failed run does not constitute complete installed
qualification. Required CI and subsequent installed evidence must establish the
final release; earlier complete runs remain identified by their revisions above.

The subsequent installed archive/deletion rerun passed all four checks in
1,864.56 seconds against the same artifact: four repeated archive/restore
cycles, full-size archive/restore, capture/Caddy/Ansible overlap, historical
replay, ordinary/emergency deletion, interrupted archived deletion recovery,
and final accounting. A separate complete remote inventory confirmed no
versions, markers, or multipart uploads. The completed-host preflight at `3754661f`
also passed against that installed host with its permanent ordinary and
administrator history retained.

Completed-host checks now reject any job that startup would queue or repair,
require matching immutable terminal results, and emit a private source/artifact
snapshot of manifest-bound archive records. Completed provider checks compare
the entire remote version/size/marker inventory to that snapshot, read each
exact version's ACL with workstation operator authority, and repeat inventory
after those ACL reads. Public or foreign grants, missing or extra versions,
delete markers, and unaccounted multipart work fail without mutation. The SDK
policy guard permits only version-specific managed-object ACL reads in addition
to its existing bucket reads; runtime network authority is unchanged.

A subsequent review correction binds each terminal ordinary result through the
runtime's existing audit validator, including digest, status, principal,
operation, tenant, transition time, and deletion/failure evidence. Its false
return for valid superseded history is retained, as is its legacy-v1 failure
exception. Administrator results independently require the exact audited reason
and result, with the deleted tenant absent. Audit publication files are rejected
before any correlation reader can retire an abandoned copy. Regression cases
cover missing and conflicting ordinary/admin audit entries and the legacy/v2
failure distinction; this gate-only change does not alter the installed artifact.

The gate also checks audit-to-result completeness. Every retained audit entry
must match one exact result; lost administrator results or a lost ordinary
authorization history cannot pass merely because the remaining audit chain is
valid. Legacy failures may omit an audit, but an existing audit must bind the
exact result and principal. The combined gate/storage suite passed 300 tests
with one separately configured MinIO case skipped, and strict typing passed for
241 files.

Executor recovery now dispatches an unpublished failed archive construction
from its captured source and exact failure audit after source deployment
replacement or collection. Fourteen real private-service regressions exercise
all three failure-publication crash boundaries and altered candidate, release
tree, result, or missing audit authority. All 39 focused handler/abort tests
passed. Cleanup retires the remote object and construction journal while the
executor continues to refuse the externally changed deployment history. This
runtime correction produces artifact
`14d6323f72a5df07902e120215ca99c10b220fb6de0d2dd32c85539b01342216`;
the earlier installed evidence remains bound to its stated artifact. Fresh
qualification and required CI must validate the new candidate before release.

Further convergence review hides archive sockets from the ordinary reconciler,
requires empty Workers-route inventories for both edge zones, and passes
completed-candidate verification explicitly into both Ansible converges. The
role still refuses ordinary tenant-history changes, legacy configuration, and
a changed selected artifact. Six tests execute the actual Ansible guards on
disposable local state. The combined gate/storage suite passed 312 tests with
one separately configured MinIO case skipped; strict typing passed for 241 files
and the production Ansible lint profile passed for 141 files. The installed
credential suite also contains a direct socket-access probe using the ordinary
reconciler's actual service policy.

## Production checkpoint: 2026-09-18

The operator completed the secure-workstation live qualification and then
explicitly authorized and completed guarded production convergence. Credentials
and private logs remained on the secure workstation. The repository retains only
the allowlisted [qualification report](evidence/m3-10-2026-09-18/qualification.json)
and its [SHA-256 file](evidence/m3-10-2026-09-18/qualification.sha256).
The returned report bytes matched that checksum, and the repository verifier
accepted its exact source/artifact binding and evidence age before convergence.

| Identity | Recorded value |
| --- | --- |
| Merged source | `22147a64e9b39e7965201cf2d96e07aeaa6d3ca1` |
| Host-agent artifact SHA-256 | `a7ae4afe77c1fe9077ae58c8750a33518b26f7c5dc42485626b1ef22cd192800` |
| Qualification report SHA-256 | `ad3dc6c314b3d2de0c3a599deba206576b7d0bfaf2d9bf5deda88b036be3ba5f` |
| Oldest supporting evidence | `2026-09-18T05:34:35.137068Z` |
| Final independent proof started | `2026-09-18T09:33:02.823995Z` |

The final correction in [PR #149](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/149)
passed review and all required checks. Its reviewed tree matched the squash
merge exactly. Both [merged-source CI](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35305647903)
and [CodeQL](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35305647759)
passed. The live report records successful create, prepare, converge,
idempotence, verify, and destroy phases. Final accounting had zero pending
intents, intake, exports, or staging; no quarantine; and no remote versions,
delete markers, or multipart uploads. The wrapper independently rechecked
whole-bucket absence before retiring the disposable host.

The operator's subsequent production preflight passed the exact preceding M3.9
host identity, disabled publication and empty authoritative state, archive
privacy/versioning/no-lifecycle policy, whole-bucket absence, both enforced
edges, and the active reviewed firewall policy. The operator confirmed an
independent secure backup of the current dedicated archive key ID and secret.

Production convergence then passed its repeated gates and zero-change second
configuration pass. Final host acceptance reported `ok=20`, `changed=0`,
`unreachable=0`, `failed=0`, `skipped=3`, `rescued=0`, and `ignored=0`.
Acceptance verified the selected artifact, disabled publication, encrypted
backup repository, and disposable restore. The operator supplied `echo $?`
immediately after the runner returned, with result `0`; its final step recorded
the exact source and artifact in the root-owned completion marker. This records
successful runner completion, not a separate readback of that marker.

M3.10 is complete with production publication disabled. The
[operational sustainability phase](../plans/m3-operational-sustainability.md)
precedes M3.11 implementation. These files preserve historical release evidence;
they do not qualify the closeout commit or a later candidate. The current
24-hour and exact-source/artifact rules remain in force until a separately
reviewed policy replaces them.
