# Independent installed checks

Use `just check-installed-group CASE` after `just setup`. Each case creates a
fresh owned systemd host and MinIO service, installs the same artifact as the
complete qualification, and checks idempotence on its source configuration. Production
admission and service resource limits remain unchanged. The controller must
reach the fixture's published SSH port. Run parallel cases on separate runners;
the fixtures share a host kernel's loop-device pool even with distinct names.
Molecule pipelines Ansible modules through its Docker connection to reduce
per-task transfer overhead.

The local MinIO fixture builds from fixed server and client commits with a pinned
Go compiler. Its image tag and build receipt bind the complete
[recipe](../../config/ansible/molecule/m3_8/Dockerfile.minio.j2). Matching local
builds are reused; an unrelated image at that tag is rejected. CI runs the
archive-storage checks first and shares the tested image within that workflow
run, so installed groups do not each compile it. This replaces the retired
upstream binary image without changing the fixture's server or client revision.

The four reconstruction cases also create a second fresh destination and a
run-owned ACME service after fencing the source. Their private provider mappings
survive destination restart; they do not contact the public ACME or DNS API.
The fixture waits at most five minutes for each requested restore phase, using
one fixed deadline and stopping immediately if the restore unit fails. The
combined two-segment restore exceeded the former three-minute observation
window; five minutes provides at least 1.5 times that observed interval.
Completion still requires cleared activation state. This harness deadline does
not extend the production coordinator's 30-minute limit or any CI job ceiling.

The [fixed registry](../../scripts/qualification_groups.py) declares every test
and parameter. It accepts no arbitrary test selector. The [reviewed selection policy](installed-selection.md) chooses required groups.
The complete installed journey remains available locally and is required on
scheduled/manual workflows; each group result remains diagnostic evidence
rather than a production qualification report.

After the original complete local lifecycle and accounting checks, that journey
also runs combined reconstruction on the same source. It preserves the earlier
tenants alongside the four new recovery states, restores their full backup, then
retires them through ordinary destination operations. Exact test completion and
fresh paired/independent storage accounting are required before removing the
destination and controlled ACME service. `complete-combined.json` records that
local diagnostic; the outer Molecule sequence still removes its source and
storage fixtures before the complete run can pass.

| Case | Preserved installed assertions and independent setup |
| --- | --- |
| `production-rollout` | Reapplies preceding main `69859cbb` with recovery/rotation disabled to an empty owned host, then runs the actual production bootstrap, four site converges, bounded backup/private restore and acceptance over verified administrator SSH. New controllers recover after namespace initialization and after retaining backup proof before acknowledgement; completed inspection preserves original records/capture. Uses a local disposable Restic repository and synthetic qualification binding; cannot qualify a live rollout. |
| `restore-reconstruction` | Own fenced source plus second fresh Ubuntu/ext4 destination; full-ID Restic restore, four tenant states, protected audit prefix/local tail, excluded upload/export decisions, exact archive proof, cold Caddy generation, immutable result replay and reboot. |
| `combined-reconstruction` | One source/destination history combines actual backup/mutation contention, excluded secret canaries, two full protected audit segments, lost snapshot response and index interruption, aged ordinary retention with interrupted forget/prune, interrupted reconstruction, reboot and historical-result replay. Local controlled-CA/MinIO evidence only; live Spaces and public-CA qualification remain separate. |
| `restore-negative` | Own source/destination; invalid target/source bindings, unknown later object, denied/corrupted exact-version downloads, rehashed audit fork, mixed roots, corrupt trusted environment/retained content and retired exact VersionId. Gated failure, unchanged installed roots and independent remote absence are mandatory. |
| `restore-tls-bootstrap` | Empty certificate storage, native DNS-01 issuance through pinned Pebble, actual DNS/CA rejection, process health insufficient for readiness, interrupted coordinator and destination restart with durable ingress gating. |
| `audit-rotation` | Own explicit lineage and combined publication/coherent-backup/rotation activation; two production-size closed segments. Hard exits after prepare, lost snapshot reply, witness/index/head publication and unlink; actual reboot, fresh remote proof and bounded service completion. Exact create/delete replays, subsequent mutation, unchanged ordinary snapshots, protected counts, privilege/resource limits and final accounting. |
| `audit-protection` | Own explicitly initialized empty lineage; publication and coherent backup activate together before supported tenant creation. Production-size closed audit segment, real ancient Restic copies and orphan adoption, exact index/witness and historical lookup, missing/corrupt/retagged protected evidence refusal before ordinary removal, journaled forget interruption and fixed-ID resume, service limits and credential-free health. Rotation and local removal remain disabled. |
| `backup-identity` | Fresh supported tenant history; real Restic config/full snapshot IDs and restore, permanent repository genesis before local commit, refusal after both local identity records are lost, retention exclusion, audit-prefix verification, repository/selection/state lock exclusion, wrong repository identity and root-only command boundaries. |
| `backup-coherence` | Own active/suspended/archived/undeployed tenants; explicit migration over existing history and idempotence, installed service failure/health and privilege bounds, real Restic capture/descriptor readback/restore/tree measurement, Caddy restart and guarded Ansible file writes; exclusion canaries. |
| `backup-mutation-overlap` | Own source and import target with empty-lineage initialization; real Restic capture/restore/tree measurement versus create/deploy/import/rollback/rename/suspend/resume/archive/restore/delete/export/emergency/reconcile, authorization repair and retained-release cleanup. |
| `core` | Creates its tenants; lifecycle results, exact retries, isolation, routing, rename, and deployment history. Configuration guards move to the two cases below. |
| `configuration-publication` | Creates an active tenant; publication-disable and operator-boundary drift refusal, restoration, unchanged tenant and routes. |
| `configuration-generation` | Creates an active tenant; unchanged reapplication and generation-input drift refusal/restoration, unchanged tenant and routes. |
| `export-roundtrip` | Creates a 100-MiB/5,000-file source; active/suspended export, deterministic repeated capture, retired replay, import quotas and provenance. |
| `export-recovery` | Creates its own tenants; unacknowledged stream, retry/conflict/expiry, capture exclusion against mutation and release cleanup. |
| `archive-cycles` | Creates its own source; repeated archive/restore, archived export/import, capture exclusion, Caddy recovery, configuration overlap, exact replay and deletion. |
| `full-size-archive` | Creates, deploys and suspends a fresh 100-MiB/5,000-file source; installed archive/restore resource limits, exact restored content and cleanup. |
| `deletion-quarantine` | Creates its own tenants; ordinary/emergency deletion, exact archived-version recovery, and quarantine recovery after journal removal. |
| `transport-recovery` | Fresh supported tenant; authenticated admission/transport faults, artifact binding, Caddy recovery, contested admitted jobs and reconciliation. |
| `overlap-deployment` | Fresh active tenant; configuration overlap with deploy, rollback and suspend. |
| `overlap-routing` | Fresh suspended tenant; configuration overlap with resume, rename and reconcile. |
| `credentials` | Installed service identities, TLS, denied cross-service storage credentials, namespace masks, credential withdrawal/draining and legacy selection. |
| `reboot-journey` | A 100-MiB/5,000-file site through supported create/deploy/export/import/archive/restore/rename/suspend, exact durable snapshot, actual reboot and startup reconciliation, restored routes/content, exact replay and a new admitted operation. |

Core, archive and transport extraction retains the original complete test entry
points. Their ordered assertion bodies remain available in that journey. The
independent archive cycles omit only the large source inherited from export;
`full-size-archive` covers that path with fresh supported setup. Configuration
and overlap assertions moved out of independent core/transport cases remain
explicitly required in the cases listed above. The reboot case preserves the
existing PID-1, reconciliation-invocation, durable-tree and route observations;
interrupted-operation fault injection remains in the transport/archive cases.
After restart, the harness rediscovers Docker's assigned SSH port while requiring
the recorded source and peer addresses to remain unchanged. It also restores the
captured disposable MinIO host mapping that Docker removes from `/etc/hosts`.
Neither restoration reapplies the production configuration.

Each stage must collect exactly its declared tests, in order, and pass setup,
call and teardown for every test. A skip, expected failure, missing test,
collection failure, or zero exit with incomplete execution produces no passing
stage receipt. Both reboot cases need before/after receipts. Every final
stage also runs the existing artifact-integrity and archive-accounting check,
or the paired reconstruction accounting check for restore groups. Those groups
retain the source fence and independently bind the destination and controlled
ACME service to recorded container IDs. The negative case must remain blocked
with unchanged installed roots; it never supplies a completed-restore receipt.
Reconstruction groups check source idempotence after enabling publication and
recovery (and rotation for `restore-reconstruction` and `combined-reconstruction`),
instead of repeating the initial dark-source configuration. They still run two full Ansible convergences:
activation, then a zero-change reapply. Only that successful reapply writes the
required receipt, bound to the run, source container, image, artifact and enabled
features. Missing or mismatched receipts prevent completion and retirement.
Successful reconstruction must finish ordinary destination accounting and all
DNS challenge cleanup. The ordinary two-resource retirement command refuses a
retained reconstruction fixture rather than orphaning its extra resources.
Paired retirement durably records both container identities, artifact and boot
incarnations before stopping either container. It stops both before removing
either and journals each removal. Repeating that transaction under the run
lease can finish after a lost stop/remove reply without requiring accounting
from an already removed destination; changed ownership or a restart refuses
continuation. Source fencing is freshly checked before each mutation.
If Docker or the controller interrupts a started paired retirement, finish that
existing transaction with:

```sh
uv run python -m scripts.qualification_restore_removal /absolute/private/run-directory
```

This requires `restore/removal.json` and acquires the original run lease. It
finishes only the authorized destination/ACME removal; the source and storage
remain retained, and the original failed diagnostic result remains unchanged.
Before teardown, the controller obtains fresh validated local accounting bound
to the run's artifact, independent root-identity whole-bucket absence for both
MinIO buckets, then rechecks container identities and local accounting.

The printed private run directory contains readable phase logs, stage receipts,
and the [timing and failure diagnostics](qualification-diagnostics.md).
`case.json` appears only after all required tests, fresh accounting and teardown
succeed. It is diagnostic evidence; the production qualification validator
rejects it. The complete secure-workstation Spaces workflow retains its fixed
verifier and receives no group-selection option.

For `full-size-archive`, `case.json` also retains the validated installed receipt:
the run identity, artifact and content hashes, entry count, and byte count.
These allowlisted fields travel with the uploaded diagnostic result; private
fixture logs and content do not.

The engineering target is 30 minutes per case **including setup**. Runtime is
not yet demonstrated for this grouping. Record actual setup, execution, pacing,
configuration, wall time and total runner minutes from normal validation before
claiming the target. A matrix can lower wall time while increasing runner cost.
`just check` remains the full local entry point; it does not silently substitute
these groups for complete qualification.

CI execution ceilings allow at least 1.5 times the typical observed duration,
including setup. The operator-authorized P6b adjustment is recorded in the
[M3.11 plan](../plans/milestone-3.11.md):

| Installed case | CI ceiling |
| --- | --- |
| `combined-reconstruction` | 90 minutes, provisional pending a complete measured run. |
| `production-rollout` | 90 minutes, provisional pending its first complete CI measurement. |
| `core`, `archive-cycles`, `backup-mutation-overlap`, `restore-reconstruction`, `restore-tls-bootstrap` | 60 minutes. |
| Other installed cases | 45 minutes. |

The combined case preserves one source/destination history through mutation,
two full protected rotations, interrupted reconstruction, reboot, replay,
retirement, accounting, and teardown. Those dependent phases cannot become
independent fixtures without losing the combined proof. Its initial ceiling
allows 1.5 times a conservative 60-minute execution window; the interrupted
45-minute run does not establish a successful duration. Measure the complete
window through normal validation and retain at least 1.5 times the typical
observed runtime when reviewing the ceiling.

The rollout case retains one host and original phase chain through each
controller departure. Its four site passes and predecessor/bootstrap setup
cannot use independent fixtures. The initial ceiling provides 1.5 times a
conservative 60-minute window while measuring the full installed case; it is
not a claim of a measured passing duration or acceptance of a target overrun.
The case needs the pinned predecessor commit in local Git history, as supplied
by CI's full checkout. Failed runs keep their original diagnostics and fixture.

The first clean local rollout case completed in 44.22 minutes including setup,
with original evidence, repeated completed inspection and owned teardown all
verified. That controller reported 32 visible CPUs; this is not a four-CPU CI
timing result. The [P6c timing amendment](../plans/milestone-3.11.md#p6c-timing-acceptance-proposal)
records this and the existing groups' target overruns for explicit review before
milestone closeout. Their higher execution ceilings do not themselves accept
those overruns.

These ceilings do not establish compliance with the 30-minute engineering
target. Production service limits, admission pacing, assertions, required
completion receipts, and the 330-minute complete-journey ceiling remain
unchanged. A higher ceiling does not lengthen a successfully completed job.

The original combined backup case passed in [CI run 35563599873](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35563599873)
but took 39.35 minutes including setup, exceeding the target. Its timing report
recorded 13.91 minutes of admission pacing across 31 spans and 8.48 minutes across
three Ansible reapplications. These categories overlap other measurements and
must not be summed. The two independent backup cases preserve its assertions
while separating configuration work from mutation contention. Measure their
fresh runs before claiming either meets the target; the original report remains
evidence of the combined case's cost.

The first protected-audit implementation passed all 17 groups in
[CI run 35648859891](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35648859891).
Audit protection took 31.80 minutes including setup, with two full Ansible
reapplications taking 391.97 seconds. Its fixture now initializes the supported
empty lineage and activates publication plus coherent backup together before
creating the supported tenant, removing one setup convergence. Nonempty-lineage
migration remains covered by `backup-coherence`. The full-size history, failure
injections, maintenance recovery and accounting assertions remain in this case.
Measure the revised case before claiming the runtime target.

That run's `archive-cycles` took 30.48 minutes, also above the target; the prior
run measured 29.79 minutes. Preserve both original reports and keep this timing
issue open through the next required matrix. A later passing measurement must
not relabel the overrun or imply a budget exception was approved. Resolve any
remaining budget gap through fixture separation or explicit review before
milestone closeout; production pacing and timeouts cannot be relaxed.

The fixture follow-up [PR #168](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/168)
passed all 17 groups in [CI run 35654060891](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35654060891)
at head `ecb6a736add8127cbb0fe13901f68f6a5421011c`. Audit protection took
27.94 minutes including setup, with one 212.47-second reapplication. Archive
cycles took 29.68 minutes; backup mutation overlap took 29.78 and core 29.92.
Every group met the target on that run, with narrow margins in those cases.
These measurements preserve the earlier overruns as separate results. The new
eighteenth `audit-rotation` case still needs its own installed timing; the
component full-size measurement cannot substitute for it.
