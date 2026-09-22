# Independent installed checks

Use `just check-installed-group CASE` after `just setup`. Each case creates a
fresh owned systemd host and MinIO service, installs the same artifact as the
complete qualification, and checks idempotence before its tests. Production
admission and service resource limits remain unchanged. The controller must
reach the fixture's published SSH port. Run parallel cases on separate runners;
the fixtures share a host kernel's loop-device pool even with distinct names.
Molecule pipelines Ansible modules through its Docker connection to reduce
per-task transfer overhead.

The [fixed registry](../../scripts/qualification_groups.py) declares every test
and parameter. It accepts no arbitrary test selector. The [reviewed selection policy](installed-selection.md) chooses required groups.
The complete installed journey remains available locally and is required on
scheduled/manual workflows; each group result remains diagnostic evidence
rather than a production qualification report.

| Case | Preserved installed assertions and independent setup |
| --- | --- |
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
stage also runs the existing artifact-integrity and archive-accounting check.
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
