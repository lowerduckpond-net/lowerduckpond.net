# Operational sustainability exit, 2026-09-20

The [sustainability plan](../plans/m3-operational-sustainability.md) has its
implementation and qualification evidence: the final candidate passed required
CI, all thirteen independent installed groups, the complete secure-workstation
Spaces workflow, and the three-run performance comparison below. This record
closes that prerequisite to M3.11 when accepted through the normal PR checks.
It does not authorize production mutation or enable publication.

## Qualified candidate and production status

The operator qualified clean source
`970f31d253da9cfb55f9215532142c60a3c0dc91` against live Spaces. Its original
[qualification report](../threat-model/evidence/sustainability-2026-09-20/qualification.json)
and [checksum](../threat-model/evidence/sustainability-2026-09-20/qualification.sha256)
are retained byte-for-byte. The checksum was checked on the workstation and
reproduced after transfer:
`5c5555ec6e3f7c4653729df57969acb6c215a408734f52d98bf9018e423252d8`.

| Identity | Value |
| --- | --- |
| Installed artifact | `0b12b64e71007d107263454f2da5cac11d74b5dac3d53e459d5a0ad89b8ef3c2` |
| Input policy | `lowerduckpond-production-inputs-v1` |
| Qualification inputs | `3b5e4a2d37abef7214f8cc1f15f2dad1334101344e8d83ab6ebeabb2de565f13` |
| Storage target | `e982ace39c2cae07de0899170481058051db3cf12c2a03d42c9e3bf0400d1528` |
| Oldest supporting evidence | 2026-09-20T19:47:32.840092Z |
| Final independent proof began | 2026-09-20T22:06:34.740396Z |

All six phases, including destroy, passed. Final intents, intake, exports,
staging, remote versions/delete markers, and multipart uploads were zero;
quarantine was false. The v2 verifier validated the original source, artifact,
input fingerprint, chronology, revocation policy, phase results and accounting.
The storage target is the trusted operator's reported identity; this workspace
did not independently read production state or query providers. Credentials and
raw logs remain on the secure workstation.

[M3.10 production convergence](../threat-model/m3-10-evidence.md#production-checkpoint-2026-09-18)
remains completed for source `22147a64e9b39e7965201cf2d96e07aeaa6d3ca1` and
artifact `a7ae4afe77c1fe9077ae58c8750a33518b26f7c5dc42485626b1ef22cd192800`.
Its original report passed all six phases, including fixture destruction; the
operator reported acceptance with 20 successful tasks, zero changes/failures,
and exit zero. Publication was disabled at that production checkpoint.
The newly qualified sustainability artifact has not been deployed by this work.
Later revocations prevent reuse of affected old evidence for a new installation;
they do not erase that historical production checkpoint.

## Delivered changes and retained guarantees

| Slice | Accepted changes and proof |
| --- | --- |
| S1: measure | [#154](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/154) adds bounded monotonic timing, source/artifact/environment identity, and overlapping category measurements. The historical baseline, final hosted comparison, and live report are retained below. |
| S2: diagnose | [#156](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/156) adds bounded, allowlisted failure reports and one read-only collection command. Provider/configuration/unavailable-host/reporter regressions preserve the first failure, unknown observations and private canaries. Diagnostic reports cannot qualify or authorize cleanup. |
| S3: reproduce | [#157](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/157) creates a fresh 100-MiB/5,000-file archive source through supported operations. Owned fixtures, ports, images and state prevent accidental cross-run reuse. Real Docker checks cover partial creation, retained/stopped hosts, lost removal responses and exact image-tag retirement. Local accounting and independent both-bucket absence precede teardown. |
| S4: pace | [#158](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/158) uses host admission history under the unchanged production rate and burst policy. Deterministic comparisons include 1,000 generated cases. Installed exact retry, restart reconstruction, clock rollback and real admission behavior remain covered. No faster production policy, upload retry or deadline relaxation was added. |
| S5: group/select | [#159](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/159) and [#161](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/161) introduce independently reproducible groups, explicit overlap/reboot coverage, conservative change selection, and a stable aggregate requiring every selected receipt. Missing, skipped, cancelled, malformed or duplicate-owner results fail. |
| S6: qualify inputs | [#151](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/151) implements [ADR 0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md): original input/artifact/target identity, revocation, record-only equivalence, and fresh live gates. The final complete Spaces run validates the changed workflow. |

Two runtime corrections were required during this work:
[#153](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/153) preserves
state-lock waiting through archive cleanup, and
[#160](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/160) preserves
it through construction, download and retirement. Their regressions fail against
the preceding implementations. The construction correction has thirteen
real-lock/private-socket regressions; its full Python validation passed 3,504
tests with three expected skips. The [cleanup revocation](2026-09-18-archive-cleanup-qualification-revocation.md)
and [construction revocation](2026-09-19-archive-construction-qualification-revocation.md)
preserve the historical evidence while preventing future reuse of affected
artifacts. The exact earlier CI worker exception was unavailable; deterministic
regressions establish the defects without claiming every prior failure's cause.

The [invariant-to-group map](../operations/installed-groups.md) records the fresh
setup, relocated assertions and remaining cross-feature coverage. The original
complete grouped-harness journey and all groups passed before selection was
activated, as recorded in the [eligibility evidence](2026-09-20-installed-grouping-eligibility.md).
Diagnostic-phase and full-size-receipt review findings were corrected before
acceptance. The selected head and squash trees match their tested merge trees.
Required CI and automatic reviewer acceptance were checked before each merge;
no review requests were sent. The operator authorized merging one sustainability
PR at a time.

## Measured feedback and cost

The [original baseline](2026-09-18-sustainability-baseline.md) has comparable
complete installed jobs of 2h49m03s and 2h40m24s. S1's instrumented PR complete
job took 2h47m30s. The [derived observations](2026-09-20-sustainability-exit.json)
retain every final group's setup, job and entry timing, report/ZIP hashes,
fixture identity, and all 25 retained CI attempts, including failures and
cancellations. These measurements came from normal validation, without extra
benchmark-only dispatches.

| Final normal sample | Slowest independent job | Full-size job | Longest fast job | Whole CI workflow | Summed group execution | Summed CI execution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [#159 prerequisite](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35475224829) | 28m13s | 13m36s | 10m43s | 2h00m30s | 4h22m24s | 6h49m35s |
| [#161 PR](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35483066487) | 29m01s | 13m32s | 8m04s | 43m08s | 4h19m25s | 4h44m07s |
| [Final main](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35485606320) | 29m13s | 13m28s | 8m03s | 38m45s | 4h25m58s | 4h51m07s |

All thirteen groups passed in each sample, with the same corrected artifact,
four-CPU GitHub runner class, MinIO and production admission policy. Group jobs
include tool setup, fresh provisioning, idempotence, assertions and cleanup.
The final selector/aggregate/fixture component run took 12.39 seconds for 157
tests. Thus measured focused checks meet five minutes, fast lanes meet fifteen
minutes, and all independent installed groups meet thirty minutes. Baseline
Ansible took 12m37s / 12m34s / 13m06s, separately from the fast-job column.
These observations require no performance-target exception.

The prerequisite workflow intentionally ran the original complete journey too:
its job took 1h59m49s. Routine PR/push workflows now omit that duplicate and wait
for Python/hooks before allocating group fixtures. Actual PR completion includes
that prerequisite delay and runner scheduling; it is not the slowest group's
duration. Different images/runner hosts and unmeasured cache state limit causal
comparisons. Precise queue time cannot be separated from scheduling/dependency
delay in the retained API timestamps; it remains unknown. Summed job execution
is not billing and excludes other workflows.

Parallel feedback costs more runner execution than the old single journey.
Selection also remains deliberately narrow: fifteen of sixteen actual historical
changes select all groups; one documentation change selects none. A mapped
emergency-plan edit selects deletion/quarantine, credentials and reboot; shared
or unknown changes select the full matrix. This is not a claim that most runtime
changes now run only a small subset.

Measured complete-entry timing fell from 10,040.176 seconds in S3 to 7,475.664
in S4. Pacing fell from about 4,405.49 to 3,775.61 seconds, but Ansible reapplication
also varied from 2,988.58 to 1,980.62 seconds before the later grouping/pipelining
change. The entire difference cannot be attributed to pacing. The subsequent
main workflow took 9,244 seconds, demonstrating normal variance. Failed runs,
link-only retries and superseded runs remain in the cost ledger; carried retry
successes are not counted as new execution. In particular, superseded #159 main
passed all thirteen groups but cancelled its complete journey and is not a
passing complete workflow.

## Full live proof and remaining expensive obligations

The original [live timing report](../threat-model/evidence/sustainability-2026-09-20/timing.json)
records 8,511.906685484 seconds (2h21m52s), exit zero, on the operator's 20-CPU
workstation with real Spaces. This is separate from the three hosted comparison
samples. It retains the full production-policy verifier and resource limits.
The complete CI safeguard remains 330 minutes; no timeout was increased for
this closeout. Complete live qualification still takes hours, rather than the
30-minute target for one independent installed group.

Within the live run, pacing summed to 3,301.852 seconds and Ansible reapplication
to 2,453.580 seconds. Only 35.343 seconds were outside the instrumented union.
Nested categories overlap and must not be added to obtain wall time. Core took
32m52s in this complete journey, which contains the configuration guard assertions
split into separate independent cases. Its three failed nested converge spans
correspond to deliberate generation, operator-boundary and publication-disable
refusals asserted by the [core lifecycle tests](../../config/ansible/molecule/m3_8/tests/test_lifecycle.py).
The top-level core and final verifier passed; the failed-span counter is not a
qualification failure.

Before this successful run, an invocation stopped before creating its private
run directory. A synthetic Docker-info failure reproduced the silent exit, but
the workstation cause was not independently confirmed. The operator then used
a private environment-file launcher outside Git to avoid retyping credentials;
its missing Mise activation was corrected and checked with real pinned tools.
These are retained operator interventions. The successful run reported no
intervention; its timing field remains `null`, not an inferred zero. Failures
before run-directory creation remain outside the automatic per-run report.

Weekly Monday 04:23 UTC and manual CI retain all groups plus the original complete
journey. The latest scheduled run checked before closeout,
[34830825296](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/34830825296),
passed on its older source. The latest manual
[35392071538](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35392071538)
was only an artifact-transfer probe and is not treated as complete qualification.
The current complete proof is the grouped prerequisite plus the final live run.
Scheduled regressions still block release under the existing selection policy.

## Evidence validity and operator handoff

The accepted ADR retains original provenance and a seven-day pending-installation
provider window from the oldest observation, with fresh host, provider, credential
and accounting checks at convergence. This is an explicit residual-risk budget
for provider behavior not covered by short probes, not a reliability guarantee.
Report creation still has its 24-hour packaging bound; historical v1 reports
retain their old policy. Revocations and changed inputs/targets override age.
An accepted equivalent installation does not require periodic redeployment.

This closeout contains only non-executable historical Markdown/JSON/checksum
files in the two excluded record namespaces. Its candidate input fingerprint
must remain the value above, and its evidence keeps source `970f31d2...` and the
original timestamps. The record does not qualify a different artifact, refresh
provider evidence, or require another production deployment.

A second operator can follow the existing, qualified instructions:

1. Use [contributor commands](../../CONTRIBUTING.md#development-workflow) for
   focused component checks, committed-change selection preview and an individual
   installed group. The [group map](../operations/installed-groups.md) gives each
   case's coverage and setup; `just check` remains the full local entry point.
2. For a created run that fails, use the single read-only
   [failure collection command](../operations/qualification-diagnostics.md#collecting-a-failure).
   Its allowlisted report distinguishes current observations from historical
   snapshots. The [owned-fixture retirement procedure](../operations/qualification-diagnostics.md)
   requires fresh local accounting and independent remote absence.
3. Before another release, follow [selection and scheduled-failure handling](../operations/installed-selection.md#full-qualification-and-release-handling).
   Production credentials stay on the secure workstation; use the
   [successor qualification workflow](../operations/m3-10-convergence-preparation.md#qualifying-a-successor-after-completed-m310)
   for changed inputs. Convergence remains a separate authorized operation.
4. Preserve original reports and follow [ADR 0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md)
   for record-only equivalence and fresh live gates. M3.11 can now build its
   independent backup/restore scenarios under the existing plan; the full M3.12
   acceptance gate remains required.
