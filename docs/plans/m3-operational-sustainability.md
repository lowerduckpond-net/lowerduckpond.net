# M3 operational sustainability plan

- Status: proposed; planning can proceed during M3.10 diagnosis
- Date: 2026-09-16
- Baseline: `9f8e95d296b93ab721c2643e751dfdae7ced0217` on `main`
- Parent: [Milestone 3](milestone-3.md)
- Placement: after M3.10 qualification, before M3.11 implementation
- Outcome: bounded development feedback, independently reproducible installed
  failures, and usable operator evidence before adding backup/recovery cases

## 1. Current constraints and sequence

M3.10 has local installed evidence, but its live Spaces qualification and
production convergence starting gate remain incomplete. The latest reported
full-size archive attempt ended in a validated rollback with an
`archive_unavailable` result, no pending intents, and no archive quarantine.
That does not establish fresh whole-bucket absence or a passing qualification.
The original service exception was not retained, so its cause is unknown.

[PR #146](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/146)
adds bounded service diagnostics. At this planning checkpoint it has reviewer
acceptance and its installed-host CI is running. It is not the archive fix.
Further review/CI corrections, diagnosis, a separate corrective PR, and another
live qualification may still be necessary. None is assumed complete here.

The delivery order is:

1. Prepare and review this plan independently of PR #146. Read existing logs
   and map tests while its checks run; do not restart its CI to carry planning.
2. Finish any PR #146 corrections, obtain passing CI and reviewer acceptance,
   and merge through the existing operator workflow. Diagnose the live failure
   with a reviewed, safe reproduction procedure. Give the actual fix its own
   regression, review, and required qualification.
3. Record passing M3.10 live qualification for the exact candidate and preserve
   its evidence. Record remaining convergence prerequisites separately.
4. Implement the bounded sustainability slices below. Complete their exit gate
   before starting M3.11 implementation; preserve the full M3.12 acceptance gate.

Planning and credential-free prototypes may proceed now. A minimal diagnostic
or reproduction improvement needed to resolve M3.10 may move forward as a
separate corrective PR. It must retain existing qualification requirements;
the broader CI redesign must not become a prerequisite for fixing the archive.
When the actual defect is known, revise affected plan details and tests before
implementing them. M3.10 corrective changes take priority over assumptions made
by this planning snapshot.

Qualification is distinct from production convergence. This plan does not
authorize production mutation or publication enablement. Production credentials
remain on the secure workstation. Passing historical evidence is retained, but
the [current report verifier](../../scripts/m3_10_qualification_report.py)
requires an exact source/artifact match and evidence no older than 24 hours.
Do not refresh timestamps, relabel reports, or reuse an old pass as a new release
gate. After this interval or a candidate change, obtain the fresh evidence
required by the [convergence runbook](../operations/m3-10-convergence-preparation.md).
That applies to source-only changes too, until a separately reviewed evidence
policy explicitly says otherwise. Coordinate the intended convergence window
before choosing the next qualification revision.

## 2. Evidence for the work

| Observed constraint | Source | Consequence |
| --- | --- | --- |
| All `packages/`, all Ansible inputs, the lockfile, and the CI workflow select the full installed lane. | [Selector](../../scripts/m3-8-ci-required) | Small runtime and harness corrections can repeat hours of validation. |
| Core lifecycle, export/import, archive, deletion, reboot, and recovery share one ordered fixture. | [Installed verifier](../../config/ansible/molecule/m3_8/verify.yml) | A late failure is difficult to reproduce independently. |
| Full-size archival discovers the tenant left by the M3.9 export test. | [Archive test](../../config/ansible/molecule/m3_8/tests/test_archive_lifecycle.py) | Selecting the archive test alone is not a complete setup procedure. |
| The harness waits 60.25 seconds per new correlation after its initial burst and conservatively ignores operation time when refilling. | [Lifecycle support](../../config/ansible/molecule/m3_8/tests/test_lifecycle.py) | Faster processors cannot remove all elapsed time; the contribution must be measured. |
| Failed runs preserve the host and private logs but have no structured failure summary. | [Spaces wrapper](../../scripts/m3-10-spaces-qualification) | Operators assemble evidence manually across logs and state. |
| Publication-enabled hosts reject artifact replacement. | [Host-agent role](../../config/ansible/roles/static_host_agent/tasks/main.yml) | A retained failed fixture cannot simply receive a new artifact via converge. |
| Fixed container names, SSH port, and artifact paths are shared. | [Molecule configuration](../../config/ansible/molecule/m3_8/molecule.yml), [wrapper](../../scripts/m3-10-spaces-qualification) | Concurrent scenarios need resource isolation before parallel execution. |

These observations establish opportunities, not a measured attribution of the
three-hour runtime. Preserve the guarantees in
[ADR 0022](../adr/0022-test-static-publication-as-a-security-boundary.md) and
the [M3.10 evidence map](../threat-model/m3-10-evidence.md). Every removed or
relocated assertion must name its replacement and the environment that proves it.

## 3. Bounded delivery slices

Use one coherent PR per slice, splitting only when the review or dependencies
justify it. Review the implementation against the then-current merged archive
fix. Obtain reviewer acceptance and the required CI for each final revision;
do not merge automatically. The first three slices provide useful improvements
even if the pacing or selection proposals need further design.

### S1: Measure execution and waiting

Add monotonic timings for fixture creation, provisioning, each verification
group, admission pacing, operator calls, Ansible reapply, reboot, and cleanup.
Separate elapsed time from summed concurrent operation time. Report runner and
tool versions, scenario, source, artifact, backend, and test policy. Produce a
short summary plus machine-readable timing data. For live runs, use allowlisted
fields and keep private logs local.

Use available completed CI logs as the initial baseline; do not rerun a full
gate solely to obtain a baseline. Collect missing detail during the next required
run. Compare like-for-like fixtures and runner classes, recording setup/cache
conditions, wall time, total runner minutes, and operator interventions. Sharding
may reduce wall time while increasing cost, which must remain visible.

Acceptance: identify the largest measured contributors and explain time outside
the instrumented groups. Timings survive an ordinary test failure and cannot
change the test result. Set the next optimization from these measurements.

### S2: Produce a bounded failure report

Extend the workstation wrapper and local harness with a versioned failure
report, separate from the passing qualification envelope. Record the failed
phase/scenario, exit status, bounded diagnostic category, selected job/result
fields, artifact/source identity, and local and remote accounting status. Use
explicit `unknown` values when the host/provider cannot be inspected. Distinguish
operation success, validated rollback, and unresolved recovery.

Generate a shareable allowlisted summary and retain raw logs in the private run
directory. Never copy arbitrary exception text, response bodies, credentials,
object names, or tenant content into a shareable artifact. The reporter must
preserve the original nonzero status, impose time/size limits, and report its
own incomplete collection without masking the first failure. Include a read-only
diagnostic command for a retained run and known environment checks, including
Docker credential-helper usability and supported filesystem/mount behavior.

Cleanup eligibility requires fresh authoritative local accounting and the
existing independent remote proof. No intents or quarantine alone is
insufficient. A report must not delete objects, retry a failed job, or grant
cleanup authority. If collection fails, preserve the host and report unknown.

Acceptance: injected provider, configuration, unavailable-host, and reporter
failures produce a bounded useful summary without private canary strings. The
operator can collect one report without assembling ad hoc journal commands.
The passing-report validator rejects diagnostic and partial-run reports.

### S3: Reproduce full-size archive independently

Extract reusable fixture construction from export/import test assertions. On a
fresh disposable installed host, create the suspended 100-MiB/5,000-file source
through the supported lifecycle, verify its identity/content, and run the
full-size archive case directly. Share fixture-building code, not the state
left by another test. Preserve real installed service isolation and resource
limits; test fixture setup cannot silently replace production code.

Give local scenarios owned container names, SSH ports, scratch/artifact paths,
Molecule state, and storage fixtures. Prove two local runs cannot inspect,
overwrite, or destroy each other's resources before adding parallel execution.
Live Spaces work stays serialized against the existing whole-bucket contract;
a prefix does not isolate quotas, quarantine, or whole-bucket absence checks.

Provide a documented single-case command with its prerequisites and expected
runtime. A failed run is retained for inspection. A new attempt gets a distinct
run/correlation identity; exact replay of a terminal failed job remains failed.
Do not implement arbitrary resume, edit durable records, or replace an artifact
on a publication-enabled retained host. Initially prefer a fresh owned fixture
after the previous run's state and remote obligations are resolved through the
existing supported workflow.

Acceptance: the case starts without running core/export assertions first,
exercises the actual full-size path, reports failure and accounting, and can
run again from a fresh fixture after safe cleanup. Its pass is diagnostic
evidence, not a complete M3.10 qualification. Keep the complete lifecycle test
until equivalent independent coverage and a cross-feature journey pass.

### S4: Reduce repeated admission waiting

Choose the smallest change supported by S1. First examine conservative harness
pacing and division into independent scenarios, retaining the real admission
rules. Exhaustive rate-window arithmetic belongs in deterministic component
tests with injected time. Keep installed tests of the real production rate,
burst, exact retry, restart reconstruction, and clock rollback behavior.

A faster installed policy is a design option, not an approved runtime switch.
If still necessary, require a separately reviewed design and any affected ADR
amendment. Prove that production installation and the live acceptance wrapper
reject it, ambient inputs cannot enable it, and reports identify the altered
policy. Evidence from that policy cannot qualify production timing or resource
behavior. Do not shorten production deadlines, add upload retries, reset durable
admission records, or bypass authenticated issuance to make tests pass.

Acceptance: show where saved time comes from, pass the unchanged production
admission contract, and retain a production-policy installed journey. If no
safe faster policy is justified, use isolated local scenarios and report the
remaining measured cost rather than introducing a test bypass.

### S5: Select and schedule the relevant installed checks

After S2-S4, split the remaining verifier into independently runnable core,
export/import, archive/deletion, and reboot/recovery groups. Each declares its
fixtures, dependencies, accounting, and covered invariants. Preserve explicit
cross-feature, configuration-overlap, and restart tests that would otherwise
be lost by splitting. M3.11 must add independent backup/restore scenarios through
this structure rather than extending one global sequential test.

Build a reviewed change-to-scenario map from actual runtime, schema, package,
unit, role, fixture, and shared-helper dependencies. Exercise selection against
representative changes, renames/deletions, shared dependencies, and missing diff
metadata. Unknown mappings select the full gate. A PR label alone cannot exempt
a change. Missing or failed selected checks fail the stable required aggregate.

| Change or event | Proposed required validation |
| --- | --- |
| Documentation outside executable inputs | Documentation and existing repository hygiene checks. |
| Narrow runtime change with mapped dependencies | Fast checks, artifact/contract checks, affected installed groups, and any required production-policy probes. |
| Shared authorization, persistence, recovery, schemas, systemd/Ansible policy, packaging, or dependency change | All affected groups; use the full gate until narrower coverage is demonstrated. |
| Changes to selection or test infrastructure; uncertain mapping | Full installed gate plus selector and fixture-isolation regressions. |
| Scheduled/manual complete qualification and release candidate | Complete installed matrix; explicit live-provider gates remain separate and mandatory where currently required. |

Run the proposed selector in comparison mode on representative changes before
making it authoritative. Complete at least one full installed run of the final
harness and selected production-policy journey before retiring the old path.
Scheduled runs already exist; document their cadence and failure handling rather
than silently moving required PR coverage into the schedule. A scheduled
regression blocks release and receives a reproducible case and corrective PR.

Keep `just check` as the full local entry point. Add clear focused/affected
commands and update contributor instructions together with the reviewed policy.
Reuse source-matched build artifacts within a run only with verified provenance;
do not cache passing results across changed inputs. Coordinate review fixes
before starting another expensive run where feasible, without delaying a known
correctness fix or allowing stale-head acceptance.

Acceptance: demonstrate representative documentation, narrow runtime, and shared
boundary changes choose the intended checks; prove unknown changes and missing
jobs fail closed. Compare coverage and wall/runner time with the S1 baseline.
Changes to the live wrapper or its verifier also require the existing complete
secure-workstation qualification before using that workflow as release evidence.

## 4. Budgets and exit gate before M3.11

These are engineering targets to validate, not performance claims:

| Work | Target, including its required setup |
| --- | --- |
| Focused component regression | At most five minutes. |
| Routine fast PR lane | At most 15 minutes from runner start to result. |
| Affected installed group, including independent full-size archive | At most 30 minutes from runner start to result. |
| Full production-policy installed and live qualification | Retain a measured bounded budget; hours can remain appropriate. |
| Failed-run triage | One documented collection command yielding one shareable summary; no routine hand-built journal queries. |

Queue time is recorded separately. Fifteen minutes describes fast feedback,
not a promise that every security-sensitive PR can merge in that time. Judge
representative ordinary PR completion time as well as individual lane timing.
Use three comparable representative runs collected through normal validation,
recording all results rather than selecting the fastest; no three extra full
qualification runs are required solely for benchmarking.

The exit record must show:

- historical passing M3.10 qualification and the disposition of its retained
  fixture, plus the separate current convergence status;
- the S1 baseline, after measurements, and remaining expensive obligations;
- the S2 failure report and independently runnable S3 case, including failure
  and cleanup behavior;
- admission-policy equivalence and an invariant-to-test map for S4/S5;
- reviewer acceptance, required CI, and final full installed qualification of
  the changed harness;
- instructions a second operator can follow without reconstructing this chat.

If a target cannot be met, record the measured result, cause, bounded alternative,
and proposed budget change for explicit operator agreement before declaring the
stabilization complete. Do not loosen coverage or repeatedly extend timeouts to
claim success. M3.11 remains dependent on this exit record.

## 5. Scope limits and reassessment

This is a bounded improvement to the existing test and operator workflow. It
does not introduce a new CI service, production credential distribution, a
general workflow engine, a host-agent rewrite, or the M4 product. M4 scope and
host-contract stability should be reviewed after this work with actual costs.
Fix environment-specific fixtures needed for supported development as part of
the relevant slice; do not redesign every developer environment.

Reassess the affected slice when the archive root cause is established, a
correction changes the artifact or service policy, measurements contradict the
pacing hypothesis, or independence would drop a required cross-feature proof.
Keep completed useful slices and narrow the next one. The deliverable is a
working short feedback loop and usable operator evidence, not an indefinitely
expanding test-framework project.
