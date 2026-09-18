# Qualification timing diagnostics

`just check-ansible-m3-8` runs the existing full installed sequence and records
monotonic timing observations. Its private timing directory is printed before
the run, under `${XDG_DATA_HOME:-$HOME/.local/share}/lowerduckpond.net/qualification/`
by default. CI places it under the runner's temporary directory and retains only
`timing.json` and `timing.txt` as the `m3-8-timing` artifact, including on failure.
An artifact-upload problem does not replace the original qualification result.

`just m3-10-spaces-qualification` records the same diagnostics in its existing
private run directory on the secure workstation. `timing.json` and `timing.txt`
contain allowlisted diagnostic fields and may be shared. Keep raw logs and
intermediate files private. Production credentials remain on that workstation.
These commands retain the production admission policy, resource limits, full
lifecycle order, existing cleanup behavior, and original exit status.

## Reading the report

- `elapsed_seconds` measures the timed entry point with the controller's
  monotonic clock. CI queue time, tool installation, and collection installation
  before this entry point must be obtained separately from the GitHub job.
  Live wrapper timing begins after its private run directory is allocated.
- Categories identify fixture creation/preparation, converge/idempotence,
  verification, cleanup/destruction, each verification group, admission pacing,
  operator calls, Ansible reapply, and reboot/readiness waits.
- `summed_seconds` adds every observed span in a category. `union_seconds`
  counts overlapping intervals only once. Categories also overlap with each
  other: operator and pacing spans sit inside groups; groups sit inside verify;
  nested Ansible phases sit inside reapply. **Do not add category totals to
  obtain wall time or runner minutes.**
- `instrumented_union_seconds` counts time covered by any emitted span once.
  `outside_instrumentation_seconds` is the remaining entry-point elapsed time.
  It includes orchestration and metadata collection. A missing child span can
  still lie inside an observed parent; this field does not prove complete
  attribution. Abnormally killed processes can leave incomplete observations.
- `failed` counts spans whose command/test raised or whose playbook failed.
  A completed operator call can return a terminal failed operation; timing is
  not a replacement for that operation's result or the qualification tests.
- Metadata includes source and checkout cleanliness, observed installed artifact
  and image digests, backend, scenario, admission/pacing policy, architecture,
  CPU count, kernel and tool versions. Missing observations say `unknown`.
  Queue time, cache conditions, and operator interventions are not inferred;
  the comparison record supplies them separately.

The summary prints total elapsed time and the longest observed groups. JSON
preserves all category counts and intervals' aggregate durations. Individual
private event records are bounded and contain only fixed labels and timing
numbers: no requests, command arguments, host names, provider responses, raw
exceptions, or test parameter values. Reporting errors print a fixed diagnostic
and cannot turn a failed command into a pass or fail a passing command.

Read `timing.txt` in the printed directory after a run. If timing collection is
unavailable, keep the original test result and record the timing as unknown;
do not recreate a historical duration by repackaging hours later. These files
use a distinct diagnostic format, grant no qualification/cleanup/retry authority,
and cannot replace `qualification.json`. An ordinary test failure still ends
qualification as before, while its completed and failing timing spans survive.

## Comparing runs

Start with the [historical baseline](../records/2026-09-18-sustainability-baseline.md).
Compare the same backend, runtime/harness obligations, runner class, fixture
state, and admission policy. Dirty local runs are exploratory. Record dependency
cache/setup conditions and operator interventions explicitly; do not assume
that absent observations mean warm caches or zero intervention.

Use GitHub job timestamps for complete job time, queue time, and summed runner
minutes. Keep these separate from entry-point elapsed time. Collect all three
representative after-change samples through normal required validation, including
failures; do not run three extra full gates just to obtain a benchmark. The
[S1–S5 plan](../plans/m3-operational-sustainability.md) uses these observations to
choose pacing and scheduling changes before making performance claims.

`just check-python` also prints the 20 slowest tests lasting at least one second.
This identifies fast-lane costs without rerunning the test suite for profiling.
