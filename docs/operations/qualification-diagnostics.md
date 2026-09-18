# Qualification diagnostics

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

## Collecting a failure

An unsuccessful installed run writes `failure.json` beside its timing report
and prints a short summary. CI retains this separate, allowlisted file as the
`m3-8-failure` artifact. The live wrapper keeps raw logs private on the secure
workstation. Share the JSON report when reporting a failure; it contains no raw
exception, provider response, credential, bucket/key name, or tenant content.

To observe the retained run again, run this from its checkout, on the machine
that owns the fixture, replacing the path with the printed run directory:

```console
uv run --frozen python -m scripts.qualification_failure collect /absolute/path/to/run
```

This is read-only against the fixture and provider. It writes a new
`failure-observation-*.json` locally, retaining the original `failure.json` and
original nonzero command status. Every observation has its own start/end time.
It does not retry the operation, restart a worker, edit durable state, or delete
anything. A later successful operation does not turn the original failed test
or qualification into a pass.

The report separates:

- The failed phase, verification group, fixed failure category, allowlisted
  test filename/line, original exit
  status, source revision, backend, and observed selected artifact digest.
- The last submission in the failed group, its bound job/result fields, and
  recorded outcome: success, validated rollback, executor rejection before
  execution, unresolved recovery, or unknown. The last submission is context;
  an assertion can fail after an operation succeeds. A recorded validation
  marker is historical evidence, not a new validation of every lifecycle
  invariant. A missing marker or missing observation is never success.
- Current counts of intents, intake, exports, staging and Caddy intents;
  quarantine presence; and a whole-bucket inventory of versions/delete markers
  and multipart uploads using the fixture's installed archive credential.
  Provider failures leave inventory unknown, not zero. No object names leave
  the fixture. These observations are not one locked transaction.
- Recent fixed-label archive service diagnostics. These labels may come from
  deliberate failure injections elsewhere in the fixture; they are explicitly
  **not bound to the last submission** and do not establish the cause by
  themselves.
- Docker credential-helper usability and controller/host filesystem types.
  The helper check invokes only `list`, discards account names, and does not
  prove registry authentication. `missing` or `unavailable` identifies the
  workstation helper problem that can prevent fixture creation. No Docker
  configuration is changed. Filesystem primitives are explicitly untested:
  the existing platform qualification remains their authority. An unexpected
  filesystem (production state expects ext4), or a different temporary mount,
  requires that platform check rather than treating a test failure as a pass.
  `controller_tmp_crosses_mount` compares actual Linux mount IDs: a separate
  temporary mount can invalidate archive-sandbox component fixtures even when
  both mounts report the same filesystem type. Use a temporary directory on
  the required mount for those focused tests; do not relax the sandbox check.

Collection binds to the container ID captured by that run. If it was not
captured, the host stopped/disappeared, or the output is malformed, fields say
`unknown` and collection is partial. An old directory never falls back to a
new container with the same name. Earlier runs without this binding cannot
retroactively acquire it through the read-only command. Ordinary reporter
failures print a fixed message and preserve the original command result.
Local Molecule currently destroys its fixture after a failed test. The outer
Ansible callback captures a bounded observation before that existing teardown.
If a fresh observation is unavailable, the report may include this snapshot,
explicitly labeled `captured-before-teardown` with its original timestamps and
the host's current unavailability. It cannot become fresh evidence by collecting
it again. The live Spaces wrapper continues to retain failed fixtures.
Individual commands have deadlines and a 64-KiB output cap; the host probe also
has its own 45-second alarm. Collection normally completes within 90 seconds.

This report grants **no cleanup authority**. Empty intents and no quarantine
are insufficient. Cleanup still requires fresh authoritative local accounting
and the existing independent operator storage proof; both are mandatory. The
runtime-key inventory above does not replace that independent proof, which the
report marks `not-collected`. Follow the M3.10 runbook for those checks. The
passing-report validator rejects this diagnostic format and partial runs.

## Reading the timing report

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
  It includes orchestration, metadata collection, and any failure snapshot
  taken before teardown. A missing child span can
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
