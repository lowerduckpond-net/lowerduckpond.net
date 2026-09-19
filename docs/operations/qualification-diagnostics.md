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
The first failed test and its submission context are retained even if later
tests or teardown also fail. Later errors remain available in the private log.
The console names the operation separately from its observed outcome. Known
burst-limit and ordinary-deletion eligibility rejections receive fixed categories;
unrecognized transport errors stay generic without copying private messages.

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
- Controller prerequisite presence for `docker`, `git`, `rsync`, `ssh` and `uv`.
  Only fixed names and `present`/`missing`/`unknown` appear; paths and lookup
  errors are omitted. Presence does not prove version compatibility or usability.
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

## Owned local fixtures

`just check-ansible-m3-8` allocates a fresh local MinIO fixture for each run.
`just check-ansible-static` also allocates its own baseline host, image tag,
artifact, controller-source fixture, and Molecule state.
The timing directory also contains a private `fixture.json` identifying its
containers and Docker endpoint. Host and storage container names, host image
tag, assigned SSH port, artifact path, and Molecule state are distinct for each
run. The supported entry point does not reuse resources from ambient fixture
variables or a previous run. Nested Ansible reapplication uses the same owned
context throughout that run.

The complete local sequence retains its existing Molecule cleanup behavior.
Failure diagnostics bind to its concrete container ID and capture state before
that cleanup. Private fixture metadata is not included in CI diagnostic
artifacts. Live Spaces continues to use its serialized secure-workstation
workflow; local resource overrides cannot redirect it.

Separate resources do not provide additional machine capacity. In particular,
privileged Docker fixtures share the host kernel's loop-device pool. This
workspace's eight exposed loop-device nodes were insufficient to prepare two
complete fixtures simultaneously. Concurrent systemd fixtures also caused
disposable MinIO TLS startup to fail with `too many open files`; stopping the
unused second host allowed the unchanged service to start. Serialize systemd
fixtures on one daemon and use separate runners for parallel installed checks;
do not detach another run's devices or prune shared Docker resources.

After reboot, operator connections rediscover Docker's assigned SSH port while
requiring the recorded source and peer addresses to remain unchanged. The
reboot verifier also restores the captured disposable MinIO hostname mapping
that Docker removes from `/etc/hosts`. These test-fixture repairs do not reapply
the production configuration or accept a changed access boundary.

## Independent full-size archive

Use `just check-archive-full-size` after the normal `just setup` prerequisites.
It requires a local MinIO backend and a Docker daemon that supports the existing
privileged systemd/ext4 fixture. The operator SSH endpoint published by that
daemon must be reachable from the controller. Live Spaces inputs are excluded.

This command creates a fresh owned host, installs the current artifact, and
checks idempotence. It then creates, deploys, and suspends a 100-MiB/5,000-file
source through the supported operator interface. Archive and restore use the
installed services and unchanged production resource/admission limits. The
restored deployment must have a new identity and exactly the original filenames,
lengths, and content hashes. The case finishes with the restored active tenant,
as the complete archive journey does, then checks settled local accounting and
installed artifact integrity before fixture teardown. Ordinary archived-tenant
deletion remains covered by the complete archive journey.

The command prints each phase and the private run directory. It writes readable
per-phase logs there. A failed command, missing installed receipt, changed
container identity, or unavailable/nonempty independent storage inventory stops
without destroying the fixture. A passing case separately checks all versions,
delete markers, and multipart uploads in both owned MinIO buckets with the
fixture's root identity before teardown. Failure reports never grant teardown
authority. A new invocation always gets a new fixture and correlation IDs; it
does not resume an earlier job or replace a retained host's artifact.

`case.json` is a diagnostic result, not a full M3.10 qualification report. Its
format is rejected by the production qualification validator. Read `timing.json`
alongside it for source revision, artifact/image identity, and measured runtime.
The first CI runs establish the expected duration; the initial job limit is
45 minutes, with the plan's 30-minute installed-case target still to be measured.
The complete existing lifecycle journey remains required for the same selected
changes, and CI runs the independent case on a separate runner.

After diagnosing an unsuccessful independent archive case, use
`just retire-archive-fixture /absolute/path/to/the/run` to remove its owned
containers when their obligations are settled. This explicit command refuses an
active controller, changed container IDs, unvalidated jobs, pending state,
quarantine, archived tenants, or unknown/nonempty independent storage inventory.
It verifies the installed artifact against the run's retained artifact and
checks local accounting again after the storage observation. A failed setup
before installation instead requires empty local state and independently empty
storage. Existing failure reports are never cleanup authority.

The create attempt records owned container IDs even if only part of creation
succeeds. A failed create may retire just that recorded subset after fresh
proof of its empty pre-installation state; a container that never started has
not executed installation or accepted work. Unknown Docker inventory is not
treated as absence, and a successful create must record both containers.

Before removal, the command durably records a private transaction binding the
exact IDs, installed artifact when present, fresh accounting, and each
container's start identity. It force-removes the host, checks storage again,
then force-removes storage. It never restarts a service or resumes an operation.
If Docker or the controller fails during removal, repeat the same retirement
command. Running containers require fresh checks; stopped containers may only
continue the already authorized removal with the same recorded start identity.
Already removed IDs are not recreated. Changed IDs, a restarted stopped
container, or missing transaction evidence prevent this continuation.

Private evidence and the artifact remain in the run directory, with a diagnostic
`retirement.json` after successful removal. The private removal transaction
authorizes only this owned fixture's interrupted destruction; ordinary diagnostic
reports do not. The command cannot replace an artifact or apply to live Spaces
fixtures. If checks cannot establish quiescence, resolve the reported operation
through its existing recovery procedure before requesting retirement.

After successful destruction or retirement, the controller removes only the
run's `molecule_local/ldp-m3-…:ubuntu-2604` image tag. It requires both owned
containers to be absent and uses neither forced image deletion nor a daemon-wide
prune. Other runs' tags, shared layers, and downloaded base/MinIO images remain.
If image removal fails after Molecule has already destroyed the containers, retry
only that step with `uv run python -m scripts.qualification_retirement --image-only
/absolute/path/to/the/run`. This checks the original manifest and Docker endpoint,
refuses an active run or remaining containers, and does not reconstruct host
proofs or issue a retirement/qualification report. Ordinary retirement can also
retry image cleanup through its existing removal transaction. Failed tests keep
their original failure status if optional post-failure image cleanup is unavailable.

## Admission pacing

Installed tests read the fixture's immutable correlation history and host UTC
before each submission. A read-only probe imports the selected installed
artifact's admission function and finds the next legal timestamp using that
unchanged function. Waiting is bounded by the controller's monotonic clock and
rechecks the host after each sleep; unavailable or malformed observations fail.
The probe does not acquire repository transaction locks, issue requests, retry
rate denials, change timestamps, or rewrite records.
Issuance remains sequential within each fixture, including cases that run the
already admitted workers concurrently. Parallel cases use separate owned hosts.

Real operation time therefore contributes to the production policy's existing
refill. Starting another verification group no longer imposes a full five-token
refill. Exact retained correlations need no new admission credit, including
after a controller restart; the normal operator still validates request binding.
The `pacing` timing category includes the host observations and waiting together.

Each group also checks burst, rolling-hour, and backwards-clock denials against
the selected installed function with synthetic timestamps. These checks never
change the host clock or durable admission history. The complete installed
journey continues through the real production policy and authenticated operator.
Component tests compare predicted boundaries with that unchanged policy across
transport delays, variable operation duration, clock drift, rollback, exact
retry, invalid history, and a stalled host clock. No faster test policy is used.
Timing metadata identifies this harness strategy as
`production-admission-host-history-pacing-v1`; the production admission limits
are unchanged. Earlier reports labeled `conservative-host-clock` describe the
preceding pacing strategy and must not be relabeled as new measurements.
