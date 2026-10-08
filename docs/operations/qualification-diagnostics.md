# Qualification diagnostics

For the dedicated M3.11 controller, use `just m3-11-unattended status RUN_UUID`,
`evidence RUN_UUID`, or `cancel RUN_UUID`; see the
[setup and lifecycle](m3-11-backup-recovery.md#unattended-qualification-on-the-dedicated-docker-host).
Its private named volume survives controller replacement and retains the
deadline supervisor's context. Restart marks an unfinished attempt interrupted
and reconciles credentials, without replaying the journey. Qualification outcome
and credential-cleanup status are independent. Sanitized export never traverses
raw controller/production logs, fixture inputs or cleanup secret spools. Existing
failed-fixture retirement authority is unchanged.

Independent Connect cleanup retains an unresolved receipt with its fixed phase
and failure category. Where available, the origin contains only an allowlisted
pinned source path, a function name read from that source and a bounded line
number. Exception text, arguments, locals, arbitrary class/function/file names
and provider output are never exported. Missing diagnostics leave the outcome
unresolved. Receipts use a GitHub run/attempt artifact name; the private
`receipt-source.json` binds a successful readback to its exact job, artifact and
digest. Earlier failed attempts remain separate evidence, including legacy
artifacts that share a name.

`just check-ansible-m3-8` runs the existing full installed sequence and records
monotonic timing observations. Its private timing directory is printed before
the run, under `${XDG_DATA_HOME:-$HOME/.local/share}/lowerduckpond.net/qualification/`
by default. CI places it under the runner's temporary directory. Installed groups,
the complete journey, and the baseline acceptance scenario retain allowlisted
reports in `installed-diagnostics-CASE`, `complete-journey-diagnostics`, and
`baseline-diagnostics`, respectively, including on failure.
An artifact-upload problem does not replace the original qualification result.

Failed or cancelled installed-group CI jobs also print the last 2 MiB of each
existing create, prepare, converge, verify and destroy log in the job's
**Show failed synthetic fixture phase logs** step. This includes pytest
tracebacks and command stderr, rather than only the summary's failure category.
The step cannot change the original result, and log text is printed with GitHub
workflow-command interpretation disabled. Baseline and complete-journey output
already goes directly to their job consoles.

This policy applies to the CI job's synthetic tenant data and disposable local
MinIO credentials. That job receives no live Spaces or Cloudflare credentials;
the local entry point also rejects a Spaces backend and removes inherited live
provider inputs. The step reads only the named phase logs; it does not upload
fixture directories or key files. Normal GitHub log masking remains in effect,
but [automatic redaction is not guaranteed](https://docs.github.com/en/actions/reference/security/secure-use);
masking alone does not make live logs safe to publish. The live-workstation raw
logs remain private. Adding live credentials or data to this CI job requires
revisiting its output policy.

If cancellation kills the timing wrapper before it writes its summary, CI makes
one separate `timing-interrupted.json` observation before uploading diagnostics.
It retains the original source and fixture identities and validates the recorded
spans. Its elapsed time runs through diagnostic collection, its exit status is
unknown (`null`), and unfinished phase spans and any incomplete final append are omitted.
It cannot establish completion or success. Existing normal summaries and the first
interrupted observation are preserved; raw timing inputs are never rewritten.

The `ansible_tasks` section separately reports the 30 longest completed tasks and
up to 30 unfinished tasks, with total counts. Task starts are appended **before**
execution, so a killed playbook can still identify an unfinished image build,
package installation, or Caddy build. Source coordinates refer only to tracked checkout
Ansible YAML or the fixed Molecule Docker create/destroy playbooks; generated
private playbooks say `unknown`. Actions and groups use fixed allowlists. Task
names, host names, loop values, arguments, environment values, and result output
are never copied. APT's recognized numeric `apt_download_seconds` is retained
after a result, allowing comparison of download time with the entire task;
unrecognized, absent, or `no_log` output leaves it `null`.

Task intervals run from the callback's task start through its next task or final
playbook statistics, including orchestration and all hosts in the current linear
strategy. They overlap the existing phase categories and nested playbooks; do not
add them to wall time. `seconds_until_collection` for an unfinished task is an
observation window, **not** a completed duration or proof that it remained active
until collection. Missing ends can also reflect diagnostic write failure. The
private task journal is bounded at 8 MiB, excludes payloads, and is not uploaded.
Collection validates it again; unavailable or corrupt task diagnostics do not
suppress the phase report or change command status. Older artifacts cannot
retroactively acquire this detail.

`just m3-10-spaces-qualification` records the same diagnostics in its existing
private run directory on the secure workstation. `timing.json` and `timing.txt`
contain allowlisted diagnostic fields and may be shared. Keep raw logs and
intermediate files private. Production credentials remain on that workstation.
These commands retain the production admission policy, resource limits, full
lifecycle order, existing cleanup behavior, and original exit status.

`just m3-11-spaces-qualification` supervises that complete live journey with a
fixed 600-minute deadline, including wrapper setup; see the
[budget amendment](../plans/milestone-3.11.md#live-qualification-deadline-amendment).
Its controller runs in a separate process group. On expiry the supervisor sends
TERM, allows at most 30 seconds for its direct child, then sends SIGKILL to remaining
group members and waits at most another 30 seconds to reap that child. A kernel
I/O stall can prevent reaping even after SIGKILL. This is recorded as
`direct_child_reaped: false`, with a fixed warning; the already determined exit
status and subsequent diagnostic collection are preserved. Docker guests are
retained; stopping controller processes does not stop their guest services.
Collection runs in a separate process with a five-minute limit and the same
bounded termination/reaping policy.
It is read-only against the fixture and providers and cannot extend qualification.

Before collection, the supervisor writes `qualification-exit.json` with the
actual status, fixed reason (`command-exit`, `deadline-exceeded` or `interrupted`),
last entered wrapper phase, configured limit and monotonic supervised duration
including controller shutdown. This allowlisted diagnostic contains no command
arguments or credentials. Deadline expiry stays 124 and TERM/INT interruptions
stay 143/130 even if a child exits zero or reporting fails. Direct signal death
of the controller also records `interrupted` and status 128 plus the signal
number (137 for SIGKILL), so a truncated final timing append does not discard
the completed spans. An ordinary command that exits 137 remains `command-exit`.
The TERM/INT traps apply only to supervised M3.11; the default M3.10 wrapper
retains its original signal handling. The supervisor records the first TERM/INT
without raising from its signal handler. Cancellation during process creation
is handled once the child handle is available; the child inherits no additional
blocked signals. During execution, waits check cancellation at most one second
apart against the original monotonic deadline. Repeated signals cannot unwind
shutdown or replace an already determined result. If process creation fails,
a pending cancellation still returns 130/143; otherwise it returns 1 with a
fixed message, without copying exception payloads. Failure collection
also records `full-run-deadline` as the controller stage for expiry. The phase
is the last entered step, not a completion receipt. If the wrapper fails before
allocating a run directory, no per-run report is available.

The supervisor preserves existing timing/failure reports. On forced termination,
new timing collection accepts only completed event appends; incomplete final
writes and unfinished spans cannot establish completion. Its elapsed time ends
at immediate collection, whereas `qualification-exit.json` fixes the supervised
duration before collection begins. A later read-only observation cannot refresh
that exit measurement. Reporter failure may leave only the exit receipt; share
it with any available `failure.json`. These diagnostics never substitute for a
passing qualification envelope.

## Collecting a failure

An unsuccessful installed run writes `failure.json` beside its timing report
and prints a short summary. CI retains it in the diagnostic artifacts named
above and prints the synthetic fixture's phase logs on failure. The live wrapper
keeps raw logs private on the secure
workstation. Share the JSON report when reporting a failure; it contains no raw
exception, provider response, credential, bucket/key name, or tenant content.
The first failed test and its submission context are retained even if later
tests or teardown also fail. Later errors remain available in the phase log.
The separately recorded first Ansible failure can come from an intentional
rejection test inside a passing group. It is context, not necessarily the cause
of the run's failure; use the failed test location and its terminal traceback.
Restore and production-rollout command failures identify the calling fixture
step rather than the shared command wrapper; the JSON summary omits command
output, while synthetic CI phase logs retain it.
The console names the operation separately from its observed outcome. Known
burst-limit and ordinary-deletion eligibility rejections receive fixed categories;
unrecognized transport errors stay generic without copying private messages.
`operator_failure` adds a fixed reason label for recognized SSH failures, client
timeouts, host handoff/result-validation failures and exhausted lock contention.
It also records the operator client's function and line at the exception. These
fields distinguish a refused connection from a completed host operation whose
response could not be delivered; no peer addresses, request data or SSH stderr
are copied. Unknown messages remain `unknown`. Older reports without this detail
cannot establish which transport failure occurred, even if a later run passes.

For M3.11 live qualification, `public-input-capture` identifies the original
public trust/DNS capture between `create` and `prepare`. Inspect the retained
private `public-inputs.log` for that failure; a successful `create.log` only
establishes fixture creation. The scenario's explicit create sequence excludes
preparation because the capture requires an unprepared host. A failed capture
stops before preparation and retains the fixture without producing a passing
report.

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
- The bound job's current worker invocation ID, state, result, exit code/status, peak memory
  and CPU usage. Only the unit named by the validated durable job is queried;
  missing units or unsupported counters remain `unknown`. These observations
  distinguish resource termination from an ordinary worker exit without
  exposing command lines or journal text. They describe the current unit
  invocation, which may have changed since the failed submission; they do not
  establish a terminal operation result or authorize a retry.
- Current termination and resource counters for the three fixed archive
  services, independently of their exception records. An OOM kill or signal can
  prevent Python from recording an exception. These service observations are
  not bound to the submitted job and may describe an earlier or later request;
  missing units remain `unknown`. Invocation IDs permit comparison with
  captured helper exceptions; a never-started unit has no observed invocation.
- Current counts of intents, intake, exports, staging and Caddy intents;
  quarantine presence; and a whole-bucket inventory of versions/delete markers
  and multipart uploads using the fixture's installed archive credential.
  Provider failures leave inventory unknown, not zero. No object names leave
  the fixture. These observations are not one locked transaction.
- Recent fixed-label archive service diagnostics. These labels may come from
  deliberate failure injections elsewhere in the fixture; they are explicitly
  **not bound to the last submission** and do not establish the cause by
  themselves.
- Fresh fixtures also collect `archive_failures` independently from the source
  and restored destination. These private helper records do not depend on
  journald or on systemd retaining an exited invocation. They contain the helper,
  invocation ID, selected artifact directory digest, fixed failure classification,
  bounded exception types and
  file basenames/line numbers. A decoded durable job supplies its job/correlation
  IDs; errors before that point remain unbound. `matches_last_submission` is true
  only for an exact known correlation match, and identifies context rather than
  granting execution or cleanup authority. Other recorded failures can be
  deliberate injections and do not establish the cause of the current failure.
  `archive_failures_before_teardown` retains the separately timestamped first
  snapshot if local CI has already removed its containers.
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

The M3.8 source and reconstruction inventories enable native archive failure
capture before tests begin; production defaults leave it disabled. Each helper
retains its latest eight failures in a root-only `0600` file below
`/var/log/lowerduckpond-archive-failures` (`0700`). Each file and its fixed atomic
staging file are bounded at 64 KiB: at most 384 KiB across the three helpers.
Successful calls do not clear failures; cleanup cannot overwrite construction
evidence. Capture never formats messages, source lines, locals, request bodies,
credentials or provider identifiers. Storage failures leave diagnostics
unavailable and preserve the original helper result. Service limits, authority
checks and deadlines are unchanged. These records are outside backup state and
cannot substitute for qualification. A missing record cannot prove that no
failure occurred: older artifacts, failures before Python starts, forced kills
and exhausted resources may leave no capture.

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
has its own 45-second alarm. Collection normally completes within 90 seconds. Reconstruction cases also
observe the recorded source, destination and controlled ACME container IDs with
separate bounded read-only probes (at most 20 seconds each). Their optional
`reconstruction` section contains phase, gate presence and fixed service
state/result/exit-status fields for the coordinator, both archive helpers, Caddy
and Caddy recovery. Unloaded or unavailable units remain `unknown`. New restore
artifacts also emit a fixed verification-step marker on failure. The optional
`failed_step` field reads only that marker from the current failed coordinator
invocation; it never copies raw journal text or attributes an earlier invocation's
failure to a new attempt. Older artifacts or unavailable journals report
`unknown`. Each archive helper also reports an allowlisted `failure_category`
from its own failed invocation, provided it started during the current
coordinator attempt. Older helper failures are not attributed to a later
restore. The category excludes exception text and provider coordinates;
unavailable journals and other services report `unknown`.
A provider-fault test stops immediately when the coordinator fails
before provider observation and Caddy readiness, preserving the underlying
failure instead of waiting for a secondary DNS-observation timeout.
Live and complete-history reconstruction observe the existing 30-minute
coordinator ceiling plus 30 seconds for shutdown/reporting. Fresh independent
fixtures keep their shorter observation windows. This does not extend the
service deadline or the 600-minute live ceiling. The corresponding provider
observer allows installed-state verification to reach Caddy startup within that
bound; once Caddy is ready it allows at most
120 seconds for the provider denial. A failed test exits before clearing its
injected fault. A later coordinator timeout with Caddy active therefore does
not, by itself, establish why the earlier observer failed. Compare the original
failure snapshot with the fresh service state and retained timing evidence.
Missing or changed identities remain `unknown`;
no DNS records, keys, object coordinates or tenant bytes are included.
Both local and M3.11 live manifests select their original Docker endpoint and
saved container identities. Live observation revalidates the private manifest
without requiring provider credentials. The live combined test is attributed to
`combined-reconstruction` in timing and failure reports.

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
  operator calls, Ansible reapply, and reboot/readiness waits. The combined drill
  also records its mutation, protected rotation, reconstruction, and reboot/replay
  phases separately. Restore cases record source activation, history preparation,
  snapshot capture/destination bootstrap, restored-state verification, and
  historical replay/retirement.
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

## Setup timeout investigation for PR 192

The first attempt of [run 36897261018](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/36897261018)
at PR head `8a39adcc9be14270af29146fba1ca65295ec4e50` reached the
45-minute limits in audit protection and negative restore. Its checkout/timing
revision was the synthetic merge `e7b90dfc87347fc91fecd80cdebc83103df7e39e`.
Unchanged retries passed; they neither explain the failures nor establish a fix.

| Completed initial phase | Audit failure | Audit retry | Negative restore failure | Negative restore retry |
| --- | ---: | ---: | ---: | ---: |
| Create | 1,242.03 s | 45.57 s | 645.52 s | 55.10 s |
| Prepare | 37.86 s | 34.71 s | 186.53 s | 37.93 s |
| Converge | Unfinished | 380.94 s | 859.94 s | 313.94 s |

The failed negative-restore artifact also contains **completed** source activation
(460.39 s), source history (38.89 s), and source capture/destination bootstrap
(397.66 s) spans. It does not support saying cancellation occurred inside those
preparation phases. The exact remaining operation is unavailable. Both failed
jobs had four reported CPUs; cache state and package download time were unmeasured.

At the next head, `aa3913fd7953b176e564b7d5b44ba313cf1a02aa`, the
[baseline Ansible job](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/36911546475/job/110535140035)
hit its separate 30-minute ceiling. Its public console records
`podman : Install rootless Podman prerequisites` from 19:07:51.070 to
19:28:16.699 UTC on 2026-10-01: **1,225.63 seconds**. The pinned Caddy build
took about 75.62 seconds. Package installation completed, but consumed most of
the job before its idempotence pass. The console lacks APT's download/install
breakdown. This establishes a slow package-install task in the shared roles;
it does not prove a mirror, network, cache, lock, or runner cause, or explain the
earlier two jobs retrospectively.

Passing artifacts from that same current-head run still show large setup
variation: core creation took 430.88 seconds, reboot-journey creation 541.61
seconds, and audit-rotation convergence 1,108.61 seconds. Audit protection and
negative restore completed their timed entry points in 1,031.62 and 1,887.77
seconds respectively. These passing executions do not resolve the baseline
timeout or the original failures. Entry-point durations exclude queue and initial
CI tool setup, and overlapping categories must not be summed.

The run finished on attempt 1 with all 24 installed groups passing, but its
overall GitHub conclusion is `cancelled`; the final `Ansible` and `Gate` checks
failed because of the baseline timeout. The last production-rollout artifact
records **1,255.79 seconds creating its fixture**, despite eventually passing
in 4,193.85 entry-point seconds. This repeats the roughly 20-minute creation
pattern seen in the original failed audit job; the missing task detail still
prevents attributing the delay to a specific Docker or APT operation. Combined
reconstruction finished in 3,123.78 entry-point seconds. No jobs were rerun.

Targeted local probes on 2026-10-01 did not reproduce the slowdown. Uncached RUN
layers of the M3.8 Dockerfile took about 48 seconds with an already available
Ubuntu base image; APT installation was 32.4 seconds. Building the same pinned
Caddy with empty Go caches took 34.14 seconds. Installing the six Podman
prerequisites, including an index refresh, took 38.37 seconds. These used a
different development host and Docker BuildKit for the image probe, whereas
Molecule uses the Docker API builder. They are setup observations, not passing
qualification, runner equivalence, or evidence that an intermittent failure is
resolved. No live provider was used.

One local baseline acceptance run exercised the new recorder through creation,
preparation, convergence, idempotence, 45 passing acceptance tests, and teardown.
Its entry point in the dirty development checkout took 915.31 seconds; the task report
retained 820 completed tasks with no unfinished tasks. Podman prerequisites took
17.62 seconds, including APT's reported three-second download. This validates
the diagnostic path and ordinary fixture cleanup, not a correction to the CI
package-install slowdown.

The task recorder and baseline artifact retention correct the missing diagnostic
evidence. They are **not a validated performance fix**. The package-install
slowdown's underlying cause remains unproved. Preserve failures; do not rerun
unchanged jobs to relabel them green. The execution-window correction below
addresses the demonstrated budget shortfall without claiming that setup became
faster.

### Setup-budget correction

The operator authorized extending execution windows if necessary on 2026-10-01.
Only the three jobs with demonstrated insufficient windows change:

| Job | Previous ceiling | Corrected ceiling | Evidence supporting the increase |
| --- | ---: | ---: | --- |
| Baseline Ansible | 30 min | 45 min | The preceding completed CI job took 20.45 min, already requiring 30.68 min under the 1.5-times runtime-margin policy. Substituting the observed 1,225.63-second Podman task for its 12.27-second task gives a 40.67-minute planning estimate. |
| Negative restore | 45 min | 60 min | The current completed entry point took 31.46 min, requiring at least 47.19 min before CI setup under the same policy. Combining the failed attempt's completed 28.20-minute initial setup with the retry's remaining 22.04 minutes gives a 50.24-minute planning estimate. |
| Audit protection | 45 min | 75 min | Cancellation found initial convergence unfinished at 44.76 entry-point minutes. The completed retry still needed 13.75 minutes for idempotence, verification and destruction after convergence. Even immediate convergence completion would imply about 58.51 minutes before remaining controller/CI overhead; 60 minutes would leave less than 1.5 minutes for the unfinished work and overhead. |

The baseline comparison is the completed
[CI job 110521007724](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/36897261018/job/110521007724)
(17:09:10–17:29:37 UTC). Its first Podman task took 12.27 seconds, and its
idempotence, verification and final destruction completed. The 40.67-, 50.24-
and 58.51-minute figures are **planning estimates assembled from measured
segments**, not completed slow-run measurements or guaranteed upper bounds.
They use sequential outer phases only, never overlapping nested categories.
The audit estimate is particularly uncertain because cancellation censored the
remaining convergence duration; its 75-minute ceiling leaves approximately
16.5 minutes above that estimate.

These changes let the existing assertions and cleanup run beyond the known
shortfalls. They neither retry failed jobs nor convert the recorded failures to
passes. Required completion receipts and the `Ansible` gate still reject missing
or unsuccessful work. Validate the workflow expression and required-result
checks locally; the next changed-revision CI run must establish its own result.

The secure workstation uses the M3.8 image and the same package/Caddy roles for
the source and reconstruction setup, so it shares this exposure. Its complete
Spaces journey has a separate 600-minute deadline, including setup; neither a
45-minute CI cancellation nor a passing retry predicts that complete duration.
The separate 600-minute window already exceeds 1.5 times the measured
311.79-minute workstation attempt (467.69 minutes); that attempt reached final
teardown before its inventory failure. There is no measured need to extend it.
The three CI ceilings above change; production service deadlines, assertions,
the 330-minute complete CI window and the 600-minute live-run budget remain.
The main-based 18,707.6-second workstation attempt failed final backup teardown
at the former 1,024-entry bound. That established cleanup defect and PR 192's
inventory correction are separate from these setup delays.

### Fixture archive transport

On 2026-10-07, the second attempt of
[PR 226's CI run](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/37671079661)
again reached the existing 600-second destination-convergence limit in
`failed-retirement` and `restore-reconstruction`. Their retained task summaries
show unfinished monitoring and baseline APT installation respectively. The
combined-reconstruction retry also exhausted that limit during backup
templating. The
preceding successful main run completed failed-retirement's destination
convergence in 297.29 seconds. The timeout identifies unfinished work; it does
not establish the cause of the hosted runner's delay.

An isolated local reproduction on the dedicated Docker host also observed an
APT HTTP connection retransmitting its request without receiving a response.
Read-only probes to `archive.ubuntu.com` and `security.ubuntu.com`, using the
same two peer addresses for each transport, produced four HTTP timeouts and
four HTTPS 200 responses in 1.63–2.22 seconds with certificate verification
enabled. These small probes establish a local transport difference, not a
complete package-install benchmark or a diagnosis of every earlier CI failure.

The baseline and M3.8 fixture images now bootstrap `ca-certificates` through
the existing signed APT path, then use HTTPS for those same Ubuntu archives.
APT signing keys, suites, package checks and qualification deadlines remain
unchanged. The initial index and CA bootstrap still use HTTP and can still be
delayed. Required installed CI and live qualification must establish their own
results with the corrected images.

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

Independent local fixtures can run concurrently when the shared host has enough
capacity. Privileged Docker fixtures share the kernel's loop-device pool, and
their systemd and MinIO processes consume per-user inotify instances. These are
separate resources: raising `fs.inotify.max_user_instances` does not expose more
loop-device nodes.

Check both the kernel's available loop devices and the nodes exposed in the
Docker daemon's `/dev`. A nested daemon can expose too few nodes even when the
kernel supports additional devices. Provision missing nodes in that daemon's
device namespace before creating fixtures, and preserve that setup when the
daemon container is recreated. Check the effective inotify limit inside the
fixtures; `too many open files` needs diagnosis before changing a limit.
Serialize runs only while capacity is insufficient, or use separate runners.
Never detach another run's devices or prune shared Docker resources.

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
CI runs each selected independent case on its own runner under the
[reviewed selection policy](installed-selection.md). The complete journey remains
mandatory for scheduled/manual qualification.

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

A successful probe does not reserve admission. If the issuer explicitly rejects
the request because its rate window changed after the probe, the harness reads
the host again, waits, and retries the identical request and correlation. This
allows at most three issuance attempts within the original 600-second monotonic
pacing budget. Other failures still stop the test. The production issuer remains
the authority for every attempt; no request timestamp or rate limit is changed.

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

## Continue a failed M3.11 reconstruction

For branch-based diagnosis beyond the first failed assertion, use the
[retained-run debugger](m3-11-debugging.md). It reuses the owned disposable hosts,
records all reachable downstream failures and supports captured branch repair
scripts. Its results are permanently diagnostic; this read-only failure collector
and the final fresh qualification keep their existing authority.

After debugging every failed M3.11 attempt, perform the
[required local and DigitalOcean closeout](m3-11-debugging.md#required-closeout-after-debugging).
Retain its resources only while investigation remains useful. Cleanup is part of
finishing the failed run, even if some diagnostic checks remain unsuccessful.
