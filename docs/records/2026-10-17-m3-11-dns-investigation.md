# M3.11 DNS-read failure investigation and timing audit

This is an investigation record, not a qualification or cleanup receipt. The
failed live attempt used source `14618cd409f63c2b1ad924527f96de72f726b609` and
artifact `4feb9c45b59380bcd1ea98fa8fa61232003cc6418f9901042aac1a5023e71970`.
Its original private records remain authoritative and unchanged.

## Established evidence and limits

The supervisor recorded exit 2 after 14,925.68 seconds (248.76 minutes), in
verification, without exhausting the 36,000-second deadline. Installation,
idempotence, the installed lifecycle, local reconstruction and reboot receipts
precede the failure. The combined public-CA phase started at 12:50:02 UTC on
October 17. Its DNS witness recorded four complete observations: empty baseline,
two challenges in each zone, two remaining in one zone, then both zones empty
at 12:50:29.926594 UTC. The next, separately required cleanup observation failed
in `CloudflareClient` with “network or TLS request failed”.

Those observations establish asynchronous challenge removal during cancellation.
They do not establish the failed fresh cleanup proof, completed cold recovery,
final accounting or qualification. There is no functional-completion checkpoint
or passing envelope; same-run finalization cannot repair this functional failure.

The handler discarded the original exception. No HTTP status, cause, request
duration or response body survived for the failed GET. Timeout, name resolution,
TLS and connection failures remain hypotheses. The preceding successful reads
do not establish a transient cause. Four complete paired reads took
0.419098, 0.385370, 0.313150 and 0.314434 seconds. They are a small, correlated
sample, not measurements of individual requests or normal slow-tail behavior.

Seven credential obligations originally retained the October 31, 08:32:53 UTC
deadline under approved failure retention. The policy has a 14-day child lifetime,
seven-day cleanup-authority reserve and October 20, 00:00 UTC start/issuance
cutoff. Zero overdue obligations is compatible with pending cleanup and unresolved
closure. After the infrastructure reboot, the original controller restarted at
23:24:08 UTC. At 23:24:12 it persisted `close-finish` before encountering the busy
cleanup lock. The first post-reboot watchdog cycle completed at 23:39:16 UTC with
unresolved cleanup: all seven removal facts existed, but the receipt established
complete revocation evidence for only one child. Later `close-cancel` and
negative-authentication facts are retained separately. These original close facts
make the lease permanently ineligible for reuse; they must never be removed or
rewritten to obtain a retry. Complete cleanup still requires both paths' fresh,
validated receipts, and a failed qualification still has unresolved closure.

The worker's restart lost its in-memory lifecycle/start flag and the delivery
file already deleted by successful failure retention. Its terminal handler
therefore requested closure despite the durable failed-run evidence. A regression
using a new Worker instance, absent delivery file and occupied cleanup lock
reproduced this failure. The correction reconstructs the original lifecycle and
requires exact attempt/start/host-drain bindings, the validated failed result,
issuer-stop proof, retention policy, original validity and no cancellation or
local/external close. It does not issue credentials, replay qualification, release
runtime ownership, or promote an unresolved cleanup status. Explicit cancellation,
expiry and existing close requests continue to require cleanup. If original local
proof is valid but the inventory reader is unavailable, cleanup stays unresolved
without publishing a new close. Later periodic checks use the same decision and
recheck cancellation/expiry after a remote read. A successful later read alone
cannot promote unresolved cleanup to pending.

## Investigation and correction plan

1. Preserve the original run, pending publications, retained credentials and
   both cleanup paths. Verify their actual receipts after infrastructure changes.
2. Preserve bounded, allowlisted transport exception types and relationships,
   numeric error codes, request stage, monotonic elapsed time, attempt count and
   safe response metadata. Never print original exception messages, arguments,
   URLs, queries, headers or response bodies. Bind DNS failures to the witness
   phase and sequence without writing a successful observation.
3. Retain single-request behavior and failed-witness poisoning. The evidence does
   not select a safe retryable cause. Test that transport, authorization, TLS,
   malformed responses and incomplete observations cannot be retried into a pass.
   A future retry policy needs its own evidence, narrow transport classification,
   failed-request history and propagation of the original coordinator deadline.
4. Preserve approved retention across controller restart using durable evidence,
   with negative tests for cancellation, expiry, close facts and invalid proofs.
5. Validate with synthetic failures, independent review and required CI. A fresh
   authorized attempt would exercise the corrected diagnostic path and the full
   unchanged proof, either producing a genuine pass or actionable causal evidence.

## Operational clocks and retained budgets

The required floor is 1.5 times the longest relevant recent completed window;
it never permits lowering an existing safe budget. Failed, cancelled or timed-out
observations are lower bounds for unfinished work. Nested spans are not summed
into an outer elapsed duration. No acceptance, performance, credential-expiry or
security requirement is relaxed by this audit.

| Budget / clock boundary | Supporting observations | Current → proposed | Basis and limitation |
| --- | --- | --- | --- |
| Live supervisor: wrapper process creation through exit, including wrapper setup and installed work | Latest `14618cd`: 248.76 min, failed; earlier `f3375f4b`: 330 min, timed out. **0 completed full live samples** | 600 → 600 min | Keep the accepted provisional 400-minute complete-window estimate and 1.5× margin. Neither failure is a completed baseline. Fresh completion must re-audit this estimate. |
| Controller launch invocation: admission/delivery/start call through return | Latest 48.80 s; preceding corrected-runtime attempt 47 s; 2 completed invocations | 900 → 900 s | Existing safe budget exceeds 1.5×48.80 s. This clock does not cover detached qualification. |
| Detached attempt: worker construction / durable attempt start through functional completion; watchdog uses persisted start time | Latest completed startup about 20m48s plus provisional 400-min complete wrapper estimate; **0 completed full attempts** | **600 → 660 min** | The former 600-min outer deadline included startup and could truncate the nested 600-min wrapper. The provisional combined window is about 420.8 min; 1.5× is 631.2 min. Keep the wrapper at 600 min and give the enclosing attempt 60 min for startup. This is conservative provisional coverage, not a new measured completion or authority to launch. |
| Launch to qualification wrapper start | Latest 08:21:04.969 to approximately 08:41:53 UTC, about 20m48s; 1 completed startup | Included in the outer attempt; 60 min allowance | Includes manifest publication, journal reads, independent confirmation, issuance and production checks. It is outside the nested wrapper clock but inside both worker and watchdog clocks. No separate startup deadline is added. Do not confuse it with the 48.8-second launch call or observer waiting. |
| Public recovery: construction of `PublicRecovery` through ordered recovery completion | Latest phase failed after about 34 s; 0 current completed phases. Historical diagnostic 365.4 s, 1 differently initialized sample | 1,800 → 1,800 s | Preserve the original coordinator/security deadline. Historical diagnostic is supporting context, not a fresh full-run baseline. Current DNS calls lack an absolute propagated coordinator deadline; adding retries would require fixing that first. |
| Cloudflare GET: blocking transport calls | 4 completed paired-zone observations, longest 0.419098 s; no individual request timings or slow-tail samples | 15 → 15 s | This is a socket/blocking timeout, **not an end-to-end wall deadline**. DNS resolution, redirects and repeated body reads may exceed it. Preserve the provisional value and collect request elapsed time; no retries/backoff are added. |
| DNS polling cadence: between completed samples while waiting for a state change | Latest cancellation needed an additional sample after 5 s | 5 → 5 s cadence | Cadence is not a failure deadline. Empty activity does not substitute for the fresh cleanup assertion. |
| Post-deadline diagnostics: reporter process creation through exit | No representative completed timeout-report sample collected in this audit | 300 → 300 s | Conservative existing reserve, outside qualification. It cannot continue functional work. |
| Termination/reap: TERM to child exit, then KILL to reaping | No representative new completed sample | 30 + 30 → 30 + 30 s per supervised process | Applies separately to controller and reporter. Worst wrapper supervisor envelope is 607 min. The detached attempt envelope is 660 min + 420 s monitor/report allowance + 30 s final reap, rounded up to an operational 668 min for polling/scheduling overhead; do not multiply nested limits. |
| Temporary-token admission: fresh check until actual original expiry | Existing two-hour reserve; new outer attempt budget | **12 → 13 hours minimum remaining** | 660-minute outer attempt plus the unchanged two-hour reserve. The reserve covers reporting/shutdown and cleanup, not additional functional runtime. No expiry, maximum lifetime or cleanup-authority reserve is extended. New credentials and one new attempt require exact approval. |

Completed nested phase spans on `14618cd` were 1,028.41 s backup/mutation,
572.17 s protected rotation, 1,986.32 s reconstruction and 2,240.04 s reboot.
Each has one current completed sample. Earlier `f3375f4b` completed corresponding
backup, rotation and reconstruction spans of 1,289.4, 626.4 and 2,585.4 s; the
historical fresh-replay diagnostic reached 2,789.9 s. These slower observations
remain relevant to the conservative outer estimate. The phases are ordered
inside the full supervisor; their observations do not create new independent
timeouts or justify summing maxima with the already enclosing 600-minute budget.

Observation at 20:34 UTC occurred hours after actual exit at about 12:50 UTC.
That delay is observer wall time, not execution time. CPU/active-work time is
not available for the entire attempt; instrumented category unions overlap and
must not be reported as CPU time.

## Cleanup and admission observations

The retained host logs contain 20 ready sweeps at `14618cd`, ranging from
699.67 to 793.48 seconds between the receipt's `observed_at` at `sweep_leases`
entry and its completed log emission. This excludes any preceding publication
preparation and sleep between cycles. Their 1.5× floor is 1,190.22 seconds.
The post-reboot unresolved sweep lasted 919.75 seconds; it is an incomplete
cleanup observation, not a successful cleanup baseline. A new deployment's
first-receipt observation window should be at least 30 minutes, conservatively
including startup/publication overhead; retain any longer existing observation
budget. In particular, the prior 90-minute launch-observation window is unchanged.
Exhausting that observation window
blocks launch readiness; it does not prove cleanup failed or stop the cleanup
actor. Host sweeps have no separate full-cycle failure deadline. The unchanged
60-second local poll, 300-second initial retry and 3,600-second healthy remote
cadence are scheduling intervals, not operation timeout budgets.

Independent cleanup runs 39051896022, 39061561654 and 39074075501 at `14618cd`
completed their actual `connect` jobs in 208, 302 and 295 seconds. The job clock
includes runner/tool setup, reconciliation and artifact upload, but excludes
queue delay. Its 30-minute timeout remains well above the 453-second floor.
The other backend's 14-minute job was unselected and is not measured by its
3–5-second no-op executions. Cache and host differences explain why independent
job durations cannot replace host sweep observations.

The production-check subprocess retains 25 minutes; the latest original
production receipt covers 25.11 seconds (one completed provider-check sample),
which excludes process/dependency setup. The 30-second Connect process timeout
and shared 30-second publication-visibility allowance remain unchanged: the
available run evidence does not isolate representative completed per-request
slow-tail timings. Visibility retries only observe the original publication;
an uncertain mutation is never reposted. Readiness after the reboot and helper
handoff must be freshly established before any authorized attempt.

## CI timing audit

The three most recent successful main runs inspected were
[38997452745](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/38997452745)
at `14618cd`,
[38907281218](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/38907281218)
at `63812db`, and
[38665809390](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/38665809390)
at `746aeb2d`. Each row below has three completed job samples, including the slowest.
The clock is GitHub job `started_at` through `completed_at`: runner/tool setup,
all steps, local retries and artifact upload are included; pre-start queue time
and dependency waits are excluded. These are wall times, not active-test timings.
The workflows took 64m10s, 81m31s and 63m52s end to end, respectively; that includes
queue/dependency waits and is not bounded by any one job timeout.

The diagnostic change adds no sleeps, retries or dependencies. Restart retention
adds original-evidence validation, and the outer-budget correction changes only
limits and admission reserve. These recent installed CI jobs remain comparable; the
next CI result must still be checked for new variability. CI's synthetic MinIO
groups are not substitutes for live Spaces timing.

| Job | Completed range (s) | Longest × 1.5 (s) | Current → proposed (min) |
| --- | --- | --- | --- |
| Python | 506–662 | 993 | **15 → 20** |
| Python recovery | 112–128 | 192 | 15 → 15 |
| Ansible static | 798–961 | 1,441.5 | 45 → 45 |
| Installed backup-coherence | 1,605–1,898 | 2,847 | **45 → 60** |
| Installed restore-reconstruction | 2,131–2,462 | 3,693 | **60 → 75** |
| Installed combined-reconstruction | 3,050–3,157 | 4,735.5 | 90 → 90 |
| Installed production-rollout | 2,165–3,059 | 4,588.5 | 90 → 90 |
| Installed failed-retirement | 1,731–1,810 | 2,715 | 90 → 90 |
| Installed audit-protection | 1,286–1,306 | 1,959 | 75 → 75 |
| Installed core | 1,694–1,891 | 2,836.5 | 60 → 60 |
| Installed archive-cycles | 1,619–1,997 | 2,995.5 | 60 → 60 |
| Installed backup-mutation-overlap | 2,011–2,061 | 3,091.5 | 60 → 60 |
| Installed restore-tls-bootstrap | 1,914–2,302 | 3,453 | 60 → 60 |
| Installed restore-negative | 1,333–1,686 | 2,529 | 60 → 60 |
| Other installed groups (each 3 samples) | Largest maximum 1,610, overlap-deployment | ≤2,415 | 45 → 45 |

The unchanged other installed job maxima in seconds are: transport-recovery
1,360; reboot-journey 1,361; overlap-deployment 1,610; deletion-quarantine 1,381;
full-size-archive 1,019; backup-identity 1,052; audit-rotation 1,469;
export-roundtrip 1,380; overlap-routing 1,487; credentials 1,402;
export-recovery 1,583; configuration-generation 1,513;
configuration-publication 1,542. Each retains 45 minutes, exceeding its 1.5× floor.
The complete scheduled MinIO journey retains 330 minutes; it is a different
execution path and none of these push jobs supplies a new completed baseline.

The three increases correct measured margin deficits in successful runs; they
do not conceal a failed test. All other inspected short CI jobs had at least
1.5× margin. No production service deadline is changed.

## Launch gate after the reboot finding

The next bounded proposal must include new seven-role issuance, because the old
lease is closing; the previous one-attempt approval has been consumed. The exact
merged revision, unchanged installed artifact, both cleanup handoffs, original
fixture preservation and quiescence, 668-minute maximum attempt/report envelope,
13-hour admission reserve, cost bounds and one-attempt stop conditions must be
reviewable before approval. Any unresolved publication, cleanup readiness,
ownership or credential-validity conflict prevents launch. The infrastructure
reboot is a cold-start change; current provisional budgets require fresh timing
evidence before being treated as established baselines.
