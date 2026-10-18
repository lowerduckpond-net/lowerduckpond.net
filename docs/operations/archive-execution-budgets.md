# Archive execution budget audit

This audit accompanies the correction to a five-minute worker runtime failure
observed during the full-size installed archive case on October 18, 2026, at
revision `d3118d87447589a83ad295c942c8e481c694f4fa`. It is a timing and enforcement
design, not a passing qualification receipt. Original private evidence remains
retained; this document contains only timing measurements and source behavior.

## Established failure and recovery

The worker journal explicitly recorded its runtime deadline and subsequent
15-second stop deadline. The operator reported `authorized job handoff failed`.
The old gateway discarded whether that immediate error came from its own
subprocess timeout, an OS error, or systemctl returning nonzero. The journal
independently proves the worker timeout; elapsed operator time alone does not.
The qualification exited with command status 2 after 6,580.603 seconds against
a 36,000-second wrapper limit. It did not exhaust that outer limit.

The archive had an immutable success result but still needed construction-intent
cleanup and final execution validation. Existing root reconciliation resumed
the **same durable job**, completed its remaining proof, removed its intent and
set `executionValidated=true`. That recovery does not change the failed
qualification into a pass. An earlier cleanup helper failed with the fixed
`local_connection` category; its exact exception was not retained. No OOM or
provider/network root cause is established by these observations.

## Measurements and comparison limits

The minimum operational allowance is 1.5 times the longest relevant completed
observed window. Existing larger safe allowances are retained. Failed, cancelled
and timed-out spans are incomplete lower bounds, never completed baselines.

| Observed window | Revision and sample | Longest seconds | 1.5× seconds | Limits on comparison |
| --- | --- | ---: | ---: | --- |
| Full-size archive operator call | `4a3b427`, one prior completed comparable call | 82.034 | 123.051 | Correlated by unchanged fixture sequence; not a separately tagged worker lifetime |
| Full-size restore operator call | `4a3b427`, one prior completed comparable call | 77.269 | 115.904 | Correlated by unchanged sequence; no current full-size restore after archive failure |
| Current short archive operator calls | `d3118d8`, 17 completed | 13.649 | 20.474 | Excludes the failed full-size call; cannot size full-size work |
| Export/import operator calls | `d3118d8`, 35 completed | 90.781 | 136.172 | Different operations; not a full-size archive-worker baseline |
| Full-size construction helper, Starting → successful deactivation | `d3118d8`, one completed | 176.939992 | 265.409988 | Includes startup/handshake, worker-preparation waiting and upload/proof; local ZIP construction happens in the worker |
| Recovery cleanup helper, Starting → successful deactivation | `d3118d8`, one completed | 193.663175 | 290.494763 | Completed recovery proof, not the failed first cleanup |
| Worker original Starting → recovered successful deactivation | `d3118d8`, one completed compound recovery | 642.949575 | 964.424363 | Includes interruption, reconciliation wait and overlapping helper activity; **not uninterrupted success** |
| Sum of worker invocation wall spans across failure and recovery | `d3118d8`, 315.323 + 196.357 | 511.680 | Not a sizing baseline | Includes startup/stop, excludes intervening wait, combines failure and success; diagnostic arithmetic only |
| Worker pre-exec startup | `d3118d8`, two Starting → Started observations | 0.206487 | 0.309731 | Existing 300-second allowance retained |
| Construction pre-exec startup | `d3118d8`, one | 0.129952 | 0.194928 | Existing 90-second allowance retained explicitly |
| Cleanup pre-exec startup | `d3118d8`, two | 0.149727 | 0.224591 | Existing 90-second allowance retained explicitly |
| Completed reconciliation pass | `d3118d8`, three in retained incident window | 30.840492 | 46.260738 | Other timed-out passes overlap held locks; exact wait site was not captured; incomplete |

The failed operator span was 302.626 seconds; the failed archive group was
1,671.023 seconds; the failed verification phase was 5,969.660 seconds. The
initial cleanup failed after 198.787 seconds. None supplies a successful-window
allowance. The earlier roughly 4-hour qualification failures likewise do not
establish complete qualification duration. Current measurements demonstrate
large variation; using only the earlier 82-second full-size call would omit the
slow observed provider-proof path.

## Clock boundaries and selected budgets

| Clock | Starts → stops | Previous → corrected | Basis |
| --- | --- | --- | --- |
| Worker coordination runtime | systemd successful exec → normal exit or runtime-stop initiation | 300 → **1,200 s** | Conservative provisional allowance above 964.425 s compound-recovery floor, with room for variability; a fresh uninterrupted full-size measurement is still required |
| Worker startup | systemd start job → successful exec | 300 → 300 s | Distinct Type=exec pre-exec clock; no reduction |
| Worker shutdown | stop request → forced kill if necessary | 15 → 15 s | Security/containment backstop; no completed cooperative-stop baseline justifies changing it |
| Local parser/construction work in worker | outermost local parser call entry → exit; cumulative over one executor invocation | within 300 s worker limit → **separate cumulative 300 s kernel timer** | Preserve the actual parser availability bound while excluding provider waiting; nested calls cannot renew it |
| Archive construction/export/cleanup service runtime | helper exec → normal exit or runtime-stop initiation | 300 → 300 s | Completed full-size helper observations fit the 1.5× floor; memory/CPU limits unchanged |
| Helper startup / shutdown | activation → exec / stop request → forced kill | inherited observed 90 / explicit 15 → **explicit 90 / 15 s** | Pin the installed default used by the enclosing socket calculation; do not increase it |
| Archive channel socket I/O | each blocking send/receive → completion or socket timeout | 300 → **420 s** | Connect to an already-listening activation socket does not prove the service has exec'd: 90 startup + 300 runtime + 15 stop + 15 response margin |
| Archive connector | Unix socket connect invocation → connected or failure | 30 → 30 s | Separate connection clock; no observed exhaustion; no new retries |
| Gateway result retrieval | entry to retrieve, before existing-result validation → durable result and lifecycle authority validated | 300 → **1,560 s** | 300 startup + 1,200 runtime + 15 stop + 45 final validation/report; includes lock observation |
| Client silent result wait | request input closed → first response header | 330 → **1,620 s** | Encloses gateway 1,560 s plus 60 s intake/handoff/header reserve |
| Asynchronous worker enqueue | systemctl invocation → command completion | 15 → 15 s | Does not wait for worker execution; one invocation, no automatic replay on uncertain response |
| Request/response transfer | transfer phase entry → completed bytes; separate progress deadline | 1,200 total / 30 idle → unchanged | Response header restores these bounds; SSH keepalives are not progress |
| Ordinary reconciler | oneshot start → completion; separate stop phase | 120 start / observed 90 stop → unchanged | Completed maximum 30.841 s fits; incomplete passes consistent with lock contention do not establish failed durable jobs |
| Emergency reconciler | oneshot start → completion / stop → kill | 300 / 15 s → unchanged | Containment/availability path; no comparable completed incident sample; no new retry or changed authority |
| Standalone archive sandbox policy | transient parser process runtime/start/stop | 300 / 300 / 15 s → unchanged | Inert policy constructor, not a production caller; preserving this constant alone would not preserve installed parser enforcement |
| Live qualification wrapper | launch of qualification child → reaped child | 36,000 s → unchanged | Current exit is incomplete observation; no completed live baseline supports reducing this conservative allowance |
| Enclosing attempt / report reserve | attempt work including startup and observation → terminal work/report | 39,600 / 40,080 s → unchanged | Keep existing room for evidence and cleanup; do not multiply every maximum into a new arbitrary ceiling |

The 1,200-second worker allowance is provisional for the whole operation; it
does not promise that every serial helper and parser phase can consume its
independent maximum. Restore first verifies the archived source, fetches it,
parses and publishes locally, then retires remote state and validates the
terminal result. Its prior completed full-size operator observation is included
above, but no uninterrupted slow-path restore observation exists for the new
revision. The next full qualification must supply that evidence as well.

The channel change is an enclosure correction, not evidence that its old deadline
caused this incident. Construction's ready handshake already excludes startup
from later requests; the common 420-second limit is conservative there. Helper
service runtime still bounds the entire exchange, and the outer worker bounds
serial exchanges. Provider SDK connect/read deadlines (10/30 seconds) and retry
policy remain unchanged. Polling cadence remains distinct from failure budgets.

Regular reconciliation can encounter locks held by the worker and use up its
120-second pass. The observed overlap is consistent with this source behavior;
no captured stack establishes the exact wait site. Its existing timer and fair bounded queue remain unchanged;
no timeout is interpreted as permission to replay provider mutations. The
automatic same-job recovery here is consistent with the durable acceptance
contract in [ADR 0020](../adr/0020-use-a-trusted-workstation-static-operator-interface.md).

## Enforcement and validation

The fixed executor must own the parser budget before repository opening and
handler construction. Seven shared public ZIP/bundle entry points cover inline
deployment, import, restore, archive, export and descriptor inspection. The
default terminating `SIGALRM` action cannot be caught by broad Python exception
handlers. Existing memory, CPU, entry/expansion limits, provider byte/identity
checks, witness requirements and credential semantics remain in force. No
system-call filter is relaxed: installed `@system-service` already includes
`@timer` and `@signal`, including `setitimer` and signal-mask queries.

Regression coverage must prove cumulative and nested accounting, no renewal
after exhaustion or ownership loss, main-thread/process ownership, signal/timer
conflict rejection, real kernel termination with a retained obligation, and
mandatory executor wiring. Fake-clock result/client tests cover a slow allowed
worker and unchanged transfer idle expiry. Handoff diagnostics retain fixed
phase/reason/type labels, attempt count, elapsed/budget seconds and numeric
errno/exit status without command arguments, output, credentials or URLs.
Wrapped exceptions remain diagnosable without publishing arbitrary messages.

Run focused tests, static checks and required installed CI for the exact head
before merge. Re-audit this table after material execution-path changes and
before another expensive live qualification. The next live attempt must use
verified installed artifacts and measure uninterrupted full-size work; neither
source tests nor recovered work are its passing receipt. Human approval waiting
is separate from operational proof freshness. No approval, external credential
expiry, retention deadline, witness guarantee or attempt allowance is renewed
by this audit. Recheck those genuine limits and cleanup reserve before launch;
report any conflict instead of silently shortening work or extending authority.
