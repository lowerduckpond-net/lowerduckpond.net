# Debug a retained M3.11 reconstruction

Use `just m3-11-debug` to continue a failed live reconstruction on its existing
disposable Docker source, destination and controlled-CA containers. It does not
rerun create/prepare/converge or the preceding lifecycle groups. The destination
can be changed for diagnosis; the original fenced source, selected artifact,
backup prefix and original failed reports remain retained during investigation.
Every failed run must be closed out locally and in DigitalOcean after debugging
is finished, including runs whose remaining failures cannot usefully be explored.

This command runs on the secure workstation in the existing private production
environment shell. It reads current storage credentials from the encrypted
OpenTofu state, checks the saved local Docker endpoint and container identities,
and takes the same archive-target lease as qualification and retirement.
`--exclusive-archive-writers` acknowledges that no other workstation or operator
is writing the shared archive target; the local lease cannot enforce that across
machines. No image build or registry credential-helper invocation is needed.

## Start with the retained failure

Start from merged `main` in the secure-workstation repository, preserving any
local changes. Use a fix branch when iterating on a newly identified problem.

```bash
cd /home/tturner/dev/lowerduckpond.net
git fetch origin
git switch main
git merge --ff-only origin/main
just m3-11-debug \
  /home/tturner/.local/share/lowerduckpond.net/m3-11/spaces-d0ec709.cYloMO \
  --exclusive-archive-writers
```

The command first marks the original run and its private working copy as
diagnostic. Original records and copied inputs are checked by hash before each
stage. Reports from either directory are rejected by qualification packaging.
The original report remains failed even when all subsequent diagnostic actions
succeed. No timestamps, original phase receipts or pytest completion are renewed.

Each invocation creates `diagnostics/workspace/attempts/<attempt-id>/` under the
retained run. It captures the checked-out revision, helper hashes, private diff,
service journals and current observations.

Checkout provenance accepts ordinary group-writable source files (mode `0664`)
and empty Python package markers. It hashes their bytes without changing their
permissions. Retained evidence keeps its stricter ownership and permission
checks; an optional repair script is captured as a private mode-`0600` copy and
checked by hash before execution. Repair scripts must be nonempty and fit the
private-input byte bound. Source capture still refuses redirected, hard-linked,
world-writable, oversized or concurrently changing files.

The controller then attempts these stages:

| Stage | Action |
| --- | --- |
| `restore` | Stop the timed-out coordinator, clear the controlled fixture's injected DNS fault, restart the same restore transaction and observe real completion under its unchanged service deadline. |
| `reconstruction` | Run the installed reconstruction assertions against the original source history and snapshot. |
| `reboot` | Restart the destination container, restart recovery and compare the completed journal. |
| `replay` | Replay historical authority and archive/delete fixture tenants through the normal installed operator interface; require real paired accounting. |
| `public-ca` | Exercise public issuance, gate checks, interruption/reboot where observable, challenge absence and native Caddy reactivation using the run's existing private disposable names. |
| `accounting` | Check the retained source inputs, destination obligations, protected history and independent whole-archive absence. |
| `teardown-check` | Check storage/DNS absence, paired ownership, image presence and original backup-prefix ownership without deleting the debugging fixture. |

A failed assertion is recorded and independent stages continue. Failed restore
completion blocks work requiring a completed destination. A changed resource
binding or timed-out action stops mutation: a timed-out `docker exec` could leave
guest work alive, so overlapping another stage would obscure the failure.
Every stage has a controller limit; none increases a production service limit.
The replay limit is 90 minutes, ordinary restore/public stages are bounded by
1,900 seconds, and accounting/teardown checks by ten minutes.

The final `summary.json` contains stage outcomes, elapsed time, fixed exception
types/locations and coverage gaps. Failed stages also include the bounded
destination observation and any invocation-bound diagnostic restore trace.
When archive tracing is installed, it also includes invocation-bound exception
types and code locations from the direct helper logs, without exception messages.
It is shareable. Raw stage logs, journals,
scripts, diffs, source history, DNS observations and all other files remain
private. Setup failures also emit a private `debug-setup-*.log` path, so a failure
before the first stage still has a traceback. Journal collection omissions are
recorded separately and do not hide the stage's result.

## Iterate on the branch

After updating the branch, repeat the command. By default it begins at the first
stage without a passing diagnostic observation, and re-executes later stages.
Earlier successes are scheduling hints only; actions recheck their live
prerequisites. A finished stage replaces its previous scheduling hint before
post-stage checks or diagnostic collection, so a failed rerun remains eligible
for the next default invocation even if a follow-up check fails.
Use `--from restore`, `--from public-ca`, or another stage from the
table when a fix requires an earlier/later starting point. Original logs are
never overwritten. Partial tenant retirement is handled by skipping tenants
already absent only in this explicitly marked diagnostic mode.

On a newly adopted failed run, an explicit later starting point first runs the
`restore` completion prerequisite if no passing diagnostic observation exists.
A failed prerequisite blocks dependent stages. Earlier checks without a saved
pass are reported as `not-run`, not as reused successes. Such a targeted attempt
remains `diagnostic-incomplete` even if all requested downstream stages pass.

For a targeted hypothesis or runtime repair, add a Python script to the branch
and use:

```bash
just m3-11-debug /absolute/path/to/failed-run \
  --exclusive-archive-writers --from restore \
  --repair scripts/the-specific-diagnostic-repair.py
```

The script must be tracked inside the checked-out repository. The controller
copies and hashes its exact bytes before execution, then runs it as root inside
the originally bound **destination** with the selected installed artifact on
Python's import path. It receives no controller environment or credentials.
Its output and exception stay in the private attempt log. The script has a
270-second guest deadline plus termination allowance; a failed repair stops the
cycle. This is an explicit branch development facility: it may probe or change
the disposable destination. It is never called by qualification or production
commands. Put the actual fixes and regressions into the branch as they are
identified; a repair script is not evidence that a fresh install contains them.

### Capture an archive failure when the journal is empty

For a completed reconstruction that failed during archive replay, use:

```bash
just m3-11-debug /absolute/path/to/failed-run \
  --exclusive-archive-writers --from replay \
  --repair scripts/m3_11_debug_archive_repair.py
```

Fresh qualification fixtures now enable bounded native archive failure capture
automatically on both hosts. Their ordinary failure report includes these
records even if the journal is empty; see
[qualification diagnostics](qualification-diagnostics.md). The repair below
remains necessary for older retained artifacts that lack native capture. Neither
mechanism establishes the cause of an earlier failure whose evidence was lost.

The repair requires a Docker destination with completed restore and inactive
workers, restore coordinator and archive helpers. It preserves each native
launcher and its selection lock in an instrumented diagnostic copy, then adds
instance-specific systemd overrides pointing to those copies. Native launchers,
selected artifact, service limits and archive decisions remain unchanged. Each
failure records its exception chain's types and code locations without messages,
arguments, locals or source lines. Startup failures also retain stderr privately.

The copies and original bytes live under
`/usr/local/libexec/lowerduckpond/archive-diagnostic-<restore-id>/`; direct logs
live under the root-only `/var/log/lowerduckpond-debug-archive/`. Neither location
is inside authoritative state or recovery evidence. Repeating the repair checks
the original and installed diagnostic bytes and preserves existing logs.
Checkpoint collection saves bounded private `<stage>.archives.log` files along
with the helper unit states. The shareable `archive_trace` accepts only records
matching the observed systemd invocation. Missing records remain unknown.

This continues through the normal operator interface with new diagnostic
requests for remaining tenants. Earlier failures and results stay immutable;
the attempt cannot repair the original qualification result. The overrides
persist on the disposable destination for subsequent diagnostic attempts and
are never installed by production convergence or fresh qualification.

### Resume the retained pre-health-quiescence destination

The retained `spaces-d0ec709.cYloMO` destination still selects its original
artifact. Updating the controller checkout does not install the later fix that
drains the periodic health reader during reconstruction. To apply that reviewed
behavior for diagnosis and locate any remaining stall, use the checked-out fix
branch with:

```bash
just m3-11-debug \
  /home/tturner/.local/share/lowerduckpond.net/m3-11/spaces-d0ec709.cYloMO \
  --exclusive-archive-writers --from restore \
  --repair scripts/m3_11_debug_restore_repair.py
```

The repair requires a stopped coordinator in its Docker destination with the
original journal at `installed` or `verified` and ingress still gated. It saves
the original administrative launcher in the private sibling directory
`/var/lib/lowerduckpond/recovery-diagnostic-launcher-<restore-id>/`,
installs the existing health admission rules, and instruments that launcher
after its original artifact verification. The instrumented launcher retains
the production launcher policy of root ownership and mode `0700`, including
when correcting an earlier diagnostic repair that published mode `0755`.
In the coordinator process it adds
the health service/timer to ordinary quiescence and schedule restoration, as the
merged implementation does. The selected artifact, source fence, journal,
archive target, TLS validation and all native service limits stay intact.
Repeating the repair in either phase verifies the saved launcher before reusing
it; after restore completes, resume without `--repair`.

The first version of this repair saved the launcher at
`recovery/diagnostic-launcher/original.py`. That extra directory violates the
closed recovery provenance inventory: native completion rejects it after
reaching `verified`. The corrected repair validates the saved original and
current launcher, then moves that exact directory to its private sibling using
a same-filesystem, no-replace rename. It preserves the original inode and bytes;
unexpected contents or a conflicting destination stop the repair. Repeating
the command above handles an already-patched destination without editing its
journal or restarting qualification. Diagnostic files must stay outside the
authoritative recovery tree; its production inventory rules remain unchanged.

The instrumented coordinator records verification-step boundaries and at most
62 stack samples at 30-second intervals. Samples contain elapsed/CPU time and
code locations, without arguments, local values or source lines. The private
journal keeps the full trace; failed-stage summaries include only a compact
trace bound to the current systemd invocation. Successful inactive units may
have their execution state unloaded by systemd, so an absent invocation or empty
helper timestamps remain unknown. They are not proof that a helper never ran.
The launcher instrumentation persists through the diagnostic reboot stage;
retiring the disposable destination removes it. It is never installed by
qualification or production convergence.

Public-CA continuation preserves the original account/certificate storage and
clean trust inputs. It records whether the attempt was cold or warm and any
missing interruption/two-zone observations. Old original inputs may be inspected
in this mode without changing their age; normal qualification freshness checks
remain enforced. Existing partially installed public inputs may need a specific
diagnostic repair; they are not silently erased into another purported cold run.

New cold attempts cancel incomplete issuance through a mode-0600 Unix socket
inside the private disposable Caddy store. The issuer remains alive while the
independent DNS witness observes its cleanup, then stops before account-byte
comparison and reboot. All waits use the original stage deadline. This avoids
losing asynchronous cleanup when Caddy exits; increasing its service stop timeout
would not make an already-exited process finish that work. Warm continuations on
older retained configurations still work when certificates are already ready;
attempting another interruption on those old inputs fails explicitly instead of
silently rewriting their recorded configuration. The retirement option below
remains available for challenges left by those older attempts.

The public-CA helper accepts the same bounded credential characters and length
as production configuration (20-256 ASCII letters, digits, `_` or `-`). It passes
the entire credential unchanged, including Cloudflare's
[account-token prefix and checksum](https://developers.cloudflare.com/fundamentals/api/get-started/token-formats/).
The provider audit establishes account ownership, policy and zone scope;
credential shape does not establish those properties. A credential-format
rejection occurs before creating public-CA inputs or starting issuance.

The independent DNS witness recognizes the 43-character DNS-01 value either bare
or inside one pair of double quotes, matching
[Cloudflare's TXT representation](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/#txt).
Private observations retain the exact provider content, including its quotes.
Malformed quotes, escapes, multiple strings and non-challenge content stop the
attempt. Continuation records existing valid challenges as activity; it cannot
turn them into a new empty baseline. Cleanup still requires both names to be empty.

If certificates are verified but cleanup reports retained challenges, compare the
saved DNS observations before deciding how to recover. A stopped issuer can leave
records from an earlier interrupted attempt. After confirming that case, explicitly
select their retirement while continuing:

```bash
just m3-11-debug /absolute/path/to/failed-run \
  --exclusive-archive-writers --from public-ca --retire-stale-dns
```

This diagnostic-only option stops the owned issuer, verifies the stored public
certificate chains, names, validity and matching keys offline, and permits deletion
only of exact TXT record IDs and contents from a prior failed cleanup observation
on this run's disposable names. New or changed
records stop the operation. The fixture uses its bound runtime credential, clean
resolver files in a private mount namespace, and captured public trust roots;
the controller's independent DNS credential remains read-only. Provider calls have
a 120-second overall deadline within the existing stage limit. Private plans and
results live in `diagnostics/workspace/diagnostic-dns-retirements/`. A fresh independent
absence observation is required before issuance or ingress activation continues.
After a partial deletion, another explicit invocation considers only the still-present
previously observed records. The option never changes qualification's DNS checks
or labels the continued attempt as a cold qualification.

The live TLS listener is checked after restarting the issuer, before ingress opens;
offline certificate validation does not establish a serving listener. Repeated
diagnostic failures still stop issuance and close ingress, while preserving the
original `failed.json`; each new failure is recorded in its controller attempt.

The ingress probe uses the existing controlled-CA container as its network peer.
That container does not retain network-administration privileges. A fixed address
setup command receives only `CAP_NET_ADMIN` after dropping Docker exec's other
capabilities; the CA process and TCP probe retain their ordinary permissions.
This also works on retained containers without recreating them. The same probe
checks closed and open ingress in the local combined-reconstruction lane before
it is used with public issuance. An issuance failure keeps ingress closed, so
the subsequent accounting check cannot report activation complete.

After restore, reconstruction, reboot and replay have passed, resume a corrected
public-CA stage directly, without the completed restore's repair script:

```bash
just m3-11-debug \
  /home/tturner/.local/share/lowerduckpond.net/m3-11/spaces-d0ec709.cYloMO \
  --exclusive-archive-writers --from public-ca
```

This rechecks public-CA recovery, accounting and teardown prerequisites while
retaining the earlier observations and original failed qualification.

The retained backup and fenced source remain the recovery reference. The
diagnostic workspace is **not** a complete disk snapshot or automatic rollback.
The diagnostic teardown-check stage retains resources for the next debugging
iteration. Completing an iteration does not mean investigation of the run has
finished.

## Required closeout after debugging

A failed run's debugging process is complete only after its local and remote
resources have been removed. Once useful investigation is finished, record the
findings and fixes in the tracked changes, then close out the run before starting
its replacement qualification. Diagnostic stages need not all pass: an unresolved
failure stays failed and a fresh run will exercise the next modifications.

In the same private environment shell, preview the closeout, then execute it:

```bash
just m3-11-debug-closeout /absolute/path/to/failed-run
just m3-11-debug-closeout /absolute/path/to/failed-run --discard
```

`--discard` declares debugging finished. The wrapper loads the current Spaces
targets from encrypted state and checks them against the original run. Closeout
holds the shared workstation storage lease and the run lock; an active local
qualification, debugger or retirement prevents cleanup. It also supports failed
creation and a workstation crash with no final exit record.
If storage preparation never saved `live-storage.json`, its backup prefix must
still be empty. A captured input file alone does not authorize deletion of data
that may have caused the original ownership claim to fail.

Closeout requires the shared archive Space and this run's public DNS challenges
to be absent before stopping anything. Resolve remaining run-owned archives
through their existing recovery/retirement path, and stale DNS through the
diagnostic retirement above, while the local ownership records are available.
Unknown or foreign archive objects are never bulk-deleted. A missing or nonempty
provider inventory leaves closeout incomplete; the failed run is still waiting
for resource cleanup even if no more code fixes are planned.

The command stops only the run's labeled Docker source, destination, controlled
CA and unused archive fixture. It permanently purges the exact
`m3-11-qualification/<run UUID>/` backup prefix, including every version, delete
marker and unfinished upload. After fresh provider absence checks, it removes
the owned containers and their anonymous volumes, the run's image tag, and the
whole private run directory, including diagnostic workspaces and any earlier
retirement disk copies. It creates no preservation copies. Shared images, other
runs and production backups stay outside its removal scope.

If interrupted, rerun the same closeout command. Completed deletions stay
permanent; the directory remains available until remote cleanup, container and
image removal have all succeeded. After successful closeout, review/merge the
fixes and run one fresh complete qualification from clean merged inputs. Only
that fresh run can supply release evidence.

Final directory disposal first publishes a small private sibling receipt named
`<run-directory>.debug-closeout.json`, after cloud and Docker cleanup succeeds.
It records the original directory identity and fixture, so the same command can
finish a partial recursive deletion even after `fixture.json` or the run root is
gone. This final local-only retry needs no provider credentials or state reads.
The receipt is locked during disposal and removed on success; it is temporary
cleanup state, with no diagnostic preservation copy.
