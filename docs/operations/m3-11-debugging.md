# Debug a retained M3.11 reconstruction

Use `just m3-11-debug` to continue a failed live reconstruction on its existing
disposable Docker source, destination and controlled-CA containers. It does not
rerun create/prepare/converge or the preceding lifecycle groups. The destination
can be changed for diagnosis; the original fenced source, selected artifact,
backup prefix and original failed reports remain retained.

This command runs on the secure workstation in the existing private production
environment shell. It reads current storage credentials from the encrypted
OpenTofu state, checks the saved local Docker endpoint and container identities,
and takes the same archive-target lease as qualification and retirement.
`--exclusive-archive-writers` acknowledges that no other workstation or operator
is writing the shared archive target; the local lease cannot enforce that across
machines. No image build or registry credential-helper invocation is needed.

## Start with the retained failure

Check out the diagnostic branch in the secure-workstation repository, preserving
any local changes. The branch initially contains the provider-observer correction
from PR #182; it can be retargeted to `main` after that PR merges.

```bash
cd /home/tturner/dev/lowerduckpond.net
git fetch origin
git switch --track origin/codex/m3-11-diagnostic-continuation
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
service journals and current observations, then attempts these stages:

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
types/locations and coverage gaps. It is shareable. Raw stage logs, journals,
scripts, diffs, source history, DNS observations and all other files remain
private. Setup failures also emit a private `debug-setup-*.log` path, so a failure
before the first stage still has a traceback. Journal collection omissions are
recorded separately and do not hide the stage's result.

## Iterate on the branch

After updating the branch, repeat the command. By default it begins at the first
stage without a passing diagnostic observation, and re-executes later stages.
Earlier successes are scheduling hints only; actions recheck their live
prerequisites. Use `--from restore`, `--from public-ca`, or another stage from the
table when a fix requires an earlier/later starting point. Original logs are
never overwritten. Partial tenant retirement is handled by skipping tenants
already absent only in this explicitly marked diagnostic mode.

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

Public-CA continuation preserves the original account/certificate storage and
clean trust inputs. It records whether the attempt was cold or warm and any
missing interruption/two-zone observations. Old original inputs may be inspected
in this mode without changing their age; normal qualification freshness checks
remain enforced. Existing partially installed public inputs may need a specific
diagnostic repair; they are not silently erased into another purported cold run.

The retained backup and fenced source remain the recovery reference. The
diagnostic workspace is **not** a complete disk snapshot or automatic rollback.
The final teardown stage deliberately retains containers and the backup prefix
for further investigation. It does not authorize generic bucket cleanup or reuse
a previous failed-fixture retirement approval.

After reaching the downstream checks and consolidating fixes, review/merge those
fixes, resolve the retained fixture through its applicable owned cleanup path,
and run one fresh complete qualification from clean merged inputs. Only that
fresh run can supply release evidence.
