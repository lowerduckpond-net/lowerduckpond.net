# Installed check selection

The stable `Ansible` check requires the baseline Ansible lane, successful
selection, every selected installed group, and a complete result for each group.
A successful matrix summary alone is insufficient. Missing, duplicate, failed,
skipped, cancelled or malformed selected results fail the required check. Each
group result requires its declared assertions, fresh local accounting,
independent whole-bucket absence, and teardown on its own fixture.

Installed groups and the complete journey start after the Python component lane
and repository hooks pass. This avoids allocating their fixtures for failed fast
checks and leaves a window for early corrections. The prerequisite time adds to
PR completion time and is recorded separately from each group's execution time.
External-link validation runs alongside these checks, allowing a link-only retry
without repeating successful installed work.

## Reviewed map

The [selector](../../scripts/qualification_selection.py) reads committed Git
changes, including file modes and both sides of a rename. The
[registry](../../scripts/qualification_groups.py) declares the complete matrix.
The initial narrow map is deliberately small:

| Changed input | Required installed groups | Dependency basis |
| --- | --- | --- |
| Regular, nonexecutable Markdown under `docs/`, root README/CONTRIBUTING, or record JSON/checksums under the existing evidence directories | None; normal fast and repository-hygiene lanes remain. | These paths are not imported by installation/runtime code. This does not change the separate production qualification-input fingerprint. |
| `emergency_plan.py` and its component regression `test_emergency_delete.py` | Backup mutation overlap, deletion/quarantine, credentials, reboot journey. | The plan is imported only by `emergency_delete.py`. Backup mutation overlap covers capture overlap with emergency deletion; installed deletion exercises root authority and exact archive retirement; credentials exercises isolated recovery; the journey retains admission/restart policy. |
| Independent core wrapper | Core and reboot journey. | No other installed module imports this wrapper. |
| Independent configuration wrapper | Both configuration cases and reboot journey. | The file contains both guards, each with a fresh active tenant. |
| Independent recovery wrapper | Transport recovery, both overlap cases and reboot journey. | The file contains all three independent entry points. |
| Independent archive wrapper / full-size archive test | Its archive case and reboot journey. | Each is an unimported test entry point; shared archive helpers remain full-matrix inputs. |
| Quarantine / credential test module | Its declared group and reboot journey. | These test modules have no consumers in other installed modules. Deletion helpers are shared with backup mutation overlap and therefore select the complete matrix. |
| Reboot or cross-feature test | Reboot journey. | Both stages are required together, including the actual restart. |
| Every other path | Complete installed matrix. | Unknown mappings never exempt coverage. This includes shared test helpers, authorization, persistence, recovery, schemas, units, Ansible roles, packaging, lockfiles, selectors, workflows and other test infrastructure. |

Adding/removing/renaming mapped code, executable or nonregular inputs, empty or
malformed diff metadata, missing revisions and shallow history also select the
complete matrix. Component regressions check the mapped modules' consumers;
a new consumer requires reviewing the map. A PR label cannot exempt a check.
The mapping is an explicit reviewed policy, not an inferred transitive-dependency
engine. Extend it only when actual consumers and their installed assertions are
identified.

The comparison regressions execute the previous and proposed selectors on the
same real Git fixture revisions. Documentation remains skipped for installed
checks. A narrow emergency-plan edit changes from the complete journey to the
four mapped groups. Shared authorization remains full. An unknown new code
path changes from the previous allowlist's skip to the complete matrix. The
regressions also cover rename into/out of docs, deletion, executable docs,
symlinks, missing history and invalid paths.

For a read-only local preview, supply full commit IDs:

```console
just plan-installed-checks BASE_COMMIT HEAD_COMMIT
```

The preview reads committed changes; uncommitted edits are not included.
The output names cases usable with `just check-installed-group CASE`. It grants
no production qualification authority. `just check` remains the full local
entry point, and `just check-ansible-m3-8` retains the complete installed journey.
Passing results are never cached across changed inputs. Each selected case builds
and validates its candidate artifact in its own run.

## Full qualification and release handling

Scheduled CI remains Monday at 04:23 UTC. Scheduled and manual workflows require
all independent groups **and** the original complete installed journey. The
cross-feature reboot journey also runs on every narrow runtime selection; PRs
changing shared boundaries require the full matrix. Explicit live Spaces and
production gates remain separate and mandatory. Parallel local groups never
run against the shared live buckets.

A scheduled failure blocks release. Read its failure report, reproduce the
named case on a fresh fixture, and deliver a corrective PR with the applicable
checks. Before release, inspect the latest scheduled/manual run as well as the
candidate's required PR checks. Do not use a historical green result or diagnostic
case report to clear an unresolved regression. Complete secure-workstation
qualification of the final changed live harness remains required before using
it as production release evidence.

The prerequisite complete grouped-harness run and explicit cross-feature journey
passed in the [grouping eligibility record](../records/2026-09-20-installed-grouping-eligibility.md).
That record retains their exact revisions, coverage, receipts and measurements
before replacing the old per-PR path. The final sustainability gate still needs
three comparable runs and secure-workstation qualification of the live harness.
Current job limits remain bounded safeguards, not performance
claims: the target is 30 minutes per affected case including setup. Compare
wall time, total runner minutes, setup and waiting using three normal comparable
validation runs; record failures and operator interventions too.
