# M3.10 lifecycle review evidence

This dependent review wires archive, exact archived export, restore, ordinary
deletion, and separate administrator deletion into durable host-agent execution.
It builds on the [archive boundary review](m3-10-boundary-evidence.md).
Installed service configuration and its full systemd acceptance follow in the
convergence review; production publication remains disabled.

| Invariant | Evidence in this slice |
| --- | --- |
| Archive binds verified construction bytes, removes both route classes, and preserves exact rollback source | `test_archive_prepare.py`, `test_archive_activate.py`, `test_archive_commit.py`, `test_archive_recover.py` |
| Cleanup independently verifies terminal job/audit authority and preserves still-bound versions | `test_archive_cleanup_service.py`, `test_archive_verification.py` |
| Restore creates a new deployment with current identity and bounded release history, then proves remote retirement | `test_restore_plan.py`, `test_restore_staging.py`, `test_restore_commit.py`, `test_restore_handler.py` |
| Ordinary deletion requires separate authorization or complete never-deployed history; tombstone precedes state removal | `test_delete_commit.py`, `test_delete_handler.py` |
| Emergency deletion has administrator provenance, reason, durable recovery, and permanent replay authority | `test_emergency_delete.py`, `test_emergency_entrypoint.py` |
| Repeated archive/restore/deletion retains bounded history and exact historical replay | `test_archive_cycles.py`, `test_archive_handler.py` |

The independently assembled slice passed all 1,732 host-agent tests that apply
locally. Two explicit skips cover the separately scheduled MinIO case and the
inapplicable archive-directory fault for a never-deployed tenant. Formatting,
lint, and strict typing passed. Required CI independently qualifies the slice's
existing installed behavior. This evidence does not claim live Spaces or
production convergence readiness.

Review follow-up: deletion now admits its intent and all remaining terminal
records in one capacity projection, after creating the runtime candidate.
Four boundary regressions cover archived and never-deployed tenants: insufficient
combined capacity leaves no transaction intent, while an exactly sufficient
allowance completes after the intent consumes its inode. The deletion suite
passed 38 tests with the same inapplicable archive-directory skip; lint,
formatting, and strict typing passed.

Further review covered archive and restore capacity and recovery. Construction
now checks terminal audit headroom before upload; local archive and restore
preparation admit the intent together with all terminal records after writing
the unselected runtime candidate. A refused archive preparation can discard
that candidate and audit/retire its upload. Restore and archived deletion cancel
a read-only retirement on verification, download, or preparation failure only while their archived source
is unchanged and no local transaction exists. Retained-object validation also
rechecks later audited transitions when the private validator raises.

The resulting full host-agent suite passed 1,755 tests with the same two
documented skips. Seven focused admission regressions passed, covering joint
capacity, pre-upload audit space, safe upload retirement, and preservation of
retirement after local intent publication. Formatting, lint, and strict typing
passed across 235 source files. Installed qualification and required CI remain
separate release evidence.

The shared retirement-cancellation follow-up passed 56 related tests, including
archived deletion's actual free-inode refusal after retirement creation and a
failed remote verification during recovery. Both paths preserve the archived
source and release the unstarted journal; retry succeeds when the refusal is
removed. Formatting, lint, and strict typing passed.

Failed restore/deletion result validation also rechecks later audited state
when retained-object verification returns false or raises. The executor and
entrypoint suite passed 214 tests, including both raced and still-current
failed-source checks. The installed entrypoint's unreturned-object callback
was exercised with its job argument and correctly passed `(job, None,
mode="accounted")` to the private client; no callback binding change was needed.

Construction now admits logical authorization-result capacity and ordinary audit
headroom before allowing upload. New correlations wait behind a construction
journal so they cannot consume that reservation; exact retries remain available.
An unpublished failure uses the captured job/journal source and can retire its
exact unbound upload after current tenant state drifts or an old deployment is
collected. Cleanup preserves current state and still refuses any bound object.
Failed-candidate verification also rechecks audited supersession when the remote
validator raises. The resulting full host-agent suite passed 1,775 tests with
the same two documented skips; the focused admission/abort/journal group passed
59 cases and the raced replay group passed eight.

A disposable run completed four restores and both tenant deletions, then exposed
an empty-host health mismatch during the last deletion's configuration overlap.
The checker now also accepts the exact namespace-bound empty generation emitted
by deletion, checking binary, environment, configuration, and route metadata and
requiring empty startup/release namespaces. Four real generation-store cases
prove acceptance and rejection of changed environment, namespace, and origin-pull
inputs. A read-only evaluation of the revised checker against the retained
disposable host returned `current`; installed artifact files were not modified.
The full 1,775-test run includes these regressions.

The next review closes reservation consumption by already-admitted jobs: each
executor transaction defers a different job while the construction journal owns
terminal capacity. Two regressions leave exactly one result slot, attempt a
pending job's failure both with and without source drift, then prove the archive
can still publish its failed result and retire its upload before the pending job
resumes. Empty-tenant health now validates the entire generation-store shape and
normal three-generation bound, including temporary, malformed, corrupt, and
excess unselected entries.

Emergency deletion now admits and appends its audit through the administrator
reserve. Successful deletion and replay after interruption pass with zero
ordinary audit allocation available. Completed emergency results already occupy
the shared permanent result inventory; regression tests prove ordinary callers
cannot reuse either their correlation or job identity. Admission additionally
refuses a correlation retained by audit evidence if its result is missing.
The focused admission, generation-store, and emergency group passed all 77
tests; formatting and strict typing across 239 source files passed.
The resulting full host-agent suite passed 1,787 tests with the same two
documented skips.

Emergency preparation now publishes and validates its unselected generation
before saving recovery authority, then rechecks terminal capacity after that
allocation. A failed preparation discards only its verified candidate while the
intent is absent; an ambiguously completed intent keeps its candidate for
recovery. All 54 emergency tests passed, including generation-capacity refusal,
terminal-capacity refusal after generation creation, and interruption before or
after intent durability. These checks preserve the selected runtime and tenant
state on preparation refusal, and prove a later retry succeeds.

The completed emergency-candidate change passed the full host-agent suite:
1,791 tests with the same two documented skips. A subsequent retention check
confirmed that ordinary route publication prunes to active plus one predecessor
before adding its candidate, so last-tenant deletion can leave three complete
generations. The namespace-bound empty health check now uses the existing normal
runtime limit of three, while validating every retained generation and rejecting
reserved temporaries. The original platform-bootstrap limit remains two.
All 61 generation/entrypoint tests passed, including a valid three-generation
history and refusal of four generations, malformed entries, and corruption.

The complete normal-retention source passed 1,792 host-agent tests with the same
two documented skips. Archived-source `archive` failures now verify their
retained source object rather than invoking unreturned-upload accounting when
the result has no candidate record. The shared retained-source path keeps its
later-audited-supersession handling. All 226 executor/entrypoint tests passed,
including 12 archived-source failure cases spanning present/missing/error
verification and raced supersession for archive and restore.
