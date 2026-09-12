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
