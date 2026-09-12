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
