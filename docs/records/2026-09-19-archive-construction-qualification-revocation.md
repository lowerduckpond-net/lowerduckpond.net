# Archive lifecycle locking qualification revocation

- Recorded: 2026-09-19
- Affected artifact: `0686e44fe9d049bf7aa49eb836a16e50c64dbb29a0752ac84c7121379c7596e1`
- Reproduced against source: `7d25ba7b72d41f512e213c62f7b7854a3a993f7c`

Archive construction could fail immediately when another process held the state
lock, including during preparation, confirmation, service authority reads, and
remote admission. Archive download, restore and deletion retirement had the
same omission. The installed worker requests blocking execution, but these
accesses did not retain that policy. Recording quarantine after a provider error
could also fail on the contended lock.

Real kernel-lock and socket regressions reproduce these failures. The correction
retains the worker's requested lock policy and makes the private archive services
wait under their existing deadlines. It preserves lock order, authority validation,
the single upload attempt, durable quarantine after ambiguous provider I/O, and
safe cancellation of an unstarted retirement after local preparation fails.

The [complete-journey failure](https://github.com/lowerduckpond-net/lowerduckpond.net/actions/runs/35438509677/job/105885236600)
left a claimed, unvalidated archive job with no intent or result and reported a
closed construction channel. Contention during preparation reproduces that
state, but the retained CI diagnostics do not identify the worker's exact
exception. This record does not claim that every earlier archive failure had
the same cause.

Under [ADR 0029](../adr/0029-bind-qualification-to-inputs-and-live-observations.md),
the [revocation policy](../../scripts/qualification-revocations.json) rejects
future qualification reuse for the affected artifact. Its passing diagnostic
groups remain historical observations; they do not qualify the corrected
artifact. Required CI and final secure-workstation qualification remain separate
obligations. This record does not authorize production mutation or cleanup.
