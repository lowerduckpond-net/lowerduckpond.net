# 0031: Retain frozen fixtures after exact archive retirement

- Status: staged implementation under final validation; native execution blocked
- Date: 2026-10-19

## Context

A failed qualification can retain a valid archive bound by canonical state and
audit. Whole-bucket-empty preflight correctly rejects that output. Preservation
does not authorize VersionId removal. Ordinary tenant delete changes more
authority and versions than required.

## Decision

Provide the explicitly approved
[frozen fixture transition](../operations/frozen-fixture-retirement.md).
Retain original records as history, permanently exclude fixture execution, and
reserve at most one exact-version deletion. Disposal is a separately authorized
transition, not permanently forbidden. Shared operation locks serialize supported
mutations against the exclusive fence transition. Uncertain submission never
permits automatic mutation replay.

The staged adapters reuse the existing exact owned-backup removal primitive.
Remote cleanup preserves every original backup version before removing only that
prefix while scoped credentials are valid. Stopped actors remain available to
active lease reuse. Terminal local disposal requires authenticated all-seven
cleanup facts and original release/drain proofs; it makes no provider calls and
opens no child credential deliveries. Both stages require distinct exact plans
and authority. Neither is included in the one-VersionId action.

An external intent and immutable-identity/path tombstones fence supported
consumers across directory removal and recreation. Shared ownership covers each
consumer's entire mutation; closeout holds exclusive ownership. A complete
private export contains all original directory entries, actor root filesystems,
logs and inspect data. Persistent mounts and unpreservable entries stop before
exclusion. Flat certificates permit later terminal consumers to verify disposal
without circular trust or missing-actor inference.

Read-only reconciliation never mutates. Explicit continuation may finish exact
metadata publication or send only provably unsubmitted remaining effects. It
cannot replay the archive DELETE or any uncertain resource removal. Interrupted
copy generations remain preserved. Qualification results and lease facts remain
independent of resource disposal.

## Consequences

Retained canonical records cease to be runnable recovery authority after this
retirement. Reupload cannot restore the original VersionId. Preserved bytes allow
inspection; this establishes no automatic tested recovery into a new fixture.
The source hard gate remains until final combined tests and independent review
are complete. An exact execution proposal and separate owner authorization are
still required afterward. Read-only evidence and credential cleanup continue.
Failed qualifications remain failed and whole-bucket acceptance stays unchanged.
