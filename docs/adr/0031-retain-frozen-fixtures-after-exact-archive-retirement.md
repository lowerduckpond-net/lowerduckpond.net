# 0031: Retain frozen fixtures after exact archive retirement

- Status: source prototype; native execution blocked pending supported closeout
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

The current source has no supported closeout adapter for a retired fixture.
Native execution is therefore blocked before submission, proof gathering and
marker creation. Approval cannot override this implementation prerequisite. The
transaction primitives remain available for offline tests. Ordinary closeout
remains blocked; a generic execution-guard bypass would reopen unsafe recovery.

The minimum subsequent implementation must reuse the existing cleanup primitives
in two stages: remote backup cleanup while existing scoped credentials are valid,
retaining the stopped actors required by active lease reuse; then local-only
disposal after authenticated terminal lease closure and quiescence. Verified
external evidence export and a persistent identity fence must survive original
directory removal. Neither stage is included in the one-VersionId action.

## Consequences

Retained canonical records cease to be runnable recovery authority after this
retirement. Reupload cannot restore the original VersionId. Preserved bytes allow
inspection; this establishes no automatic tested recovery into a new fixture.
Until that adapter is implemented, tested and independently reviewed, no live
retirement proposal is ready. A promised future closeout is not sufficient before
an irreversible effect. Read-only evidence and credential cleanup continue.
Failed qualifications remain failed and whole-bucket acceptance stays unchanged.
