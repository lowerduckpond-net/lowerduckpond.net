# 0031: Retain frozen fixtures after exact archive retirement

- Status: proposed; irreversible execution needs separate approval
- Date: 2026-10-19

## Context

A failed qualification can retain a valid archive bound by canonical state and
audit. Whole-bucket-empty preflight correctly rejects that output. Preservation
does not authorize VersionId removal. Ordinary tenant delete changes more
authority and versions than required.

## Decision

Provide the explicitly approved
[frozen fixture transition](../operations/frozen-fixture-retirement.md).
Retain original records as history, commit a permanent fixture execution and
disposal fence, and reserve at most one exact-version deletion. Shared operation
locks serialize supported mutations against the exclusive fence transition.
Uncertain submission never permits automatic mutation replay.

## Consequences

Retained canonical records cease to be runnable recovery authority after this
retirement. Reupload cannot restore the original VersionId. Preserved bytes allow
inspection; this establishes no automatic tested recovery into a new fixture.
Disposal/closeout also remains blocked, requiring explicit acknowledgement of
continued local retention. Read-only evidence and credential cleanup continue.
The qualification stays failed and whole-bucket acceptance stays unchanged.
