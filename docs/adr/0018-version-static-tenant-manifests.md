# 0018: Version the static tenant manifest contract

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 needs a durable desired-state contract before the portal and control
plane exist. That contract must support idempotent operator commands now and
queued reconciliation later without changing tenant identity or treating host
paths as application state.

## Decision

Commit a strict JSON Schema for `hosting.lowerduckpond.net/v1alpha1` static site
manifests. Accept safe YAML as the human-authored representation and persist a
canonical JSON form. Reject unknown fields so misspellings do not silently
weaken policy.

Use UUIDv7 values for immutable tenant and deployment IDs. Restrict slugs to
lowercase ASCII letters, digits, and interior hyphens, and maintain a committed
reserved-name list. Derive the Milestone 3 hostname as
`<slug>.lowerduckpond.net`; do not accept an arbitrary domain in this version.

The desired manifest records the tenant ID, slug, `runtime: static`, desired
lifecycle state, and quotas. `create` persists a manifest with
`desiredState: undeployed` and no `desiredDeployment`. The deployment reference,
containing a deployment UUIDv7 and archive SHA-256, becomes required when the
state changes to `active`, `suspended`, or `archived`. An immutable deployment
record carries its creation time and correlation ID. Keep observed activation
status, including the active release, separate from desired state so
reconciliation can detect and repair drift.

Persist desired and observed state, deployment and archive records, and audit
history in root-owned stores. The root activator validates and commits desired
state, changes observed state, and appends audit events. The provisioner may
read only the records required to construct or reconcile work and cannot write,
replace, or remove authoritative state or audit history.

The initial platform ceilings are 100 MiB of extracted content and 5,000 total
archive entries, counting both regular files and directories.
The desired lifecycle states are `undeployed`, `active`, `suspended`, and
`archived`. Schema conditionals reject a deployment reference in an undeployed
manifest and require one in every other state. Deletion removes desired state
only through an audited operation and retains a tombstone audit event rather
than representing ordinary mutable state as `deleted`.

Schema-version changes require explicit migration code and fixtures. A stable
tenant ID does not change when its slug or active deployment changes.

## Consequences

Milestone 4 can store or enqueue the same contract without importing the
operator transport. Canonical JSON makes hashing and comparison deterministic,
while YAML remains approachable for an operator. Custom domains require a later
schema version and ownership-verification design.

Desired and observed state require separate root-owned storage and
reconciliation logic.
UUIDv7 avoids another identifier dependency on Python 3.14 but changes the
illustrative ULID-shaped identifier in the original roadmap.

## Alternatives considered

ULID was rejected because Python 3.14 provides UUIDv7 directly. Caller-supplied
hostnames were rejected because wildcard subdomains are the only approved
Milestone 3 routing scope. Permissive schemas were rejected because ignored or
misspelled security fields are unsafe at a privileged boundary. Combining
initial creation and deployment was rejected because the accepted operator
interface exposes them as separate idempotent operations.

## References

- [0004: Make static hosting the default](0004-static-first.md)
- [0008: Support archive upload before Git deployment](0008-archive-upload-first.md)
- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
