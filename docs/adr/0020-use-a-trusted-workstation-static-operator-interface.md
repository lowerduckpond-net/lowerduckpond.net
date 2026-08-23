# 0020: Use a trusted-workstation static operator interface

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 must demonstrate the complete static lifecycle before Milestone 4
provides authentication, a portal, or a production job queue. Building a
temporary web administration surface would enlarge the public attack surface
and couple tenant operations to a transport that will soon be replaced.

## Decision

Provide a trusted-workstation CLI, exposed through documented `just` recipes,
for `create`, `deploy`, `rollback`, `suspend`, `resume`, `rename`, `export`,
`archive`, `restore`, `delete`, and `reconcile`.

The client connects through the existing restricted administrative SSH path and
transfers structured operation requests, manifests, and archives into a
dedicated non-public intake boundary. It never edits live host files. Host-side
commands accept structured inputs, return machine-readable results, and require
a caller-supplied UUIDv7 correlation ID. Reusing a correlation ID and request
converges on the same result rather than duplicating releases or audit events.
Before any parser or correlation lookup, the host adapter applies ADR 0017's
raw byte ceiling, bounded read, deadline, and constrained-decoder contract to
every invocation, including retries. The client cannot use transport framing,
discardable syntax, or an established ID to bypass those limits.

The SSH adapter, rather than `scp`, SFTP, or shell redirection, owns artifact
intake. Before reading artifact bytes it acquires the exclusive root-owned
intake-admission lock, reconciles abandoned intake, and claims the host's one
in-progress-or-admitted artifact slot. It streams bounded chunks into an
exclusively created mode-`0600` regular temporary file beneath the fixed intake
directory, without following links. A deploy ZIP may contain at most 100 MiB;
an explicit restore may contain at most the 120-MiB portable-bundle ceiling; an
operation that takes no artifact rejects one. The adapter reads at most the
applicable ceiling plus one byte, requires EOF at or below the ceiling, and
never writes the extra byte.

Partial bytes count against an intake-wide allocation ceiling of the applicable
artifact limit rounded up by one filesystem block. Admission and every write
also preserve the configured host free-space reserve. A 30-second idle deadline
and 15-minute total monotonic transfer deadline bound an abandoned live
connection. Only after the complete file and intake directory are synced does
an atomic rename make the artifact available to the activator. Disconnect,
timeout, excess data, reserve failure, and every other terminal error remove
the temporary artifact and sync the directory. Startup reconciliation removes
an abandoned temporary or admitted artifact before accepting another; an
artifact it cannot safely classify or remove closes admission. The intake lock
and slot remain held through activator claim, so concurrent transfers and
retries cannot accumulate files ahead of privileged validation.

The `create` request supplies a slug and quotas but no tenant ID. The root
activator generates that immutable ID and returns the resulting canonical
manifest and UUID-derived tenant origin from the pinned platform namespace.
Later operations identify the tenant by that ID; a slug is a mutable alias and
is never accepted as proof of tenant identity or authority.

Keep manifest validation, archive validation, lifecycle orchestration, and
privileged activation behind transport-independent Python interfaces. The SSH
client is a Milestone 3 adapter; Milestone 4 can enqueue the same operations
without inheriting SSH or trusted-workstation assumptions.

Do not add FastAPI endpoints, public authentication, or a production queue in
Milestone 3. The unprivileged provisioner receives only the exact privileged
activation capability defined by ADR 0017, not general sudo or Caddy access.
Ordinary `delete` cannot bypass archive evidence. The emergency deletion
command defined by ADR 0021 remains a distinct root-only administrative entry
point and is never exposed through the worker interface or provisioner sudo
rule.

## Consequences

An administrator can exercise every lifecycle operation without manual host
editing, while the public service remains only Caddy. The operator must use the
trusted workstation and administrative network until Milestone 4 is complete.

The command contract and result model become compatibility surfaces. Tests must
prove that local, SSH-adapted, and later queued invocation cannot change core
semantics.

## Alternatives considered

A temporary administrative web UI was rejected because it would require early
authentication and authorization work. An Ansible role per tenant was rejected
because tenant lifecycle is application state, not durable host configuration.
Manual SSH editing was rejected because it cannot satisfy the milestone's
idempotence or audit requirements.

## References

- [0002: Use Ansible for durable host configuration](0002-use-ansible.md)
- [0006: Separate the control plane and provisioner](0006-separate-control-plane-provisioner.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
