# 0020: Use a trusted-workstation static operator interface

- Status: accepted
- Date: 2026-08-22
- SSH identity selected by: [ADR 0026](0026-separate-static-operation-from-host-administration.md)

## Context

Milestone 3 must demonstrate the complete static lifecycle before Milestone 4
provides authentication, a portal, or a production job queue. Building a
temporary web administration surface would enlarge the public attack surface
and couple tenant operations to a transport that will soon be replaced.

## Decision

Provide a trusted-workstation CLI, exposed through documented `just` recipes,
for `create`, `deploy`, `rollback`, `suspend`, `resume`, `rename`, `export`,
`import`, `archive`, `restore`, `delete`, and `reconcile`.

The client connects as `ldp-operator` through the dedicated-key,
forced-command SSH path from ADR 0026 and transfers one structured operation
request and, only for `deploy` or `import`, one operation-specific ZIP artifact
into a dedicated non-public intake boundary. Routine operations never use the
`ldp-admin` account or its key. The versioned protocol has no standalone
manifest frame and rejects an artifact for every other operation. It never
edits live host files.
Host-side commands accept structured inputs, return machine-readable results,
and require a caller-supplied UUIDv7 correlation ID. The restricted SSH adapter
derives the operator principal from the authenticated SSH boundary, never from
a request field. Before any parser, authorization, or correlation lookup, it
applies ADR 0017's raw byte ceiling, bounded read, deadline, and constrained
decoder contract to every invocation, including retries. The client cannot use
transport framing, discardable syntax, or an established ID to bypass those
limits.

After validating and canonicalizing the request, the adapter prepares a
versioned immutable root-owned authorization job. It binds a root-generated job
ID, authenticated operator principal, operation, target tenant ID or explicit
`create`-expects-absence condition, correlation ID, complete canonical request
and its digest, artifact digest and size or explicit absence, and the expected
authoritative source lifecycle, manifest, deployment, and archive-record
digests applicable to the operation. For `create`, it instead binds the
platform namespace record and expected tenant absence; slug availability and
all other state are still revalidated at execution. No caller may supply the
operator principal, job ID, expected-state digest, or job storage path.

The SSH adapter, rather than `scp`, SFTP, or shell redirection, owns artifact
intake. Before reading artifact bytes it acquires the exclusive root-owned
intake-admission lock, reconciles abandoned intake, and claims the host's one
in-progress-or-admitted artifact slot. It streams bounded chunks into an
exclusively created mode-`0600` regular temporary file beneath the fixed intake
directory, without following links. A deploy ZIP may contain at most 100 MiB;
an import may contain at most the 120-MiB portable-bundle ceiling; restore reads
its exact bound remote object and accepts no uploaded artifact. An operation
that takes no artifact rejects one. The adapter reads at most the applicable
ceiling plus one byte, requires EOF at or below the ceiling, and never writes
the extra byte.

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

For `deploy` or `import`, the adapter computes the artifact digest and size
while streaming, independently verifies the caller-declared digest, and creates
the authorization job only after the completed artifact and intake directory
are synced. An interruption before job commit leaves an unauthorized intake
artifact that reconciliation removes; a job can never refer to partial bytes.
Operations without an uploaded artifact bind explicit absence, and the
activator rejects any artifact. Restore binds the expected authoritative
archive record and remote object version rather than caller bytes.

The adapter writes and syncs the complete job through an exclusive temporary
regular file, atomic rename, and parent-directory sync. The provisioner's sudo
allowlist exposes only the fixed, root-owned `execute-authorized-job`
executable. Ubuntu 26.04's `sudo-rs` does not support regular expressions or
wildcards in command arguments, so the rule does not pretend to validate the
argument. The executable starts in an isolated runtime, accepts exactly one
canonical lowercase UUIDv7 matched with an ASCII `fullmatch`, and derives the
path beneath one fixed root-owned directory. It cannot accept a separator or
caller path, call the activator with raw operation fields, or invoke the job
issuer.

The parent-directory sync is the operation's acceptance point: the adapter does
not report acceptance earlier, and after it the exact job may execute even if
the SSH response or queue handoff is lost. Root reconciliation may requeue a
committed pending job by its stored ID; it never reconstructs authority from an
intake artifact or provisioner request.

The activator opens the root-owned job without following links, verifies its
ownership, mode, link count, schema, request and artifact bindings, and exact
expected source state, then claims it through a durable phase transition before
mutation. State drift fails the job without applying it and requires a newly
authorized request. A retry of the same job or the same established correlation
and request returns the immutable result; a collision with any different
binding fails closed.

The provisioner receives only the job ID and bounded execution status. It has
no directory access to authorization jobs, artifacts, tenant exports, or full
results. A completed export remains root-owned and is returned only through the
authenticated adapter that can prove the job's operator binding. Startup
reconciliation removes unauthorized intake artifacts, requeues committed
pending jobs, resumes claimed jobs idempotently, and never converts a
provisioner-created file or request into authority. Job envelopes, phases, and
results consume the existing bounded correlation-record count and byte
allowance rather than a second unbounded store.

The `create` request supplies a slug and quotas but no tenant ID. The root
activator generates that immutable ID and returns the resulting canonical
manifest and UUID-derived tenant origin from the pinned platform namespace.
Later operations identify the tenant by that ID; a slug is a mutable alias and
is never accepted as proof of tenant identity or authority.

The supported client may translate a bounded local safe-YAML `create`
specification into that request after rejecting duplicate keys and unknown
fields. It sends only the structured request. YAML is not a host input, and a
full desired manifest is never accepted as operation authority. Root constructs
each new manifest from the validated operation and current authoritative state.

`import` identifies an already-created `undeployed` target by tenant ID and
uploads a caller-held portable export. It is authenticated like `deploy`, but the
host derives the target slug, quotas, identity, canonical origin, and candidate
manifest exclusively from current root-owned state. The bundle supplies only
validated content and provenance. The separate `restore` command remains
available only for an `archived` tenant and consumes its exact authoritative
remote object version without accepting caller bytes.

Keep manifest validation, archive validation, lifecycle orchestration, and
privileged activation behind transport-independent Python interfaces. The SSH
client is the Milestone 3 authorization issuer; Milestone 4's authenticated
control plane can create the same authorization envelope and enqueue its job ID
without inheriting SSH or trusted-workstation assumptions. Autonomous startup
or scheduled reconciliation runs inside the root boundary; an externally
requested `reconcile` still requires an authorized job.

Do not add FastAPI endpoints, public authentication, or a production queue in
Milestone 3. The unprivileged provisioner receives only the exact privileged
job-execution capability defined by ADR 0017, not authorization issuance,
general sudo, or Caddy access. Ordinary `archive` and `delete` each require
their own expected-state-bound operator jobs as well as archive evidence. The
emergency deletion command defined by ADR 0021 remains a distinct root-only
administrative entry point and is never exposed through the worker interface
or provisioner sudo rule.

## Consequences

An administrator can exercise every lifecycle operation without manual host
editing, while the public service remains only Caddy. The operator must use the
trusted workstation and administrative network until Milestone 4 is complete.

The command contract and result model become compatibility surfaces. Tests must
prove that local, SSH-adapted, and later queued invocation cannot change core
semantics. The authorization envelope is also a compatibility surface between
the trusted SSH issuer now and the authenticated control plane later.

The fixed sudo rule authorizes attempts to invoke its one executable with
arbitrary argument vectors because `sudo-rs` cannot express the UUID grammar.
That executable is therefore the privileged argument boundary: it must remain
root-owned, purpose-built, isolated from caller-controlled interpreter state,
and tested against missing, additional, noncanonical, separator-bearing, and
lookalike arguments. Sudo must still reject every other executable.

## Alternatives considered

A temporary administrative web UI was rejected because it would require early
authentication and authorization work. An Ansible role per tenant was rejected
because tenant lifecycle is application state, not durable host configuration.
Manual SSH editing was rejected because it cannot satisfy the milestone's
idempotence or audit requirements. Allowing the provisioner to construct raw
activator requests was rejected because syntax and archive evidence do not
authorize an operation; a compromised worker could otherwise archive and then
delete a tenant through two individually valid transitions.
Adding a standalone manifest frame was rejected because no lifecycle operation
accepts wholesale desired-state replacement. Operation-specific requests avoid
conflicting copies of caller-controlled fields and keep root-generated identity,
origin, deployment, and lifecycle values out of caller authority.

## References

- [0002: Use Ansible for durable host configuration](0002-use-ansible.md)
- [0006: Separate the control plane and provisioner](0006-separate-control-plane-provisioner.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [0026: Separate static operation from host administration](0026-separate-static-operation-from-host-administration.md)
