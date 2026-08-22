# 0022: Test static publication as a security boundary

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 combines parser, filesystem, privilege, routing, concurrency, and
recovery behavior. Unit tests alone cannot demonstrate the installed ownership,
Caddy, systemd, backup, or host-reboot boundaries, while production-only testing
would discover security and destructive-lifecycle failures too late.

## Decision

Deliver Milestone 3 through these reviewable layers:

1. threat model, ADRs, schema, fixtures, and test matrix;
2. manifest parsing, validation, slug and immutable-origin rules, and
   desired/observed state;
3. hostile archive validation and deterministic portable export;
4. root-owned immutable release activation and generated Caddy routing;
5. lifecycle commands, reconciliation, rollback, and audit records;
6. backup locking and restored-state reconciliation; and
7. disposable host integration followed by a production canary acceptance
   drill.

Use unit and property-based tests for schemas, normalization, archive limits,
state transitions, idempotency, and route generation. Use process-level tests
for concurrent operations and failure injection at every publication commit
step. Use Molecule and Testinfra to exercise actual Unix identities,
permissions, immutable releases, the privileged helper, Caddy validation and
reload, backup overlap, restore, and reboot-relevant service configuration.

Manifest fixtures include duplicate YAML keys for lifecycle, deployment, and
quota fields and prove rejection occurs before schema validation and canonical
JSON generation. Slug fixtures cover 1- and 63-byte valid labels, reject empty
and 64-byte labels, and verify the complete alias-hostname limit. They also
append LF, CR, CRLF, NUL, spaces, non-ASCII, and other control characters and
prove both schema validation and the independent root ASCII `fullmatch` reject
them before uniqueness or persistence. Tenant-ID fixtures prove `create`
rejects a caller-supplied ID, generates a UUIDv7, derives the canonical
hostname without hyphens, and enforces its complete DNS length independently
of the alias.

An installed-host concurrency test pauses tenant activation while Ansible has a
candidate Caddy base transaction ready to commit, then proves that only one
transaction can select a complete runtime generation and own a reload or
restart intent at a time. At every durability phase it kills Caddy to trigger
automatic restart and proves the recovery gate and launcher select one
manifest-verified generation, never a mixed binary, environment, base
configuration, or tenant route set. It verifies that the resulting Caddy
configuration and observed tenant state describe the same committed generation.

Restart-handoff tests pause after intent creation, active-reference selection,
non-blocking job submission, pre-start transition, launcher pinning,
post-start health verification, rollback selection, and recovery restart.
They prove the initiating transaction never retains the publication lock while
systemd needs it, later mutations return busy while intent is nonterminal, a
lost or duplicated job submission is idempotent, and every crash converges on
the complete candidate or preceding generation. Candidate and
last-known-good start failures must preserve intent and evidence, stop after the
single candidate and single recovery transitions, and never enter an automatic
restart loop.

Bootstrap tests interrupt the initial and upgrade maintenance transactions
between stop, mask, unit installation, launcher installation, systemd reload,
reconciliation, unmask, and start. Until every bootstrap component is compatible
and verified, Caddy must remain masked and unavailable rather than automatically
starting with mixed bootstrap or runtime inputs.

Generation-retention tests use shared hard links and distinct binary versions,
fill byte and inode ceilings, interrupt every cleanup phase, and keep old Caddy
process descriptors open across selection. They prove unique-inode accounting,
the three-generation maximum, host free-space admission, preservation of every
active/previous/intent/running target, eventual cleanup, and absence of Caddy
environment or adapted configuration in backups and diagnostics.

Admission tests create concurrent unique tenants, deployments, correlations,
results, and audit records up to and beyond every global count, byte, inode,
request-size, reason-size, rate, burst, and host-free-space boundary. They prove
rejection occurs before staging or desired-state mutation, retries do not spend
new capacity, hard links are counted once, and busy/rejected floods cannot fill
audit or journald. Rotation tests verify hash chains and Restic evidence, reject
unbacked segment removal, deny provisioner rotation and administrator-reserve
use, and recover interrupted rotation without losing or duplicating evidence.
Restart and clock-skew tests prove accepted-correlation timestamps reconstruct
the rolling rate window and cannot reset or refund consumed admission.
Free-space fixtures exercise both the absolute and percentage block/inode floors
and prove root-reserved blocks are excluded from admission capacity.

Durability tests record filesystem operations and inject failure after every
file sync, directory sync, rename, reload, restart-intent transition, systemd
job handoff, post-start verification, state commit, audit append, and intent
removal boundary. Reconciliation must select only a fully durable new
generation or the durable prior generation. Installed-host tests additionally
terminate the activator and each restart helper at every externally visible
phase and verify recovery.

Hostile fixtures must cover traversal, absolute and ambiguous paths, links,
special entries, duplicate and case-colliding names, expansion and quota abuse,
arbitrary route input, cross-tenant reads, interrupted activation, failed Caddy
reload, concurrent deployment, repeated correlation IDs, and restore followed
by reconciliation. Tests must also prove that the provisioner cannot invoke or
simulate the operator-authenticated emergency deletion path, modify manifests
or observed state, or truncate, replace, or remove audit evidence.

Archive-parser fixtures include stored and Deflate success; BZIP2, LZMA with an
oversized dictionary request, Deflate64, unknown methods, malformed end and
central-directory records, overlapping or overflowing offsets, excessive
metadata, and disagreement between central and local flags, methods, names,
CRC, or sizes. Installed-host tests exhaust each process limit and verify failed
staging cleanup, an audit result, no publication, and continued Caddy and backup
service health.

Path fixtures cover NFC-normalization and case-fold collisions, strict UTF-8 and
ASCII flag behavior, 255/256-byte components, 1,024/1,025-byte paths, 32/33
components, explicit and implicit directory accounting, file/directory
collisions, and all separator and dot-component forms. Structural fixtures
cover multiple or misplaced end records, prepended/trailing bytes, central
directories at and over 8 MiB, comments, bounded allowlisted timestamp extras,
unknown/oversized/malformed extras, ZIP64, record-count mismatch, overlapping or
aliased regions, gaps, and every checked-arithmetic boundary.

Lifecycle concurrency tests delay an active-state rollback until after
suspension commits and prove that it can update only the remembered deployment,
leaves both routes absent, and requires a later explicit `resume` to publish.
They also race two creates, and a create against a rename, for the same slug and
prove that exactly one root-owned state transaction can commit the name.
Table-driven tests cover every lifecycle operation against every absent,
undeployed, active, suspended, and archived source, including idempotent
same-state requests and every fail-closed cell. Deploy and rollback while
suspended must change only the remembered deployment; rename while archived
must fail rather than invalidate bound archive evidence.

Origin tests activate tenant A, record its canonical UUID-derived hostname,
rename it, and assign the released slug to tenant B. They prove B's alias
redirects to a different canonical origin while A's content route and browser
origin remain unchanged. Repeat the handoff after ordinary deletion and prove
the deleted canonical hostname is not routed or reassigned. Suspension and
archive remove both route classes, while resume and restore republish both for
the same tenant ID.

Alias tests prove only an exact `GET` or `HEAD` for a current active slug's bare
root receives the fixed `302`; it includes `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`, sets no cookie, and derives its destination only
from root-owned tenant state. Paths, queries, other methods, unknown or inactive
slugs, and attempts to supply a redirect target never reach tenant content.
Browser acceptance verifies no tenant can register a service worker or store
tenant-controlled state at a slug alias and that alias reassignment exposes no
state from the preceding canonical origin. Logging tests send sensitive path,
query, cookie, authorization, and referrer values to aliases and prove none
persist in access logs or diagnostics.
Export concurrency tests overlap snapshot capture with deploy, rollback,
rename, suspension, and garbage collection. Every resulting bundle must contain
a canonical manifest and immutable release from the same generation, and the
captured release must remain available until export construction completes.
They flood concurrent export and archive requests, leave work interrupted at
each staging phase, and fill both byte and inode allowances. Tests prove one
global construction slot, one unacknowledged result, hard spool and free-space
admission limits, startup cleanup, expiry, acknowledged cleanup, and idempotent
retry without an additional snapshot.

Lock-schedule tests exercise every permitted pair and triple of export,
publication, and tenant-state acquisition, including backup, archive, Ansible,
Caddy restart, and ordinary lifecycle operations. They prove the global order,
non-blocking busy response, absence of leaked waiters, and archive rejection if
its source generation changes between snapshot and exclusive commit.

Export fixtures give tenant content each reserved metadata basename and prove
that round-trip restore preserves it below `content/`. Negative fixtures cover
metadata outside the versioned envelope, duplicate metadata, unknown envelope
entries, checksum mismatch, and using an export as an ordinary deployment ZIP.
Golden export fixtures assert the complete ZIP bytes, including JSON and
checksum serialization, member and central-directory order, timestamps, flags,
modes, CRC and size fields, lack of extras/comments/descriptors/ZIP64, and final
archive digest. Repeated processes and supported hosts must produce the same
bytes from the same snapshot. The fixture parser also compares every fixed
numeric local-header, central-directory, and end-record field rather than
relying only on successful extraction.

Lifecycle tests delete a never-deployed reservation through the ordinary
audited path, then prove that any deployment record or ambiguous history makes
the same archive-free operation fail closed without requiring or exposing the
emergency command.

Deletion tests archive, restore, and deploy a newer generation, then prove the
old archive record cannot authorize deletion. They independently alter every
bound archive-evidence field and prove delete fails closed until the current
canonical manifest and deployment have a freshly verified durable bundle.
Archive failure-injection tests terminate the activator after bundle upload,
archive-record staging, intent commit, no-route selection, Caddy reload,
authoritative archive-record and manifest commit, observed-state commit, and
audit append. Run every phase from both `active` and `suspended`. Startup
reconciliation must produce only the exact preceding manifest, observed state,
remembered deployment, runtime generation, and route set or the archived
manifest and absent routes. In particular, no failure or recovery path may
publish either route for a suspended source; only a later explicit `resume` may
do so.

After CI and disposable-host acceptance pass, publish a reserved production
canary in the approved origin-isolated tenant namespace. Verify browser
registrable-domain behavior, the platform-only alias redirect, canonical HTTPS,
rollback, suspension, restore, backup recovery, and idempotence, and remove all
canary state through the same operator interface. Dynamic or destructive
isolation tests remain off the production host.

## Consequences

The implementation is split along contract and trust boundaries instead of
arriving as one massive pull request. CI takes longer, but most review findings
are reproducible before production. The canary drill provides evidence for the
Milestone 3 exit criterion without onboarding a real tenant.

Production acceptance requires an explicit operator action from the trusted
workstation, as in Milestone 2. Sanitized results should be recorded without
tenant content, credentials, or backup metadata.

## Alternatives considered

One end-to-end implementation pull request was rejected because privilege and
state-model problems would be difficult to isolate. Unit tests without an
installed-host scenario were rejected because ownership, Caddy, and systemd are
material boundaries. Running destructive hostile tests on production was
rejected because a disposable environment can exercise them safely.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [Static-publication threat model](../threat-model/static-publication.md)
