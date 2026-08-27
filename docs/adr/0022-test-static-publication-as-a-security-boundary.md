# 0022: Test static publication as a security boundary

- Status: accepted
- Date: 2026-08-22

## Context

Milestone 3 combines parser, filesystem, privilege, edge, routing,
concurrency, and recovery behavior. Unit tests alone cannot demonstrate the
installed ownership, Cloudflare, Caddy, systemd, backup, or host-reboot
boundaries, while production-only testing would discover security and
destructive-lifecycle failures too late.

## Decision

Deliver Milestone 3 through these reviewable layers:

1. threat model, ADRs, schema, fixtures, and test matrix;
2. authenticated job issuance, root-domain manifest generation and validation,
   slug and immutable-origin rules, and desired/observed state;
3. hostile archive validation and deterministic portable export/import;
4. root-owned immutable release activation and generated Caddy routing;
5. lifecycle commands, reconciliation, rollback, and audit records;
6. backup locking and restored-state reconciliation; and
7. disposable Cloudflare-edge and host integration followed by a production
   canary acceptance drill.

Use unit and property-based tests for schemas, normalization, archive limits,
state transitions, idempotency, and route generation. Use process-level tests
for concurrent operations and failure injection at every publication commit
step. Use Molecule and Testinfra to exercise actual Unix identities,
permissions, immutable releases, the privileged helper, Caddy validation and
reload, backup overlap, restore, and reboot-relevant service configuration.

The contract layer includes a minimal root-domain package so its canonical
manifest vectors come from the real producer rather than a test substitute.
Its UUIDv7 generator receives injected clock and entropy sources, and its pure
constructor accepts no caller-selected identity or origin. Tests prove the
package performs no persistence, lifecycle transition, or authorization. Later
host-agent and installed-host layers prove only the privileged boundary can use
its output to write authoritative state.

While static publication is disabled, real-SSH installed-host tests prove the
forced-command restrictions and rejection of every external tenant request
before artifact acceptance or job allocation. Unit and process suites exercise
successful immutable issuance, handoff, recovery, and result delivery against
mutation-free test state; no production-visible override bypasses the gate.
Repeat the successful installed-host job-lifecycle cases only after the
disposable host has publication enabled and the lifecycle handlers exist.

Client create-spec fixtures include duplicate YAML slug or quota keys and prove
local rejection occurs before request construction. The corresponding host
suite bypasses the supported client, submits duplicate structured-request
member names, and proves rejection occurs before schema validation, correlation
lookup, or canonicalization. It also proves no operation accepts a standalone
manifest frame and that root-generated, restored, and bundle-embedded manifest
bytes pass strict JSON validation and the canonical 16-KiB limit. Slug fixtures
cover 1- and 63-byte valid labels, reject empty and 64-byte labels, and verify
the complete alias-hostname limit. They also
append LF, CR, CRLF, NUL, spaces, non-ASCII, and other control characters and
prove both schema validation and the independent root ASCII `fullmatch` reject
them before uniqueness or persistence. Tenant-ID fixtures prove `create`
rejects a caller-supplied ID, generates a UUIDv7, derives the canonical
hostname without hyphens, and enforces its complete DNS length independently
of the alias.

As lifecycle handlers arrive and publication is enabled only on the disposable
host, an installed-host concurrency test pauses tenant activation while Ansible
has host-only Caddy inputs staged but has not acquired publication. The core
lifecycle phase commits deploy, rollback, suspension, resume, rename, and
reconciliation independently in that window. The archive phase extends the
same fixture with restoration and deletion. Every case proves the host
transaction rereads authoritative state and builds and validates its final
route-bearing generation only after it holds the lock.
Only one transaction can select a complete runtime generation and own a reload
or restart intent at a time. At every durability phase the test kills Caddy to
trigger automatic restart and proves the recovery gate and launcher select one
manifest-verified generation, never stale tenant routes or a mixed binary,
environment, base configuration, or route set. The resulting Caddy
configuration and observed tenant state must describe the same committed
generation.

Before that lifecycle-integrated test is available, the platform-only layer
tests generation construction, selection, restart and recovery, descriptor
pinning, retention, failure injection, bootstrap interruption, and Ansible
overlap using host-only inputs. It keeps publication disabled and proves every
tenant-bearing generation fails closed rather than claiming lifecycle coverage.

Restart-handoff tests pause after intent creation, active-reference selection,
non-blocking job submission, pre-start transition, launcher pinning,
post-start health verification, rollback selection, and recovery restart.
They prove the initiating transaction never retains the publication lock while
systemd needs it, later mutations return busy while intent is nonterminal, a
lost or duplicated job submission is idempotent, and every crash converges on
the complete candidate or preceding generation. Candidate and
last-known-good start failures must preserve intent and evidence, stop after the
single candidate and single recovery target transitions, and never enter an
unbounded automatic restart loop. Tests prove the unit pins three attempts per
target and a 60-second rate-limit interval. For every automatic retry, they
require a new invocation ID, durably record the preceding failed attempt, and
rebind only the same selected generation before its launcher runs. Delayed or
duplicated pre-start and post-start callbacks for every earlier invocation must
fail without advancing intent. Tests exhaust the candidate attempt and systemd
start-rate limits, prove the recovery helper durably selects the preceding
generation before releasing the lock, then require `reset-failed` to complete
before its non-blocking recovery start. They interrupt both commands and prove
reconciliation repeats them idempotently without refunding an attempt,
selecting another generation, duplicating a pending job, or leaving a healthy
prior generation blocked by the candidate's exhausted counter. Exhausting all
three recovery attempts leaves one nonterminal intent and no further automatic
target transition.

Ordinary-start tests begin with no intent and exercise the first
post-migration start, a normal boot, an explicit stop/start, and an automatic
restart after a previously successful transaction cleared its intent. Before
the launcher runs, the pre-start gate must validate the active generation and
current authoritative route state and durably create an `ordinary-starting`
intent bound to the current invocation. Post-start verifies that binding and
clears it only after committing observed startup-health evidence. Failure
injection around intent creation, parent sync, launcher handoff, verification,
and clearing proves retries remain bound to the same active generation. Tests
exhaust all three attempts and prove neither `OnFailure=` nor reconciliation
selects last-known-good, resets the counter, creates an operation result, or
starts another target. Missing, malformed, stale-route, and unreferenced active
generations fail before Caddy executes.

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
audit or journald. Rotation tests prove an ordinary scheduled snapshot cannot
authorize removal, while a restore-verified
`lowerduckpond-audit-archive` snapshot is excluded from ordinary retention and
is durably indexed before local deletion. They interrupt snapshot creation,
verification, index commit, local removal, `forget`, `prune`, and restore;
enumerate tagged descriptors to recover an unindexed attempt; reject any
missing, ambiguous, retagged, or expiring snapshot; deny provisioner rotation
and administrator-reserve use; and reconstruct the complete ordered audit chain
without losing or duplicating evidence.
Restart and clock-skew tests prove accepted-correlation timestamps reconstruct
the rolling rate window and cannot reset or refund consumed admission.
Free-space fixtures exercise both the absolute and percentage block/inode floors
and prove root-reserved blocks are excluded from admission capacity.

Raw-input tests stream requests at 32 KiB and 32 KiB plus one, an invented
manifest frame, delayed or missing EOF, invalid UTF-8, enormous discardable
whitespace, deep nesting, and oversized scalar syntax. They prove the byte gate
and deadline run before parser entry and correlation lookup, the decoder process
limits terminate adversarial inputs, canonical requests and results still obey
16 KiB, and an established-correlation retry cannot bypass any raw or canonical
limit. Rejection logs and results contain no submitted bytes and stay within
their fixed bounds.

Authorization tests exercise every operator command through the authenticated
SSH issuer and then invoke the provisioner's only sudo entry point directly.
The latter accepts a root-generated job ID only: raw requests, caller-selected
paths, separators, noncanonical or non-UUIDv7 IDs, unknown IDs, and attempts to
invoke the issuer or activator operation entry points fail without allocating a
correlation, job, artifact, result, or audit payload. Requests cannot supply or
spoof the authenticated SSH principal.

The provisioner cannot list, read, create, hard-link, symlink, replace, cancel,
or change the mode of authorization jobs and cannot read an export artifact or
full result.

Field-isolation fixtures alter the job version, job ID, operator, operation,
target, correlation ID, canonical request or digest, artifact size or digest,
explicit artifact absence, and each expected lifecycle, manifest, deployment,
and archive-record binding independently. Every mismatch fails before staging
or mutation. Tests issue a valid job, change target state before execution, and
prove compare-and-swap failure requires a newly authenticated job. They replace
artifact bytes before and after intake publication and prove the independently
computed job digest and immutable activator snapshot detect both cases.

Authorization durability tests terminate the SSH adapter around completed
artifact sync, temporary-job sync, job rename, parent sync, queue handoff, claim,
result commit, and delivery to the authenticated client. Recovery removes an
artifact with no committed job and never authorizes a partial job. A synced job
is the acceptance point: recovery requeues it if still pending or converges it
if claimed, even when the queue handoff or client response was lost. Concurrent
or repeated execution of one job produces one result. A second job with the
same correlation and different binding fails, while an exact retry returns the
established result without consuming capacity. Job envelopes, phases, and
results are filled through the shared 10,000-record/64-MiB ceiling and cannot
create a second unbounded store.

Destructive-chain tests authorize and execute `archive`, then let a compromised
provisioner substitute `delete`, reuse the archive job, invent a correlation,
or submit a raw request. Every attempt fails and the bound archive remains. Only
a separately authenticated `delete` job issued after archive, and bound to the
resulting archived manifest, deployment, and exact archive record, can enter
ordinary deletion. Equivalent tests cover deploy, rollback, suspend, resume,
rename, export, import, restore, and externally requested reconcile; autonomous
root reconciliation remains available without provisioner-created authority.

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
by reconciliation. The same fixtures cover import followed by reconciliation.
Tests must also prove that the provisioner cannot invoke or simulate the
operator-authenticated emergency deletion path, modify manifests or observed
state, or truncate, replace, or remove audit evidence.

Archive-parser fixtures include stored and Deflate success; BZIP2, LZMA with an
oversized dictionary request, Deflate64, unknown methods, malformed end and
central-directory records, overlapping or overflowing offsets, excessive
metadata, and disagreement between central and local flags, methods, names,
CRC, or sizes. Installed-host tests exhaust each process limit and verify failed
staging cleanup, an audit result, no publication, and continued Caddy and backup
service health.

Intake tests stream deploy and import artifacts immediately below, at, and one
byte above their respective 100-MiB and 120-MiB limits. They disconnect and
stall at every transfer phase, race a second transfer and an idempotent retry,
exhaust the host free-space reserve, and terminate the adapter before and after
file and directory sync. At no point may intake hold more than one artifact or
allocated blocks beyond its operation-specific ceiling rounded by one
filesystem block. Every terminal path and startup reconciliation removes the
partial or abandoned inode before reopening admission; an unclassifiable inode
must keep admission closed.

Archive-upload tests instrument the S3-compatible client and fail if managed
archive code calls `CreateMultipartUpload`, `UploadPart`,
`CompleteMultipartUpload`, or a high-level transfer API. Bundles immediately
below, at, and one byte above 120 MiB prove the writer uses one known-length
`PutObject` only within the limit. Faults before request transmission, during
body transmission, after remote commit but before response delivery, and before
the local `uploaded` phase prove reconciliation sees either no version or one
complete version and never clears the reserved charge prematurely. The
installed-host exercise lists incomplete multipart uploads below `archives/`
before and after these cases and requires none. An expendable injected multipart
upload proves reconciliation detects and accounts for its exact upload identity,
closes archive admission, explicitly aborts it through the cleanup boundary, and
confirms absence before admission can reopen. Changing the SDK or upload path
must preserve these assertions; no lifecycle cleanup backstop exists.

Path fixtures cover NFC-normalization and case-fold collisions, strict UTF-8 and
ASCII flag behavior, 255/256-byte components, 1,024/1,025-byte paths, 32/33
components, explicit and implicit directory accounting, file/directory
collisions, and all separator and dot-component forms. They prove an exactly
spelled explicit directory plus one or many descendants' identical implicit
parent coalesces and consumes one entry, while a duplicate explicit record or
an explicit/implicit pair with distinct pre-NFC spelling that collides after NFC
or case folding fails. Structural fixtures
cover multiple or misplaced end records, prepended/trailing bytes, central
directories at and over 8 MiB, comments, bounded allowlisted timestamp extras,
unknown/oversized/malformed extras, ZIP64, record-count mismatch, overlapping or
aliased regions, gaps, and every checked-arithmetic boundary.
Deployment, import, and restore fixtures also reject `cdn-cgi` as the
case-insensitive normalized first tenant component before release construction.

Portable-artifact fixtures for import and restore separately exercise
regular-file envelope names at 1,056/1,057 bytes, directory names including
their marker at 1,057/1,058 bytes, depths 34/35, central-directory record counts
5,004/5,005, and raw member data at 106 MiB and one byte over. Canonical round
trips with 1,024-byte,
32-component tenant file and directory paths—including the directory's added
marker—and another with 5,000 tenant entries must pass the raw gate and then the
unchanged tenant validator. Every canonical bundle's explicitly emitted
directory records must coalesce with its descendants' exact implicit parents
and round-trip without changing the counted tenant tree. Fixed metadata or the
implicit envelope root cannot
consume tenant quota, while a fifth envelope record, metadata over its own
bound, or a tenant subtree over any ordinary limit must fail before extraction.

Lifecycle concurrency tests delay an active-state rollback until after
suspension commits and prove that it can update only the remembered deployment,
leaves both routes absent, and requires a later explicit `resume` to publish.
They repeatedly deploy and roll back while suspended and prove each committed
remembered deployment triggers the same three-release cleanup without
publishing either route. Cleanup must preserve releases pinned by an export or
intent, recover after interruption, and remove them once the pin clears without
letting one tenant consume the host-wide release allowance.
They also repeat archive and restore beyond the retention window, interrupt
cleanup after every removal and directory-sync boundary, and prove each
successful restore retains only its selected release and two deployment
predecessors. Export, lifecycle, and retirement pins survive; once cleared,
startup reconciliation removes every superseded release without republishing a
route or disturbing the restored deployment.
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

Dual-domain browser tests serve hostile JavaScript from tenant A below
`lowerduckpond.com` and a controlled fixture below `lowerduckpond.net` through
Cloudflare's public edge and the authenticated Caddy origin. They
prove `.com` cannot create, replace, read, or receive the fixture's host-only
`.net` cookie and that requests between the domains are cross-site. They also
record the accepted limitation by proving A can create a
`Domain=lowerduckpond.com` cookie visible at tenant B. Installed-host tests then
prove Caddy removes `Cookie` before every static tenant handler, removes every
tenant-controlled `Set-Cookie` before the response reaches Cloudflare for every
tenant, alias, unknown-host, and `.com` apex response,
sets `Cache-Control: no-store` on every `.com` apex redirect and fallback,
never varies a route or body by those cookies, and never logs their values.
Browser tests prove a correctly formed, case-sensitive `__Host-` cookie remains
bound to its exact tenant host even when a sibling uses the same unprefixed or
ordinary cookie names. Oversized or quota-exhausting cookie behavior is
recorded as a per-browser residual risk, not misreported as isolation.

Cloudflare may add its own documented security cookies after the origin
response. Tests distinguish those provider-controlled values from tenant
output, and Lower Duck Pond never treats them as application authentication or
authorization.

Live edge tests prove both public zones use proxied DNS, Full (strict) origin
TLS, account-specific Authenticated Origin Pulls, explicit cache bypass, and an
API-observed disabled Always Online setting. The read-only M3.0 preflight stops
if either zone has Always Online enabled rather than mutating zone-wide state.
The installed origin must reject direct HTTPS, any client certificate not
issued by the project CA, spoofed forwarding headers, and traffic from outside
the reviewed Cloudflare network set. Port 80 admits only that network
set and can only redirect or reject; it never returns tenant bytes. Repeated
edge requests prove no route, redirect, error, platform response, or tenant
body is served from cache in Milestone 3, while method, path, query, host, and
alias semantics remain unchanged. Making only the disposable origin
unavailable must produce a documented Cloudflare origin-unavailable `520`–`527`
status and never a tenant, platform, stale-cache, or Internet Archive
representation. Tests separately identify the public edge
certificate and the Caddy origin certificate so one cannot substitute for the
other. A disposable rollover test installs both old and replacement origin-pull
CA certificates, moves the edge to the replacement leaf, proves both rollback
and forward paths, then removes the old CA and proves its leaf is rejected.
Origin-versus-edge fixtures include email addresses, strict CSP, scripts,
fonts, insecure-looking URLs, and analytics-shaped markup; they require
`no-transform`, disabled optional transformations, and byte-identical bodies
without injected provider markup. A separate provider-security fixture may
return a Cloudflare block or challenge but cannot be mistaken for tenant
content or cached. Requests to `/cdn-cgi`, `/cdn-cgi/trace`, descendants, case
variants, and encoded lookalikes prove the managed WAF blocks the reserved
namespace before Caddy and exposes no diagnostic body.

Import identity tests export active, suspended, and archived tenant A fixtures,
create an undeployed tenant B through the ordinary serialized slug-allocation
path, and import each portable bundle into a fresh target. They prove every content path
and byte round-trips while the target retains its own tenant ID, canonical
origin, slug, runtime, and quotas and receives a new deployment ID. Alter each
embedded source identity, origin, slug, quota, deployment, and lifecycle field
independently and prove none can become target state. Import to an absent, active, suspended, or
archived target fails without publication; an exact correlation-and-bundle
retry converges, while a new correlation after activation fails. A separate
fixture releases A's slug, reserves it normally for B, imports the bundle, and
proves the reused alias points only to B's distinct canonical origin.
Concurrency fixtures pause import after validation, then rename the undeployed
target or change its quotas. Commit must re-read current target state, publish
only its current alias if the measured content still fits, and otherwise fail
without a release or route; it never applies embedded or stale target policy.

Namespace tests initialize the root-owned platform record only with completely
empty tenant state and history, then create a tenant and prove the suffix cannot
be reinitialized even after ordinary deletion. They alter configured suffix,
persisted suffix, and `metadata.canonicalOrigin` independently across Ansible
convergence, activator startup, reconciliation, export/import/restore, and
disaster recovery. A missing record alongside tenant history and every
disagreement must fail closed before selecting a new Caddy generation;
restoring the matching record must reproduce the exact preceding canonical
origin.

Alias tests prove only an exact `GET` or `HEAD` for a current active slug's bare
root receives the fixed `302`; it includes `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`, sets no cookie, and derives its destination only
from root-owned tenant state. Every alias response, including every `404`, must
carry `Cache-Control: no-store`. Run the complete matrix over both HTTP and
HTTPS. A qualifying HTTP request redirects directly to the canonical HTTPS
origin, without an intermediate alias upgrade; paths, queries, other methods,
unknown or inactive slugs, and attempts to supply a redirect target receive the
generic scheme-local `404` with no `Location` and never reach tenant content.
Fixtures prove no alias path or query appears in an HTTP response header or
body. Lifecycle tests first receive an alias `404`, then deploy, resume,
restore, rename, or reassign the slug and prove the next request observes the
new redirect rather than a cacheable negative response.
Browser acceptance verifies no tenant can register a service worker or store
tenant-controlled state at a slug alias and that alias reassignment exposes no
state from the preceding canonical origin. Logging tests send sensitive path,
query, cookie, authorization, and referrer values to aliases and prove none
persist in access logs or diagnostics.
The Cloudflare-owned `/cdn-cgi/` namespace is the sole exception to the Caddy
alias `404` body: edge tests require the managed provider denial and prove the
request never selects an alias or tenant route.

Export concurrency tests overlap snapshot capture with deploy, rollback,
rename, suspension, and garbage collection. Every resulting bundle must contain
a canonical manifest and immutable release from the same generation, and the
captured release must remain available until export construction completes. An
ordinary export must bundle the captured current manifest. An archive from
either active or suspended must retain that source manifest only as private
compare-and-swap evidence and put the derived proposed archived manifest in
`manifest.json`. Mutating any source field before commit must abort and remove
or quarantine the unreferenced object without creating an archive record.
They flood concurrent export and archive requests, leave work interrupted at
each staging phase, and fill both byte and inode allowances. Tests prove one
global construction slot, one unacknowledged result, hard spool and free-space
admission limits, startup cleanup, expiry, acknowledged cleanup, and idempotent
retry without an additional snapshot.

Remote archive failure injection terminates construction before and after
construction-intent sync, during upload, after remote success but before the
`uploaded` phase, after that phase, and across lifecycle-intent reconciliation
and authoritative archive-record commit. Recovery must discover the exact
unique key from durable local state, recover the returned version ID or list the
key when that phase was not synced, and preserve a version only when the
reconciled authoritative record binds its bucket, key, and version ID.
Versioning fixtures require cleanup to permanently delete every data version
and delete marker and confirm an empty version listing; an unversioned delete
that only creates a marker must leave construction or quarantine charged and
archive admission closed. Repeated source-change aborts, crashes, and retries
must never retain more than the one classified object under cleanup.

Remote-retirement tests interrupt restore, ordinary deletion, and emergency
deletion of archived state before and after retirement-intent sync, lifecycle
intent creation, authoritative-state and audit commit, each version-specific
delete, absence confirmation, cleanup-result commit, and intent removal. They
prove a still-bound version is never deleted; a committed unbinding eventually
purges every version and marker for the unique key; and an ambiguous or failed
cleanup remains durably charged and blocks another archive. Admission fixtures
fill the managed prefix to 25 unique keys, 25 total data versions or delete
markers, and 3,000 MiB, then test each boundary with the reserved 120-MiB upload.
They include unknown and noncurrent versions, markers, interrupted accounting,
and repeated restore/re-archive cycles and prove no process restart, lifecycle
retry, or storage rule can exceed or refund the hard remote allowance.

Lock-schedule tests exercise every permitted pair and triple of export,
publication, and tenant-state acquisition, including backup, archive,
archive-retiring restore and deletion, Ansible, Caddy restart, and ordinary
lifecycle operations. They prove the global order, non-blocking busy response,
absence of leaked waiters, and archive rejection if its source generation
changes between snapshot and exclusive commit.

Export fixtures give tenant content each reserved metadata basename and prove
that round-trip import preserves it below `content/` for ordinary and archived
exports. Negative fixtures cover
metadata outside the versioned envelope, duplicate metadata, unknown envelope
entries, checksum mismatch, and using an export as an ordinary deployment ZIP.
Golden ordinary-export and archive fixtures assert the complete ZIP bytes,
including their respective current or proposed archived manifest, JSON and
checksum serialization, member and central-directory order, timestamps, flags,
modes, CRC and size fields, lack of extras/comments/descriptors/ZIP64, and final
archive digest. Repeated processes and supported hosts must produce the same
bytes from the same snapshot. The fixture parser also compares every fixed
numeric local-header, central-directory, and end-record field rather than
relying only on successful extraction.

Digest fixtures assert every byte of the manifest-v1 and release-tree-v1 domain
separators, big-endian lengths, type tags, entry count, normalized path order,
and file content. They distinguish path/content concatenation collisions,
include empty and implicit directories, vary creation order and discarded
filesystem metadata, and cover zero and maximum lengths and counts. Golden
values must survive process and activator upgrades; an unknown format or
algorithm fails closed rather than being recomputed with current defaults.

Lifecycle tests delete a never-deployed reservation through the ordinary
audited path, then prove that any deployment record or ambiguous history makes
the same archive-free operation fail closed without requiring or exposing the
emergency command.

Deletion tests archive, restore, and deploy a newer generation, then prove the
old archive record cannot authorize deletion. They independently alter every
bound archive-evidence field and prove delete fails closed until the current
canonical manifest and deployment have a freshly verified durable bundle.
They also prove successful restore and deletion retain the prior object through
the authoritative commit, then retire it without losing the digest and object
identity recorded in immutable audit evidence.
Archive failure-injection tests terminate the activator after bundle upload,
archive-record staging, intent commit, no-route selection, Caddy reload,
authoritative archive-record and manifest commit, observed-state commit, and
audit append. Run every phase from both `active` and `suspended`. Startup
reconciliation must produce only the exact preceding manifest, observed state,
remembered deployment, runtime generation, and route set or the archived
manifest and absent routes. In particular, no failure or recovery path may
publish either route for a suspended source; only a later explicit `resume` may
do so.

After CI and disposable edge-and-host acceptance pass, publish a reserved
production source canary in the approved untrusted `.com` tenant namespace, then import
its export into a separately created undeployed target. Verify the `.com` to
`.net` browser boundary, the documented sibling-cookie behavior and Caddy
stripping, Cloudflare cache bypass, authenticated-origin enforcement,
Always Online disabled, forwarded-header authenticity, the platform-only alias
redirect, canonical HTTPS, rollback, suspension, backup recovery, reboot, and
idempotence for the resulting two
tenants. Archive, restore, rearchive, and ordinarily delete the source;
separately archive and ordinarily delete the imported target. Prove both route
classes are absent for both tenants and every bound archive object is retired
while audit evidence remains. Dynamic or destructive isolation tests remain
off the production host.

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
installed-edge and installed-host scenario were rejected because Cloudflare
configuration, ownership, Caddy, and systemd are material boundaries. Running
destructive hostile tests on production was rejected because a disposable
environment can exercise them safely. Treating the current direct-origin
qualification as public-traffic evidence was rejected because it cannot
demonstrate proxy, cache, client-certificate, source-network, or
forwarding-header behavior.

## References

- [0016: Model static publication as an untrusted boundary](0016-model-static-publication-threats.md)
- [0017: Atomically activate immutable static releases](0017-atomically-activate-static-releases.md)
- [0023: Separate reusable slugs from immutable tenant origins](0023-separate-reusable-slugs-from-tenant-origins.md)
- [0024: Separate trusted platform and untrusted tenant domains](0024-separate-platform-and-tenant-domains.md)
- [0028: Use Cloudflare as the public web edge](0028-use-cloudflare-as-the-public-web-edge.md)
- [Static-publication threat model](../threat-model/static-publication.md)
