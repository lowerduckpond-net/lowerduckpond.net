# Milestone 3 implementation plan

- Status: implementation in progress; M3.0 qualification complete
- Updated: 2026-08-27
- Outcome: deliver the complete static-tenant lifecycle through the trusted
  workstation without enabling the Milestone 4 public control plane

## 1. Scope and fixed decisions

Milestone 3 implements the contracts accepted in ADRs 0016 through 0028. Five
implementation defaults that were unresolved when the original design was
accepted are now fixed:

1. `lowerduckpond.net` is the trusted platform domain and
   `lowerduckpond.com` is the untrusted tenant domain. No PSL submission or
   recognition is assumed. The public platform website is served directly at
   the `.net` apex, `hosting` and `www` redirect there, and `secure` is reserved
   for the future trusted application. Reusable `<slug>.lowerduckpond.com`
   aliases remain platform-controlled, and tenant bytes are served only from
   immutable `t-<tenant-uuid-without-hyphens>.lowerduckpond.com` origins. The
   `.com` apex is a stateless, non-cacheable `404` until Milestone 7 designates
   an ordinary municipal tenant by immutable ID. Caddy ignores incoming cookies
   and removes outgoing `Set-Cookie` on all Milestone 3 `.com` routes. Trusted
   generated handlers originate no cookies, untrusted proxy responses receive
   an immediate blanket scrub, and the enclosing response scrub is defense in
   depth. No cookie allowlist exists in M3; sibling browser-local cookie
   integrity remains an accepted static-tier limitation.
2. Tenant archives use a separate private, versioned production Space and a
   dedicated bucket-only key. They do not share the Restic bucket or key.
3. Routine operations use a dedicated-key, forced-command `ldp-operator`
   account. `ldp-admin` remains the Ansible and emergency-administration
   identity.
4. `static_publication_enabled` defaults to false and stays false in production
   until the complete acceptance gate passes.
5. Cloudflare is the public HTTP/HTTPS edge for both zones. Caddy remains the
   application origin behind Full (strict) TLS, account-specific Authenticated
   Origin Pulls, and Cloudflare-only web ingress. Milestone 3 explicitly bypasses
   Cloudflare caching for every route and keeps Always Online disabled; cache,
   stale-serving policy, and lifecycle-aware purging remain a Milestone 5
   feature. Administrative SSH continues directly to the reserved address
   through its separate CIDR allowlist.

The milestone includes static manifests, archive admission, immutable releases,
generated Caddy routes, authorization jobs, trusted-workstation commands,
lifecycle operations, exports, imports, remote archival, reconciliation,
backup coordination, audit retention, and the production canary.

It does not include public FastAPI endpoints, customer authentication, a portal,
a database-backed job queue, renewal scheduling, custom domains, PHP, tenant
SQL, or real-customer onboarding. Those remain Milestones 4, 6, and 7.

## 2. Component and repository boundaries

Add these components without moving Milestone 4 concerns into the privileged
host:

```text
clients/
└── operator/
    ├── pyproject.toml
    ├── src/lowerduckpond_operator/
    └── tests/
packages/
├── static-contracts/
│   ├── pyproject.toml
│   ├── src/lowerduckpond_static_contracts/
│   └── tests/
└── static-domain/
    ├── pyproject.toml
    ├── src/lowerduckpond_static_domain/
    └── tests/
services/
├── host-agent/
│   ├── pyproject.toml
│   ├── src/lowerduckpond_host_agent/
│   └── tests/
└── provisioner/
    └── existing package, narrowed to opaque authorized-job execution
schemas/
└── static-publication/v1alpha1/
tests/
└── static-publication/
    ├── fixtures/
    ├── integration/
    ├── qualification/
    └── browser/
config/ansible/roles/
├── static_host_agent/
└── static_operator/
```

`static_contracts` contains version identifiers, strict schema loading,
canonical JSON, typed protocol values, digest representations, and result/error
codes that the client and host must agree on. It contains no filesystem,
privilege, lifecycle, or authorization behavior.

`static_domain` owns UUIDv7 tenant-ID generation and the pure canonical-origin
and manifest constructor. It accepts injected clock and entropy sources but has
no persistence, lifecycle-transition, authorization, or other I/O behavior.
Only the host-agent uses its output to write authoritative state; the operator
and provisioner do not import it.

`host-agent` is the privileged trusted computing base. It owns authoritative
state, validation, archive parsing, extraction, publication, lifecycle,
authorization jobs, results, audit, and reconciliation. It exposes separate
entry points for the forced-command issuer, the exact authorized-job executor,
systemd Caddy hooks, autonomous reconciliation, and root-only emergency tools.

`provisioner` receives an opaque root-generated job ID, performs only bounded
non-authoritative preflight, invokes the one sudo-allowed executor command, and
returns bounded status. It cannot import the host-agent implementation, read
its state, or originate a request.

`operator` validates local inputs, generates the correlation UUIDv7, frames the
request and optional artifact, invokes the forced SSH command, and verifies the
versioned response. It never derives authoritative state or edits the host.

## 3. Installed host layout

Ansible creates this root-owned layout. All paths are constants in host-agent
code; no request supplies a path component.

```text
/opt/lowerduckpond/static-host-agent/<version>/  # immutable installed code
/opt/lowerduckpond/static-host-agent/current     # root-selected version ref
/var/lib/lowerduckpond/static/
├── platform/                 # namespace and launch records
├── tenants/<uuid>/
│   ├── desired.json
│   ├── observed.json
│   ├── deployments/
│   └── archives/
├── authorization/
│   ├── jobs/
│   ├── results/
│   └── correlations/
├── intents/                  # lifecycle, publication, archive, retirement
├── intake/                   # one bounded root-owned artifact slot
├── exports/                  # bounded authenticated-delivery spool
├── audit/                    # hash-chained segments and protected index
└── locks/                    # export, publication, tenant-state, intake
/srv/lowerduckpond/sites/<uuid>/releases/<deployment-uuid>/
/etc/caddy/
├── generations/<generation-uuid>/
├── active
└── intents/
```

Desired state, observed state, deployment and archive records, authorization
evidence, lifecycle intents, platform records, audit indexes, and immutable
releases are backed up. Intake, delivered or expired exports, Caddy runtime
generations, sockets, caches, environment files, and other reconstructible or
secret-bearing runtime data are explicitly excluded.

Files use root ownership and minimum required modes. Caddy receives read and
traverse access only to the selected releases and selected generation inputs.
`ldp-provisioner` and `ldp-operator` receive no directory access to the
authoritative tree.

## 4. Wire, job, and process contracts

The SSH protocol is binary framed so an artifact cannot be confused with a
request suffix. Version 1 uses a fixed magic/version, a network-order request
length, an explicit artifact-present flag and network-order artifact length,
the structured request bytes, optional artifact bytes, and required EOF. The
adapter rejects an unknown version or impossible length before parser entry,
then independently decodes, validates, and canonicalizes the request rather
than trusting client serialization. The response uses the same versioned
framing for a bounded canonical result and an optional authenticated export
payload.

There is no manifest frame. No operation accepts a caller-supplied desired
manifest: root derives every candidate manifest from the validated request and
authoritative source state, while import treats the source manifest inside its
portable bundle only as provenance. The raw request is limited to 32 KiB plus
one detection byte; canonical requests, results, and root-generated desired
manifests remain limited to 16 KiB. Deploy and import streams retain their
100-MiB and 120-MiB ceilings, idle deadline, total deadline, single-slot
allocation, and host free-space reserve from ADR 0020.

Every successful issuer call creates one immutable authorization job containing
at least:

- schema version and root-generated UUIDv7 job ID;
- root-configured operator principal and caller correlation UUIDv7;
- exact operation, target UUID or create-expects-absence condition;
- canonical request bytes and versioned digest;
- artifact absence or exact size and digest;
- expected lifecycle, manifest, deployment, archive-record, and platform-state
  digests applicable to the operation; and
- accepted timestamp, bounded phase, and compatibility version.

The job's synced parent-directory rename is the acceptance point. A templated
systemd job service runs as `ldp-provisioner` with only that UUID instance. Its
only privilege is the fixed sudo-selected `execute-authorized-job` executable;
that isolated root-owned parser accepts exactly one canonical UUIDv7 argument.
The root executor opens and verifies the job without following links, durably
claims it, independently revalidates all bindings, and commits one immutable
result. A lost handoff or SSH response is recovered by correlation and job
reconciliation, never by reconstructing authority from an artifact.

## 5. Delivery sequence

Every numbered phase is a separately reviewable PR unless a phase is split
further. A PR must deliver one complete proof obligation; unrelated cleanup is
deferred. Production remains dark through phases 0–11.

### M3.0: qualify dangerous platform assumptions

Implementation status: complete. The explicitly authorized live qualification
passed all 54 required checks on 2026-08-27 against source revision
`17418c8976e8a26fb46e6caa879e8e5fef4be229`. Run
`01a04330-42aa-77b5-8748-c154bfcf2270` produced a sanitized report with SHA-256
`2c4eb6abf902220900375c0dc8823730dbed09fb0c3deb5543c72f7cf898c4f9`.
Teardown destroyed all 17 OpenTofu resources, left the encrypted remote state
empty, and independently confirmed the Droplet, firewall, project assignment,
four DNS records, four Authenticated Origin Pulls associations, six rulesets,
ACME records, and four uploaded leaves absent. Both temporary Cloudflare tokens
were revoked and disposable trusted-workstation material was removed. The
backed-up CA roots remain retained pending the production-CA decision required
before M3.12. M3.1 subsequently completed, and M3.2 is the next implementation
phase; the M3.0 result does not enable production or satisfy any later
Milestone 3 gate.

Add executable qualification probes and a sanitized report before depending on
host behavior that the current Molecule suite does not reproduce.

Deliver:

- verify ownership, registration auto-renewal, and authoritative Cloudflare
  service for both domains; add a
  browser harness proving `.com` content cannot set or receive `.net` cookies,
  proving the two domains are cross-site, and recording that sibling `.com`
  tenants can share a parent-domain cookie without misreporting that residual
  behavior as isolation;
- provision the four disposable hostnames as proxied records, identify both the
  Cloudflare edge certificate and Caddy origin certificate, and prove Full
  (strict) validation, account-specific Authenticated Origin Pulls, and
  Cloudflare-only ingress over the reviewed provider network set; issue the
  disposable origin-pull leaf for 30 days immediately before upload and reject
  or reissue it locally if fewer than 14 full days remain;
- prove a direct connection, any client certificate not issued by the project
  CA, and spoofed forwarding headers cannot reach tenant or platform content;
  trust the forwarded visitor address only on the authenticated edge path;
- prove project-CA rollover by staging dual trust, moving the disposable edge
  from an old leaf to a replacement-CA leaf, verifying rollback before the
  switch commits, then retiring the old leaf and trust anchor;
- set explicit cache bypass for both zones and prove repeated platform, tenant,
  alias, unknown-host, redirect, and error requests are not served from edge
  cache; keep port 80 edge-only and limited to redirect or rejection while
  preserving method, path, query, host, and alias semantics;
- read and require `always_online = off` on both zones without changing that
  zone-wide state, then make only the disposable origin unavailable and prove
  Cloudflare returns a documented origin-unavailable `520`–`527` status rather
  than tenant, platform, stale-cache, or Internet Archive content; stop for a
  separate reviewed settings change if either preflight value is enabled;
- disable every optional Cloudflare response-body rewrite and script injection,
  require origin `no-transform`, and compare origin and edge representations;
  distinguish an explicit provider security block from tenant content; use a
  host-agnostic Caddy site address bound only to loopback for the origin-side
  comparison so the reviewed public `Host` values reach their component routes;
- block `/cdn-cgi` and its descendants with the managed zone WAF, prove no
  diagnostic endpoint or request reaches Caddy, and prove archive admission
  rejects the normalized, case-insensitive first path component;
- prove Caddy can remove `Cookie` before static tenant handling, remove
  `Set-Cookie` from every `.com` route class, prohibit trusted generated
  handlers from positively emitting it, strip hostile parent-domain and
  host-only upstream cookies at the proxy boundary, keep routing and bodies
  cookie-independent, and omit cookie values from logs;
- verify the production filesystem type and mount behavior, directory `fsync`,
  atomic same-filesystem rename, hard-link accounting, `O_NOFOLLOW`, and shared
  and exclusive `flock` semantics on a disposable Ubuntu 26.04 host;
- prototype descriptor-pinned Caddy start and reload, its Unix admin socket,
  systemd pre/post hooks, invocation IDs, bounded restart attempts,
  `reset-failed`, and non-blocking recovery handoff;
- prove the installed sudo version selects only one fixed root-owned executable
  and rejects other commands; prove that executable's isolated parser accepts
  exactly one canonical UUIDv7 argument and rejects separators, additional
  arguments, and lookalikes;
- prove a private systemd temporary filesystem enforces both 64 MiB and 4,096
  inodes;
- qualify Python 3.14 support and lock the schema, RFC 8785, property-test, and
  low-level S3 libraries before privileged code imports them; separately lock
  the safe-YAML library used only by the trusted-workstation client's optional
  local `create` specification.

Gate: every technical probe either passes on the production-equivalent stack or
produces an accepted replacement design. The dual-domain browser, Caddy cookie,
Cloudflare proxy, authenticated-origin, cache-bypass, Always Online,
origin-unavailability, direct-origin-denial, forwarded-header,
representation-fidelity, and reserved-path probes are mandatory; there is no
external PSL step. A warning or skipped technical probe is not a pass. The
exact production `.com` apex is
still exercised locally in M3.0 because the disposable boundary may not change
that record; M3.12 repeats the complete edge matrix against the real production
apex and wildcard configuration before enablement.

Rollback: probes use a disposable host, create no tenant state, and select no
production Caddy input. Teardown removes every test record, origin-pull
association and uploaded leaf, edge rule, firewall, project assignment, and
Droplet, then proves the dedicated remote state is empty. It never changes a
production apex, wildcard association, or zone-wide Always Online setting.

### M3.1: provision isolated archive storage

Implementation status: complete. On 2026-08-28, protected plan run
`33216049669` and apply run `33216599520` created exactly two resources, changed
exactly two resources in place, and destroyed none against source revision
`5d0260ed9c81ad1b2918e8ee12958518edca6663`. The fully paginated preflight
proved the retired backup prefix empty immediately before and after apply.
Trusted-workstation acceptance run `01a04a98-a393-714c-9955-a7aa77cc8df8`
passed, its sanitized report and SHA-256 sidecar were verified and backed up,
and an independent version-aware and multipart-aware probe proved the entire
archive bucket empty. Protected run `33219502391` then passed ordinary
production policy and reported no changes with the migration flag disabled.
The archive credential remains in operator custody and off the production host
until M3.10. M3.2 is the next implementation phase; M3.1 does not enable
production or satisfy any later Milestone 3 gate.

Add a `digitalocean-tenant-archives` module rather than renaming the existing
backup module or its state address. Extend the production stack with the second
bucket, dedicated key, sensitive outputs, project assignment, and plan-policy
assertions. Remove the obsolete `archives/` lifecycle rule from the backup
bucket only after a version-aware preflight proves that prefix empty.

The archive bucket enables versioning, prevents destroy, has no current or
noncurrent expiration, and has no lifecycle rule. The pinned provider cannot
express an abort-only rule without an object or version expiration, so managed
code prohibits multipart and qualification explicitly proves that no multipart
uploads exist. M3.1 exposes separately named sensitive archive outputs only for
trusted-workstation retrieval, acceptance, and backup. It neither overloads the
Restic variables nor places the archive credential in an inventory, artifact,
or production-host environment; installation waits for the root-owned archive
component in M3.10.

Immediately before apply, a protected, fully paginated preflight must prove
that the backup bucket's obsolete `archives/` prefix contains no current object,
historical or null version, delete marker, or incomplete multipart upload. Run
the check with the existing protected Spaces operator credential, fail closed
on every ambiguous response, and repeat it after apply.

Gate: a dedicated one-time migration policy permits exactly two creates—the
archive bucket and its one-bucket `readwrite` key—and exactly two in-place
updates—removal of only the backup bucket's `archives-retention` rule and
addition of only the archive bucket URN to the durable project assignment. It
permits no destroy or replacement. After migration, ordinary policy requires
both durable buckets and both independently scoped keys.

After approved apply, acceptance first proves each runtime credential can use
its own bucket and that both list/read and unique-prefix writes are mutually
denied across buckets. If an unexpected cross-bucket write succeeds, capture
and permanently purge its exact returned version before failing. Using only the
dedicated archive credential and an expendable unique qualification prefix,
exercise one small known-length `PutObject`, require a non-null returned version
ID, verify exact-version bytes, perform an unversioned delete, verify its delete
marker while the old exact version remains readable, then force
`ListObjectVersions` pagination with a one-entry page while both entries still
exist. Follow both continuation markers until the data version and marker have
each been observed exactly once. Permanently delete both exact entries only
after that pagination proof. Fully paginated version and multipart listings must
finally establish that the entire new archive bucket—not merely its
current-object view—contains zero versions, markers, and uploads. Finish with a
sanitized acceptance report and a no-change production plan.

Before the live gate, strict fake-client protocol tests, negative saved-plan
fixtures, and a pinned local versioned-S3 integration test must cover pagination,
delete markers, cleanup, and failure after every remote step. Local emulation
cannot replace the live DigitalOcean key-isolation and version-semantics proof.

Rollback: retain the isolated bucket and revoke its key if necessary. If a
failed probe leaves an ambiguous version or marker, preserve and account for it
until version-aware cleanup proves absence. Do not destroy versioned durable
storage as an application rollback.

### M3.2: establish contracts and the test spine

Implementation status: in progress. The first review slice establishes the
standalone `static_contracts` package, strict schema set, canonical and digest
vectors, identifier reservations, lifecycle matrix, client-only YAML
translation, and accepted and hostile fixtures. The separate root-domain
constructor, its injected UUIDv7 generator, and the combined M3.2 gate remain
required before this phase is complete.

Add strict schemas for platform namespace and launch records, desired and
observed tenant state, deployment and archive records, requests, authorization
jobs, intents, audit entries, and results. Commit accepted and hostile golden
fixtures, RFC 8785 canonical bytes, versioned SHA-256 vectors, UUIDv7 and slug
vectors, lifecycle tables, and deterministic error codes.

The host request decoder rejects duplicate object member names before schema
validation, and every contract rejects unknown fields, type coercion, non-ASCII
or noncanonical identifiers, and unsupported versions. The optional client-side
YAML create-spec parser rejects duplicate keys and unknown fields before
constructing the request; no YAML parser is present on the host. Implement slug
reservation for `hosting`, `secure`, `www`, and canonical-origin-shaped labels
within the `.com` tenant namespace.
Add a minimal root-domain package, separate from the contract package. It owns
UUIDv7 tenant-ID generation and a pure constructor that derives canonical
origins from the pinned namespace and constructs canonical manifests from
validated caller choices plus exact authoritative inputs. Apart from injected
clock and entropy sources for UUIDv7 generation, it performs no I/O; it performs
no persistence, lifecycle transition, or authorization. Contract code may
validate identity fields but cannot generate or authorize them.

Gate: unit and property tests prove client/host round trips, canonical byte
agreement, rejection of a standalone manifest frame, all lifecycle table
entries and default denials, request/result size limits, root-domain manifest
generation, rejection of caller-selected identity or origin, origin derivation,
hostname length, and mutation-free rejection.

Rollback: the contract and root-domain packages are unused by production and
the publication flag remains false.

### M3.3: implement the durable state kernel

Create the host-agent package around the root-domain constructor and add its
root-only state repository. Implement
directory-relative no-follow opens, exclusive creation, atomic replacement,
file and parent-directory sync, immutable-record writes, compare-and-swap
digests, shared/exclusive locks, capacity admission, release-tree digests,
hash-chained audit, correlation idempotency, and intent discovery.

Commit the global lock order as executable assertions:

```text
export → publication → tenant-state
```

Intake has its own outer admission lock and never nests contrary to that order.
Busy operations return before artifact staging or durable allocation. State
readers validate ownership, mode, link count, schema, canonical representation,
and path containment before trusting bytes.

Gate: process-level concurrency and failure injection after every write, sync,
rename, lock, and audit boundary proves that restart selects one complete old or
new state. Capacity and rate-limit tests reach every boundary and prove retries
do not spend capacity twice.

Rollback: no system service calls the package and no production authoritative
state has been initialized.

### M3.4: implement the hostile ZIP and portable-bundle engine

Build the bounded structural ZIP gate before calling a general decoder. Parse
end records, central records, local headers, flags, methods, lengths, offsets,
regions, names, extra fields, and comments with explicit integer and allocation
bounds. Accept only stored and Deflate entries and require local/central
agreement.

Normalize and collision-check all paths before extraction. Accept only regular
files and directories; reject links and special files. Extract through
directory descriptors into an unpublished root-owned staging tree while
rechecking CRC, sizes, ratio, entry, path, byte, inode, and free-space limits.
Run the parser/extractor through a systemd sandbox with fixed memory, no swap,
task, descriptor, CPU, runtime, filesystem, and network constraints.

Implement the deterministic stored-ZIP export envelope and separate artifact,
manifest, release-tree, and bundle digests. Import treats all embedded identity
and lifecycle metadata as untrusted provenance.

Gate: the complete ADR 0019 hostile corpus, property tests, parser-process limit
tests, deterministic cross-run vectors, and boundary-valid export/import
round trips pass without creating a public release.

Rollback: the engine remains library-only and has no production entry point.

### M3.5: install the dark host boundary

Ansible installs a hash-pinned host-agent artifact in a versioned root-owned
path, creates the state layout, and adds the `static_host_agent` role. Package
installation must be reproducible from the lockfile and may not resolve mutable
dependencies on the production host.

Migrate the empty Milestone 2 manifest and audit directories to the new
root-owned layout only after proving they contain no tenant history. Remove the
provisioner's persistent writable home and job tree. Give each worker invocation
a private 64-MiB/4,096-inode workspace and the accepted systemd sandbox.

Add `static_publication_enabled: false` to defaults and production inventory.
Install the gate at both job issuance and Caddy generation. Back up the new
authoritative state, but exclude intake, export spool, Caddy runtime generations,
and secrets.

Gate: two Molecule converges plus installed Testinfra checks prove ownership,
modes, mounts, unit hardening, backup inclusion/exclusion, zero tenant routes,
and rejection before allocation while disabled. Production convergence remains
idempotent and continues serving the Milestone 2 fixture.

Rollback: select the preceding installed package and Ansible configuration. The
empty migrated directories may remain root-owned; do not recreate a persistent
provisioner-writable job store.

### M3.6: deliver authenticated issuance and opaque job execution

Add the `ldp-operator` account, root-owned authorized-key location, key-bound
principal, forced command, exact issuer sudo rule, and SSH restrictions from ADR
0026. Add the operator client and `just` entry points. Implement bounded framing,
artifact intake, immutable job issuance, systemd handoff, provisioner execution,
result retrieval, exact correlation retry, startup reconciliation, and
authenticated export delivery plumbing.

The installed provisioner command accepts only one job UUID. The sudo rule
selects only the fixed `execute-authorized-job` executable, and that root-owned
parser accepts only one canonical UUIDv7 argument. Neither the provisioner nor
operator can list state. All lifecycle handlers remain disabled or return a
versioned not-implemented result without state mutation until their phases land.

Gate: use a real SSH daemon in the installed-host suite. Prove shell, command,
PTY, forwarding, SFTP/SCP, environment, and path restrictions, and prove that
raw-operation, unknown-ID, standalone-manifest, and every externally requested
tenant job fail before artifact acceptance or job allocation while publication
is disabled. Separately exercise immutable issuance, field isolation,
expected-state drift, artifact replacement, replay, disconnect, lost handoff,
and lost result through the unit and process suites using mutation-free test
state. Do not add a production-visible test override. Repeat the successful
installed-host job-lifecycle cases in M3.8 after the disposable host alone has
publication enabled and real lifecycle handlers.

Rollback: revoke the operator key or remove the forced-command account. Root
state stays intact and `ldp-admin` remains usable.

### M3.7: replace mutable Caddy inputs with complete generations

Extend the production OpenTofu stack with a second instance of the existing
Cloudflare DNS module for the `lowerduckpond.com` apex and wildcard, then evolve
both instances into the reviewed public-edge module. Add a separately named
non-secret `.com` zone-ID input and plan-policy assertions. The module manages
proxied public A records, Full (strict), explicit cache bypass, Always Online
disabled, account-specific Authenticated Origin Pull configuration, and the
reviewed Cloudflare network set used by both DigitalOcean and host firewalls.
It leaves explicitly non-HTTP verification and administrative records DNS-only.
It also disables optional response-body transformations and installs the
two-zone `/cdn-cgi/` block. Never manually toggle proxy status or edge features
outside OpenTofu.

Keep Cloudflare capabilities separate. The Caddy DNS-01 token retains
only Zone Read and DNS Edit for the two zones. The OpenTofu edge token receives
only the two-zone DNS, origin-pull association, zone-setting, SSL-setting, and
ruleset permissions required by reviewed resources. A separate expiring
operator token uploads and later retires each origin-pull leaf certificate from
the trusted workstation, and is revoked after qualification teardown or
production rotation; OpenTofu receives only the returned non-secret certificate
ID. The local leaf key is discarded after upload verification. Neither the
project CA nor any leaf private key enters OpenTofu configuration, plan, or
state. No
Milestone 3 runtime receives a
cache-purge token; a future purge-only credential belongs to the Milestone 5
cache lifecycle.

Refactor the Caddy role and host-agent publication module together. One complete
immutable generation binds the Caddy binary, environment, platform base config,
generated tenant routes, and exact releases. The generator accepts only typed
root-owned state and emits allowlisted routes; it never accepts Caddy text,
filesystem paths, or redirect destinations.

Install the frozen launcher and pre/post-start helpers. Under the publication
lock, build, sync, validate, and select a candidate, then release the lock before
non-blocking systemd handoff. Implement candidate, last-known-good, recovery,
and ordinary-start intent state machines with distinct invocation IDs, three
attempts per selected target, a 60-second start-limit interval, stale-callback
fencing, and no ordinary-start rollback authority.

Ansible stages host inputs first, then takes publication, rereads authoritative
tenant state, and creates the final route-bearing generation. Bootstrap changes
stop and mask Caddy until the compatible launcher, unit, and recovery helpers
are completely installed. Retain only active, preceding, and current-intent
generations within 256 MiB and 4,096 unique inodes.

The platform-only generation serves the public platform fixture directly at
the `.net` apex, permanently redirects equivalent `hosting` and `www` requests
to that canonical site, reserves the secure host, and returns the generic
stateless `404` with `Cache-Control: no-store` from the exact `.com` apex. Its
`.com` wildcard rejects unknown hosts generically. Every `.com` route removes
incoming `Cookie` before handling and outgoing `Set-Cookie` before response.
With publication disabled it rejects every tenant canonical or alias route.
The municipal apex designation and redirect are deferred to Milestone 7 and
are not an M3 route exception.

Serve Cloudflare-to-Caddy HTTPS with Caddy's public DNS-01 origin certificate
and require an account-specific origin-pull client certificate. Port 80 cannot
use that client-certificate boundary, so its Cloudflare-only source allowlist,
strict host handling, and redirect-or-reject-only behavior form a narrower
exception. Caddy trusts Cloudflare forwarding headers only on the admitted,
authenticated path. Cloudflare may add provider-managed security cookies after
Caddy, but Lower Duck Pond never trusts them for application authentication or
authorization.

Roll production out in fail-safe phases: install and validate the origin-pull
CA configuration without requiring it; configure Full (strict), cache bypass,
Always Online disabled, origin-pull certificates, and proxied records; verify
edge and origin behavior; then enforce client-certificate and Cloudflare-network
ingress. CI compares the
committed network set with Cloudflare's published ranges and reports drift, but
a live plan never downloads and trusts an unreviewed replacement. Range changes
first add the reviewed superset to both firewalls, verify edge reachability, and
only then remove retired ranges from both boundaries.

Rotate the project CA as a second phased transaction: add the replacement CA to
Caddy without removing the old one, move both zones to replacement-CA leaves,
verify every hostname, retire the old leaves, and remove the old CA only in a
later convergence. Alert before either the CA or a leaf reaches its rotation
window.

Gate: the reviewed OpenTofu plan and approved apply add only the intended
`.com` resources and two-zone edge policy. Obtain and renew apex and wildcard
origin certificates in both zones. Prove proxied public DNS, Full (strict),
account-specific origin pull, explicit cache bypass, Always Online disabled,
direct-origin denial, forwarded-header authenticity, response fidelity,
`/cdn-cgi/` denial, and Cloudflare-only ingress before enforcement.
Prove forwarded-header authenticity from the bounded Caddy access-log suffix
for nonce-tagged requests: the peer must be in the reviewed Cloudflare ranges,
and Caddy's parsed client address must be global and differ from both the
attacker-supplied sentinel and the Cloudflare peer. Do not expose visitor
addresses in public response headers or qualification evidence.
Run the local disposable Caddy/browser cookie gate plus the platform-only
Caddy/systemd, cookie-policy, host-input Ansible overlap,
descriptor-pinning, generation-retention, start-limit, failure-injection, and
bootstrap-interruption cases in ADR 0022. Publication remains disabled, every
tenant-bearing generation fails closed, and the lifecycle-integrated
Caddy/systemd and Ansible overlap cases remain gated on M3.8 and M3.10 as their
handlers arrive. Reboot the disposable host and prove the selected
platform-only generation returns through the edge while direct origin access
remains denied.

Rollback: reopen origin ingress and relax origin-pull enforcement before
changing affected records to DNS-only, then durably select and verify the
preceding platform-only generation. DNS-only emergency operation intentionally
loses Cloudflare DDoS protection and must not leave a source-restricted or
client-certificate-required origin unreachable.
Never restore the old mutable `Caddyfile` path once tenant-capable code exists.

### M3.8: implement core tenant lifecycle

Implement `create`, `deploy`, `rollback`, `suspend`, `resume`, `rename`, and
`reconcile` through authorization jobs. Initialize the namespace record only
before tenant history exists. Create starts undeployed; deploy generates the
root UUIDv7 deployment, extracts an immutable release, commits desired and
observed state with a complete Caddy generation, and retains the selected
release plus two predecessors.

Suspended deploy and rollback change the remembered selection without
publishing. Resume alone republishes. Rename atomically moves the live slug
mapping without changing the tenant ID or canonical origin. Reconciliation
rederives origins and routes, resolves intents, removes unreferenced staging,
and fails closed on namespace, manifest, or observed-state disagreement.

Gate: lifecycle table, concurrency, same-slug create/rename, slug reuse,
retention, delayed rollback, idempotency, cross-tenant access, Caddy failure,
process termination, reboot, and reconcile tests pass on the disposable host.
Repeat the successful installed-host issuance, expected-state-drift,
artifact-replacement, replay, disconnect, lost-handoff, and lost-result cases
deferred from M3.6. Run the core-lifecycle Caddy/systemd and Ansible overlap
cases deferred from M3.7 for deploy, rollback, suspension, resume, rename, and
reconciliation; restoration and deletion remain gated on M3.10. These tests run
with publication enabled only in that disposable environment.

Rollback: reconcile to the preceding complete generation and state. Failed
operations keep evidence and never require manual file editing.

### M3.9: implement export and portable import

Implement shared-lock snapshots, the global export spool, deterministic bundle
construction, authenticated download, acknowledgement, and bounded expiry.
Export active and suspended tenants without changing lifecycle. Reuse the same
snapshot and bundle contract for archived export, whose exact remote-version
integration lands with archive support in M3.10.

Import accepts a caller-held bundle only into an existing undeployed tenant,
creates a new deployment, and preserves only content and provenance. The target
ID, canonical origin, slug, runtime, and quotas come from current root-owned
target state. After validation under the required locks, root derives the
`active` lifecycle and generates the new deployment ID; neither value comes
from the portable bundle or a nonexistent undeployed-target deployment.

Gate: round-trip active and suspended source states, race capture against every
available core mutation—deploy, rollback, suspension, resume, rename, and
reconciliation—and against release cleanup. Fill byte/inode/result limits,
interrupt every snapshot and delivery phase, and prove byte-identical repeat
exports. Archive, restore, and deletion snapshot races remain gated on M3.10.

Rollback: expire unacknowledged spool artifacts through root reconciliation;
authoritative tenants and releases remain unchanged.

### M3.10: implement remote archive, restore, and deletion

Wire the low-level S3 client only to the dedicated archive credential. Implement
the construction intent, remote capacity reservation, one known-length
`PutObject`, exact returned-version verification, archive lifecycle transaction,
quarantine, retirement intent, version/marker purge, absence confirmation,
restore as a new deployment, ordinary deletion, and never-deployed deletion.
Complete archived-tenant export by delivering the exact bound remote bundle
through the authenticated result path without treating it as target state.

Archive preserves whether the source was active or suspended for failure
recovery, stores the proposed archived manifest in the bundle, binds exact
versioned evidence, and removes both route classes only in the committed
transaction. Ordinary delete requires a distinct post-archive authorization
job. Emergency deletion remains root-only and outside provisioner sudo.

Gate: fake-client protocol assertions plus real expendable-prefix tests cover
every interruption before, during, and after remote commit; lost responses;
unknown versions; delete markers; quota ceilings; repeated restore/rearchive;
and mutual credential denial. Run the archive, restore, and deletion snapshot
races deferred from M3.9 and the restoration and deletion Caddy/systemd and
Ansible overlap cases deferred from M3.8. Export the exact bound version from
archived state and round-trip it through import into a fresh undeployed tenant.
Managed code must make no multipart or high-level transfer call.

Rollback: preserve a still-bound version. An ambiguous object stays quarantined
and charged with archive admission closed until reconciliation proves its exact
state.

### M3.11: complete backup, audit, and restored-state recovery

Acquire the tenant-state lock in shared mode for backup and exclusive mode for
mutation. Update Restic sources and excludes for every authoritative M3 path.
After a disposable restore, validate state and release digests, reconcile
intents, regenerate Caddy runtime inputs from trusted host configuration plus
restored tenant state, and publish only after consistency checks.

Implement bounded ordinary audit segments. Rotate a closed segment only after a
dedicated `lowerduckpond-audit-archive` snapshot is created, restore-verified,
excluded from ordinary 7/5/12 retention, and durably indexed. Maintenance
enumerates and verifies the protected chain before forget/prune.

Gate: overlap backup with every mutation, interrupt snapshot/index/prune/restore
phases, age ordinary snapshots, rebuild a disposable host from backup plus the
archive Space, and prove the audit chain and selected tenant generations are
complete before publication.

Rollback: retain local audit segments and old backup sources until the new
restore drill passes. Never prune evidence merely to complete a rollout.

### M3.12: qualify and enable production

Run the complete suite on a disposable NYC1 Droplet built by OpenTofu and
Ansible, using production-equivalent filesystem, systemd, Caddy, Cloudflare,
Spaces, backup, reboot, and resource limits. Store a sanitized evidence report
with tool versions and digests.

Before production enablement:

- repeat the complete public-edge matrix against the real `.net` and `.com`
  apex and wildcard policy: proxied DNS, distinct edge and origin certificates,
  Full (strict), account-specific origin pulls, Cloudflare-only ingress,
  forwarded-header authenticity, cache bypass, Always Online disabled,
  direct-origin denial, strict unknown-host behavior, and safe port 80 handling;
- pass live supported-browser tests proving the `.com`/`.net` boundary, the
  known sibling `.com` cookie behavior, host-bound `__Host-` behavior, and the
  Caddy request/response cookie policy;
- rerun apex and wildcard ACME issuance/renewal qualification in both zones;
- confirm the dedicated operator key used since M3.6 remains backed up and only
  its public half is installed;
- verify the archive bucket begins with accounted zero objects and versions;
- resize production to the accepted 2-vCPU/4-GiB class unless measured peak
  usage proves the smaller host retains all configured reserves; and
- take and restore-verify a final platform backup.

Change only the reviewed production variable to
`static_publication_enabled: true`, converge twice, and verify the durable launch
record. Run a synthetic source tenant through create, deploy, replace, rollback,
suspend, resume, rename, slug reuse, and export. Create a separate undeployed
target through the ordinary slug-allocation path, import the source bundle, and
verify that the active target retains only its own identity and policy. Exercise
both tenants through backup, disposable restore, reconciliation, reboot, and
HTTPS. Archive, restore, rearchive, and ordinarily delete the source; separately
archive and ordinarily delete the imported target. Verify both route classes
are absent for both tenants, every bound archive object has been retired, audit
continuity is preserved, and no manual host edits occurred.

Gate: the sanitized canary report maps every ADR 0022 invariant to passing
evidence. Only then mark Milestone 3 complete and permit Milestone 4 work to
depend on the host contract. Real customer onboarding still waits for
Milestone 7.

Rollback: before the first tenant, select the preceding platform-only
generation and set the gate false. After tenant history exists, do not toggle
the gate; use tested lifecycle or emergency operations and preserve evidence.

## 6. Test and CI entry points

Add focused recipes as their implementations arrive:

```text
just check-static-contracts
just check-static-unit
just check-static-integration
just check-static-host
just check-static-browser
just qualify-static-publication
just acceptance-static-disposable
just acceptance-static-production
```

`just check` runs every hermetic contract, unit, integration, schema, hostile
fixture, Ansible, and static host test suitable for CI. Live Cloudflare, Spaces,
DigitalOcean, reboot, and live browser-boundary checks remain explicit acceptance
recipes with bounded credentials and sanitized reports; they may not silently
skip when invoked.

Every implementation PR updates the threat-model traceability table so each
changed invariant names its unit, process, installed-host, live-service, and
recovery evidence. A passing happy-path test cannot substitute for required
failure-injection evidence.

## 7. Principal risks

| Priority | Risk | Control or decision point |
| --- | --- | --- |
| Critical | Implementation or later documentation silently treats sibling `.com` tenants as cookie-isolated or places privileged state in that shared namespace. | Encode the `.net`/`.com` split and static cookie policy in schemas, route generators, browser tests, threat invariants, and the launch record. Require a new ADR before any authenticated, dynamic, or privileged `.com` application. |
| Critical | Caddy, systemd, and Ansible cannot provide the descriptor-pinned, restart-safe transaction already specified. | Prove the mechanism in M3.0 before state code depends on it; stop for architecture review on any failed primitive. |
| Critical | Incorrect sync or intent ordering publishes a mixed or non-durable generation after process or power loss. | Centralize durable primitives, record every barrier, inject failure at every boundary, and reconcile from evidence rather than in-memory phase. |
| Critical | The privileged ZIP parser turns crafted metadata or decompression into root compromise or host exhaustion. | Structural gate first, narrow accepted methods, descriptor-relative extraction, systemd resource sandbox, hostile corpus, and no publication on failure. |
| Critical | A direct origin path or forged forwarding header bypasses Cloudflare policy or attributes an attacker-selected address to a request. | Require account-specific origin pulls, pin reviewed Cloudflare networks in both firewalls, trust forwarded headers only on that authenticated path, and test denial from outside it. |
| Critical | Cloudflare serves a tenant, alias, error, or lifecycle response across a state change or identity boundary through cache or Always Online. | Install explicit two-zone cache bypass and disable Always Online in M3, retain origin `no-store`, and test repeated responses, lifecycle transitions, and disposable origin unavailability. Design cache keys, stale serving, purges, failure handling, and a purge-only credential separately in M5 before enabling either mechanism. |
| High | Cloudflare rewrites a validated tenant representation or serves its reserved endpoint instead of the platform contract. | Disable optional transformations, emit `no-transform`, compare origin and edge representations, block `/cdn-cgi/`, reserve the colliding archive path, and fail M3.0 if the provider endpoint cannot be preempted. |
| High | Root host-agent scope grows until its review boundary is no longer understandable. | Keep contracts and operator client unprivileged, divide host-agent modules by state/archive/publication/lifecycle, and deliver one invariant group per PR. |
| High | Spaces behavior differs from assumed S3 version, delete-marker, pagination, multipart-listing, or visibility semantics. | Test the exact DigitalOcean operations and interruption states with forced pagination; quarantine ambiguity and close archive admission rather than guess. |
| High | Archive or backup credentials create a combined destructive blast radius. | Separate bucket-scoped keys, processes, environment files, health checks, and mutual-denial acceptance tests. |
| High | Molecule passes while the real filesystem, sshd, systemd, Caddy, or object store fails. | Preserve hermetic CI but require disposable production-equivalent qualification and restore before enabling production. |
| High | Dual-zone DNS, certificate, or route generation sends tenant bytes to `.net` or trusts cookies on `.com`. | Generate route classes from pinned suffixes, limit Cloudflare credentials to the two zones, qualify all four certificate names, and run hostile host/cookie matrices before enablement. |
| High | Cloudflare configuration or provider availability changes edge semantics or makes public HTTP unavailable. | Manage edge state in OpenTofu, alert on provider-network drift, retain a sequenced DNS-only rollback, and accept that emergency bypass intentionally loses edge protection. |
| High | The 1-vCPU/2-GiB host violates parser, Caddy, backup, or free-space reserves under concurrency. | Measure peak acceptance workload and plan the reversible 2-vCPU/4-GiB resize before the canary. |
| High | Review fatigue hides cross-component gaps. | Keep PRs phase-scoped, require invariant traceability, avoid speculative refactors, and do not stack later phases on unresolved security review. |

## 8. Dangerous assumptions to disprove

These are hypotheses, not design facts:

1. Supported browsers enforce the `.com`/`.net` registrable-domain boundary as
   expected while allowing the documented sibling `.com` parent-cookie behavior.
2. Caddy can apply request-cookie removal before every static tenant handler
   and response-cookie removal after every `.com` route without an uncovered
   handler, error, redirect, or logging path.
3. The Cloudflare plugin can issue and renew both apex and wildcard
   certificates in both zones using credentials restricted to exactly those
   zones.
4. Cloudflare can proxy both zones while preserving the exact host, method,
   path, query, redirect, cookie, and unknown-host contracts; explicit bypass
   prevents every Milestone 3 response class from entering edge cache, Always
   Online stays disabled and serves no representation during disposable origin
   unavailability, optional transformations stay disabled, and the zone WAF
   preempts `/cdn-cgi/`.
5. Full (strict), account-specific Authenticated Origin Pulls, and the reviewed
   Cloudflare network set prevent direct-origin and cross-account access without
   making renewal, restart, port 80 handling, or recovery unavailable.
6. The OpenTofu provider can manage the required proxy, SSL, origin-pull,
   zone-setting, and cache-bypass resources with narrowly scoped two-zone
   credentials; its API model does not require an unaccepted account-wide grant.
7. Cloudflare accepts the project-CA leaves, a 30-day qualification lifetime
   with at least 14 full days remaining at upload, a one-year production
   lifetime, per-hostname and zone-level association, and the overlap required
   by the rotation contract.
8. The production and disposable filesystems implement the tested directory
   sync, rename, hard-link, descriptor, and locking behavior.
9. Ubuntu 26.04's systemd, OpenSSH, and sudo versions support the exact restart,
   forced-command, sandbox, invocation-ID, reset, and fixed-executable
   contracts. `sudo-rs` argument matching is explicitly not assumed; the
   isolated root-owned executable owns that grammar.
10. DigitalOcean Spaces enforces mutual denial between the two bucket-scoped
    credentials and returns and exposes exact object versions, delete markers,
    pagination markers, and multipart listings consistently enough for the
    proposed intent, cleanup, and quarantine algorithm.
11. The systemd temporary-filesystem implementation enforces inode as well as
   byte limits on the actual host.
12. The selected parsing, canonicalization, schema, property-test, and S3
   libraries support Python 3.14 and preserve the required strict semantics.
13. The Milestone 2 provisioner-owned manifest and audit directories and the old
   backup `archives/` prefix still contain no tenant history or object versions.
14. The expanded authoritative backup set can be captured under one shared lock
   and restored without accidentally restoring Caddy secrets or transient data.
15. The current Droplet has enough CPU, RAM, block, and inode headroom to run
    failure-injection, backup, Caddy, and parser workloads concurrently.
16. A dedicated SSH key and forced command provide a distinct operator identity
    without leaving an alternate shell, forwarding, environment, or file-transfer
    path.
17. The accepted documentation contains no contradictory lifecycle or recovery
    rule that only becomes visible when executable state machines are written.

M3.0 owns assumptions 1–9, 11, and 12. M3.1 owns assumption 10 and first checks
assumption 13; M3.5 rechecks assumption 13 before migrating the empty host
directories. M3.11 owns assumption 14. M3.12 owns assumptions 15 and 16. Every
implementation phase table-tests its relevant transitions and may stop for an
ADR amendment if assumption 17 fails; it may not patch around a contradictory
boundary.

## 9. Open questions and operator prerequisites

No unanswered product choice blocks M3.0. The following questions are
deliberately deferred and must not be answered incidentally by Milestone 3
code:

1. **Dynamic tenant origins:** PHP applications cannot inherit the static
   tier's blanket cookie stripping. Milestone 6 must decide whether to constrain
   tenant cookies, use custom or provider-isolated domains, or select another
   boundary before enabling dynamic tenants.
2. **Reference tenant:** Milestone 7 still needs the content, repository name,
   and ordinary `.com` slug for the municipal site. Its ordinary tenant must be
   created before its immutable ID is selected in root-owned state as the
   stateless `.com` apex redirect target.
3. **Custom domains:** ownership proof, certificate authority, transfer,
   canonical URLs, and browser-state migration remain a later feature; the
   immutable tenant identity stays compatible with such a design.

No additional secret is required to begin the hermetic parts of M3.0–M3.4.
Before the corresponding production phases, the operator owes these numbered
actions:

1. provide the non-secret `lowerduckpond.com` Cloudflare zone ID as a GitHub
   production environment variable; replace the OpenTofu Cloudflare token with
   one granting only the two-zone DNS, zone-setting, SSL-setting, origin-pull
   association, and ruleset permissions the implemented plan demonstrates it
   needs; and replace
   the non-expiring Caddy token with one granting Zone Read and DNS Edit only to
   those same two zones; back up both production tokens before convergence;
2. use the selected globally unique production archive bucket name
   `lowerduckpond-net-production-tenant-archives-4f3e6b91` as
   `ARCHIVE_BUCKET_NAME`, approve the narrowly bounded OpenTofu plan/apply, and
   place its generated sensitive outputs only in the established production
   secret path; OpenTofu creates this durable, service-lifetime bucket, so do
   not create it manually or treat it as an expendable qualification resource;
3. create and back up the dedicated `ldp-operator` Ed25519 key on the trusted
   workstation, then provide only its public key and chosen audit principal;
4. before the revised M3.0 live gate, create and back up the project
   origin-pull CA only on the trusted workstation, authorize the short-lived
   disposable DigitalOcean host and Cloudflare records, and use a separate
   upload token valid for at most seven days to install a 30-day per-hostname
   leaf immediately after issuance and only while at least 14 full days remain;
   provide only the public CA certificate and non-secret uploaded certificate
   ID to the qualification tooling, discard the local leaf key after upload
   verification, then use the still-expiring token to remove the leaf during
   complete teardown before revoking it; repeat the reviewed rotation procedure
   for production zone-level leaves before M3.12; and
5. approve the reversible production CPU/RAM resize if M3.12 measurements do
   not prove the current host has sufficient reserve.

These actions are scheduled at their first dependency rather than requested in
one large secret-creation ceremony. The implementation must never ask the
operator to place a private SSH key, Spaces secret, Cloudflare token, or Restic
password in the repository or development workspace.

## 10. Milestone completion evidence

Milestone 3 is complete only when all phase gates pass and the production canary
report demonstrates that:

- every external operation was authorized by an immutable job from the
  dedicated operator boundary;
- the provisioner could neither originate authority nor read tenant state or
  export bytes;
- hostile and interrupted inputs never became public;
- tenant content remained confined to `.com`, platform trust remained confined
  to `.net`, and Caddy enforced the documented static cookie policy without
  claiming sibling tenant cookie isolation;
- public HTTP/HTTPS traversed Cloudflare with Full (strict), account-specific
  origin pulls, Cloudflare-only ingress, authentic forwarding headers, and
  explicit cache bypass while Always Online remained disabled and direct origin
  access remained denied; disposable origin unavailability returned no stale or
  archived representation, origin and edge representations agreed, and
  `/cdn-cgi/` was blocked and unavailable to tenant archives;
- lifecycle and slug reuse converged without transferring a tenant origin;
- Caddy survived replacement, failed activation, restart, Ansible convergence,
  and reboot using only complete generations;
- the separate archive Space retained or permanently removed the exact intended
  versions without touching Restic;
- backup and disposable restore reconstructed authoritative state, releases,
  audit, and publication consistently;
- both the source and separately imported canary tenants were removed through
  their ordinary audited lifecycles, with routes absent and archive objects
  retired; and
- production remained manually unedited throughout the drill.

The existing roadmap exit criterion is then satisfied through evidence, not
merely by merging the final implementation PR.
