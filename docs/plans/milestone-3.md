# Milestone 3 implementation plan

- Status: implementation in progress; M3.0 live gate pending
- Updated: 2026-08-24
- Outcome: deliver the complete static-tenant lifecycle through the trusted
  workstation without enabling the Milestone 4 public control plane

## 1. Scope and fixed decisions

Milestone 3 implements the contracts accepted in ADRs 0016 through 0027. Four
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
   and removes outgoing `Set-Cookie` on all Milestone 3 `.com` routes; sibling
   browser-local cookie integrity is an accepted static-tier limitation.
2. Tenant archives use a separate private, versioned production Space and a
   dedicated bucket-only key. They do not share the Restic bucket or key.
3. Routine operations use a dedicated-key, forced-command `ldp-operator`
   account. `ldp-admin` remains the Ansible and emergency-administration
   identity.
4. `static_publication_enabled` defaults to false and stays false in production
   until the complete acceptance gate passes.

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
only privilege is the sudo-regex-matched
`execute-authorized-job <canonical-uuidv7>` command. The root executor opens and
verifies the job without following links, durably claims it, independently
revalidates all bindings, and commits one immutable result. A lost handoff or
SSH response is recovered by correlation and job reconciliation, never by
reconstructing authority from an artifact.

## 5. Delivery sequence

Every numbered phase is a separately reviewable PR unless a phase is split
further. A PR must deliver one complete proof obligation; unrelated cleanup is
deferred. Production remains dark through phases 0–11.

### M3.0: qualify dangerous platform assumptions

Implementation status: the hermetic, disposable-host, domain, Caddy, and
three-engine browser probes are implemented. M3.0 is not complete until an
explicitly authorized live run produces one passing 36-check sanitized report
and the disposable resources are confirmed destroyed.

Add executable qualification probes and a sanitized report before depending on
host behavior that the current Molecule suite does not reproduce.

Deliver:

- verify ownership, registration auto-renewal, and authoritative Cloudflare
  service for both domains; add a
  browser harness proving `.com` content cannot set or receive `.net` cookies,
  proving the two domains are cross-site, and recording that sibling `.com`
  tenants can share a parent-domain cookie without misreporting that residual
  behavior as isolation;
- prove Caddy can remove `Cookie` before static tenant handling, remove
  `Set-Cookie` from every `.com` route class, keep routing and bodies
  cookie-independent, and omit cookie values from logs;
- verify the production filesystem type and mount behavior, directory `fsync`,
  atomic same-filesystem rename, hard-link accounting, `O_NOFOLLOW`, and shared
  and exclusive `flock` semantics on a disposable Ubuntu 26.04 host;
- prototype descriptor-pinned Caddy start and reload, its Unix admin socket,
  systemd pre/post hooks, invocation IDs, bounded restart attempts,
  `reset-failed`, and non-blocking recovery handoff;
- prove the installed sudo version can match exactly one canonical UUIDv7
  argument and rejects separators, additional arguments, and lookalikes;
- prove a private systemd temporary filesystem enforces both 64 MiB and 4,096
  inodes;
- qualify Python 3.14 support and lock the schema, RFC 8785, property-test, and
  low-level S3 libraries before privileged code imports them; separately lock
  the safe-YAML library used only by the trusted-workstation client's optional
  local `create` specification.

Gate: every technical probe either passes on the production-equivalent stack or
produces an accepted replacement design. The dual-domain browser and Caddy
cookie probes are mandatory; there is no external PSL step. A warning or
skipped technical probe is not a pass.

Rollback: probes use a disposable host, create no tenant state, and select no
production Caddy input.

### M3.1: provision isolated archive storage

Add a `digitalocean-tenant-archives` module rather than renaming the existing
backup module or its state address. Extend the production stack with the second
bucket, dedicated key, sensitive outputs, project assignment, and plan-policy
assertions. Remove the obsolete `archives/` lifecycle rule from the backup
bucket only after a version-aware preflight proves that prefix empty.

The archive bucket enables versioning, prevents destroy, has no current or
noncurrent expiration, and may abort incomplete multipart uploads as defense in
depth. Extend production inventory validation and the trusted-workstation secret
handoff with separately named archive variables; never overload the existing
Restic variables.

Gate: plan policy permits only the expected additive bucket/key/project changes
and lifecycle correction. After approved apply, acceptance proves mutual access
denial between the backup and archive credentials. Using only the dedicated
archive credential and an expendable unique prefix, it exercises one
known-length `PutObject`, the returned version ID, immediate
`ListObjectVersions`, exact-version reads and deletes, delete markers, and
version-aware absence confirmation. The probe must permanently purge its test
versions and markers and establish an empty archive-accounting baseline.

Rollback: retain the isolated bucket and revoke its key if necessary. If a
failed probe leaves an ambiguous version or marker, preserve and account for it
until version-aware cleanup proves absence. Do not destroy versioned durable
storage as an application rollback.

### M3.2: establish contracts and the test spine

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
accepts only `execute-authorized-job <canonical-uuidv7>`. Neither the provisioner
nor operator can list state. All lifecycle handlers remain disabled or return a
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
Cloudflare DNS module for the `lowerduckpond.com` apex and wildcard. Add a
separately named non-secret `.com` zone-ID input and plan-policy assertions.
Replace the infrastructure and Caddy Cloudflare tokens with values restricted
to exactly the `.net` and `.com` zones and their already documented
permissions; do not grant account-wide DNS access.

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

Gate: the reviewed OpenTofu plan and approved apply add only the intended
`.com` records and inputs. Obtain and renew apex and wildcard certificates in
both zones. Run the platform-only Caddy/systemd, cookie-policy, host-input
Ansible overlap, descriptor-pinning, generation-retention, start-limit,
failure-injection, and bootstrap-interruption cases in ADR 0022. Publication
remains disabled, every tenant-bearing generation fails closed, and the
lifecycle-integrated Caddy/systemd and Ansible overlap cases remain gated on
M3.8 and M3.10 as their handlers arrive. Reboot the disposable host and prove
the selected platform-only generation returns.

Rollback: durably select and verify the preceding platform-only generation.
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
| High | Root host-agent scope grows until its review boundary is no longer understandable. | Keep contracts and operator client unprivileged, divide host-agent modules by state/archive/publication/lifecycle, and deliver one invariant group per PR. |
| High | Spaces behavior differs from assumed S3 version and visibility semantics. | Test the exact DigitalOcean operations and interruption states; quarantine ambiguity and close archive admission rather than guess. |
| High | Archive or backup credentials create a combined destructive blast radius. | Separate bucket-scoped keys, processes, environment files, health checks, and mutual-denial acceptance tests. |
| High | Molecule passes while the real filesystem, sshd, systemd, Caddy, or object store fails. | Preserve hermetic CI but require disposable production-equivalent qualification and restore before enabling production. |
| High | Dual-zone DNS, certificate, or route generation sends tenant bytes to `.net` or trusts cookies on `.com`. | Generate route classes from pinned suffixes, limit Cloudflare credentials to the two zones, qualify all four certificate names, and run hostile host/cookie matrices before enablement. |
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
4. The production and disposable filesystems implement the tested directory
   sync, rename, hard-link, descriptor, and locking behavior.
5. Ubuntu 26.04's systemd, OpenSSH, and sudo versions support the exact restart,
   forced-command, sandbox, invocation-ID, reset, and argument-matching
   contracts.
6. DigitalOcean Spaces returns and exposes exact object versions consistently
   enough for the proposed intent and quarantine algorithm.
7. The systemd temporary-filesystem implementation enforces inode as well as
   byte limits on the actual host.
8. The selected parsing, canonicalization, schema, property-test, and S3
   libraries support Python 3.14 and preserve the required strict semantics.
9. The Milestone 2 provisioner-owned manifest and audit directories and the old
   backup `archives/` prefix still contain no tenant history or object versions.
10. The expanded authoritative backup set can be captured under one shared lock
   and restored without accidentally restoring Caddy secrets or transient data.
11. The current Droplet has enough CPU, RAM, block, and inode headroom to run
    failure-injection, backup, Caddy, and parser workloads concurrently.
12. A dedicated SSH key and forced command provide a distinct operator identity
    without leaving an alternate shell, forwarding, environment, or file-transfer
    path.
13. The accepted documentation contains no contradictory lifecycle or recovery
    rule that only becomes visible when executable state machines are written.

M3.0 owns assumptions 1–5, 7, and 8. M3.1 owns assumption 6 and first checks
assumption 9; M3.5 rechecks assumption 9 before migrating the empty host
directories. M3.11 owns assumption 10. M3.12 owns assumptions 11 and 12. Every
implementation phase table-tests its relevant transitions and may stop for an
ADR amendment if assumption 13 fails; it may not patch around a contradictory
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
   production environment variable, replace the OpenTofu Cloudflare token with
   one granting DNS Edit only to the `.net` and `.com` zones, and replace the
   non-expiring Caddy token with one granting Zone Read and DNS Edit only to
   those same two zones; back up the Caddy token before convergence;
2. choose the globally unique production archive bucket name, approve the
   OpenTofu plan/apply, and place its generated sensitive outputs only in the
   established production secret path;
3. create and back up the dedicated `ldp-operator` Ed25519 key on the trusted
   workstation, then provide only its public key and chosen audit principal;
4. authorize the short-lived disposable DigitalOcean qualification host and
   associated Cloudflare test records when M3.0 and M3.12 reach their live
   gates; and
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
