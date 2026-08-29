# Lower Duck Pond Hosting: Implementation Roadmap

This roadmap turns the architecture in [`architecture.md`](architecture.md) into incremental, independently demonstrable releases. The ordering intentionally establishes static hosting, reproducible infrastructure, backups, and operational visibility before enabling untrusted PHP.

## Progress

Status as of 2026-08-29:

| Milestone | Status | Outcome |
| --- | --- | --- |
| 0: Repository foundation | Complete | The public repository, development workflow, CI gates, application boundaries, and architecture decisions are established. |
| 1: DigitalOcean foundation | Complete | OpenTofu manages the production network, Droplet, reserved IP, firewall, DNS, state, and durable backup storage; the guarded rebuild drill succeeded. |
| 2: Reproducible host configuration | Complete | One trusted-workstation command converges production idempotently and passes host, HTTPS, backup, restore, and post-reboot acceptance checks. |
| 3: Static tenant MVP | Current | M3.0 qualification, M3.1 isolated archive storage, and M3.2 contracts and test spine are complete; M3.3 durable-state implementation is next. |
| 4: Control plane and lifecycle automation | Planned | Expose the static lifecycle through the FastAPI control plane with approvals, jobs, policy, and audit history. |
| 5: Backup, observability, and operations | Planned | Complete platform-level recovery, central observability, alerting, and operator runbooks. Host backup and monitoring foundations arrived early in Milestone 2. |
| 6: Dynamic PHP pilot | Planned | Introduce isolated PHP and tenant-scoped SQL only after the static platform and recovery path are proven. |
| 7: Reference tenant and community pilot | Planned | Deploy a platform-owned reference site through the ordinary `.com` tenant contract and onboard a small resident cohort. |

“Complete” means the milestone's exit criterion has been demonstrated, not
merely that its implementation was merged. “Current” identifies the active
implementation target. Milestone 3's design is accepted, and the M3.0 live
qualification passed all 54 checks before its complete disposable teardown.
M3.1's protected production migration, live acceptance, evidence backup,
independent empty-bucket proof, and final no-change plan also passed. M3.2's
strict contracts, pure root-owned identity and manifest construction, and
combined package-isolation gate passed. M3.3 is the current implementation
phase. Production remains disabled, and Milestone 3 remains incomplete until
every phase gate through M3.12 passes.

## 1. Proposed platform repository

```text
.
├── .github/
│   └── workflows/
├── docs/
│   ├── adr/
│   ├── operations/
│   └── threat-model/
├── infra/
│   └── opentofu/
│       ├── bootstrap-state/
│       ├── modules/
│       │   ├── cloudflare-dns/
│       │   ├── digitalocean-host/
│       │   ├── digitalocean-spaces/
│       │   └── digitalocean-tenant-archives/
│       └── environments/
│           ├── development/
│           └── production/
├── config/
│   └── ansible/
│       ├── inventories/
│       ├── playbooks/
│       └── roles/
├── platform/
│   ├── caddy/
│   ├── quadlet/
│   ├── monitoring/
│   └── backup/
├── services/
│   ├── control-plane/
│   └── provisioner/
├── schemas/
│   └── tenant-manifest/
├── tests/
│   ├── infrastructure/
│   ├── configuration/
│   ├── integration/
│   ├── isolation/
│   └── e2e/
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── SECURITY.md
```

A platform-owned reference site should eventually live in a separate
repository and deploy at an ordinary `.com` slug and immutable origin through
the same contract available to residents. Its content, repository name, and
slug remain a Milestone 7 product choice. The exact `lowerduckpond.com` apex is
a non-cacheable stateless platform `404` during Milestone 3 and will then
redirect without caching directly to the designated municipal tenant's
immutable canonical origin while that tenant is active.

## 2. Decisions to record before implementation

Create short architecture decision records for:

1. OpenTofu rather than Terraform for infrastructure definitions.
2. Ansible rather than cloud-init for durable host configuration.
3. Caddy with Cloudflare DNS-01 for wildcard TLS.
4. Static hosting as the default tier.
5. Rootless Podman and Quadlet for dynamic tenant workloads.
6. Control-plane/provisioner privilege separation.
7. Initial SQL engine: MariaDB or PostgreSQL.
8. Tenant deployment interface: repository integration, archive upload, or both.
9. Signup identity and approval policy.
10. State backend and serialization strategy.
11. Initial license for original project code is Apache-2.0.
12. Control-plane application stack: FastAPI with SQLAlchemy 2 and `uv`.
13. Developer workflow: `mise`, `just`, pre-commit, and Renovate.
14. Initial host baseline: Ubuntu 26.04 LTS with its distribution Podman package.
15. Start on a small Droplet and preserve reversible CPU/RAM resizing.

Operator-accepted defaults:

- Use MariaDB for tenant PHP databases unless the selected control-plane framework strongly favors PostgreSQL.
- Support archive upload first; add Git-based deployment after the deployment manifest and rollback behavior are stable.
- Require administrative approval during the pilot.
- Keep Milestone 0 limited to repository foundations; define the tenant manifest in Milestone 3.

## 3. Milestone 0: repository foundation — complete

### Deliverables

- Public repository with license, contribution guide, security policy, code owners, and issue templates.
- Architecture and roadmap documents.
- ADR template and initial decisions.
- Tool version pinning for OpenTofu, Ansible, Python/Go/Node as applicable, Caddy, and Podman.
- Pre-commit configuration for formatting, linting, secret detection, and malformed YAML/JSON.
- Dependabot or Renovate configuration.
- A development command runner such as `just` or `make` with documented entry points.

### CI gates

- Markdown linting and link checking.
- Secret scanning.
- OpenTofu formatting and validation.
- Ansible linting and syntax checking.
- Unit-test placeholder that proves the selected application stack runs in CI.
- Independently packaged control-plane and provisioner skeletons that preserve the privilege boundary.

### Exit criteria

A contributor can clone the repository, install documented prerequisites, run one validation command, and receive the same result as CI.

### Completion record

[PR #1](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/1)
delivered the repository foundation. The locked `just check` workflow and the
required GitHub checks exercise the same validation entry points.

## 4. Milestone 1: DigitalOcean foundation — complete

### OpenTofu resources

- DigitalOcean project.
- VPC.
- Administrative SSH public key.
- Basic Droplet parameterized by region, image, and size.
- Reserved IP and assignment.
- Cloud Firewall.
- Spaces bucket for backups and archives.
- Bucket lifecycle policy and narrowly scoped Spaces credentials.
- Cloudflare apex and wildcard DNS records.
- Outputs suitable for generating the Ansible inventory.

The operator-created `lowerduckpond.net` DigitalOcean project is referenced by
ID rather than recreated. OpenTofu owns assignment of the resources it creates
to that project.

The firewall should expose only:

- TCP 80 from the Internet.
- TCP 443 from the Internet.
- TCP 22 from an explicit administrative allowlist during the initial release.
- Required outbound traffic for operating-system updates, ACME, backups, and monitoring.

Keep host-level nftables policy under Ansible as a second boundary.

This records the completed Milestone 1 direct-origin baseline. ADR 0028
supersedes its public-web posture: Milestone 3 will restrict ports 80 and 443 to
reviewed Cloudflare proxy networks and add account-specific origin
authentication before the proxy becomes the production path. SSH retains the
independent administrative CIDR allowlist.

### State bootstrap

Create remote state separately from the production stack. DigitalOcean Spaces
is S3-compatible; encrypt state and saved plans client-side with OpenTofu before
storing them there. OpenTofu's native S3 lockfile depends on conditional-write
behavior that must be verified against the selected Spaces configuration.

Until that verification exists:

- Enable Spaces bucket versioning.
- Serialize all production plan/apply jobs through one protected CI environment and a GitHub Actions concurrency group.
- Never run an uncoordinated local production apply.
- Keep backend credentials in CI secrets rather than backend configuration committed to the repository.

### Validation

- `tofu fmt -check`
- `tofu validate`
- TFLint
- Trivy configuration scanning or an equivalent IaC policy scanner
- Generated-plan review in pull requests
- Automated assertions over plan JSON for public ports, disk encryption expectations, tags, and destructive replacements

### Exit criteria

A CI-authorized apply can create a fresh Droplet and supporting resources without console intervention, and a destroy/recreate exercise retains the reserved address and off-host backup storage as designed.

### Completion record

[PR #2](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/2)
delivered the DigitalOcean and Cloudflare foundation. The guarded rebuild drill
then proved that the Droplet could be replaced while retaining its reserved IP
and off-host state and backup buckets. Follow-up
[PR #3](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/3) and
[PR #4](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/4)
incorporated the drill and project-membership review findings into the durable
plan policy. Milestone 1 delivered one Space for the then-combined backup and
archive design; ADR 0025 adds a separate archive Space in Milestone 3 and leaves
the existing resource dedicated to Restic.

## 5. Milestone 2: reproducible host configuration — complete

### Ansible roles

Implement small composable roles rather than one monolithic playbook:

- `base`: users, packages, time, locale, updates, journald, and basic hardening.
- `firewall`: host ingress/egress policy and metadata-endpoint protection.
- `caddy`: pinned custom Caddy build, configuration, durable certificate storage, and reload validation.
- `podman`: rootless Podman prerequisites, subordinate IDs, lingering, storage, and networks.
- `database`: database engine, durable storage, local-only administration, backup account, and tuning.
- `backup`: database dumps, Restic, schedules, retention, and health reporting.
- `monitoring`: a loopback-only node exporter, local textfile metrics, scheduled
  health checks, and journald reporting. Central collection, dashboards, and
  routed alerts remain deferred to Milestone 5.
- `provisioner`: an unprivileged non-login service account and private job,
  manifest, and audit directories. It receives no queue integration, tenant
  content ownership, Caddy access, sudo rule, or other privileged operation in
  this milestone.

Milestone 2 does not grant the provisioner a Caddy reload or route-publication
capability. Milestone 3 introduces one privileged activation contract covering
both immutable tenant content and its generated root-owned route, so neither
half can be changed independently after validation.

For the initial 1-vCPU/2-GiB development node, install a loopback-only node
exporter and emit service/backup health through its textfile collector and
journald. Keep Caddy's metrics endpoint loopback-only. A central Prometheus,
Grafana, and Alertmanager stack is deferred until control-plane and tenant
semantics exist; running those services now would consume scarce node capacity
without providing meaningful tenant dashboards. DigitalOcean monitoring
remains the external host-level signal in the interim.

Production convergence runs from the trusted administrative workstation, not a
GitHub-hosted runner. This preserves the administrative CIDR restriction and
keeps the passphrase-protected human SSH key outside GitHub. The runner reads
the bucket-scoped backup key from encrypted OpenTofu state, accepts the Caddy
and Restic credentials only through its environment, and never writes a secret
inventory or variables file.

### Host acceptance tests

Use Molecule plus Testinfra, Goss, or equivalent assertions to verify:

- Only intended ports are listening publicly.
- Caddy serves a known static fixture over HTTPS.
- Caddy configuration validation runs before every reload.
- Rootless Podman runs under a non-login service account.
- Required systemd and user services survive reboot.
- Database administrative interfaces are not public.
- Backup jobs can reach Spaces.
- Reapplying Ansible reports no unintended changes.
- A disposable restore of the latest Restic snapshot contains the known static
  fixture.

### Exit criteria

A newly provisioned Droplet becomes a working empty hosting node after one
operator command. That command performs a second converge with zero changes and
runs host, HTTPS, backup, and disposable-restore acceptance checks.

### Completion record

[PR #5](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/5)
delivered the host roles and production runner. Corrective
[PR #6](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/6),
[PR #7](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/7), and
[PR #8](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/8)
resolved standalone acceptance scope, removed misleading skipped-loop output,
and added static verification of the installed systemd units.

On 2026-08-22, production was cleanly rebooted and the operator reran `just
configure-production` from the trusted workstation against current `main`.
The second converge reported zero changes, and the host, HTTPS, encrypted
backup, disposable-restore, service, timer, and rootless user-service checks
all passed. This demonstrates the exit criterion and boot persistence on the
real host.

## 6. Milestone 3: static tenant MVP — current

### Accepted implementation decisions

Milestone 3 implementation is governed by the
[static-publication threat model](threat-model/static-publication.md) and these
accepted decisions, in dependency order:

1. [Model static publication as an untrusted boundary](adr/0016-model-static-publication-threats.md).
2. [Atomically activate immutable static releases](adr/0017-atomically-activate-static-releases.md).
3. [Version the static tenant manifest contract](adr/0018-version-static-tenant-manifests.md).
4. [Constrain static archives and exports](adr/0019-constrain-static-archives-and-exports.md).
5. [Use a trusted-workstation static operator interface](adr/0020-use-a-trusted-workstation-static-operator-interface.md).
6. [Define static tenant lifecycle semantics](adr/0021-define-static-tenant-lifecycle-semantics.md).
7. [Separate reusable slugs from immutable tenant origins](adr/0023-separate-reusable-slugs-from-tenant-origins.md).
8. [Test static publication as a security boundary](adr/0022-test-static-publication-as-a-security-boundary.md).
9. [Separate trusted platform and untrusted tenant domains](adr/0024-separate-platform-and-tenant-domains.md).
10. [Separate tenant archives from platform backups](adr/0025-separate-tenant-archives-from-platform-backups.md).
11. [Separate static operation from host administration](adr/0026-separate-static-operation-from-host-administration.md).
12. [Gate production static publication](adr/0027-gate-production-static-publication.md).
13. [Use Cloudflare as the public web edge](adr/0028-use-cloudflare-as-the-public-web-edge.md).

The reviewable implementation sequence, file ownership, phase gates, rollout
evidence, risks, and dangerous assumptions are maintained in the
[Milestone 3 implementation plan](plans/milestone-3.md).

### Tenant manifest v1

Define and version a machine-readable contract before building the portal. The
accepted v1alpha1 shape begins with the following readable illustration of
root-generated state; this YAML rendering is not a host input or upload format:

```yaml
apiVersion: hosting.lowerduckpond.net/v1alpha1
kind: Site
metadata:
  id: 0191e2c4-8f7a-7c3b-8d1e-5f62047a2100
  slug: duck-repair
  canonicalOrigin: t-0191e2c48f7a7c3b8d1e5f62047a2100.lowerduckpond.com
spec:
  runtime: static
  desiredState: active
  desiredDeployment:
    id: 0191e2ca-49f2-7608-8cf3-f80ab2cab151
    archiveSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  quotas:
    storageMiB: 100
    entries: 5000
```

The root activator generates the stable UUIDv7 tenant ID during `create`; a
caller cannot select it. Tenant content is served at
`t-<tenant-uuid-without-hyphens>.lowerduckpond.com`, separately registered from
all trusted platform services on `lowerduckpond.net`. A reusable
`<slug>.lowerduckpond.com` platform alias redirects only its bare root to that
canonical origin and never serves tenant-controlled content. Arbitrary and
custom domains are not accepted in this version. Dual-zone proxied DNS, edge
and origin certificates, Full (strict), account-specific origin pulls,
Cloudflare-only ingress, cache bypass, Always Online denial, browser-boundary,
and Caddy cookie-policy qualification are required before the production
canary; no PSL submission or recognition is assumed. A versioned root-owned
platform record pins the suffix
before the first tenant is created, and each root-generated manifest stores the
complete origin.
Convergence and reconciliation fail closed unless configuration, the platform
record, and the rederived manifest origin agree. The tenant ID and canonical
origin do not change when a public slug changes. Desired manifests are stored
as canonical JSON, while observed activation state and immutable deployment
records remain separate. The host accepts no standalone desired manifest:
operation-specific requests carry only authorized caller choices, and root
derives each candidate manifest from the request plus authoritative source
state. The trusted client may translate a bounded local YAML create
specification into the strict request, but YAML never crosses the privileged
transport boundary.

### Operator and provisioner behavior

Implement idempotent commands or jobs for:

- Create desired tenant state and root-owned immutable release storage.
- Represent a newly created tenant as undeployed, without requiring a synthetic
  deployment ID or archive digest.
- Migrate authoritative manifest and audit storage from the empty Milestone 2
  provisioner-owned directories to root ownership before accepting tenant data.
- Remove the provisioner's persistent writable home and job directory; place
  its temporary work in a private service workspace hard-capped at 64 MiB and
  4,096 inodes while root owns intake, job records, and activation staging.
- Create a dedicated-key, forced-command `ldp-operator` SSH account for routine
  lifecycle commands while retaining `ldp-admin` for Ansible and emergency host
  administration. Make its adapter the Milestone 3 authorization issuer. Commit a
  root-owned immutable job binding the SSH-authenticated operator, operation,
  target, correlation and canonical request, artifact or absence, and expected
  source state before allowing execution.
- Expose only `execute-authorized-job <root-generated-job-id>` through the
  provisioner sudo rule. Deny it access to the issuer, job and intake stores,
  tenant exports, full results, and raw activator operation entry points.
- Initialize and back up the root-owned platform namespace record only before
  tenant history exists; reject later configured suffix drift unless a future
  explicit origin-migration design authorizes it.
- Generate immutable tenant IDs at the root boundary; persist and independently
  rederive each canonical tenant hostname from the pinned namespace without
  accepting a caller ID or domain.
- Validate live slug uniqueness and both canonical and alias hostname lengths.
- Reserve slugs inside the serialized root-owned state transaction so
  concurrent creates or renames cannot commit the same alias.
- Enforce a 1–63-byte ASCII DNS-label grammar and complete alias-hostname length
  with both an absolute-end JSON Schema pattern and an independent root
  `fullmatch` before persisting a slug.
- Stage and validate an uploaded archive.
- Stream artifacts through one root-owned intake slot while enforcing the
  100-MiB deploy or 120-MiB import ceiling, aggregate allocated-space and host
  free-space bounds, transfer deadlines, and terminal/startup cleanup before
  any privileged parser runs.
- Reject unsafe or ambiguous paths, links, special files, archive expansion,
  excessive entry counts, and quota violations.
- Gate ZIP structure with bounded metadata reads, permit only stored and Deflate
  entries, match local and central headers, and run privileged parsing inside
  fixed memory, swap, task, descriptor, CPU, and runtime limits.
- Bound normalized path, component, depth, central-directory, extra-field, and
  region layout; count each materialized directory once. Coalesce an exactly
  matching explicit directory with its implicit parent, but reject duplicate
  explicit records, type conflicts, and distinct spellings that collide after
  normalization or case folding before extraction.
- Revalidate and extract through the narrow root-owned activator.
- Atomically activate one complete Caddy runtime generation whose manifest binds
  its binary, environment, full configuration, and immutable tenant releases.
- Retain the selected active or suspended remembered release and its two
  preceding releases; run post-commit cleanup after deploy, rollback, and
  restore and repeat it during reconciliation while preserving export- and
  intent-pinned releases.
- Generate allowlisted canonical content routes and platform-only slug redirect
  routes without accepting Caddy text or a redirect target.
- Enforce the exact bare-root, non-cached, no-referrer alias contract and omit
  raw path, query, cookie, authorization, and referrer values from alias logs.
  Apply `no-store` to every alias redirect and `404`. Apply the allowlist before
  automatic HTTPS on both listeners, redirecting only a qualifying HTTP request
  directly to the canonical HTTPS origin.
- Keep all trusted services on `.net` and every static tenant route on `.com`.
  Remove incoming `Cookie` before static tenant handling, remove outgoing
  `Set-Cookie` from every `.com` route, and never vary routing or content by
  cookie state. Browser tests must demonstrate both the `.com`/`.net` boundary
  and the accepted sibling `.com` parent-cookie limitation.
- Put public HTTP/HTTPS for both domains through managed proxied Cloudflare
  records while retaining Caddy as the only application origin. Require Full
  (strict), account-specific Authenticated Origin Pulls, reviewed
  Cloudflare-only web ingress, and authentic forwarded addresses; deny direct
  origin access and never treat Cloudflare-managed cookies as application
  authority.
- Explicitly bypass Cloudflare cache for every Milestone 3 response. Keep
  aliases, the `.com` apex, unknown hosts, errors, and the future secure
  application permanently uncacheable. Defer tenant content cache keys, TTLs,
  purge ordering, stale behavior, and a separate purge-only credential to
  Milestone 5.
- Manage Always Online as disabled for both zones and prove a disposable origin
  outage cannot serve stale cache or Internet Archive content.
- Disable optional Cloudflare body rewriting and script injection, require
  `Cache-Control: no-transform`, block the provider-reserved `/cdn-cgi/`
  namespace, and reject its colliding first path component from tenant archives.
- Validate, select, reload, and advance every restart or rollback phase under
  one publication lock, while releasing it before any systemd job must
  reacquire it.
- Enforce the global export → publication → tenant-state lock order, reject
  contended requests before staging, and revalidate two-phase archive capture
  under exclusive state before commit.
- Apply explicit file and parent-directory `fsync` barriers around releases,
  complete Caddy generations, intent, active references, state, audit, and
  rollback.
- Refactor Ansible Caddy convergence to commit every mutable live Caddy input in
  one runtime generation under the publication lock. Stage only host inputs
  beforehand; after locking, reread authoritative tenant state and construct
  and validate the final route-bearing candidate so a stale route set cannot be
  selected. Use durable phased intent and a non-blocking systemd handoff for
  binary or environment restarts, with post-start verification and rollback
  after independent lock acquisitions. Before a recovery start, durably select
  the prior generation, release publication, reset the exhausted systemd failed
  and start-limit state, and then queue the start idempotently. Pin three
  attempts per selected target and the rate-limit interval; durably bind each
  automatic retry's new invocation ID and fence callbacks from prior attempts.
  Freeze a small systemd bootstrap that reconciles intent and pins one
  generation before every start. When no transaction intent exists, durably
  create an ordinary-start intent for the manifest-verified active generation;
  retry only that target and never infer rollback authority from service
  startup.
- Retain only active, last-known-good, and current-intent Caddy generations;
  enforce a 256-MiB/4,096-inode aggregate cap, unique-inode accounting,
  free-space admission, and secret-safe cleanup.
- Suspend, resume, export, import, archive, restore, and delete a site.
- Keep canonical tenant origins stable across rename and restore; release slugs
  after committed rename or deletion without reassigning a tenant origin.
- Enforce and table-test the complete lifecycle operation/state matrix; reject
  every unlisted pair without desired or observed state changes.
- Commit archive evidence, `desiredState: archived`, and both-route removal
  through one write-ahead transaction that reconciles to the exact preceding
  active-or-suspended state and route set or the complete archived generation.
- Allow audited archive-free deletion of a never-deployed reservation only when
  its complete root-owned history proves no deployment ever existed.
- Capture each export's canonical manifest and immutable release into a
  root-owned snapshot under the shared tenant-state lock before bundling it.
- For archive, retain the active or suspended source manifest only for final
  compare-and-swap and put the separately derived proposed archived manifest in
  the durable bundle, with its digest bound by the archive record.
- Before enabling archive operations, provision a separate private, versioned
  tenant-archive Space and dedicated credential. Configure no current or
  noncurrent age expiration. Retain every bundle bound by authoritative
  archived tenant state until a coordinated, audited deletion transition makes
  it unreferenced; Milestone 4 owns retention expiry and scheduled deletion.
- Persist and sync a construction intent containing the exact unique Spaces key
  before archive upload, then bind the returned version ID after verification.
  Upload the at-most-120-MiB completed bundle with one known-length `PutObject`;
  prohibit multipart and high-level transfer APIs so incomplete parts cannot
  escape version and capacity accounting.
  Reconcile it with any lifecycle intent and authoritative archive record before
  admitting another archive; permanently purge and confirm absence of every
  unreferenced version and delete marker or keep them durably quarantined and
  charged.
- Before restore or deletion unbinds an archive, sync a retirement intent for
  its exact key and version. Reconcile lifecycle state first, preserve any
  still-bound version, and permanently purge a committed retired key before
  clearing its charge or admitting another archive.
- Limit the managed archive prefix to 25 unique keys, 25 total data versions or
  delete markers, and 3,000 MiB across all data versions. Reserve one key, one
  version, and 120 MiB before upload; charge bound, constructing, retiring,
  quarantined, and unknown objects until exact version listing proves absence.
- Serialize export and archive construction globally; enforce one snapshot,
  one unacknowledged result, a 256-MiB/5,120-inode spool, a 120-MiB output cap,
  the host free-space reserve, and bounded acknowledgement/expiry cleanup.
- Wrap portable exports in the versioned `lowerduckpond-export-v1/` envelope,
  with fixed metadata paths and all tenant-controlled files below `content/`.
- Import a caller-held portable export only into an existing `undeployed` target.
  Preserve the target's root-owned identity, canonical origin, slug, runtime,
  and quotas; create a new deployment and treat every embedded source-manifest
  field as untrusted provenance rather than target state.
- Give portable import and restore a separate raw-envelope budget of 5,004
  records, 1,056-byte file names or 1,057-byte directory names including their
  marker, 34 components, and 106 MiB of member data. Strip the marker and fixed
  prefix before reapplying unchanged tenant-tree quotas so boundary-valid
  exports remain importable and bound archives remain restorable.
- Canonicalize every portable ZIP field and use stored entries so the same
  export snapshot has byte-identical output and a reproducible archive digest.
- Store versioned SHA-256 evidence for canonical manifest bytes and a
  length-delimited, type-tagged, path-sorted release tree; keep uploaded artifact
  and complete portable-bundle byte digests distinct.
- Reconcile actual host state against all desired manifests.
- Permit the provisioner to preflight and execute an already authorized job
  without granting authority to originate or alter state changes or access to
  desired state, observed state, audit history, or export payloads.
- Cap raw operation requests at 32 KiB before any host parser or correlation
  lookup, decode under fixed process limits, reject any standalone manifest
  frame, and retain the 16-KiB canonical request, result, and root-generated
  manifest ceilings for every retry. A local YAML create specification is a
  bounded client convenience, not a host input or authorization document.
- Bound indirect root-owned growth to 25 tenants, 10 GiB/500,000 release inodes,
  10,000/64-MiB shared authorization/correlation records, 128 MiB of
  hash-chained ordinary audit, and 60 issuer-created IDs/hour; fail closed and
  rotate audit only after a restore-verified, durably indexed
  `lowerduckpond-audit-archive` Restic snapshot is protected from ordinary
  retention and prune.
- Install all production components with `static_publication_enabled: false`.
  While disabled, reject tenant jobs before allocation and reject tenant-bearing
  Caddy candidates. Enable it only after the complete disposable-host suite and
  production preflight pass, then exercise a synthetic two-tenant canary
  scenario through both ordinary audited lifecycles before onboarding a real
  tenant.

### End-to-end tests

- Create an undeployed tenant and verify that it persists without a release or
  public routes.
- Provision a tenant and observe a valid HTTPS response.
- Deploy a replacement and verify atomic cutover.
- Roll back to the previous release.
- Reject traversal paths and escaping symlinks.
- Reject hostile links, special entries, collisions, and archive expansion.
- Exhaust the provisioner's private workspace by bytes and by inodes and prove
  the limits cannot consume the host filesystem or leave persistent entries
  after a service restart.
- Overflow, interrupt, stall, and race root-owned intake transfers and prove
  their streaming limits, single slot, free-space reserve, and cleanup prevent
  accumulated artifacts before activation.
- Forge and alter every authorization-job field, replace its artifact, drift
  target state, replay its correlation, and invoke the provisioner sudo entry
  with raw operations or unknown IDs; prove only the exact root-owned job can
  claim capacity or mutate state and the worker cannot read export results.
- Execute an authorized archive, then prove its job, correlation, and evidence
  cannot be transformed into deletion. Only a separately authenticated delete
  job bound to the resulting archived state may remove the tenant.
- Suspend and restore without data loss.
- Export active, suspended, and archived tenants, import each bundle into a separately
  created undeployed tenant, and prove content round-trips while target
  identity, origin, slug, quotas, and a new deployment remain authoritative.
- Delete a never-deployed reservation normally, then prove that deployed or
  ambiguous history cannot use the archive-free transition.
- Prove the production storage policy cannot expire a current archive bundle
  while authoritative archived tenant state still binds it.
- Delay a rollback across suspension and prove it cannot republish the tenant;
  only resume may leave the suspended state.
- Repeatedly deploy and roll back while suspended and prove retention remains at
  the selected release plus two predecessors without publishing a route or
  deleting an export- or intent-pinned release.
- Rename a slug while preserving the tenant identity.
- Assign the released slug to another tenant and prove its alias points to a
  different canonical origin while no tenant bytes, path, query, cookie, or
  service worker are exposed at the alias.
- From a hostile `.com` tenant, prove `.net` platform cookies are unreachable;
  record the expected sibling `.com` parent-cookie behavior; and prove Caddy
  removes request and response cookies without changing a static route or body.
- Change or remove the configured and persisted tenant-origin suffix across
  convergence, startup, reconciliation, backup restore, and an empty-live-tenant
  state; prove every mismatch fails closed and no canonical route changes.
- Run the same provisioning job twice and prove convergence.
- Race creates and rename against the same slug and prove exactly one operation
  can commit it.
- Recover the preceding publication after interrupted activation or reload
  failure.
- Serialize activation with backup and reconcile a restored state snapshot.
- Rotate a closed audit segment, age ordinary 7/5/12 snapshots through
  forget/prune, and prove the protected tagged snapshot and complete audit chain
  remain discoverable and restore-verifiable.
- Overlap export capture with lifecycle mutations and release garbage
  collection and prove each bundle describes one complete generation.
- Interrupt archive construction around every local-intent, remote-upload, and
  lifecycle-commit boundary and prove recovery preserves a bound object or
  version-purges/quarantines the one discoverable unreferenced object before
  retry, without treating a delete marker as reclaimed storage. Assert the
  archive writer issues only one bounded `PutObject` and leaves no incomplete
  multipart upload at any interruption point.
- Interrupt archive-retiring restore and deletion around every journal,
  lifecycle, audit, version-purge, confirmation, and cleanup-commit boundary;
  prove a bound version survives and a committed retired version cannot
  accumulate or release its remote charge early.
- Fill remote archive key, version/marker, and aggregate-byte accounting at and
  beyond each limit, including unknown and noncurrent versions, then prove
  reservation, restart, and repeated restore/re-archive cannot exceed it.

### Exit criteria

From the trusted workstation, an administrator can create, deploy, replace,
roll back, suspend, resume, rename and reuse a slug, export, import into a
separate tenant, archive, restore, rearchive with current evidence, delete,
reconcile, back up, and disposable-restore a static site without manually
editing the host. HTTPS and consistent publication survive a reboot.

Every externally requested operation executes from an immutable authenticated
job issued through the dedicated forced-command operator boundary. The
provisioner cannot originate or transform lifecycle authority, read
authoritative tenant state, or read an export payload. The production canary
uses a source and separately imported target and passes only after both are
removed through their ordinary audited lifecycles. The dual-domain browser and
Caddy cookie boundary, Cloudflare proxy, cache-bypass and Always Online policy,
authenticated-origin and direct-origin-denial boundary, isolated archive
Space, Caddy/systemd recovery, hostile-archive, durability, backup, and audit
gates are demonstrated with `static_publication_enabled` deliberately enabled.

## 7. Milestone 4: control plane and lifecycle automation — planned

### Minimum domain model

- User
- Authentication identity
- Site
- Domain
- Deployment
- Runtime tier
- Quota
- Database allocation
- Host assignment
- Provisioning job
- Lifecycle event
- Notification
- Policy acceptance
- Audit event

### Minimum user flows

- Sign up and verify identity.
- Request an available site slug.
- Accept the hosting and content policies.
- Await approval during the pilot.
- Upload and deploy a static site.
- View deployment and quota status.
- Download a complete site export.
- Renew, suspend voluntarily, reactivate, or cancel.

### Administrative flows

- Review and approve or reject applications.
- Inspect provisioning failures and retry safely.
- Suspend immediately for operational or policy reasons.
- Adjust quotas with an audit trail.
- Preview archival and deletion candidates.
- Restore a tenant within its retention window.
- View resource use by tenant and host.

### Lifecycle scheduler

The authenticated control plane should calculate desired transitions and issue
immutable authorization envelopes; the scheduler enqueues their opaque job IDs
and the provisioner executes them. Neither scheduler nor provisioner should
directly delete files or databases or change a job's actor, operation, target,
request, artifact, or expected source state. Notifications and grace periods
are first-class records so retries cannot accidentally send repeated notices
or skip required stages.

Suggested configurable defaults for the pilot:

- Renewal confirmation after 90 days without owner login or deployment.
- Notices before suspension, with at least three delivery attempts.
- Dynamic workloads may stop during suspension; static content policy may be more generous.
- Archive remains recoverable for at least 90 days.
- Final deletion requires both an expired retention period and a successful archive record.

### Exit criteria

The complete static-site lifecycle operates through the control plane, produces an audit history, and can recover cleanly from duplicated or interrupted jobs.

## 8. Milestone 5: backup, observability, and operations — planned

### Backup implementation

- Consistent control-plane backup.
- Per-tenant database dump when applicable.
- Encrypted Restic snapshot to Spaces.
- Retention and pruning policy.
- Backup freshness metric.
- Periodic restore into an isolated test location.
- Documented Droplet rebuild and full-platform restore procedure.

### Monitoring implementation

- DigitalOcean host alerts for outside-the-machine signals.
- Prometheus-compatible host and service metrics.
- Grafana dashboards for host, edge, tenant, provisioning, and backup views.
- Alertmanager routing to the project operator.
- Structured Caddy and application logs with bounded retention.
- CrowdSec integration for edge and authentication logs.

### Cloudflare cache lifecycle

- Keep the Milestone 3 two-zone cache bypass until this phase's threat-model
  amendment and acceptance tests pass.
- Keep Always Online disabled unless a distinct lifecycle decision approves its
  stale-cache and Internet Archive behavior; enabling ordinary CDN caching does
  not implicitly approve it.
- Define exact eligible route classes, cache keys, browser and edge TTLs, stale
  serving behavior, and cross-tenant denial; aliases, the `.com` apex, unknown
  hosts, errors, and the trusted administration application remain ineligible.
- Bind deploy, rollback, suspend, resume, rename, archive, restore, delete, and
  slug reuse to purge ordering and failure recovery so an operation cannot be
  reported complete while obsolete bytes remain eligible at the edge.
- Use a distinct purge-only runtime credential and prove that Caddy's ACME token
  and OpenTofu's edge token cannot purge cached tenant content.
- Exercise cache fill, purge, timeout, lost response, provider outage, and
  emergency DNS-only rollback before enabling caching in production.

### Initial service-level indicators

- HTTPS reachability of a synthetic tenant.
- Successful response percentage.
- Edge request latency.
- Provisioning success percentage and duration.
- Oldest queued provisioning job.
- Most recent successful backup and restore test.
- Host disk/inode headroom.
- Tenant quota saturation.

### Operational documentation

- Rebuild a failed Droplet.
- Restore one tenant.
- Restore the entire platform.
- Rotate DigitalOcean, Cloudflare, database, and Restic credentials.
- Handle a full disk.
- Quarantine a tenant.
- Roll back Caddy or tenant-runtime releases.
- Respond to suspected cross-tenant access.

### Exit criteria

An operator can detect a failed service, identify the affected tenant or subsystem, restore a test tenant from backup, and follow a documented recovery procedure.

## 9. Milestone 6: dynamic PHP pilot — planned

Do not expose PHP publicly until the static platform and recovery path are working.

### Origin and cookie prerequisite

Record a new architecture decision before implementing the public dynamic
route. Arbitrary PHP applications need server-side cookies and therefore cannot
inherit Milestone 3's blanket `.com` request/response cookie stripping. Decide
whether the pilot constrains cookie behavior, assigns stronger isolated or
custom domains, or adopts another boundary. Include sibling cookie injection,
same-site CSRF, cookie-capacity denial of service, and framework parsing in the
dynamic threat model.

### Runtime image

Build and pin a minimal maintained image containing:

- PHP-FPM.
- A deliberately small extension set.
- Production-safe PHP limits.
- An unprivileged runtime user.
- Health check endpoint or process check.
- No package manager or compiler in the runtime image unless required.

### Tenant container generation

Generate one rootless Quadlet unit per dynamic tenant with:

- Dedicated Unix identity.
- Read-only image/root filesystem.
- Tenant-specific content and data mounts.
- Temporary filesystems for ephemeral paths.
- CPU, memory, PID, and restart limits.
- Loopback-only published endpoint.
- Internal network policy.
- Dropped capabilities and `no-new-privileges`.
- Explicit image digest.

### SQL allocation

- Generate a random per-tenant credential.
- Create exactly one tenant database and least-privilege user.
- Deliver the credential to the runtime without writing it into the public manifest or logs.
- Revoke the user on suspension or cancellation according to policy.
- Dump the database during export and archival.

### Isolation test suite

Treat isolation as a product feature with executable tests. From a deliberately hostile tenant fixture, verify that it cannot:

- Read another tenant's files or environment.
- Reach another tenant's PHP endpoint directly.
- Authenticate to another tenant database.
- Reach the host container socket.
- Reach the DigitalOcean metadata endpoint.
- Bind a public host port.
- Escape storage, memory, PID, request-time, or upload limits.
- Preserve an unauthorized process after suspension.

Run destructive isolation tests on an ephemeral test Droplet rather than the production host.

### Exit criteria

A small approved cohort can run PHP with tenant-scoped SQL, measured quotas, clean suspension/export behavior, and passing cross-tenant isolation tests.

## 10. Milestone 7: reference tenant and community pilot — planned

Build a platform-owned reference site in its separate repository and deploy it
through an ordinary `.com` slug alias and UUID-derived canonical origin. Its
content, repository name, and slug are open product questions. Designate its
immutable tenant ID in root-owned state as the municipal target for the exact
`.com` apex. The apex remains stateless and redirects only a query-free `GET`
or `HEAD` for `/` directly to the active tenant's UUID-derived immutable origin,
never through its reusable slug; it never serves tenant content directly, and
every redirect or fallback response carries `Cache-Control: no-store`. The
reference tenant should exercise:

- Ordinary wildcard DNS and HTTPS in the tenant namespace.
- Static assets and intentionally period-inappropriate styling.
- Ordinary deployment, rollback, export, and restore.
- Rename, suspension, restoration, and slug reassignment, including reassigning
  a former slug after the apex response is issued and proving the immutable
  destination cannot reach the replacement tenant.
- No platform-side exception beyond the documented root-owned apex
  designation and redirect.

Then onboard a deliberately small set of residents. Track where the support burden actually appears: content upload, DNS expectations, PHP compatibility, quota confusion, forgotten renewals, or moderation.

### Exit criteria

The reference site and several resident sites survive at least one complete
renewal, backup, restore, and platform upgrade cycle.

## 11. Scaling triggers and responses

| Observed trigger | First response | Later response |
| --- | --- | --- |
| Sustained CPU or memory pressure | Resize the Droplet | Add tenant execution nodes and host assignment |
| Tenant storage pressure | Enforce/adjust quotas; attach block storage | Separate static delivery or storage tier |
| Database contention | Tune and constrain workloads | Move SQL to a dedicated service |
| Provisioning blocks web requests | Move work to the job queue | Deploy per-host reconciliation agents |
| One tenant dominates resources | Suspend, throttle, or relocate it | Risk-based node pools |
| Host failure recovery is too slow | Improve image/bootstrap and restore automation | Maintain warm capacity |
| Edge/routing becomes a bottleneck | Separate Caddy from tenant execution | Introduce deliberate multi-node routing/load balancing |

Scaling work starts from metrics and incidents. The tenant manifest, host-assignment field, idempotent provisioner, and portable archives are the architectural investments that make it possible.

## 12. Quality strategy

This project is unusually well suited to demonstrating quality architecture rather than only application-level tests.

### Test layers

- **Static checks:** formatting, linting, schemas, secret detection, dependency and container scanning.
- **Infrastructure contract tests:** inspect OpenTofu plan JSON for required network, storage, tagging, and lifecycle properties.
- **Configuration tests:** run Ansible roles in disposable environments and assert idempotence.
- **Unit tests:** lifecycle policy, slug rules, quota calculations, manifest generation, notification deduplication, and job convergence.
- **Integration tests:** control plane, queue, provisioner, database allocation, Caddy generation, and backup adapter.
- **Isolation tests:** hostile tenant attempts against filesystem, network, process, SQL, metadata, and resource boundaries.
- **End-to-end tests:** signup through HTTPS deployment, renewal, suspension,
  export, portable import, restore, and cancellation.
- **Recovery tests:** recreate a host and restore one tenant and the platform control data.

### Ephemeral environment strategy

Provide a manually triggered or scheduled workflow that:

1. Creates a uniquely tagged temporary Droplet and DNS namespace.
2. Configures it with the production Ansible roles.
3. Provisions static and hostile dynamic test tenants.
4. Runs lifecycle, isolation, TLS, and restore tests.
5. Collects sanitized logs and test reports.
6. Destroys the temporary infrastructure even when tests fail.

Add a maximum-age cleanup job for tagged test resources so an interrupted CI run cannot leave them indefinitely billable.

## 13. Delivered foundation pull requests

The original three-pull-request implementation sketch evolved during review
into eight focused pull requests:

- [PR #1: repository skeleton and contracts](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/1)
- [PR #2: single-host infrastructure](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/2)
- [PR #3: rebuild-drill guardrails](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/3)
- [PR #4: project-membership plan policy](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/4)
- [PR #5: configured static host](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/5)
- [PR #6: standalone production acceptance](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/6)
- [PR #7: unambiguous backup convergence output](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/7)
- [PR #8: static systemd unit verification](https://github.com/lowerduckpond-net/lowerduckpond.net/pull/8)

Together they provide a reproducible foundation and a working empty-host
vertical slice without yet accepting tenant content or untrusted runtime code.

## 14. Definition of initial public launch

The first public release is ready when:

- Infrastructure and host configuration can rebuild the service from scratch.
- Apex and wildcard HTTPS renew automatically in both owned zones.
- Signup and approval create a static tenant without manual server edits.
- Deploy, rollback, suspend, export, import, archive, restore, and delete are
  idempotent.
- Quotas and audit events are visible.
- Encrypted off-host backups and a restore test are current.
- A platform-owned reference site is deployed through an ordinary `.com` slug
  and immutable tenant origin.
- Operator runbooks cover the likely failure modes.
- The acceptable-use, privacy, retention, and service-expectation policies are published.
- The PHP tier remains disabled unless its isolation test suite and operational controls are complete.

## 15. Reference documentation

- [DigitalOcean infrastructure automation](https://docs.digitalocean.com/reference/terraform/)
- [DigitalOcean provider resources](https://docs.digitalocean.com/reference/terraform/reference/resources/)
- [DigitalOcean Droplet user data](https://docs.digitalocean.com/products/droplets/how-to/provide-user-data/)
- [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https)
- [Caddy DNS challenge configuration](https://caddyserver.com/docs/caddyfile/directives/tls)
- [Podman Quadlet](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- [OpenTofu S3-compatible backend](https://opentofu.org/docs/language/settings/backends/s3/)
