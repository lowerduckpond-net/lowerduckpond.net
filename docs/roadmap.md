# Lower Duck Pond Hosting: Implementation Roadmap

This roadmap turns the architecture in [`architecture.md`](architecture.md) into incremental, independently demonstrable releases. The ordering intentionally establishes static hosting, reproducible infrastructure, backups, and operational visibility before enabling untrusted PHP.

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
│       │   └── digitalocean-spaces/
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

The `lowerduckpond.com` city site should live in a separate repository and deploy through the same contract available to ordinary tenants.

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

Operator-accepted defaults:

- Use MariaDB for tenant PHP databases unless the selected control-plane framework strongly favors PostgreSQL.
- Support archive upload first; add Git-based deployment after the deployment manifest and rollback behavior are stable.
- Require administrative approval during the pilot.
- Keep Milestone 0 limited to repository foundations; define the tenant manifest in Milestone 3.

## 3. Milestone 0: repository foundation

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

## 4. Milestone 1: DigitalOcean foundation

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

The firewall should expose only:

- TCP 80 from the Internet.
- TCP 443 from the Internet.
- TCP 22 from an explicit administrative allowlist during the initial release.
- Required outbound traffic for operating-system updates, ACME, backups, and monitoring.

Keep host-level nftables policy under Ansible as a second boundary.

### State bootstrap

Create remote state separately from the production stack. DigitalOcean Spaces is S3-compatible and is suitable for encrypted state storage, but OpenTofu's native S3 lockfile depends on conditional-write behavior that must be verified against the selected Spaces configuration.

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

## 5. Milestone 2: reproducible host configuration

### Ansible roles

Implement small composable roles rather than one monolithic playbook:

- `base`: users, packages, time, locale, updates, journald, and basic hardening.
- `firewall`: host ingress/egress policy and metadata-endpoint protection.
- `caddy`: pinned custom Caddy build, configuration, durable certificate storage, and reload validation.
- `podman`: rootless Podman prerequisites, subordinate IDs, lingering, storage, and networks.
- `database`: database engine, durable storage, local-only administration, backup account, and tuning.
- `backup`: database dumps, Restic, schedules, retention, and health reporting.
- `monitoring`: exporters, collection, dashboards, and alerts.
- `provisioner`: service account, directories, queue access, and restricted privileged operations.

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

### Exit criteria

A newly provisioned Droplet becomes a working empty hosting node after one Ansible command, and a second run is idempotent.

## 6. Milestone 3: static tenant MVP

### Tenant manifest v1

Define and version a machine-readable contract before building the portal. For example:

```yaml
apiVersion: hosting.lowerduckpond.net/v1alpha1
kind: Site
metadata:
  id: 01JEXAMPLE0000000000000000
  slug: duck-repair
spec:
  runtime: static
  domains:
    - duck-repair.lowerduckpond.net
  quotas:
    storageMiB: 100
    files: 5000
  state: active
```

The stable tenant ID must not change when a public slug changes.

### Provisioner behavior

Implement idempotent commands or jobs for:

- Create tenant directory and metadata.
- Validate slug and hostname uniqueness.
- Stage and validate an uploaded archive.
- Reject unsafe paths, symlinks escaping the site root, excessive file counts, and quota violations.
- Atomically activate a deployment.
- Retain a bounded number of previous releases.
- Generate the tenant's Caddy route.
- Validate and reload Caddy.
- Suspend, resume, export, archive, restore, and delete a site.
- Reconcile actual host state against all desired manifests.

### End-to-end tests

- Provision a tenant and observe a valid HTTPS response.
- Deploy a replacement and verify atomic cutover.
- Roll back to the previous release.
- Reject traversal paths and escaping symlinks.
- Suspend and restore without data loss.
- Rename a slug while preserving the tenant identity.
- Run the same provisioning job twice and prove convergence.

### Exit criteria

An administrator can create, deploy, suspend, restore, export, and delete a static site without manually editing the host.

## 7. Milestone 4: control plane and lifecycle automation

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

The scheduler should calculate desired transitions and enqueue jobs; it should not directly delete files or databases. Notifications and grace periods are first-class records so retries cannot accidentally send repeated notices or skip required stages.

Suggested configurable defaults for the pilot:

- Renewal confirmation after 90 days without owner login or deployment.
- Notices before suspension, with at least three delivery attempts.
- Dynamic workloads may stop during suspension; static content policy may be more generous.
- Archive remains recoverable for at least 90 days.
- Final deletion requires both an expired retention period and a successful archive record.

### Exit criteria

The complete static-site lifecycle operates through the control plane, produces an audit history, and can recover cleanly from duplicated or interrupted jobs.

## 8. Milestone 5: backup, observability, and operations

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

## 9. Milestone 6: dynamic PHP pilot

Do not expose PHP publicly until the static platform and recovery path are working.

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

## 10. Milestone 7: first customer and community pilot

Build `lowerduckpond.com` in its separate repository and deploy it through the ordinary tenant interface. It should exercise:

- Independent domain verification and HTTPS.
- Static assets and intentionally period-inappropriate styling.
- Ordinary deployment, rollback, export, and restore.
- No undocumented platform-side exceptions.

Then onboard a deliberately small set of residents. Track where the support burden actually appears: content upload, DNS expectations, PHP compatibility, quota confusion, forgotten renewals, or moderation.

### Exit criteria

The city site and several resident sites survive at least one complete renewal, backup, restore, and platform upgrade cycle.

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
- **End-to-end tests:** signup through HTTPS deployment, renewal, suspension, export, restore, and cancellation.
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

## 13. Suggested first three pull requests

### PR 1: repository skeleton and contracts

- Documentation, license, contribution and security files.
- Tool pinning and common developer commands.
- Minimal independently packaged control-plane and provisioner entry points.
- CI for Markdown, schemas, secrets, OpenTofu, and Ansible.

### PR 2: single-host infrastructure

- DigitalOcean and Cloudflare OpenTofu modules.
- Production environment inputs with secret-free examples.
- Remote-state bootstrap documentation.
- Plan assertions and deployment workflow with protected, serialized apply.

### PR 3: configured static host

- Minimal cloud-init.
- Ansible roles for base, Caddy, static tenant directories, backup, and monitoring.
- A fixture tenant served at a test subdomain.
- Host acceptance and idempotence tests.

After those three pull requests, the project has a reproducible foundation and a working vertical slice without yet accepting untrusted runtime code.

## 14. Definition of initial public launch

The first public release is ready when:

- Infrastructure and host configuration can rebuild the service from scratch.
- Wildcard HTTPS renews automatically.
- Signup and approval create a static tenant without manual server edits.
- Deploy, rollback, suspend, export, archive, restore, and delete are idempotent.
- Quotas and audit events are visible.
- Encrypted off-host backups and a restore test are current.
- `lowerduckpond.com` is deployed as an ordinary tenant.
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
