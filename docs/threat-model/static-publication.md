# Static-publication threat model

- Status: accepted Milestone 3 baseline
- Date: 2026-08-22
- Related decision: [ADR 0016](../adr/0016-model-static-publication-threats.md)

## Scope

This model covers the Milestone 3 path from a static tenant manifest and ZIP
archive on the trusted operator workstation through intake, validation,
immutable release installation, Caddy route activation, lifecycle operations,
backup, restore, and reconciliation on the single production host.

It excludes the Milestone 4 public control plane, custom domains, PHP, tenant
containers, tenant SQL, and arbitrary executable server-side content. Those
features require their own threat-model extensions before activation.

## Security objectives

- Tenant content cannot read or modify host secrets, host configuration, Caddy
  administration, another tenant, or backup credentials.
- A compromised provisioner cannot turn its narrow activation capability into
  arbitrary root, filesystem, process, or Caddy authority.
- Only validated, quota-compliant regular files become publicly readable.
- Caddy serves only a root-generated route pointing to the intended immutable
  release.
- A failed, concurrent, repeated, or interrupted operation converges on either
  the preceding valid publication or the complete requested publication.
- Backup and restore preserve enough consistent desired state, immutable
  content, and audit evidence to reconcile safely.
- Destructive lifecycle operations require explicit intent and recoverable
  archive evidence.

## Assets

- The Cloudflare DNS-edit token read by Caddy.
- Caddy's root-owned configuration and Caddy-only admin socket.
- Administrative SSH access and the root privilege boundary.
- Tenant manifests, immutable releases, routes, archives, and audit history.
- Other tenants' content and future credentials.
- Restic password, Spaces credentials, repository contents, and backup health
  evidence.
- Host availability, disk and inode capacity, and the integrity of Caddy and
  backup services.

## Actors and trust

| Actor or component | Trust assumption |
| --- | --- |
| Anonymous visitor | Untrusted; controls requests, hostnames, paths, and request volume. |
| Archive author | Untrusted; controls every ZIP byte and filename. |
| Unprivileged provisioner | Potentially compromised; may request valid tenant operations but must not choose host paths, commands, or Caddy syntax. |
| Trusted-workstation client | Authenticated operator transport; trusted to request operations, not to bypass root validation. |
| Root activator | Trusted computing base; narrowly implements validation, release, route, lock, and recovery contracts. |
| Caddy | Trusted edge process with read-only tenant content and no provisioner-writable configuration. |
| Backup service | Trusted root service holding repository credentials; synchronized with tenant-state mutation. |
| Operating system and pinned dependencies | Trusted platform boundary, maintained through the reviewed host baseline. |

An authorized root administrator and compromise of the operating system or
root activator are outside the containment guarantee. They remain operational
and supply-chain risks.

## Trust boundaries and data flow

1. The operator submits a strict manifest and ZIP through the restricted SSH
   adapter into a fixed, non-public intake area.
2. The unprivileged provisioner performs an advisory preflight and constructs a
   structured request with a correlation ID.
3. The root activator opens only the fixed intake artifact, revalidates it, and
   extracts it into a new root-owned temporary release.
4. The activator normalizes and seals the release, generates a complete
   root-owned candidate route set, and validates it with Caddy.
5. Under the publication lock, the activator records intent, atomically selects
   the candidate route set, reloads Caddy, and records observed state. Failure
   restores the preceding route-set reference.
6. Backup holds a shared tenant-state lock while reading content, manifests,
   and audit state. Restore writes outside live paths and reconciliation applies
   the same activation contract.

No public request, tenant file, or unprivileged process can reach Caddy's admin
socket or write an active route, immutable release, backup environment, or
authoritative desired-state, observed-state, archive, deployment, or audit
record.

## Threats and required controls

| Threat | Required control and evidence |
| --- | --- |
| Path traversal or absolute extraction | Normalize and validate every path twice; extract through directory-relative, no-follow operations; hostile fixtures must fail. |
| Symlink, hard-link, device, FIFO, socket, or permission abuse | Accept only regular files/directories; normalize modes; inspect ZIP metadata and actual created objects. |
| ZIP bomb, oversized entry set, disk or inode exhaustion | Enforce compressed, expanded, per-file, total-entry, and ratio limits during streaming extraction; count directories as entries and delete failed staging trees. |
| Duplicate, Unicode, slash, backslash, or case ambiguity | Normalize first, reject ambiguity and collisions, and generate deterministic manifests and exports. |
| Duplicate YAML mapping keys | Reject duplicates during YAML composition, before schema validation or canonical JSON generation can discard the ambiguity. |
| Mutation after validation | Root performs final extraction; active releases and route sets are root-owned and immutable to Caddy and the provisioner. |
| Arbitrary Caddy behavior or secret disclosure | Generate allowlisted routes from validated primitives; accept no Caddy text; keep the admin socket Caddy-only. |
| Validation-to-reload race | Validate an immutable complete route-set generation and select it under the shared publication lock. |
| Concurrent or replayed jobs | Serialize publication, bind results to correlation IDs and request digests, and make retries idempotent. |
| Manifest or audit tampering | Keep desired and observed state and append-only audit operations root-owned; allow the provisioner no direct write, replacement, truncation, or deletion authority. |
| Crash between filesystem, route, reload, and state changes | Write intent first; retain the prior route set; reconcile incomplete records on startup and before later operations. |
| Cross-tenant read or overwrite | Derive all paths from validated UUIDs, prohibit caller paths, use root ownership, and test hostile operations across two tenants. |
| Backup captures incompatible generations | Backup uses a shared tenant-state lock; mutation uses it exclusively; restored state must reconcile before publication. |
| Unsafe archive, restore, or deletion | Verify portable export checksums and durable archive evidence; restore as a new deployment; keep emergency deletion behind a distinct root-only operator command that the provisioner cannot invoke. |
| Intake artifact replacement | Open beneath the fixed intake directory without following links, bind validation to the opened artifact digest, and move or mark the claimed request before activation. |

## Security invariants

Implementation and review must preserve these invariants:

1. No provisioner-writable path is reachable through a live Caddy document root
   or active route import.
2. No caller can supply Caddy syntax, a destination path, an arbitrary command,
   a Unix identity, or a service name to the root activator.
3. Every live route refers to one validated immutable release belonging to the
   same tenant ID.
4. Candidate validation, active-route selection, reload, and rollback occur
   while holding the global publication lock.
5. Desired state, observed state, releases, and audit events are recoverable and
   reconciliation never publishes unvalidated content.
6. Unknown manifest fields, unsupported archive semantics, and unrecognized
   lifecycle transitions fail closed; duplicate YAML keys are rejected before
   schema validation.
7. Credentials never enter tenant content, provisioner logs, results, exports,
   manifests, or audit payloads.
8. The provisioner's capability cannot bypass archive evidence for deletion;
   emergency deletion requires the separately authenticated administrative
   entry point.
9. Authoritative manifests, observed state, deployment and archive records, and
   audit history are root-owned and writable only through narrow validated or
   append-only operations.

## Residual risks

- A vulnerability in the root activator, Caddy, Python ZIP parser, kernel, or
  filesystem can cross the intended boundary.
- Static JavaScript can harm or mislead site visitors even though it does not
  execute on the host; content policy and browser protections remain necessary.
- Limits reduce but do not eliminate availability impact from expensive valid
  content or high request volume.
- The single host remains one availability and blast-radius boundary.
- A trusted administrator can intentionally override deletion safeguards or
  directly modify the host.

These risks are accepted for the static pilot and must be revisited before
custom domains, public upload, PHP, or multi-host provisioning.

## Review and acceptance gates

- Each root-activator input and filesystem transition has a documented
  allowlist and negative tests.
- Unit, property, concurrency, failure-injection, Molecule, Testinfra, restore,
  and reconciliation tests required by ADR 0022 pass.
- A disposable-host exercise passes before production.
- A reserved production canary completes deploy, HTTPS, rollback, suspension,
  restore, backup recovery, reconciliation, and cleanup from the trusted
  workstation.
- Sanitized evidence is recorded without credentials, production backup
  metadata, or tenant content.
