# Static-publication threat model

- Status: accepted Milestone 3 baseline
- Date: 2026-08-22
- Related decisions: [ADR 0016](../adr/0016-model-static-publication-threats.md)
  and [ADR 0023](../adr/0023-separate-reusable-slugs-from-tenant-origins.md)

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
- Tenant JavaScript cannot set parent-domain cookies that reach the platform or
  another tenant.
- Reassigning a human-readable slug cannot transfer a browser origin, service
  worker, cookie, or tenant-controlled storage to the next tenant.
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
- The pinned platform namespace record, tenant manifests, immutable releases,
  canonical-origin and alias routes, archives, and audit history.
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
| Ansible Caddy transaction | Trusted host-configuration path; stages candidates and shares the publication lock, but is not callable through provisioner sudo. |
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
3. A fixed-buffer privileged reader enforces raw operation and manifest byte
   ceilings plus a read deadline before any constrained structured parser or
   correlation lookup. The root activator then claims the fixed intake
   artifact, copies its bytes once into a newly created root-owned snapshot
   while enforcing the upload limit and computing its digest, and closes the
   intake descriptor. It verifies, revalidates, and extracts only that
   non-provisioner-writable snapshot into a new root-owned temporary release.
4. The activator normalizes and seals the release, generates a complete
   root-owned Caddy runtime generation containing a manifest-bound binary,
   environment, canonical tenant-content routes, platform-only slug-alias
   routes, and base configuration, and validates the generation with its own
   inputs. Every canonical origin must match both its manifest and independent
   derivation from the pinned platform namespace record.
5. Under the publication lock, the activator records intent and atomically
   selects the candidate runtime generation. Configuration-only changes reload
   and commit synchronously. Binary or environment changes persist a phased
   restart intent, release the lock, and queue a non-blocking systemd restart;
   pre-start and post-start helpers separately acquire the lock to pin, verify,
   and commit the generation. Failure uses the same handoff to restore the
   preceding complete generation.
6. Backup holds a shared tenant-state lock while reading content, manifests,
   and audit state. Restore writes outside live paths and reconciliation applies
   the same activation contract.
7. Ansible stages a complete Caddy runtime generation outside live paths and
   uses a root-owned transaction under the global publication lock to select it
   and persist restart intent, then releases the lock before handing the restart
   to systemd. A frozen systemd bootstrap reconciles intent and pins one
   generation directory before each start or automatic restart.

No public request, tenant file, or unprivileged process can reach Caddy's admin
socket or write an active route, immutable release, backup environment, or
authoritative desired-state, observed-state, archive, deployment, or audit
record.

## Threats and required controls

| Threat | Required control and evidence |
| --- | --- |
| Path traversal or absolute extraction | Normalize and validate every path twice; extract through directory-relative, no-follow operations; hostile fixtures must fail. |
| Symlink, hard-link, device, FIFO, socket, or permission abuse | Accept only regular files/directories; normalize modes; inspect ZIP metadata and actual created objects. |
| ZIP bomb, decoder allocation, oversized or overlapping metadata, deep paths, implicit-directory inflation, disk or inode exhaustion | Structurally gate end, directory, extra-field, offset, region, path-byte, component, and depth bounds before a decoder; count explicit and implicit directories; allow only stored and Deflate deployment methods; require matching local and central headers; and constrain the privileged parser by memory, swap, task, descriptor, CPU, and runtime limits. Give portable restore a bounded raw-envelope allowance, then strip its fixed prefix and enforce the unchanged tenant-tree limits. Enforce compressed, expanded, per-file, total-entry, and ratio limits during streaming extraction and delete failed staging trees. Remove persistent provisioner-writable storage, hard-cap its private ephemeral workspace by aggregate bytes and inodes, bound root snapshots and cleanup, and preserve a host free-space reserve. |
| Duplicate, Unicode, slash, backslash, case, or export-encoding ambiguity | Normalize first and reject ambiguity and collisions. Generate manifests canonically and define every portable ZIP byte: JSON, checksums, member order, stored encoding, timestamps, flags, modes, metadata, central directory, and archive digest. |
| Duplicate YAML mapping keys | Reject duplicates during YAML composition, before schema validation or canonical JSON generation can discard the ambiguity. |
| Platform or cross-tenant cookie poisoning | Serve tenant content only from immutable UUID-derived hostnames that are distinct registrable domains according to supported browser Public Suffix List behavior. Keep `lowerduckpond.net` responses platform-controlled and platform authentication cookies host-only. |
| Slug reassignment transfers persistent browser state | Treat the slug hostname only as a platform alias. Redirect its exact bare root without caching, referrer, cookie, path, query, tenant body, tenant header, or caller-selected target to the immutable tenant origin. Never reassign a tenant ID or canonical hostname; release only the slug mapping. |
| Alias becomes a confused deputy, secret sink, or stale content URL | Generate its destination solely from root-owned tenant ID and suffix, redirect only active tenants, reject every non-root path, query, and unsupported method without forwarding, discard sensitive alias request fields before logging, and test that uploaded bytes and service workers are unreachable at the alias. |
| Mutation after validation | Root performs final extraction; active releases and complete Caddy generations are root-owned and immutable to Caddy and the provisioner. |
| Arbitrary Caddy behavior or secret disclosure | Generate allowlisted complete Caddy configurations from validated primitives; accept no Caddy text; keep generation environment files Caddy-only and excluded from backup, and keep the admin socket Caddy-only. |
| Validation-to-reload race | Validate one immutable complete runtime generation with its manifest-bound binary and environment, select it through one active reference under the publication lock, and reload from directory-pinned open inputs. |
| Ansible convergence selects stale tenant routes or automatic restart mixes Caddy inputs | Stage only host inputs before locking; under publication reread authoritative tenant state, construct and validate the final complete route-bearing generation, and then select it through phased root-owned intent. Before every start, the frozen bootstrap reconciles intent and pins one manifest-verified generation directory. Change the bootstrap only while Caddy is stopped and masked. |
| Synchronous restart deadlocks or exhausted candidate retries block recovery | Persist and select a restart candidate under the lock, release it before queuing a non-blocking systemd job, and let pre-start, launcher, post-start, and rollback helpers acquire it independently. After durably selecting the prior generation and releasing the lock, reset the service failed/start-limit state before queuing recovery. Block later mutations on durable intent, and never wait for a lock-acquiring systemd hook while retaining the lock. |
| Runtime generations exhaust disk or retain secrets indefinitely | Admit at most active, last-known-good, and intent candidate generations; enforce aggregate unique-inode byte/inode and host-free-space bounds; clean unreferenced staging after terminal states and startup; keep environment/config Caddy-only and backup/diagnostic-excluded. |
| Concurrent or replayed jobs | Serialize publication, bind results to correlation IDs and request digests, and make retries idempotent. |
| Oversized structured syntax exhausts the privileged parser before canonicalization | Read at most the raw ceiling plus one byte under a deadline before parsing, reject excess without inspecting correlation data, run the decoder under fixed process limits, and then enforce the smaller canonical request, result, and manifest ceilings. Apply the same path to retries. |
| Valid operations indirectly exhaust root-owned state | Enforce host-wide tenant, release byte/inode, correlation record, audit, request/result size, reason, and admission-rate ceilings before staging. Preserve audit in bounded hash-chained segments rotated only after verified off-host backup, with an isolated root-administrator reserve. |
| Ordinary backup retention expires rotated audit evidence | Remove a local segment only after a dedicated tagged audit snapshot is restore-verified and durably indexed. Exclude that tag from ordinary `forget`/`prune`, verify every referenced snapshot during maintenance, and reconstruct the chain from tagged descriptors during recovery. |
| Nested locks deadlock or accumulate waiters | Acquire export, publication, and tenant-state only in that global order; never upgrade; return retryable busy before allocating work; revalidate archive source state after its unlocked construction phase; and never wait for a systemd job that reacquires publication while holding it. |
| Delayed rollback undoes suspension | Recheck lifecycle state under the publication lock; while suspended, change only the remembered deployment and require explicit resume before publishing. |
| Repeated suspended deployments evade release retention | Apply the same selected-release-plus-two-predecessors cleanup after active or suspended deploy and rollback commits and during reconciliation, while preserving export- and intent-pinned releases. |
| Interrupted archive republishes a suspended tenant | Require reconciled source state before archive, bind the exact preceding lifecycle, observed state, remembered deployment, runtime generation, and route presence in intent, and restore that complete source rather than assuming it was active. |
| Manifest or audit tampering | Keep desired and observed state and append-only audit operations root-owned; allow the provisioner no direct write, replacement, truncation, or deletion authority. |
| Crash or power loss between filesystem, route, reload, restart handoff, and state changes | Durably sync generation targets and parents before intent, sync intent before selecting and syncing the active reference, persist every restart phase before releasing its lock, sync desired/observed state and audit before clearing intent, and reconcile from durable evidence. |
| Cross-tenant read or overwrite | Derive all paths from validated UUIDs, prohibit caller paths, use root ownership, and test hostile operations across two tenants. |
| Configured origin-suffix drift abandons or reassigns browser origins | Pin the normalized suffix in backed-up root-owned platform state before the first tenant, persist each complete derived origin in its manifest, and require configuration, platform state, tenant ID, and manifest origin to agree before route mutation. A change requires an explicit future origin-migration design. |
| Backup or export captures incompatible generations | Backup uses a shared tenant-state lock; mutation uses it exclusively. Ordinary export captures its current manifest and immutable release into a root-owned snapshot while holding that shared lock. Archive separately snapshots the source manifest for compare-and-swap and the proposed archived manifest for the bundle. Construction consumes only that snapshot, and restored state reconciles before publication. |
| Concurrent exports exhaust privileged storage | Serialize export and archive construction behind one root-owned host lock; enforce one snapshot, one unacknowledged result, aggregate spool byte/inode ceilings, an encoded-output ceiling, a host free-space reserve, and root-owned terminal, startup, acknowledgement, and expiry cleanup. |
| Crash or abort after versioned archive upload leaves billable remote bytes | Sync a construction intent containing a unique key before upload and its returned version ID afterward, then reconcile any associated lifecycle intent. Preserve only an exactly bound version; otherwise permanently delete every version and marker for the key and confirm absence, or keep quarantine charged and archive admission closed. |
| Unsafe or implementation-dependent archive, restore, or deletion evidence | Put the proposed archived manifest—not its active or suspended source—in the durable bundle and bind the archive record to versioned canonical-manifest and length-delimited release-tree digests, the desired deployment, exact bundle bytes, and stored object version. Recompute the specified representations before archive commit and delete; restore as a new deployment. Permit ordinary archive-free deletion only when root-owned history proves the tenant was never deployed, and keep emergency deletion behind a distinct root-only operator command that the provisioner cannot invoke. |
| Oversized, stalled, or abandoned intake transfer exhausts disk | Admit exactly one root-owned artifact, enforce the operation-specific byte ceiling plus aggregate allocation and host-free-space bounds while streaming, bound idle and total transfer time, publish only after sync, and clean every terminal or startup artifact before reopening admission. |
| Intake artifact replacement or mutation through an existing descriptor | Open beneath the fixed intake directory without following links and claim the request. Stream the opened bytes exactly once into an exclusively created root-owned snapshot while enforcing the compressed-size limit and computing the digest; sync and close the snapshot, then verify the request digest and perform all parsing, validation, and extraction against that snapshot. Never return to the provisioner-writable inode. |

## Security invariants

Implementation and review must preserve these invariants:

1. No provisioner-writable path is reachable through a live Caddy document root
   or active route import.
2. No caller can supply Caddy syntax, a destination path, an arbitrary command,
   a Unix identity, or a service name to the root activator.
3. Every live canonical content route refers to one validated immutable release
   belonging to the same tenant ID. Every slug route is a platform-only alias
   to that tenant's UUID-derived canonical origin and cannot reach a release.
4. Candidate validation, active-generation selection, synchronous reload, and
   every restart or rollback phase transition occur while holding the global
   publication lock; no other path mutates live Caddy inputs. External systemd
   waits occur only after releasing it.
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
10. No tenant-controlled response is served from `lowerduckpond.net` or a
    hostname sharing a registrable domain with the platform or another tenant.
    A slug alias returns only the fixed root-generated redirect contract in ADR
    0023 and holds no tenant or authentication state. Its HTTP listener applies
    the alias allowlist before general HTTPS upgrades and never forwards a
    rejected path or query.
11. A rollback cannot transition a tenant out of `suspended`; only `resume` may
    restore its public routes.
12. No active reference is durably selected before its immutable release and
    complete Caddy-generation targets; intent, state, audit, rollback, and
    intent removal follow the ordered file and parent-directory `fsync` protocol
    in ADR 0017.
13. Privileged digest verification, archive parsing, validation, and extraction
    consume the same root-owned intake snapshot, which cannot be modified by
    the provisioner through its pathname or a previously opened descriptor.
14. The provisioner has no general-purpose persistent writable filesystem; its
    private ephemeral workspace has kernel-enforced aggregate byte and inode
    limits and is not a live publication, intake, state, or backup path.
15. Ordinary deletion of any previously deployed tenant requires a verified
    durable archive bound to the current canonical manifest and desired
    deployment; evidence for an older generation grants no deletion authority.
16. Portable-bundle construction is globally serialized and cannot exceed one
    root-owned snapshot, one unacknowledged output, or the aggregate export-spool
    byte, inode, output, and host free-space bounds.
17. Archive commits the proposed archived manifest and removal of its canonical
    and alias routes through one recoverable intent transaction; reconciliation
    exposes only the exact preceding active-or-suspended state and route set or
    the complete archived generation.
18. Privileged ZIP parsing starts inside its resource-limited service process;
    a bounded structural gate rejects every method except stored and Deflate
    before any entry decoder runs.
19. One active reference selects the manifest-bound binary, environment, and
    complete Caddy configuration together. Every start reconciles intent and
    pins that generation once; automatic restart cannot combine live paths from
    different generations. A restart commits only after post-start verification,
    and no initiator holds publication while waiting for systemd to reacquire it.
20. Nested operations acquire export, publication, and tenant-state only in that
    order, never upgrade, and do not queue unbounded waiters. Archive revalidates
    its captured source generation under exclusive state before committing.
21. ZIP entry names, metadata, offsets, and data regions satisfy explicit byte,
    depth, count, field, and non-overlap bounds before extraction; implicit
    directories consume the same entry budget as explicit entries.
22. Every lifecycle operation is allowlisted by source state; an unlisted pair
    changes nothing, and no operation except `resume` may leave `suspended`.
23. Caddy runtime storage contains at most the active, immediate
    last-known-good, and current-intent candidate generations and remains within
    its aggregate byte, inode, and host-free-space bounds.
24. A provisioner request cannot cause root-owned tenant, release, correlation,
    audit, request/result, reason, or rate limits to be exceeded; audit evidence
    is never overwritten or rotated without restore-verified, durably indexed
    off-host evidence protected from ordinary retention and prune.
25. A tenant ID and its canonical origin are immutable and never reassigned.
    The backed-up platform namespace record pins the suffix, and each manifest
    stores an origin that must exactly match independent derivation from that
    record and ID. Configuration drift fails closed. Rename and deletion may
    release only the platform-controlled slug alias; allocation consults live
    desired state rather than historical effort or browser cleanup.
26. No structured parser reads an unbounded transport. Raw operation and
    manifest byte ceilings and deadlines run before decoding or correlation
    lookup, constrained decoding precedes canonical-size enforcement, and
    retries receive no alternate path.
27. Root-owned artifact intake contains at most one in-progress or admitted
    regular file. The SSH adapter enforces the deploy or restore byte ceiling,
    aggregate allocated-space ceiling, host free-space reserve, transfer
    deadlines, durable publication, and terminal/startup cleanup while reading;
    no artifact parser is required to bound intake growth after the fact.
28. Every durable archive upload has a locally synced construction intent that
    already names its unique key and later binds its exact version ID. Recovery
    resolves a related lifecycle intent, then either proves authoritative
    archive state binds that version or purges all versions and markers for the
    key; unconfirmed cleanup remains quarantined, charged, and admission-blocking.

## Residual risks

- A vulnerability in the root activator, Caddy, Python ZIP parser, kernel, or
  filesystem can cross the intended boundary.
- Static JavaScript can harm or mislead site visitors even though it does not
  execute on the host; content policy and browser protections remain necessary.
- Limits reduce but do not eliminate availability impact from expensive valid
  content or high request volume.
- A stale or non-conforming cache can follow an obsolete alias redirect to the
  preceding tenant's separate canonical origin. The `no-store` response and
  non-forwarding alias contract reduce this usability risk; it cannot transfer
  control of the new tenant's origin.
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
