# Static-publication threat model

- Status: accepted Milestone 3 baseline
- Updated: 2026-08-25
- Related decisions: [ADR 0016](../adr/0016-model-static-publication-threats.md)
  through [ADR 0028](../adr/0028-use-cloudflare-as-the-public-web-edge.md)

## Scope

This model covers the Milestone 3 path from a strict operation request and an
operation-specific optional ZIP artifact on the trusted operator workstation
through Cloudflare's public edge and the authenticated Caddy origin, intake,
validation, portable import, immutable release installation, route activation,
lifecycle operations, backup, restore, and reconciliation on the single
production host.

It excludes the Milestone 4 public control plane, custom domains, PHP, tenant
containers, tenant SQL, and arbitrary executable server-side content. Those
features require their own threat-model extensions before activation.

## Security objectives

- Tenant content cannot read or modify host secrets, host configuration, Caddy
  administration, another tenant, or backup credentials.
- Tenant JavaScript cannot set cookies that reach the trusted `.net` platform,
  no Milestone 3 `.com` origin route consumes incoming cookies, and no
  tenant-controlled `Set-Cookie` reaches Cloudflare or a visitor. A
  Cloudflare-managed security cookie is not tenant state or LDP
  authentication. Cross-tenant browser-local `.com` cookie integrity is not a
  security objective.
- Public HTTP traffic reaches the origin only through Cloudflare's reviewed
  networks; HTTPS additionally authenticates the project-specific origin pull,
  and spoofed forwarding headers cannot become trusted visitor identity.
- Cloudflare does not cache any Milestone 3 platform or tenant response, and
  Always Online cannot republish a stale or externally archived representation
  while the origin is unavailable.
- Cloudflare does not rewrite or inject into an accepted Milestone 3 origin
  representation, and its reserved `/cdn-cgi/` namespace cannot collide with a
  tenant release or bypass alias rejection behavior.
- Reassigning a human-readable slug cannot transfer a browser origin, service
  worker, cookie, or tenant-controlled storage to the next tenant.
- Importing a portable bundle cannot claim its embedded tenant identity,
  canonical origin, slug, quotas, deployment, or lifecycle state.
- A compromised provisioner cannot turn its narrow activation capability into
  arbitrary root, filesystem, process, or Caddy authority.
- A compromised provisioner cannot originate, alter, retarget, or chain a
  tenant mutation, export, archive, restore, or deletion; it may execute only
  an immutable job issued through the authenticated operator boundary.
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

- The Cloudflare DNS-edit token read by Caddy, the separately scoped OpenTofu
  edge token, origin-pull CA and leaf material, and managed edge configuration.
- Caddy's root-owned configuration and Caddy-only admin socket.
- Administrative SSH access and the root privilege boundary.
- The separately registered `.net` platform and `.com` tenant namespaces.
- Root-owned authorization jobs, the pinned platform namespace record, tenant
  manifests, immutable releases, canonical-origin and alias routes, archives,
  and audit history.
- Other tenants' content and future credentials.
- Restic password, mutually isolated backup and archive Spaces credentials,
  repository contents, archive versions, and backup health evidence.
- Host availability, disk and inode capacity, and the integrity of Caddy and
  backup services.

## Actors and trust

| Actor or component | Trust assumption |
| --- | --- |
| Anonymous visitor | Untrusted; controls requests, hostnames, paths, and request volume. |
| Archive author | Untrusted; controls every ZIP byte and filename. |
| Unprivileged provisioner | Potentially compromised; may preflight and execute an already authorized root-owned job but cannot originate or alter an operation, choose host paths, or read tenant exports. |
| Trusted-workstation client and `ldp-operator` key | Authenticated, forced-command operator transport and Milestone 3 job issuer; trusted to authorize operations, not to bypass root validation. Separate from the `ldp-admin` host-administration identity. |
| Root activator | Trusted computing base; narrowly implements validation, release, route, lock, and recovery contracts. |
| Ansible Caddy transaction | Trusted host-configuration path; stages candidates and shares the publication lock, but is not callable through provisioner sudo. |
| Cloudflare | Trusted public edge for DNS, visitor TLS, DDoS handling, cache bypass, and authenticated origin pulls; not tenant, lifecycle, or platform-authentication authority. |
| Caddy | Trusted authenticated origin with read-only tenant content and no provisioner-writable configuration. |
| Backup service | Trusted root service holding repository credentials; synchronized with tenant-state mutation. |
| Operating system and pinned dependencies | Trusted platform boundary, maintained through the reviewed host baseline. |

An authorized root administrator and compromise of the operating system or
root activator are outside the containment guarantee. They remain operational
and supply-chain risks.

## Trust boundaries and data flow

1. A visitor resolves a proxied public hostname and reaches Cloudflare.
   Cloudflare terminates visitor TLS, applies DDoS controls and explicit cache
   bypass, then forwards HTTP or Full (strict) HTTPS to the allowlisted origin.
   HTTPS presents the project-specific origin-pull certificate. Caddy rejects
   unknown hosts and trusts forwarded visitor identity only on that admitted,
   authenticated path.
2. The operator submits one strict request and, only for deploy or import, one
   optional ZIP through the restricted SSH adapter into a fixed, non-public
   intake area. The protocol rejects a standalone manifest frame. The adapter
   derives the operator from the authenticated SSH boundary, enforces raw input
   limits, validates the caller-declared artifact digest, and commits an
   immutable root-owned job binding that operator, operation, target,
   correlation, canonical request, artifact or absence, and expected source
   state. Root derives the candidate desired manifest from that request and
   authoritative source state.
3. The unprivileged provisioner may perform advisory preflight and submit only
   the root-generated job ID to its fixed sudo entry point. It cannot invoke the
   issuer, pass raw operation fields to the activator, inspect the job store, or
   read an export result.
4. The root activator opens and durably claims the authorization job, verifies
   every binding and current expected state, then claims the fixed intake
   artifact. It copies artifact bytes once into a newly created root-owned
   snapshot while enforcing the upload limit and computing its digest, and
   closes the intake descriptor. It verifies, revalidates, and extracts only
   that non-caller-writable snapshot into a new root-owned temporary release.
5. The activator normalizes and seals the release, generates a complete
   root-owned Caddy runtime generation containing a manifest-bound binary,
   environment, canonical tenant-content routes, platform-only slug-alias
   routes, and base configuration, and validates the generation with its own
   inputs. Every canonical origin must match both its manifest and independent
   derivation from the pinned platform namespace record.
6. Under the publication lock, the activator records intent and atomically
   selects the candidate runtime generation. Configuration-only changes reload
   and commit synchronously. Binary or environment changes persist a phased
   restart intent, release the lock, and queue a non-blocking systemd restart;
   pre-start and post-start helpers separately acquire the lock to pin, verify,
   and commit the generation. Failure uses the same handoff to restore the
   preceding complete generation.
7. Backup holds a shared tenant-state lock while reading content, manifests,
   and audit state. Restore writes outside live paths and reconciliation applies
   the same activation contract.
8. Ansible stages a complete Caddy runtime generation outside live paths and
   uses a root-owned transaction under the global publication lock to select it
   and persist restart intent, then releases the lock before handing the restart
   to systemd. A frozen systemd bootstrap reconciles intent and pins one
   generation directory before each start or automatic restart. If no
   transaction intent exists, it first durably binds the current invocation to
   the manifest-verified active generation in an ordinary-start intent.

No public request, tenant file, or unprivileged process can reach Caddy's admin
socket or write an active route, immutable release, backup environment, or
authoritative desired-state, observed-state, archive, deployment, or audit
record.

## Threats and required controls

| Threat | Required control and evidence |
| --- | --- |
| Path traversal or absolute extraction | Normalize and validate every path twice; extract through directory-relative, no-follow operations; hostile fixtures must fail. |
| Symlink, hard-link, device, FIFO, socket, or permission abuse | Accept only regular files/directories; normalize modes; inspect ZIP metadata and actual created objects. |
| ZIP bomb, decoder allocation, oversized or overlapping metadata, deep paths, implicit-directory inflation, disk or inode exhaustion | Structurally gate end, directory, extra-field, offset, region, path-byte, component, and depth bounds before a decoder; count each materialized explicit or implicit directory once; allow only stored and Deflate deployment methods; require matching local and central headers; and constrain the privileged parser by memory, swap, task, descriptor, CPU, and runtime limits. Give portable import and restore a bounded raw-envelope allowance, then strip its fixed prefix and enforce the unchanged tenant-tree limits. Enforce compressed, expanded, per-file, total-entry, and ratio limits during streaming extraction and delete failed staging trees. Remove persistent provisioner-writable storage, hard-cap its private ephemeral workspace by aggregate bytes and inodes, bound root snapshots and cleanup, and preserve a host free-space reserve. |
| Duplicate, Unicode, slash, backslash, case, or export-encoding ambiguity | Retain pre-normalization spelling and provenance. Coalesce only an exactly matching explicit directory and implied parent; reject duplicate explicit records, file/directory conflicts, and distinct spellings that collide after NFC normalization or case folding. Generate manifests canonically and define every portable ZIP byte: JSON, checksums, member order, stored encoding, timestamps, flags, modes, metadata, central directory, and archive digest. |
| Ambiguous structured input or duplicate local YAML keys | Reject duplicate object member names in the host request decoder before schema validation. If the supported client reads an optional local YAML create specification, bound it before composition, reject duplicate keys and unknown fields locally, and transmit only the strict request. Never install a host YAML parser or accept a standalone desired manifest. |
| Tenant content poisons platform authentication cookies or exploits same-site request handling | Keep every tenant-controlled origin on `lowerduckpond.com` and every trusted application on `lowerduckpond.net`. Use only unique host-bound `__Host-` platform session cookies, exact-Origin and CSRF validation, no credentialed tenant CORS, and no state-changing safe-method routes. Browser tests prove `.com` cannot set or receive `.net` cookies and that the two registrable domains are cross-site. |
| One `.com` tenant injects parent-domain cookies visible to another tenant | Treat the complete `.com` namespace as untrusted. Remove incoming `Cookie` before every static tenant handler, remove tenant-controlled outgoing `Set-Cookie` before responses reach Cloudflare, never vary routing or static bytes by cookies, and omit their values from logs. Treat any Cloudflare-managed security cookie as edge infrastructure rather than tenant or LDP authentication state. Test and document that JavaScript can still create `Domain=lowerduckpond.com` cookies, confuse ordinary client-side cookie names, consume shared cookie capacity, or trigger a per-browser oversized-header failure. Require host-bound `__Host-` names where a tenant needs cookie-name integrity and a new ADR before any dynamic, authenticated, or privileged `.com` application. |
| A visitor bypasses Cloudflare and attacks the known reserved origin address | Proxy every public web hostname, admit origin ports only from a reviewed snapshot of Cloudflare networks, require project-specific origin-pull authentication on HTTPS, keep administrative SSH on its separate CIDR, and prove direct HTTP/HTTPS denial from an ordinary source. |
| A request spoofs Cloudflare forwarding headers or comes through another Cloudflare customer | Reject unknown hosts, trust forwarded visitor identity only from the pinned networks and authenticated HTTPS origin pull, and treat unauthenticated port 80 as a redirect-or-reject surface that serves no tenant bytes. |
| Cloudflare serves a prior deployment, suspended tenant, released slug, redirect, error, or cookie-dependent response | Install explicit edge cache-bypass rules and manage Always Online as disabled for both zones throughout Milestone 3; retain origin `no-store` on every alias, apex, unknown-host, and error response; repeat requests through the real edge while changing lifecycle-shaped fixtures; and prove origin unavailability returns no stale or Internet Archive representation. Cache or stale-serving eligibility requires a later lifecycle-aware ADR and purge/recovery tests. |
| Cloudflare transforms tenant headers or emits security cookies | Prove tenant-controlled `Set-Cookie` is absent before the edge, classify Cloudflare-owned cookies separately, forbid LDP authentication from trusting them, and exercise edge responses in every supported browser rather than inferring browser behavior from direct-origin tests. |
| Cloudflare rewrites an accepted HTML body or injects a provider script | Disable every optional body-transforming feature in managed edge policy, emit `Cache-Control: no-transform`, compare origin and edge representations in qualification, and treat a security block or challenge as a provider availability response rather than tenant content. |
| Cloudflare serves a provider endpoint from `/cdn-cgi/` or hides a tenant file under that prefix | Block the complete reserved namespace at the zone WAF, reject `cdn-cgi` as a case-insensitive normalized first tenant path component, record the provider denial as the sole alias-path exception, and prove the request never reaches Caddy. |
| Origin-pull material expires, leaks, or rotates incompletely | Keep CA private keys offline, expose only replaceable leaves to Cloudflare, overlap old and replacement CA trust before moving edge leaves, retire the old CA only after every association changes, alert before expiry, and test rejection and rollback at every phase. |
| Slug reassignment transfers persistent browser state | Treat the slug hostname only as a platform alias. Redirect its exact bare root without caching, referrer, cookie, path, query, tenant body, tenant header, or caller-selected target to the immutable tenant origin. Never reassign a tenant ID or canonical hostname; release only the slug mapping. |
| Alias becomes a confused deputy, secret sink, or stale content URL | Generate its destination solely from root-owned tenant ID and suffix, redirect only active tenants, reject every non-root path, query, and unsupported method without forwarding, apply `Cache-Control: no-store` to every redirect and generic failure so lifecycle changes cannot leave a cached positive or negative result, discard sensitive alias request fields before logging, and test that uploaded bytes and service workers are unreachable at the alias. |
| Mutation after validation | Root performs final extraction; active releases and complete Caddy generations are root-owned and immutable to Caddy and the provisioner. |
| Arbitrary Caddy behavior or secret disclosure | Generate allowlisted complete Caddy configurations from validated primitives; accept no Caddy text; keep generation environment files Caddy-only and excluded from backup, and keep the admin socket Caddy-only. |
| Validation-to-reload race | Validate one immutable complete runtime generation with its manifest-bound binary and environment, select it through one active reference under the publication lock, and reload from directory-pinned open inputs. |
| Ansible convergence selects stale tenant routes or automatic restart mixes Caddy inputs | Stage only host inputs before locking; under publication reread authoritative tenant state, construct and validate the final complete route-bearing generation, and then select it through phased root-owned intent. Before every start, the frozen bootstrap reconciles intent and pins one manifest-verified generation directory. Change the bootstrap only while Caddy is stopped and masked. |
| Synchronous restart deadlocks, no-intent starts bypass fencing, automatic retries lose fencing, or exhausted candidate retries block recovery | Persist and select a restart candidate under the lock, release it before queuing a non-blocking systemd job, and let pre-start, launcher, post-start, and rollback helpers acquire it independently. For a start without transaction intent, validate current authoritative state and durably create an ordinary-start intent bound to the active generation and current invocation before launch. Pin three attempts per candidate, recovery, or ordinary-start target. Under the lock, durably bind each automatic retry's distinct invocation ID and attempt number only to the unchanged selected generation; reject stale callbacks. Never roll back an ordinary start. After durably selecting the prior generation for a failed transactional candidate and releasing the lock, reset the service failed/start-limit state before queuing recovery. Block later mutations on durable intent, and never wait for a lock-acquiring systemd hook while retaining the lock. |
| Runtime generations exhaust disk or retain secrets indefinitely | Admit at most active, last-known-good, and intent candidate generations; enforce aggregate unique-inode byte/inode and host-free-space bounds; clean unreferenced staging after terminal states and startup; keep environment/config Caddy-only and backup/diagnostic-excluded. |
| Concurrent or replayed jobs | Let only the authenticated issuer allocate a root-owned job and correlation. Bind operator, operation, target, canonical request, artifact, and expected state; durably claim before execution; serialize publication; and make an exact retry return one immutable result. Unknown IDs and changed bindings allocate nothing. |
| Compromised provisioner chains valid archive and delete operations | Accept only a root-generated authorization-job ID through provisioner sudo. Archive and delete require distinct authenticated jobs and correlations; the latter can be issued only against and bind the resulting archived manifest, deployment, and exact archive record. Keep job issuance and emergency deletion outside provisioner authority. |
| Oversized structured syntax exhausts the privileged parser before canonicalization | Read at most the raw request ceiling plus one byte under a deadline before parsing, reject excess without inspecting correlation data, run the decoder under fixed process limits, and then enforce the smaller canonical request and result ceilings. Independently bound each root-generated manifest. Apply the same path to retries. |
| Valid operations indirectly exhaust root-owned state | Let only the authenticated issuer spend new job/correlation capacity. Enforce host-wide tenant, release byte/inode, shared authorization/correlation record, audit, request/result size, reason, and admission-rate ceilings before staging. Preserve audit in bounded hash-chained segments rotated only after verified off-host backup, with an isolated root-administrator reserve. |
| Ordinary backup retention expires rotated audit evidence | Remove a local segment only after a dedicated tagged audit snapshot is restore-verified and durably indexed. Exclude that tag from ordinary `forget`/`prune`, verify every referenced snapshot during maintenance, and reconstruct the chain from tagged descriptors during recovery. |
| Nested locks deadlock or accumulate waiters | Acquire export, publication, and tenant-state only in that global order; never upgrade; return retryable busy before allocating work; revalidate archive source state after its unlocked construction phase; and never wait for a systemd job that reacquires publication while holding it. |
| Delayed rollback undoes suspension | Recheck lifecycle state under the publication lock; while suspended, change only the remembered deployment and require explicit resume before publishing. |
| Repeated suspended deployments or archive/restore cycles evade release retention | Apply the same selected-release-plus-two-predecessors cleanup after active or suspended deploy, rollback, and restore commits and during reconciliation, while preserving export- and intent-pinned releases. |
| Interrupted archive republishes a suspended tenant | Require reconciled source state before archive, bind the exact preceding lifecycle, observed state, remembered deployment, runtime generation, and route presence in intent, and restore that complete source rather than assuming it was active. |
| Manifest or audit tampering | Keep desired and observed state and append-only audit operations root-owned; allow the provisioner no direct write, replacement, truncation, or deletion authority. |
| Crash or power loss between filesystem, route, reload, restart handoff, and state changes | Durably sync generation targets and parents before intent, sync intent before selecting and syncing the active reference, persist every restart phase before releasing its lock, sync desired/observed state and audit before clearing intent, and reconcile from durable evidence. |
| Cross-tenant read or overwrite | Derive all paths from validated UUIDs, prohibit caller paths, use root ownership, and test hostile operations across two tenants. |
| An in-flight municipal apex redirect follows a reassigned slug to another tenant | Bind the designation to the municipal tenant's immutable ID and derive `Location` directly as its UUID-based canonical origin. Never route the apex through a reusable slug; test reassignment after response issuance and before navigation. |
| Configured origin-suffix drift abandons or reassigns browser origins | Pin the normalized suffix in backed-up root-owned platform state before the first tenant, persist each complete derived origin in its manifest, and require configuration, platform state, tenant ID, and manifest origin to agree before route mutation. A change requires an explicit future origin-migration design. |
| Backup or export captures incompatible generations | Backup uses a shared tenant-state lock; mutation uses it exclusively. Ordinary export captures its current manifest and immutable release into a root-owned snapshot while holding that shared lock. Archive separately snapshots the source manifest for compare-and-swap and the proposed archived manifest for the bundle. Construction consumes only that snapshot, and restored state reconciles before publication. |
| Concurrent exports exhaust privileged storage | Serialize export and archive construction behind one root-owned host lock; enforce one snapshot, one unacknowledged result, aggregate spool byte/inode ceilings, an encoded-output ceiling, a host free-space reserve, and root-owned terminal, startup, acknowledgement, and expiry cleanup. |
| Crash or abort during archive upload leaves an unaccounted version or incomplete multipart parts | Sync a construction intent containing a unique key before upload, send the bounded completed bundle through one known-length `PutObject` with multipart and high-level transfer APIs prohibited, and bind its returned version ID afterward. Reconcile any associated lifecycle intent. Preserve only an exactly bound version; otherwise permanently delete every version and marker for the key and confirm absence, or keep quarantine charged and archive admission closed. The lifecycle abort rule is defense in depth, not accounting. |
| Repeated restore, re-archive, or deletion accumulates successfully retired bundles | Before a transition unbinds an archive, sync a retirement intent for its exact object and hold the global export lock. Reconcile lifecycle state before cleanup, never delete a still-bound version, and permanently purge and confirm every version and marker after committed unbinding. Charge bound, constructing, retiring, quarantined, and unknown objects against hard aggregate remote key, version/marker, and byte ceilings; failed cleanup closes archive admission. |
| Archive operations or credentials damage platform backups | Put tenant archives in a separate versioned Space with a dedicated bucket-only credential and no age expiration. Keep the Restic and archive credentials mutually unable to access the other's bucket; expose the archive credential only to the root archive boundary. |
| Partial Milestone 3 rollout publishes through an incomplete boundary | Default `static_publication_enabled` to false, reject all tenant jobs and tenant-bearing Caddy candidates while disabled, require the full disposable-host and production preflight gates, and record the explicit first enablement before the synthetic canary. |
| Portable import reclaims a tenant identity or bypasses slug and quota policy | Permit import only into an existing `undeployed` target selected by root-owned tenant ID. Validate the bundle and source manifest as untrusted provenance, then under publication and exclusive tenant-state re-read current target state, recheck measured content against current quotas, and derive the active manifest only from current authoritative identity, origin, slug, runtime, quotas, and a new root-generated deployment. Require ordinary `create` to resolve slug allocation first; use full-platform backup restore, not import, to preserve a lost identity. |
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
   publication lock; no other path mutates live Caddy inputs. Every bounded
   automatic retry durably binds its distinct invocation ID and attempt number
   to the unchanged selected generation, and only that binding may verify the
   start. External systemd waits occur only after releasing the lock.
5. Desired state, observed state, releases, and audit events are recoverable and
   reconciliation never publishes unvalidated content.
6. Unknown manifest fields, unsupported archive semantics, and unrecognized
   lifecycle transitions fail closed. The host rejects duplicate members in a
   structured request before schema validation, accepts no standalone desired
   manifest, and constructs authoritative manifests only inside the root
   boundary. Optional local YAML duplicate keys fail in the client before
   request construction.
7. Credentials never enter tenant content, provisioner logs, results, exports,
   manifests, or audit payloads.
8. The provisioner's capability cannot originate archive or deletion, convert
   one authorized operation into another, or bypass archive evidence. Ordinary
   archive and delete require separate expected-state-bound authorization jobs;
   emergency deletion requires the separately authenticated administrative
   entry point.
9. Authoritative manifests, observed state, deployment and archive records, and
   audit history are root-owned and writable only through narrow validated or
   append-only operations.
10. No tenant-controlled response is served from any `lowerduckpond.net` host,
    the exact `lowerduckpond.com` apex, or a reusable slug alias. Tenant bytes
    are served only from immutable UUID-derived `.com` origins. Every Milestone
    3 `.com` response from Caddy strips tenant-controlled `Set-Cookie`, every
    static tenant handler receives no `Cookie`, every exact `.com` apex response carries
    `Cache-Control: no-store`, and no route depends on cookie state. A slug
    alias returns only the fixed root-generated redirect contract in ADR 0023
    and holds no tenant or authentication state. The alias HTTP listener applies
    the allowlist before general HTTPS upgrades and never forwards a rejected
    path or query. The future municipal apex
    redirect derives the designated tenant's immutable origin directly from its
    root-owned ID and never traverses that reusable alias.
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
    pins that generation once; when no transaction intent exists, pre-start
    durably creates an ordinary-start intent for the validated active generation
    and current invocation. Automatic restart cannot combine live paths from
    different generations. A start commits only after post-start verification,
    and no initiator holds publication while waiting for systemd to reacquire it.
    Exhausted ordinary-start attempts leave Caddy unavailable and cannot select
    another generation.
20. Nested operations acquire export, publication, and tenant-state only in that
    order, never upgrade, and do not queue unbounded waiters. Archive revalidates
    its captured source generation under exclusive state before committing.
21. ZIP entry names, metadata, offsets, and data regions satisfy explicit byte,
    depth, count, field, and non-overlap bounds before extraction. Each
    materialized directory consumes one entry whether explicit, implicit, or an
    exact merge of both. Duplicate explicit records, type conflicts, and
    different pre-NFC spellings that normalize or case-fold together remain
    invalid.
22. Every lifecycle operation is allowlisted by source state; an unlisted pair
    changes nothing, and no operation except `resume` may leave `suspended`.
23. Caddy runtime storage contains at most the active, immediate
    last-known-good, and current-intent candidate generations and remains within
    its aggregate byte, inode, and host-free-space bounds.
24. A provisioner request cannot allocate a new job or correlation. Authorized
    work cannot cause root-owned tenant, release, shared
    authorization/correlation, audit, request/result, reason, or rate limits to
    be exceeded; audit evidence is never overwritten or rotated without
    restore-verified, durably indexed off-host evidence protected from ordinary
    retention and prune.
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
    regular file. The SSH adapter enforces the deploy or import byte ceiling,
    aggregate allocated-space ceiling, host free-space reserve, transfer
    deadlines, durable publication, and terminal/startup cleanup while reading;
    no artifact parser is required to bound intake growth after the fact.
28. Every durable archive upload has a locally synced construction intent that
    already names its unique key. The at-most-120-MiB bundle uses exactly one
    known-length `PutObject`; managed archive code cannot initiate multipart
    upload. The intent later binds the exact returned version ID. Recovery
    resolves a related lifecycle intent, then either proves authoritative
    archive state binds that version or purges all versions and markers for the
    key; unconfirmed cleanup remains quarantined, charged, and admission-blocking.
29. Every lifecycle transition that makes a bound archive unreferenced first
    syncs a retirement intent for its exact object. Recovery preserves a
    still-bound version or permanently purges and confirms a committed retired
    key before clearing its charge. The managed prefix cannot exceed 25 unique
    keys, 25 total data versions or delete markers, or 3,000 MiB across data
    versions; a pending upload reserves one key, version, and 120 MiB.
30. Portable import is allowed only for an existing `undeployed` target and
    creates a new deployment from validated content. No embedded source field
    can replace the target's root-owned ID, canonical origin, slug, runtime,
    quotas, or lifecycle intent; `create` owns slug conflict resolution and
    full-platform restore owns recovery of an existing identity.
31. Every successful deploy, rollback, or restore runs the same post-commit
    selected-release-plus-two-predecessors cleanup. Reconciliation repeats
    interrupted cleanup, and no release pinned by an export or transaction
    intent is removed.
32. Every externally requested tenant operation has an immutable root-owned
    authorization job binding its SSH-authenticated operator, exact operation
    and target, correlation and canonical request, artifact or absence, and
    expected authoritative source state. The provisioner can execute that job
    ID but cannot issue, inspect, alter, retarget, or chain jobs or read export
    payloads. State drift fails closed before mutation.
33. Every public apex and wildcard web record is proxied. The DigitalOcean and
    host firewalls admit web ingress only from the reviewed Cloudflare network
    snapshot; HTTPS also requires the project-specific origin-pull client
    certificate. A range rotation admits and verifies the new superset at both
    firewalls before either removes a retired range. Administrative SSH retains
    its independent CIDR boundary.
34. Caddy trusts forwarded visitor identity only on the admitted,
    authenticated Cloudflare path. Port 80 serves only allowlisted redirects or
    generic rejection and no tenant bytes. Unknown hosts never select a
    platform or tenant route.
35. Cloudflare cache is explicitly bypassed for both zones throughout
    Milestone 3. Origin `no-store` remains mandatory for the `.com` apex,
    reusable aliases, unknown hosts, errors, and the trusted administration
    application. OpenTofu manages Always Online as disabled; an unavailable
    disposable origin serves no stale-cache or Internet Archive representation.
    No cache-purge credential exists in the runtime boundary.
36. Origin-pull CA private material never reaches the host, repository,
    provisioner, Caddy environment, OpenTofu configuration, plan, state, or
    platform backup. An expiring operator credential uploads and later retires
    only a replaceable leaf from the trusted workstation; its local private key
    is discarded after upload verification. OpenTofu receives the non-secret
    certificate ID and Caddy receives only CA certificates. Rotation first
    installs an old-and-new trust bundle, then changes every leaf association,
    and removes the old CA only after verification. Qualification tears down
    every disposable per-hostname association and certificate before revoking
    the operator credential.
37. Managed edge configuration disables optional body rewriting and script
    injection, and Caddy emits `Cache-Control: no-transform`. The zone WAF
    blocks `/cdn-cgi` and its descendants before they reach Caddy; archive,
    import, and restore reject that normalized first component.

## Residual risks

- A vulnerability in Cloudflare configuration, the root activator, Caddy,
  Python ZIP parser, kernel, or filesystem can cross the intended boundary.
- Static JavaScript can harm or mislead site visitors even though it does not
  execute on the host; content policy and browser protections remain necessary.
- Tenant JavaScript can create parent-domain `.com` cookies visible to sibling
  tenants, consume shared browser cookie capacity, and cause client-side
  cookie-name confusion or per-browser request failure. Caddy ignores and
  strips HTTP cookies for the static tier, and the separate `.net` domain keeps
  this residual risk outside platform authentication, but tenant cookie jars
  are not mutually isolated.
- Limits reduce but do not eliminate availability impact from expensive valid
  content or high request volume.
- A Cloudflare or browser defect can disregard cache bypass, disabled Always
  Online, or `no-store` and retain an obsolete response. Edge repetition and
  origin-unavailability tests plus the non-forwarding alias contract reduce
  this risk; CDN caching and stale serving stay disabled until a separate
  lifecycle-aware design is accepted.
- Cloudflare is an additional availability and request-semantics dependency.
  Emergency DNS-only rollback restores direct service but intentionally loses
  edge DDoS protection until the proxy boundary is repaired.
- The single host remains one availability and blast-radius boundary.
- A trusted administrator can intentionally override deletion safeguards or
  directly modify the host.

These risks are accepted for the static pilot and must be revisited before any
authenticated or dynamic `.com` application, custom domains, public upload,
PHP, or multi-host provisioning.

## Review and acceptance gates

- Each root-activator input and filesystem transition has a documented
  allowlist and negative tests.
- Authorization tests prove only the authenticated issuer can allocate a job,
  every job and expected-state binding is verified, archive authority cannot be
  transformed into deletion authority, and the provisioner cannot read export
  results.
- Unit, property, concurrency, failure-injection, Molecule, Testinfra, restore,
  and reconciliation tests required by ADR 0022 pass.
- A disposable-host exercise passes before production.
- Browser, edge, and installed-host evidence proves the `.com`/`.net` boundary,
  Caddy cookie policy, Cloudflare cache bypass, Always Online disabled and no
  representation during disposable origin unavailability, Full (strict) and
  origin-pull authentication, direct-origin denial, forwarding-header
  authenticity, and the accepted sibling `.com` cookie behavior.
- A reserved production source canary and separately imported target complete
  HTTPS, backup recovery, reconciliation, and reboot checks. The source
  completes rollback, suspension, archive, restore, rearchive, and ordinary
  deletion; the imported target completes archive and ordinary deletion. Both
  route sets and all bound archive objects are absent afterward while audit
  evidence remains.
- Sanitized evidence is recorded without credentials, production backup
  metadata, or tenant content.
