# M3.11 backup and recovery operations

M3.11 implementation is in progress. The accepted [plan](../plans/milestone-3.11.md)
defines the complete qualification and production handoff. These P2–P6 commands
are preparation and verification tooling; production convergence remains an
explicit later operator step after the final M3.11 qualification. M3.12 is
unstarted and production publication stays disabled.

## Unattended qualification on the dedicated Docker host

The explicitly approved dedicated Coder/Docker host may run M3.11 without the
operator workstation staying online. This is an exception for qualification,
not production deployment. Processing actual production credentials makes that
Docker host trusted. Docker access and sibling containers are not a hard security
boundary. Do not transfer old virtual environments, private configuration, logs
or credentials from another workspace.

`just m3-11-unattended` prepares and operates a detached controller. It calls the
existing `just m3-11-spaces-qualification`, deadline supervisor, live wrapper,
provider/storage checks, Molecule phases, combined recovery and report packager.
The start operation counts provisioning and the short production check against
the original 600-minute ceiling, with the existing bounded diagnostic allowance.
Provisioning has a separate 14-hour credential deadline; it cannot extend
qualification. Neither controller
restart nor diagnostic continuation reruns or promotes an interrupted attempt.

The controller joins the **daemon's host network** and receives the daemon-side
Unix socket. A forwarded Unix socket by itself does not establish the network
topology needed for published SSH ports. On the dedicated Coder template inspected
for this implementation, the workspace and Docker daemon have different network
namespaces. Docker's data directory is in the template's persistent Docker volume;
qualification code, private evidence, configuration and storage leases use inner
named volumes. Controller and watchdog use `unless-stopped` restart policies.
Before provisioning, the controller verifies that its mounted socket reaches
the exact Docker-host identity recorded in the approved preparation.

Terminal disconnection does not own these containers. A workspace-agent exit
does not intrinsically stop a sibling daemon container. Coder stop/rebuild can
stop/recreate that daemon: persistence depends on retaining the template's Docker
volume and mounting it back at `/var/lib/docker`. A Docker-host restart interrupts
qualification; restart reconciles its immutable attempt and revokes credentials.
Deleting the Coder/Docker volume loses private evidence, not the independent
1Password obligations. Do not claim an actual Coder stop/rebuild or host restart
survival test solely from mount inspection; retain the observed lifecycle results
with the implementation's qualification record.

### Initial setup and authority

First install the locked repository dependencies and prepare a clean, exact commit:

```console
mise install
mise exec -- just setup
mise exec -- just m3-11-unattended prepare FULL_COMMIT_SHA --output /private/prepared.json
mise exec -- just m3-11-unattended setup-template > /private/setup.json
```

Fill the non-secret manifest with the approved region, production archive/backup
buckets, Cloudflare account, both production zone IDs, and the Page Rules user's
ID. Coordinates come from approved configuration, never decrypted state. The
manifest uses immutable `op://VAULT_ID/ITEM_ID/FIELD_ID` references. Create four
dedicated 1Password vaults: provisioning bootstrap, cleanup bootstrap, production
reader inputs, and the append-only obligation journal. No unrelated items belong
in those vaults. Use three separate service accounts:

| Role | Vault access and provider authority |
| --- | --- |
| Provisioning | Read provisioning bootstrap; read/write obligation journal. DigitalOcean `spaces_key:create_credentials`, `spaces_key:delete`, `spaces_key:read`, `spaces:read`, `regions:read`, `sizes:read`, `actions:read`. Separate Cloudflare account Account API Tokens Write on the approved account and user API Tokens Write on the approved user. |
| Cleanup | Read cleanup bootstrap; read/write obligation journal. A distinct DigitalOcean token with deletion and the same reads, without credential creation. Distinct Cloudflare account/user token-write authorities. No production-state passphrase or production vault access. |
| Production checking | Read only the dedicated production-reader vault containing references for state access, state bucket, state decryption passphrase and the existing production Caddy token. No provisioning or journal authority. |

Record the service-account expiry from its creation ceremony. Bootstrap authority
must outlive every child deadline by at least two days; seven days is a practical
initial bootstrap lifetime. The helper never rolls or extends existing credentials.
Cloudflare's user-token bootstrap uses its **Create additional tokens** template;
the User/API Tokens permission is not available in the ordinary custom builder.
Its policy must bind the approved `com.cloudflare.api.user.USER_ID` resource.
Provisioning and cleanup Cloudflare authorities must have no token conditions,
including IP restrictions that could prevent the independent cleanup actor from
using them. Expiry alone must bound their availability.

DigitalOcean's public Spaces API does not expose PAT scope/expiry introspection.
After inspecting the exact scopes and expiry in the provider console, run
`attest-digitalocean --token-reference op://... --expires-at UTC_TIMESTAMP
--role provision|cleanup --attest-provider-console --output /private/metadata.json`.
The helper reads the token through a hidden service-account prompt and writes
metadata bound to its SHA-256, without exporting the token. Import this JSON into
the dedicated metadata item's `notesPlain` field and set `digitalocean_metadata`
to that reference. This is an explicit operator attestation, not provider-side
expiry verification. Child Spaces grants are read back from the provider.

```console
mise exec -- just m3-11-unattended setup \
  --manifest /private/setup.json --output /private/controller.json
mise exec -- just m3-11-unattended install-github-cleanup \
  --config /private/controller.json --helper-revision FULL_COMMIT_SHA
```

Setup asks for the three **new** service-account tokens using hidden terminal
prompts, or accepts a mode-0600 `--service-accounts-file` delivered privately.
Never paste secrets into chat, arguments or reports. It checks separated vault
visibility, bootstrap metadata, live provider reads and independent journal
write/readback. It does not decrypt production state or create provider credentials.
Start delivers the private configuration over stdin and atomically creates
mode-0600 files owned by the container user. Workspace file ownership is not
carried across Docker; the strict private-file ownership checks remain active.
The explicit GitHub setup operation creates a main-only environment named
`m3-11-credential-cleanup`, with no per-execution human approver, installs only
the cleanup subset as `M3_11_CLEANUP_CONFIG`, and pins
`M3_11_CLEANUP_REVISION`. It refuses to weaken an existing environment's protection
policy. Review changes to that protected workflow and its pinned helper as
credential-deletion authority.

The cleanup workflow must be present on **main** before scheduling works. If the
implementation PR is still open, arrange a reviewed bootstrap of that workflow
on main and pin its explicitly approved helper commit; a branch-only scheduled
workflow is insufficient. Dispatch it once and inspect its result. Every new
start requires a ready GitHub heartbeat no older than 90 minutes, for the exact
helper, and no outstanding credential obligations. No live provisioning is
authorized by successful setup alone.

Provider contracts used by setup are documented by
[DigitalOcean Spaces keys](https://docs.digitalocean.com/products/spaces/reference/api/spaces-keys/),
[Cloudflare token creation](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/),
[1Password service accounts](https://developer.1password.com/docs/service-accounts/), and
[GitHub environments](https://docs.github.com/en/rest/deployments/environments).

### Staging Connect bootstrap

The operator can stage Connect access using a normal 1Password login on the
**secure workstation**. This setup step does not use service-account quota.
Sign in to the operator's normal 1Password account before running the helper.
The shared Connect server belongs in the existing Unraid `services` Compose
project; workspaces receive scoped clients. The server credentials file stays
on Unraid. Keep its API behind the private HTTPS route and retain its persistent
encrypted cache.

The setup helper reads the previously approved, non-secret setup manifest from
an immutable 1Password item reference and verifies the supplied digest of the
whole journal record. It grants the shared server access to the same four
dedicated vaults and creates three native seven-day clients: provisioning and
cleanup each read their own bootstrap vault and read/write the journal;
production checking reads only its production-input vault. It separately creates
a Connect server identity and client limited to cleanup and the journal for
GitHub. That identity allows the cleanup job to start its own Connect
instance without depending on Unraid being available.

From a checkout of the exact committed setup revision, with locked dependencies
installed, preview the operation on the **secure workstation**:

```console
mise exec -- uv run --no-sync --frozen python -m scripts.m3_11_unattended.connect_setup \
  --revision FULL_COMMIT_SHA \
  --manifest-reference op://JOURNAL_VAULT_ID/SETUP_ITEM_ID/notesPlain \
  --manifest-sha256 APPROVED_SETUP_RECORD_SHA256 \
  --shared-url https://op-connect.example.net \
  --shared-server 'Unraid services' \
  --output "$HOME/.config/lowerduckpond/m3-11-connect-bootstrap"
```

Add `--apply` to create the bootstrap. To deliver it in the same operation, add
`--unraid root@UNRAID_HOST --workspace CODER_CONTAINER_NAME
--workspace-id APPROVED_WORKSPACE_UUID`. Delivery checks the workspace ID,
container identity and persistent home volume through the parent `coder_dind`
daemon before streaming only the three client tokens to
`/home/coder/.config/lowerduckpond/m3-11/connect-bootstrap.json`. The independent
server credentials and cleanup client go only to the existing main-only GitHub
environment, in a new `M3_11_CONNECT_BOOTSTRAP` secret. No credential value enters
arguments or terminal output. The operation retains mode-0600 creation intents,
returned credentials and provider metadata on the workstation. Repeating it
reuses completed issuance; a lost token response records inventory and stops
without creating another token. Keep those private files for reconciliation.
If a step fails, its message identifies the operation and a sanitized failure
category. Replace `--apply` with `--diagnose` and omit the delivery arguments for
read-only checks of sign-in, the approved manifest and shared server lookup.
Diagnosis lists only the presence of fixed setup files and never retries an
uncertain credential creation or prints their contents.

**Staging is not activation.** The staging bundle cannot be used as controller
configuration. Activation authenticates each client, checks its native and
signed vault policy, and proves independent cleanup before installing a separate
Connect controller configuration. It never falls back to service accounts.

See the official [Connect CLI reference](https://www.1password.dev/cli/reference/management-commands/connect)
and [Connect authorization model](https://www.1password.dev/connect/security).

### Activating independently recoverable Connect cleanup

Run activation in the **Coder workspace**, after the exact runtime revision has
passed review and required CI and reached main. The protected cleanup environment
must allow only main and require no human approval for each cleanup execution.
The Connect job uses `actions: read` to verify retained artifacts and
`statuses: write` to append checkpoint references on one fixed commit. These are
additional GitHub permissions requiring operator approval before workflow
activation. No additional provider authority or production-vault access is given
to GitHub. The GitHub token grants apply across this repository; the helper's
code confines their use to the cleanup workflow and fixed checkpoint commit/context.

The helper uses the bootstrap bundle already delivered to the workspace and the
existing GitHub login. Keep the same private activation directory when resuming:

```console
mise exec -- uv run --no-sync --frozen python -m scripts.m3_11_unattended.connect_activate \
  --revision FULL_COMMIT_SHA \
  --bootstrap /home/coder/.config/lowerduckpond/m3-11/connect-bootstrap.json \
  --manifest-reference op://JOURNAL_VAULT_ID/SETUP_ITEM_ID/notesPlain \
  --manifest-sha256 APPROVED_SETUP_RECORD_SHA256 \
  --directory /home/coder/.config/lowerduckpond/m3-11/connect-activation \
  --output /home/coder/.config/lowerduckpond/m3-11/controller.json
```

This operation creates provenance records and encrypted journal checkpoints;
it creates no provider child credentials and launches no qualification. It reads
the non-secret setup manifest and authenticates the production reader without
reading production secrets. Existing controller configuration is retained privately
before an approved conversion or helper update.

Activation first records immutable probe identities. The shared and independent
Connect servers each attempt to claim the other's native author. Both native
readbacks must reject that impersonation. The independent GitHub instance then
captures the exact complete initial journal in an encrypted genesis artifact,
publishes its immutable reference, and reads it back. Activation binds both
servers, actual authors, the full target selection, approved manifest, original
helper and complete initial inventory. Existing credential intents prevent a new
genesis; an existing epoch is never reset to work around incomplete history.

Before freezing that inventory, activation selects `connect-initializing` and
waits for older queued or running cleanup executions to finish. Native cleanup
remains enabled using the reviewed helper from the same protected selection.
It suppresses only an idle heartbeat after a fresh complete read proves there
are no credential intents. Any intent, including a historical resolved one,
takes the normal cleanup/proof path and blocks new genesis. Read failures remain
unresolved. Quiet execution emits no admission heartbeat. This does not require
successful service-account access while its quota is exhausted: independent
Connect discovery supplies the complete inventory barrier. It may learn a final
empty legacy heartbeat beyond the shared cache's initial snapshot; the shared
cache must synchronize that exact complete map before genesis. No event is
discarded and final genesis inventory checks remain exact.

Connect's vault item count may lag its item list after a successful write. The
ledger compares two complete unfiltered item inventories, validates every native
item binding and retains all known event hashes. The aggregate count remains a
conservative lower bound; neither matching cache reads nor HTTP 200 creation
readback establishes independent persistence. Returned item IDs are saved before
further inspection, including when inspection fails.
After a journal POST, the helper polls for its exact event in a complete stable
inventory within a 60-second monotonic readback window. It stops scheduling polls
at that deadline, caps each exchange to the remaining budget and refuses late
success. Controller cancellation is checked between reads; independent cleanup
keeps its own uncancelled reader. A restart with the retained creation intent uses
the same readback path and never resends that POST. Missing events or a moving
snapshot stay unresolved at the deadline; invalid metadata and conflicting
contents fail immediately. This wait only settles cache visibility: provider
creation still requires independent encrypted persistence and acknowledgement,
and no provisioning or qualification deadline is extended.

A reviewed helper correction can resume an unchanged `initializing` selection
before discovery has started. It requires the original private inputs, both probe
records and shared-probe spool, and rejects any credential intent or independent
probe for that epoch. It retains the old/new marker, inventory and evidence hashes
before publishing the helper change. Retrying that same upgrade preserves its
epoch and reconciles either publication outcome. Missing evidence, a prior
different upgrade or any started discovery/genesis prevents this migration;
retain the activation directory and diagnose without resetting it.

Once discovery or genesis has started, a reviewed and merged successor can act
as the workspace coordinator while the independent ceremony keeps its original
helper. Recovery requires the unchanged private inputs, requests, probes,
dispatches and protected selection, both helpers merged, and no credential
intents. Before continuing, it retains an immutable recovery record of both
revisions and every existing private JSON evidence hash. It completes the
original ceremony, then changes the active helper and requires fresh independent
readiness before installing the controller. It never rebinds a pending request
or starts a replacement epoch.
If the pending stage was published before its private dispatch/submission records
were retained, successor recovery refuses it as indistinguishable from lost
evidence. Retain the directory and resume that boundary with the original helper.

If a defect in the original executable prevents genesis completion, an explicit
`--replace-failed-activation /private/original-activation` option permits a new
activation attempt **only before any registered genesis or credential lifecycle
activity**, after the original genesis execution has failed. Use the reviewed,
merged correction with unchanged bootstrap inputs
and a new `--directory` beside the original private directory. Both attempts share
the same parent lock. Keep that replacement directory and the option when retrying.

Replacement verifies the original failed GitHub execution and all retained inputs,
requests, probes and dispatch records. Before changing protected configuration it
records the old selection, execution, evidence hashes, orphan artifact identities,
new epoch and transition record. It publishes a non-admitting transition marker,
drains all pending cleanup executions and checks the original registry again.
Any registry entry, incomplete read, changed binding or credential creation/cleanup
history blocks replacement. A terminal-path revocation request from an attempt
that never provisioned is retained only when its exact event hash was already in
the original approved history and both complete replicas contain no intent,
created, cleanup or resolved events. This exception does not prove revocation;
new or changed revocation requests still block replacement.
Replacement freezes the discovery request against that original history before
publishing initialization; an arrival after the snapshot cannot be adopted on retry.
Old files, uploaded artifacts and the failed result remain
intact. The new attempt preserves every prior logical journal record and repeats
independent discovery, both native author-forgery checks, genesis persistence and
fresh cleanup readiness. A hidden obligation in the independent replica blocks
genesis. An interrupted transition resumes only its retained new epoch; it never
allocates another automatically. This exception does not apply to an active or
registered genesis, and it does not qualify or replay a failed qualification run.

Cleanup receipts are named by GitHub run and attempt. Readback verifies the
successful native Connect job, workflow/repository/revision metadata, artifact
digest and receipt observation time, and retains `receipt-source.json` with the
run, attempt, job and artifact identities. For older workflows whose reruns used
the same artifact name, exactly one upload must fall strictly after the current
job started and no later than it completed. Stale, ambiguous or invalid results
remain unresolved. Failed attempts and their artifacts are preserved; a rerun
does not turn the original failed result into a pass.

The pinned checkpoint uploader receives a private, pre-created Actions output file.
An uploaded artifact alone is insufficient: encrypted readback and append-only
registry publication must also succeed before the journal acknowledges durability.

`M3_11_CONNECT_CONFIGURATION` holds those non-secret protected bindings and the
active executable helper in one atomic publication. The workflow captures that
one value for both checkout and execution. `M3_11_CLEANUP_BACKEND=connect` selects
Connect explicitly; the legacy `M3_11_CLEANUP_REVISION` is left unchanged for the
service-account backend. A later reviewed helper keeps
the original epoch, genesis, registry and historical obligations while changing
the active helper. Fresh independent readiness at that helper is required before
the controller configuration is installed. Older failed results stay failed.

Each independent job starts pinned API/sync containers on GitHub's Docker host
with its cleanup-only master and client. It recovers the genesis and latest full
encrypted checkpoint, waits for its own replica, and reconciles provider removal.
Only its exactly owned ephemeral Connect resources are removed at job exit.
Neither the Unraid endpoint nor this workspace is required to recover outstanding
credential identities. A timeout, missing checkpoint, invalid history or failed
provider read remains unresolved.

The launcher dispatches one uniquely identified, twelve-minute witness job for
the exact approved attempt. It waits for a fresh, natively authored and durably
acknowledged readiness record from that running GitHub execution before starting
the detached controller. Run and creation-intent acknowledgements additionally
require fresh provider authority, no unresolved credentials, sufficient checkpoint
capacity and the original ten-minute provisioning window. Admission time is
rechecked after acknowledgement I/O. The controller independently enforces that
original cutoff immediately before each provider CREATE, so a delayed or retained
acknowledgement cannot reopen it. The separate five-minute provider-response
settlement range remains available for ownership and cleanup. Lost dispatch replies
are reconciled by the saved execution identity, never by blind resubmission.
No GitHub token enters the detached controller or fixture.

The independent journal uses encrypted GitHub artifacts retained for 30 days and
an append-only commit-status registry. Full history is checked for missing,
replayed or reordered entries. New attempts require at least 384 remaining
registry entries, reserving room for witnessing and cleanup below GitHub's
1,000-status limit per commit/context. The launcher must refuse if capacity is
insufficient; it never automatically replaces an epoch. Artifact expiry or lost
registry history cannot be interpreted as an empty obligation list. Monitor
cleanup receipts and unresolved/overdue counts even after qualification finishes.
The unchanged immediate cleanup, watchdog and hourly GitHub reconciliation paths
continue to require provider removal and available negative-authentication proof.

Connect avoids service-account request quota for this path. Same-cache readback
alone never authorizes credential creation: an independent encrypted checkpoint
and native acknowledgement are required first. Actual independent Connect startup,
the live credential rehearsal, complete M3.11 and verified revocation still need
operational evidence; local doubles do not establish those outcomes.

### Review, start and monitor

Before the first live issuance, present the prepared source/helper commit,
artifact digest, controller image ID, Docker-host identity, targets, credential
scopes/deadlines and independent-cleanup readiness together. Obtain explicit live
approval. Record its reference and exact bindings in a private
`lowerduckpond-m3-11-live-approval-v1` document. Approval expires within one day and
authorizes one rehearsal and one qualification attempt on that revision. A changed
executable revision needs a new approval and correctly bound attempt.

The seven fresh runtime credentials are separate: archive `readwrite` on its
bucket, backup `readwrite` on its bucket, account-wide Spaces `fullaccess` operator,
account-owned fixture Caddy Zone Read + DNS Write on both zones, account-owned
observer Zone Read + DNS Read on both zones, account-owned Account API Tokens Read
audit, and user-owned Page Rules Read on exactly both zones. Full policy, identity,
activity and lifetime are verified; Page Rules activity alone is insufficient.
Cloudflare children use native 14-hour expiry, with at least 12 hours remaining
at startup. Existing audit eight-day and Page Rules 91-day **remaining-time**
upper bounds are retained. Spaces has no documented native key expiry: its
recorded deadline triggers deletion, not provider-enforced expiry.

Bucket-scoped keys reach whole production buckets, and DNS Write reaches both
whole zones. Run prefixes are ownership accounting, not an IAM boundary.
The Spaces fullaccess operator stays controller-side. Provisioning bootstrap
never enters qualification or guests. A separate short production-check process
alone reads encrypted state, verifies the existing non-expiring exact-policy
production Caddy token and runs the existing production archive/backup
`ldp-m3-archive credential-check`, including mutual denial. Its bound sanitized
receipt is distinct from the fixture receipt. Managed qualification inputs must
be complete; state cannot replace them or serve as a fallback.

```console
mise exec -- just m3-11-unattended start FULL_COMMIT_SHA \
  --mode rehearsal --approval /private/live-approval.json \
  --config /private/controller.json --daemon-socket /docker-sock/docker.sock
mise exec -- just m3-11-unattended status RUN_UUID
mise exec -- just m3-11-unattended evidence RUN_UUID
mise exec -- just m3-11-unattended cancel RUN_UUID
mise exec -- just m3-11-unattended cleanup-status --config /private/controller.json
```

Start reserves the daemon-wide container name `ldp-m311-admission` before checking
existing controllers or writing run inputs, and releases it after launch. A
concurrent start fails immediately. If a launcher dies before releasing this
inert reservation, new starts remain blocked. Confirm that no launcher is still
running, inspect existing controllers and retained run state, and reconcile any
credential obligations before removing that reservation by its inspected
container ID. Never remove another launcher's reservation or prune the daemon.

The rehearsal performs bounded real production/fixture probes, delivers private
inputs, signals the controller's cancellation handler, revokes and records the
interruption. Before `start --mode qualification`, GitHub must independently
read back every rehearsal revocation. The full run uses the same start operation
with that mode. Status and evidence work from another terminal; routine monitoring
does not require operator log-pasting. Raw logs and any retained cleanup secrets
stay private. `cleanup-status` reads external obligations without a Docker
dependency and exposes overdue obligations and stale GitHub execution. Logs
stay in `ldp-m311-evidence` under `/evidence/runs/RUN_UUID`. Named helper/source
volumes retain the clean checkouts. `evidence` exports validated status and
revocation receipts, and the existing strictly verified passing report.

### Independent revocation and unresolved results

Before each create request, an immutable external 1Password item records the
run, unique provider name, exact scope, source/helper, baseline inventory and
deadline.
Each intent also pins its cleanup authority's secret hash: a different account's
empty inventory or a replaced bootstrap token cannot manufacture removal proof.
Changing that authority with outstanding obligations needs a separate reviewed
authorization decision, not an automatic token roll.
Returned IDs are immediately recorded locally and externally, before rejecting
a missing secret or invalid metadata. Usable secrets remain private; an ID-only
record does not claim that negative authentication was tested. Controller and
watchdog recovery restore retained creation records before evaluating ownership,
including when the original external acknowledgement failed. Lost
responses reconcile exact intent metadata and provider inventory; no creation
request is retried. Missing or ambiguous ownership remains unresolved.

Terminal cleanup, a separate persistent watchdog, and the protected GitHub
workflow independently reconcile those obligations. The watchdog checks local
processes every minute and immediately reconciles a newly detected terminal path.
Unresolved terminal cleanup first retries after five minutes, then backs off through
10, 20 and 40 minutes to hourly retries. A newly detected terminal path still triggers
immediate reconciliation. Routine remote reconciliation and GitHub scheduling are
hourly; GitHub execution may be delayed. Stale execution,
overdue obligations and provider failures remain visible. No exact-time Spaces
deletion guarantee is made. A successful DELETE alone is insufficient: require
fresh complete inventory and detail absence, plus negative authentication where
the secret remains available. Failed negative probes retain the obligation and
private cleanup material. Cleanup interruption resumes reconciliation, never
qualification. Failed revocation blocks closure and new starts independently of
the qualification outcome.
After verifying every owned credential, the watchdog retains a private revocation
receipt, clears only its temporary credential files, and finishes the local cleanup
state. The original journey result and diagnostics remain unchanged; the dead
controller leaves the fast retry queue.
Local controller and watchdog reconciliation share a lock on the persistent
evidence volume, separate from the journey lock. They refresh the journal only
after acquiring it and hold it through probes and temporary-key removal. Process
death releases the lock. An authentication failure also records an explicit
obligation whose event ID must be covered by a denied-authentication proof;
a concurrent independent readback without the secret cannot clear it. New proof
coverage does not depend on the actors' clock ordering.

Revocation deletes credentials only. It never removes failed-run evidence,
containers, backups, DNS records or remote data. Existing ownership and explicit
approval requirements for destructive retirement remain in force. Diagnostic
recovery after revocation needs newly authorized temporary credentials and cannot
change the original failed qualification result.

With the service-account backend, 1Password's account-wide daily request quota
is shared by all service accounts.
Before issuing credentials, the controller checks both provisioning and cleanup
quota metadata, requiring headroom for the journey, retained journal history and
cleanup. This observes capacity; it cannot reserve it against unrelated account
activity. Quota exhaustion never clears an obligation or suppresses revocation.
The hourly remote cadence avoids consuming the quota with idle one-minute reads.
The controller and watchdog share an encrypted cache of immutable journal reads
on the private evidence volume; GitHub retains its own cache independently. Each
cache is keyed by its cleanup service account and vault. It contains no provider credentials or
production inputs. Every sweep still lists the live vault and validates each
cached record against its current metadata and content-hash title; new records
are fetched, and changed or disappeared records fail closed. Provider removal
and negative-authentication evidence are never replaced by cache observations.
Cache loss requires fresh journal reads and may need more quota. See
[1Password request limits](https://developer.1password.com/docs/service-accounts/rate-limits/).
An invalid or unreadable cache triggers complete live journal reads. A cache that
is too large or cannot be written is omitted without blocking credential cleanup.
The GitHub workflow separates restored input from newly validated encrypted output
and saves only the latter, including when provider revocation fails. Repeated failures
reuse an outstanding negative-authentication obligation rather than appending identical
markers. Every retry still requires fresh provider readback and authentication checks
where credentials remain available; reduced journal traffic cannot turn a failure into
verified cleanup.

## Repository identity and audit lineage

The installed backup configuration supplies the repository and node identity.
No command accepts another repository, arbitrary state path, lineage ID, password
or retention policy on its command line. The root-only helper loads the existing
private `/etc/lowerduckpond/backup.env`; use the existing secure-workstation
environment workflow rather than copying credentials into the coder workspace.

On an owned disposable host with the new artifact, a configured Restic format-2
repository, a canonical platform namespace and the complete local audit chain:

```console
sudo systemctl start lowerduckpond-backup-identity.service
sudo /usr/local/libexec/lowerduckpond/backup-state-identity --verify
```

The service explicitly initializes a missing lineage once. Under tenant-state it
publishes and syncs a candidate at `static/locks/audit-lineage-genesis.json`.
After releasing tenant-state, it saves the exact canonical bytes in a dedicated
Restic snapshot containing only `/audit-lineage-genesis.json`. It verifies the
complete tree and reads back the exact bytes, then reacquires tenant-state,
revalidates namespace and audit history, and publishes the identical primary
`static/platform/audit-lineage.json`. Initialization cannot succeed before the
repository evidence exists and verifies.

The permanent snapshot has exactly `lowerduckpond-audit-lineage`,
`lineage-<uuid>` and `repository-<binding>` tags with the bound node. It has no
`scheduled` tag and stays outside ordinary retention indefinitely. Never delete
or retag it. Every subsequent invocation verifies this unique snapshot before
using either local record. Missing, ambiguous, corrupt or differently bound
repository evidence fails closed. An interrupted write with a lost response is
discovered and verified on the next invocation; it never blindly repeats the
snapshot. No command automatically deletes duplicate evidence.

If only the primary is lost, explicit `--initialize` can restore the original
bytes after matching the local candidate, repository evidence, namespace and
initial audit prefix. `--verify` never repairs or initializes. If an older or
incomplete platform backup loses both local files, the permanent repository
snapshot prevents allocation of a new UUID. This P2a command refuses that state;
reconstruct the original records through the later P5 recovery workflow, never
reset lineage. A primary without its local candidate also fails closed. Never
delete records, an index or a snapshot to make initialization succeed.

Successful verification emits only `backup_identity_verified`. Failure emits
`backup_identity_unverified`, or `backup_identity_lock_unverified` when the fixed
lock metadata/lease is invalid. Inspect the service result privately:

```console
sudo systemctl show lowerduckpond-backup-identity.service --property=Result,ExecMainStatus
sudo journalctl --unit lowerduckpond-backup-identity.service --no-pager --lines=20
```

Both private, immutable records are canonical JSON plus LF, at most 16 KiB each,
root-owned mode 0600. They contain the versioned
repository identity (full config ID, node and canonical location), its digest,
root-generated UUIDv7, namespace digest, initialization time, original audit
entry count and terminal digest. Repository binding uses ADR 0030's domain and
unsigned 64-bit length framing. Existing namespace/audit digests retain their
original formats. Local repository aliases are resolved before binding; S3
endpoint host case, default HTTPS port and a trailing separator normalize to
one location. Ambiguous paths, credential-bearing URLs and unsupported backends
fail. Changing credentials/cache/retention does not change repository identity.

The command serializes repository access before leasing the selected artifact.
Both exclusive tenant-state transactions validate the complete local audit
chain; no network operation holds tenant-state. Each local publication uses file
and parent-directory sync. An interruption resumes the same durable candidate
and repository snapshot. An abandoned pre-publication temporary grants no
authority. No audit entries are renumbered or rewritten, and no backup credential
or network access is added to ordinary workers or the provisioner.

The service is manual, has no timer and is not started by convergence in P2a.
Its bounds are 30 minutes, 512 MiB, no swap, 32 tasks and one CPU; each Restic
operation has a five-minute deadline. Snapshot discovery is limited to 16 MiB
and 8,192 complete-ID records. Genesis content is limited to 16 KiB, with 32 KiB
bounds on tree listings and write-command output. Oversized, duplicate or
malformed metadata fails without displaying provider output. The only write is
the dedicated genesis snapshot; the command never runs forget, prune, unlock,
repair or retagging. P3 adds protected audit-segment verification and guarded
maintenance; this small lineage snapshot does not qualify audit archival.

Reapplying or reverting P2a tooling leaves the immutable records and original
audit untouched. Keep both records in all subsequent platform backups. Genesis
is authoritative metadata, not a kernel lock: recreating lock inodes during host
reconstruction must preserve this record and the recovery cursor. A changed
repository/location/node needs an explicit reviewed migration; there is no
automatic rebind switch. Scheduled source policy and production rotation remain
unchanged until the dependent slices and recovery qualification are complete.

Run its independent installed proof with `just check-installed-group backup-identity`.
The case uses real Restic on an owned local repository and supported tenant
operations. Local evidence does not qualify Spaces or restored-host service.

## Coherent scheduled capture

P2b installs the coherent capture path behind the explicit Ansible boolean
`backup_static_recovery_enabled`, default `false`. It requires immutable Caddy
generations, the verified selected artifact, a canonical namespace and the P2a
repository-backed lineage. Enabling it verifies existing lineage and explicitly initializes/verifies the
P3 protected audit index; convergence does not initialize or rebind identity. Production activation remains part of
the final M3.11 handoff, after reconstruction and cold-certificate qualification.
No operator production action is required by this implementation slice.

The policy captures `/srv/lowerduckpond`, `/var/lib/lowerduckpond/static`,
`/var/lib/lowerduckpond/recovery`, a consistent compressed MariaDB logical dump,
and the staged recovery descriptor. It excludes static intake/export delivery,
release staging, validated abandoned state/recovery publication temporaries,
generated Caddy configuration/environment and certificate/ACME storage.
An ext4 content volume's `lost+found` is excluded only after verifying an empty,
root-owned mode-0700 directory on the content filesystem. Recovered files,
symlinks, unsafe ownership/mode, extended attributes or a changed inode fail
capture; no recovered content is silently discarded.
Temporary-looking **content** filenames remain authoritative and are included.
The source-policy digest and backup health scope change with this policy.
Existing snapshots remain in the repository under their original scope.

The outer command takes the repository lock and stages SQL with the existing
least-privilege database identity. It proves the selected artifact under its
shared selection lease, then verifies the unique permanent repository genesis
before acquiring shared publication followed by shared tenant-state. It measures
the complete classified tree, stages a private descriptor outside the source
roots, invokes fixed-source Restic, checks the full snapshot ID and unique capture
tag, and independently dumps the descriptor for exact byte comparison. Both
static leases remain held until all those steps finish. Restic inherits the
exact locked descriptors, so parent death cannot release exclusion while a
surviving reader runs. Names/inodes are revalidated after blocking and before
success. Shared capture never reconciles state or removes its temporaries.

On an explicitly migrated owned host, the fixed manual invocation is:

```console
sudo systemctl start lowerduckpond-backup.service
sudo systemctl show lowerduckpond-backup.service --property=Result,ExecMainStatus
sudo journalctl --unit lowerduckpond-backup.service --no-pager --lines=20
```

Success emits `backup_static_verified FULL_SNAPSHOT_ID` and updates the private,
scope-bound success status. Failure emits `backup_static_unverified`, or
`backup_static_artifact_unverified` before selected code runs, and updates failure
status without refreshing success. SQL staging is removed on exit; the last
descriptor remains private diagnostic evidence. In this mode convergence reuses
only a matching local success status or runs a new verified capture. Repository
tags alone cannot reconstruct a success status. A partial Restic exit, lost
response, duplicate capture tag, changed source/inode, unsafe metadata, unknown
record, oversized input or failed readback fails without retry, deletion,
retagging or fallback. Preserve the repository and private descriptor for diagnosis.

Capture/readback does not authorize serving a restored host. P5 supplies audit,
exact-version archive, unfinished-operation, trusted runtime and TLS recovery.

### Descriptor and limits

`/var/cache/lowerduckpond-backup/staging/static-recovery.json` is canonical JSON
plus LF, root-owned mode 0600, at most 256 KiB, with schema
`lowerduckpond-static-backup-v1`. It binds the root-generated UUIDv7/time, source
policy, selected artifact, lineage, namespace, optional launch record, audit
head/counts, complete authority-tree digest/counts, sorted tenant and retained
release inventories, unfinished intents, and non-secret Caddy generation/start
evidence. Caddy evidence includes active/candidate/previous references, selected
target and exact invocation-fenced start intent. It contains no environment,
adapted configuration, credentials, tenant content or audit events.

Existing contract digests retain their original formats. New backup digests use
ADR 0030's domain-separated unsigned 64-bit length framing. Existing artifact
and manifest hashes have explicit format names. The snapshot ID is external;
the `capture-UUID` tag binds readback. Scheduled snapshots also carry the bound
scope, lineage, repository and `lowerduckpond-static-backup` tags.

Bounds include 25 tenants, four retained/candidate records and releases per
tenant, two intents, and the existing authorization/release allocation limits.
A fourth release is accepted only as a named interrupted candidate; admission
limits do not increase. The complete tree is limited to 800,000 entries, 12 GiB,
32-MiB individual files and depth 40; its inventory streams through a private,
at-most-1-GiB temporary file. Capacity reservations retain the existing
5-GiB/10-percent and 100,000-inode/10-percent free floors. Special files, symlinks,
hardlinks, nested mounts, extended attributes and unsafe ownership/modes fail.
The recovery root admits only the classified P5 journal, receipt and provenance
schemas, with explicit bounds. Safe publication temporaries are ignored intact.

The whole backup service has a 30-minute deadline, 512 MiB, no swap, 32 tasks,
1,024 descriptors and one CPU. Capture has a 30-minute Restic deadline within
that service envelope; metadata/readback calls retain five-minute bounds.
Output is bounded; provider stderr is not copied into diagnostics. Archive
credentials remain masked. The provisioner gains no source or backup access.

### Source writer inventory

| Authority | Writers and exclusion |
| --- | --- |
| Namespace, launch, tenant manifests/observations, deployment/archive records, operation results, authorization pairs, intents, quarantine, audit | Repository transactions and repair/replay use exclusive tenant-state; runtime/release transitions also hold exclusive publication in the established order. Backup takes both shared. |
| Published releases, retained history and retired release cleanup | Release-store mutation and lifecycle recovery require exclusive publication; capture measures under shared publication/state and refuses nonempty staging or unclassified retired names. |
| Non-secret Caddy generation/start evidence | Generation publication, reload/start target and invocation evidence use exclusive publication. Capture verifies referenced immutable payloads under its shared lease. Secret-bearing bytes never enter the descriptor. |
| Content parent, fixture, state/release directory metadata and Caddy generation/intent directories | Scoped root-only `configure-static-python` acquires publication then tenant-state exclusively before the actual Ansible file/template module writes. Each module releases both on exit; no synchronous service wait runs inside the wrapper. |
| Recovery journal, receipts, provenance and directory metadata | Guarded Ansible creates the directory. Root source fencing and reconstruction hold the repository lease, selected-artifact lease and separate coordinator exclusion; coherent backup uses that same repository exclusion. Only classified P5 records are capturable. |
| SQL and descriptor staging | Root backup command under the exclusive repository lease; neither staging path belongs to the static authority tree. SQL retains the consistent database dump protocol. |

The Ansible wrapper validates all four existing kernel lock inodes and never
replaces them. First bootstrap is allowed only before any selected artifact,
backup configuration, genesis or authoritative history exists, allowing the
original create-only-missing lock tasks to finish. An existing host with missing,
linked, nonempty, misowned or incorrectly protected locks refuses convergence.
Kernel lock creation precedes artifact selection. This 0700 interpreter accepts
privileged Ansible modules; it grants no ordinary-user command capability.

Run `just check-installed-group backup-coherence` for its independently owned
active, suspended, archived and undeployed tenants. It migrates over existing
history, verifies mode-on idempotence and service failure/health boundaries, and
uses real Restic capture/restore during Caddy restart and guarded Ansible writes.
Exclusion canaries and a temporary-looking authoritative file check the actual
source policy.

Run `just check-installed-group backup-mutation-overlap` for a separate fresh
fixture initialized with an empty audit lineage. A single normal convergence
enables disposable publication and coherent backups before its own tenant
history. It races capture against create/deploy/import/rollback/rename/suspend/
resume/archive/restore/delete/export/emergency/reconcile, authorization repair
and release cleanup. Every restored tree in both cases is measured against its
descriptor. Accounting and teardown remain mandatory. The [installed group
guide](installed-groups.md) retains the measured cost that motivated this split.
Results are diagnostic local/MinIO evidence; live Spaces and host reconstruction
require later qualification.

## Protected audit verification and maintenance

The protected readers and maintenance guard operate with rotation disabled.
P4 installs a separate hourly rotation timer, disabled by default. Complete
P2 lineage initialization before enabling `backup_static_recovery_enabled` on
an owned disposable host. Convergence starts the explicit index initializer,
then enables verification at boot and daily:

```console
sudo systemctl start lowerduckpond-audit-initialize.service
sudo systemctl start lowerduckpond-audit-verify.service
sudo systemctl show lowerduckpond-audit-verify.service --property=Result,ExecMainStatus
sudo journalctl --unit lowerduckpond-audit-verify.service --no-pager --lines=20
```

The initializer requires the existing unique repository-backed genesis and
identical local records. It may create an empty head only when no committed
index or remote rotation exists. Verification never recreates a lost head,
lineage, index or witness. Missing or corrupt authority requires diagnosis and
the later recovery workflow. Do not remove metadata to permit initialization.

Every proof inventories the repository and verifies all referenced and discovered
protected snapshots by their full IDs, exact tags, node, repository and lineage.
It reads the stored Restic trees, checks the exact two-file payload and metadata,
restores one bounded segment into a fresh private workspace, then reconstructs
its canonical witness and checks the complete digest chain. Local immutable
indexes and witnesses commit only after a second state transaction proves the
same authority, closed source bytes and durable successor. Equivalent snapshots
remain protected duplicates; an existing selected ID is preserved. Missing,
retagged, conflicting or corrupt evidence refuses the proof. A lost creation
response can be reconciled from equivalent repository evidence without repeating
snapshot creation or deleting a duplicate.

Local audit readers join the archived witness prefix to the contiguous local
suffix, requiring exact bytes wherever they overlap. Correlation lookup, retry,
replay, historical deployment and deletion evidence use that same chain. Ordinary
workers read these local witnesses without backup credentials or network access.
The verifier preserves every local segment even after a verified index commits.
Only the explicitly enabled rotator may remove an indexed closed source.

The verifier and initializer run for at most five minutes with 256 MiB, no swap,
32 tasks, 256 descriptors and one CPU. The private verification workspace admits
at most 32 MiB and 128 inodes; metadata under the audit archive admits at most
32 MiB and 8,192 inodes. Unsafe or unknown workspace entries are preserved and
refused. The shared 5-GiB/10-percent block and 100,000/10-percent inode free floors
and 8-MiB administrator audit reserve remain enforced. Root commands are 0700;
all backup units mask tenant archive credentials and sockets.

### Retention and interruption

```console
sudo systemctl start lowerduckpond-backup-maintenance.service
sudo systemctl show lowerduckpond-backup-maintenance.service --property=Result,ExecMainStatus
sudo journalctl --unit lowerduckpond-backup-maintenance.service --no-pager --lines=20
```

Maintenance performs fresh protected verification before selecting ordinary
`scheduled` snapshots for the configured node, grouped by host and source paths.
The fixed policy is 7 daily, 5 weekly and 12 monthly. It writes a durable intent
binding the exact ordinary remove IDs and current protected proof, forgets those
IDs, verifies their absence and every protected snapshot, then separately prunes,
checks repository integrity and proves protection again. Restic's oldest-snapshot
fallback is preserved. Protected genesis, audit snapshots and duplicate copies
remain indefinitely, even when older than every ordinary retention window.

After interruption, rerun the same service. The journal's remove set cannot
expand to newly eligible snapshots. An interrupted prune resumes with integrity
and protected-content checks before one bounded prune and its final checks.
This also covers interruption after publishing `pruning` but before child launch;
a durable `checked` phase needs only final revalidation before journal removal.
No command unlocks, repairs, retags or expires protected history. Any failed
proof preserves the remaining evidence and records a failure without refreshing success.
Maintenance has a 30-minute, 512-MiB, no-swap, 32-task, 1,024-descriptor, one-CPU
service envelope. Forget, prune and integrity checking each use that operation
deadline within the same overall service envelope; metadata requests retain a
five-minute bound. Timeout is failure; do not raise limits to qualify a run.

The reviewed [legacy compatibility amendment](../plans/milestone-3.11.md#p3-activation-and-legacy-compatibility-amendment)
permits ordinary maintenance only before **any** M3.11 local or remote authority
exists. That path checks the complete archive-free precondition before explicit
ordinary-ID forget and separate prune; it never initializes a lineage or journal.
Once P2 identity exists, legacy maintenance refuses until coherent mode is
activated. Disabling coherent mode cannot bypass protected retention. Do not
roll back to older unguarded maintenance after protected history exists.

Backup configuration writes serialize under the repository lock, followed by
publication and tenant-state locks. An activation digest rejects older queued
commands after policy changes. Configuration modules release all locks before
service/network work. Upgrading from pre-P3 commands requires draining the older
backup and maintenance processes in the final P6 handoff.

### Health and evidence

Existing textfile health adds `lowerduckpond_audit_protection_verified`, protected
snapshot count/bytes, rotation-pending state and fixed failure categories:
`protection`, `rotation-pending`, `index-corruption`, `archive-unavailable` and
`resource-exhaustion`. The root health reader uses only the selected artifact,
local witness/index and scoped proof cache. It receives no backup or tenant
archive credentials and makes no network call. Missing, wrong-scope, future or
older-than-24-hour proof closes ordinary audit admission. Administrator reserve
remains available for evidence-preserving diagnosis. The ordinary 65,536-entry
ceiling counts the complete verified chain, including the local suffix, before
a new entry is admitted; the archived head alone cannot supply that count.
Existing traffic need not stop solely for this backup health failure;
restored-host service remains a separate P5 gate.

Run `just check-installed-group audit-protection` on its fresh owned fixture.
It uses the unchanged 8-MiB production segment bound, actual Restic snapshots
with ancient timestamps, equivalent duplicates, missing/corrupt/retagged indexed
evidence, and process exit immediately after durable forget completion. A newly
eligible ordinary snapshot added after interruption proves the resumed remove
set stays fixed. Fault restoration touches only known encrypted snapshot objects
inside the explicitly owned local fixture; it is not a production repair tool.
The case also checks historical lookup, privilege/resource limits, health,
accounting and teardown. Its result is diagnostic local/MinIO evidence, not a
live-provider or restored-host qualification.

| Obligation | Component evidence | Installed evidence |
| --- | --- | --- |
| Strict schemas, witness reconstruction and complete historical readers | `test_audit_archive_formats.py`, `test_audit_archive_store.py`, `test_audit_archived_history.py` | Production-size segment, duplicate proof, indexed overlap and supported tenant deletion |
| Exact Restic trees, bounded workspace and ordinary-only 7/5/12 selection | `test_audit_archive_restic.py`, `test_audit_archive_workspace.py`, `test_audit_archive_inventory.py` | Actual Restic restoration, ancient duplicates and aged ordinary snapshots |
| Crash-safe index publication and fixed maintenance phases | `test_audit_archive_local.py`, `test_audit_archive_coordinator.py` | Orphan adoption and hard exit after forget; original remove set on resume |
| Admission reserve, health and activation serialization | `test_audit_archive_admission.py`, `test_audit_archive_health.py`, `test_backup_configuration_lock.py`, `test_backup_configuration_scope.py` | Installed service bounds, provisioner denial, health and coherent-mode reapplication |
| Legacy migration refusal and fixed root entrypoints | `test_backup_legacy_retention.py`, `test_backup_audit_entrypoint.py` | Baseline legacy maintenance plus explicit mode-on migration |

## Audit rotation

`backup_audit_rotation_enabled` defaults to `false`. P4 installs the machinery;
production activation still requires P5 recovery consumers and the P6 complete
qualification and operator handoff. The independent owned-fixture case enables
both `backup_static_recovery_enabled` and `backup_audit_rotation_enabled` after
explicit namespace and repository-backed lineage initialization. Rotation without
coherent backup mode is rejected. The activation digest binds both flags, so an
older queued command cannot use a newly activated policy.

On that explicitly activated host, the persistent hourly
`lowerduckpond-audit-rotate.timer` processes at most one oldest closed segment
per invocation. It never closes the current tail merely to reclaim space. Use
the same bounded service for a manual invocation or interrupted-attempt resume:

```console
sudo systemctl start lowerduckpond-audit-rotate.service
sudo systemctl show lowerduckpond-audit-rotate.service --property=Result,ExecMainStatus,MemoryPeak
sudo journalctl --unit lowerduckpond-audit-rotate.service --no-pager --lines=20
```

The service holds the repository and selected-artifact leases. Short local
transactions validate the complete audit chain and exact source generation;
network work releases tenant-state exclusion. A durable prepared intent seals
the descriptor before snapshot creation. Fresh repository discovery precedes
every creation attempt, including retries after a lost response. Matching remote
copies are restore-verified and adopted without another backup request. The
full snapshot ID, exact restored bytes, witness, immutable index and committed
head must agree before removal. Staging is classified and cleaned before the
local source is unlinked; each removal syncs its parent directory.

After interruption, rerun the service. Even when the source is already absent,
the indexed attempt needs fresh remote proof before directory synchronization
and intent cleanup. Missing remote evidence, changed source generation, absent
witnesses, conflicting copies or unknown staging preserve the remaining evidence
and fail. Do not delete a pending intent, stage, witness or index to permit a
retry. A pending uncreated attempt can be completed only by the rotator; generic
verification and maintenance continue to refuse that unfinished state. Existing
selected snapshot IDs and every equivalent protected copy remain retained.

The service retains the verifier's five-minute, 256-MiB, no-swap, 32-task,
256-descriptor and one-CPU limits. Its sealed two-file snapshot input has a
32-MiB/128-inode staging ceiling; admission also reserves the complete independent
verification workspace and metadata publication. Rotation cannot borrow the
8-MiB administrator reserve or cross the filesystem free floors. Local ordinary
audit allocation at 64 MiB sets `lowerduckpond_audit_rotation_warning 1`, before
the 128-MiB ordinary ceiling. A warning does not itself mark protected evidence
invalid. The existing pending/failure metrics still report unfinished work.

Run `just check-installed-group audit-rotation` for the fresh independent case.
It keeps the production segment bound: two successive real 8-MiB closures span
supported tenant creation and deletion. Hard process exits cover prepared intent,
lost snapshot response, witness/index/head publication and local unlink. An
actual host reboot separates unlink from cleanup. The second complete rotation
runs through the unmodified bounded service with the first archived prefix
already present. Exact historical replies, deletion authority, subsequent tenant
operations, protection health, service limits, account denial and final fixture
accounting remain required. All original ordinary snapshot IDs are preserved.

| Obligation | Component evidence | Installed evidence |
| --- | --- | --- |
| Sealed attempt, lost reply, no duplicate creation and no network under state exclusion | `test_audit_rotation.py` | Actual Restic capture, full-ID inventory before/after each hard exit |
| Every write/sync/rename/unlink boundary resumes with fresh proof | `test_audit_rotation.py`, `test_audit_archive_local.py` | Publication exits, unlink exit, real reboot and service-driven cleanup |
| Strict staging, source generation, free floors and administrator reserve | `test_audit_rotation_stage.py`, `test_audit_archive_admission.py` | Installed fixed service limits, mode gate and both ordinary accounts denied |
| Exact history with a sealed pending source and after local removal | `test_audit_rotation.py`, `test_audit_archived_history.py`, `test_audit_archive_formats.py` | Two full segments, original create/delete replays and new supported operations |

The local component and MinIO cases do not establish live-provider behavior or
full reconstruction. Those qualifications, production execution and records-only
closeout remain later M3.11 deliverables. Before local removal, rollback may use
the compatible protected reader with rotation disabled. After removal, preserve
the working archived-history reader and use forward repair or the reviewed
restored-host workflow; older local-only readers cannot serve this state.

## Gated host reconstruction (P5)

`restore-static-host` reconstructs static authority on a distinct, explicitly
bootstrapped destination. It requires a coherent snapshot made with the **same
P5-capable artifact** installed at the destination. P4 and older artifacts are
not silently upgraded during a restore. Keep those snapshots; first install the
reviewed P5 artifact, take a new coherent backup and qualify its reconstruction.
Publication and rotation remain off in production until the separately reviewed
M3.11 handoff. The commands below describe disaster recovery and owned drills;
they do not authorize a production reconstruction or start M3.12.

The source must be fenced before creating or changing the destination. The
installed root command closes the persistent web gate, drains the repository
and artifact-selection leases, stops ordinary work and records the exact source
identity/snapshot. Its receipt has no automatic expiry. Keep the source fenced
through verification and retirement; there is no automatic un-fence command.
An absent or unverified source receipt blocks this workflow. A source that
cannot provide the receipt requires a separately reviewed fencing decision;
removing the receipt check or fabricating a successful source command is not a
recovery procedure.

Fencing and destination recovery also stop the periodic health timer and drain
its service. The read-only audit health check holds a shared tenant-state lock;
it must not race root replacement or installed verification. Its recovery
admission drop-ins keep it stopped across reboot while the gate is closed.
Successful completion restores the health timer with the ordinary schedules.

Use the secure workstation's existing private environment file/disposable shell
from [production preparation](m3-10-convergence-preparation.md), verified SSH host
keys and administrator identity. Keep the original report, selected artifact,
namespace/launch policy, old public origin-pull CA certificates, new reviewed
Caddy binary/environment/current CA inputs and original repository/node/storage
target available. Do not source an environment file from the restored snapshot.
The archive credential belongs to its separate installed helper; backup and
Caddy credentials remain in their existing private configuration domains.

Set the following nonsecret values in that shell. SSH aliases must refer to the
reviewed source and **distinct fresh destination**, never a load-balanced name.
The full snapshot ID comes from the retained coherent-backup evidence.

```bash
umask 077
export LDP_RECOVERY=/absolute/private/reconstruction
export LDP_SOURCE_SSH=reviewed-source-alias
export LDP_DESTINATION_SSH=reviewed-destination-alias
export LDP_SNAPSHOT_ID=REPLACE_WITH_64_LOWERCASE_HEX_DIGITS
export LDP_RESTORE_ID=$(uv run --frozen python -c 'import uuid; print(uuid.uuid7())')
mkdir -m 0700 "$LDP_RECOVERY"
ssh "$LDP_SOURCE_SSH" sudo /usr/local/sbin/fence-static-host \
  --snapshot "$LDP_SNAPSHOT_ID" --restore-id "$LDP_RESTORE_ID"
ssh "$LDP_SOURCE_SSH" sudo cat \
  "/var/lib/lowerduckpond/recovery/source-fence-$LDP_RESTORE_ID.json" \
  > "$LDP_RECOVERY/source-fence.json"
```

Expect `restore_source_fenced` and the same restore UUID. Source fencing fails
if the snapshot, artifact or repository authority does not verify. A failure
may already have closed the source gate; inspect it privately and resume the
same command/UUID. Do not allocate a new identity to bypass retained evidence.

Prepare a fresh supported Ubuntu destination with the ordinary administrator
SSH boundary and required storage capacity. State/content/Caddy installation
roots must be absent; their **parents** must permit same-filesystem renames.
A mount directly at `/etc/caddy` or `/srv/lowerduckpond` cannot be renamed by
this workflow. Preserve at least the normal 5-GiB/100,000-inode/10% free floors
*after* reserving restored candidates, generated runtime, verification workspace
and retained prior roots. The coordinator independently calculates admission
from the full Restic tree; a capacity refusal does not permit reducing floors.

Before bootstrap, stage the reviewed public OS trust bundle and pinned Caddy
binary through the administrator's ordinary baseline preparation. Obtain the
actual destination machine ID and trust bundle over verified SSH. Keep a private
workstation copy of the exact reviewed binary; its installed absolute path must
match the pinned Caddy path selected by the Ansible role. Prepare canonical
`namespace.json` and optional `launch.json` from the independently reviewed
platform policy, plus the original and current public origin-pull certificates.
Do not copy source Caddy certificate/account storage to the destination.

Restic and the original descriptor preserve numeric file ownership. Reserve the
original source Caddy **group ID** on the fresh destination before baseline
packages allocate other accounts; do not renumber an occupied group. The
destination Caddy user can have a new UID because its certificate storage is
new. Create that account without a home directory so bootstrap can prove empty
storage. A GID mismatch fails descriptor/content validation rather than silently
rewriting captured metadata.

```bash
export LDP_CADDY_GID=$(ssh "$LDP_SOURCE_SSH" getent group caddy | cut -d: -f3)
ssh "$LDP_DESTINATION_SSH" sudo groupadd --system --gid "$LDP_CADDY_GID" caddy
ssh "$LDP_DESTINATION_SSH" sudo useradd --system --gid caddy \
  --home-dir /var/lib/caddy --shell /usr/sbin/nologin --no-create-home caddy
```

```bash
export LDP_DESTINATION_ID=$(ssh "$LDP_DESTINATION_SSH" cat /etc/machine-id)
ssh "$LDP_DESTINATION_SSH" cat /etc/ssl/certs/ca-certificates.crt \
  > "$LDP_RECOVERY/destination-trust.pem"
export LDP_CADDY_BINARY_PATH=/usr/local/lib/lowerduckpond/REPLACE_WITH_PINNED_CADDY_NAME
uv run --frozen python - <<'PY'
import os
import re
from pathlib import Path
root = Path(os.environ['LDP_RECOVERY'])
token = os.environ['CADDY_CLOUDFLARE_API_TOKEN']
assert re.fullmatch(r'[A-Za-z0-9_-]{20,256}', token)
path = root / 'reviewed-caddy-environment'
with path.open('x', encoding='ascii') as stream:
    stream.write('CLOUDFLARE_API_TOKEN=' + token + '\n'
                 'XDG_CONFIG_HOME=/etc/caddy\nXDG_DATA_HOME=/var/lib/caddy\n')
path.chmod(0o600)
PY
uv run --frozen python -I -m lowerduckpond_static_host_agent.host_restore_prepare \
  --fence "$LDP_RECOVERY/source-fence.json" \
  --namespace "$LDP_RECOVERY/namespace.json" \
  --destination-id "$LDP_DESTINATION_ID" \
  --binary "$LDP_RECOVERY/reviewed-caddy-binary" \
  --binary-path "$LDP_CADDY_BINARY_PATH" \
  --environment "$LDP_RECOVERY/reviewed-caddy-environment" \
  --ca "$LDP_RECOVERY/current-origin-pull-ca.pem" \
  --original-ca "$LDP_RECOVERY/original-origin-pull-ca.pem" \
  --trust-bundle "$LDP_RECOVERY/destination-trust.pem" \
  --archive-region "$SPACES_REGION" --archive-bucket "$SPACES_ARCHIVE_BUCKET" \
  --output "$LDP_RECOVERY/target"
```

Add `--launch "$LDP_RECOVERY/launch.json"` when the captured platform has a
launch record. Supply each `--ca`/`--original-ca` twice, in reviewed order, for
dual trust. Public CA inputs contain certificates only. Preparation creates a
new directory exclusively, defaults publication and rotation to **false**, and
writes only canonical policy, source fencing and original public trust. Tokens,
private keys and repository credentials are not copied into that output. Review
`target/target.json` privately. `--publication-enabled` and
`--audit-rotation-enabled` express a separately reviewed activation policy;
neither is part of M3.11 dark-production rollout by default.

Create a private single-host inventory named `destination.yml` with the
`hosting_nodes` group, verified destination SSH alias/address, administrator
user/key and the **original** `backup_node_name`. Reuse the existing production
input mapping through `--extra-vars` below, with the retained artifact path and
SHA256 in `STATIC_HOST_AGENT_ARTIFACT_PATH` and
`STATIC_HOST_AGENT_ARTIFACT_SHA256`. They must match `originalArtifactSha256` in
the prepared policy. `BACKUP_REPOSITORY` must select the original repository and
canonical location; a freshly initialized or unrelated repository is refused.
For a local repository, an independently preserved exact copy must be at that
same canonical path. The destination must have its dedicated archive credential
for the reviewed region/bucket.

For example, adapt this inventory privately using the original backup node name
and an SSH alias already verified on the secure workstation:

```yaml
all:
  children:
    hosting_nodes:
      hosts:
        recovery-destination:
          ansible_host: reviewed-destination-ssh-alias
          ansible_user: ldp-admin
          backup_node_name: lowerduckpond-production-01
```

```bash
uv run --frozen python - <<'PY'
import json
import os
from pathlib import Path
root = Path(os.environ['LDP_RECOVERY'])
value = {
    'host_recovery_bootstrap_enabled': True,
    'host_recovery_restore_id': os.environ['LDP_RESTORE_ID'],
    'host_recovery_input_directory': str(root / 'target'),
    'backup_static_recovery_enabled': True,
    'backup_audit_rotation_enabled': False,
    'static_publication_enabled': False,
}
with (root / 'bootstrap.json').open('x') as stream:
    json.dump(value, stream)
    stream.write('\n')
PY
uv run --frozen python -I -m lowerduckpond_static_host_agent.host_restore_bootstrap \
  --directory "$LDP_RECOVERY/target" --destination "$LDP_DESTINATION_ID" \
  --restore-id "$LDP_RESTORE_ID"
ANSIBLE_CONFIG=config/ansible/ansible.cfg uv run --frozen ansible-playbook \
  -i "$LDP_RECOVERY/destination.yml" \
  --extra-vars @config/ansible/inventories/production/group_vars/hosting_nodes.yml \
  --extra-vars "@$LDP_RECOVERY/bootstrap.json" config/ansible/playbooks/site.yml
ssh "$LDP_DESTINATION_SSH" sudo /usr/local/sbin/restore-static-host \
  --snapshot "$LDP_SNAPSHOT_ID"
ssh "$LDP_DESTINATION_SSH" sudo /usr/local/sbin/restore-static-host --status
```

Bootstrap validates source fencing and reviewed destination inputs before its
mutating tasks. It installs the durable gate before ordinary services, keeps
Caddy/mutation/retention inactive and leaves certificate storage empty. It never
selects a normal empty generation over restored tenant state. A plain converge
cannot bypass an unfinished journal. Bootstrap may resume its own gate before
journal creation; once the journal exists, use the restore command.

### Resume, readiness and failure

`--status` is read-only and reports restore/snapshot identity, durable phase and
`activationPending`. The phase sequence is `prepared`, `restored`, `validated`,
`reconciled`, `runtime-prepared`, `installed`, `verified`, `complete`. Before
`installed`, changes remain in private trees. The coordinator records root
inode identities before each same-filesystem rename, retains prior roots and
recreates the four kernel lock files while preserving the recovery cursor.
A partial root installation resumes only its original transaction.

Repeat the **same** full-ID command after resolving an external cause. It does
not accept another repository, path, credential, issuer, snapshot alias or
restore identity. `verified` and `complete` with ordinary admission still gated
obtain fresh remote/state/runtime/TLS proof before activation. Once ordinary
admission commits, a repeated command finishes only pending firewall cleanup
and leaves later tenant work alone. Reboot cannot open an unfinished gate,
even if runtime masks disappeared.

Actual Caddy DNS-01 issuance must produce trusted current certificate/key pairs
for both apex/wildcard pairs, and the certificates presented on loopback must
match. Native process/admin health alone is insufficient. Authenticated origin
pulls remain required; no HTTP application probe or internal/self-signed issuer
fallback is used. Keep acquired Caddy account/certificate storage on retry.
Do not reset startup attempts or extend service/coordinator deadlines.

`complete` is durable before activation. The coordinator clears its startup
transaction and restores reviewed publication/schedules. It records a durable
`ingress-pending.json` bound to the completed journal, clears the ordinary
admission gate while public ingress remains closed, then removes only the
restore-specific nftables table and clears the ingress intent. `activationPending`
remains true until both commits finish. A crash before admission commits leaves
public traffic closed; a later retry finishes firewall cleanup without replaying
tenant-state checks. Boot reinstalls the firewall gate while the ingress intent
remains. Backups refuse unfinished ingress activation. The volatile schedule
token cannot authorize ordinary mutation while the admission gate remains.
Bootstrap installs the gate-preserving ordinary firewall configuration before
enabling its boot guard, so a partially bootstrapped reboot cannot flush the
restore table. Other firewall tables and SSH/outbound access stay in place.

The coordinator retains 30 minutes, 512 MiB, no swap, 32 tasks and one CPU.
The archive helper retains five minutes, 128 MiB, no swap, 16 tasks, one CPU and
120 CPU seconds. It receives the actual coordinator/artifact leases over a
root-only socket and only fixed state aliases/public recovery policy. It cannot
read the backup password, Caddy token or tenant content. The coordinator cannot
read the archive credential. Required exact versions are downloaded and parsed
under the archive boundary; unknown versions, delete markers, multipart work,
ambiguous audit history or changed inventories keep the whole host closed.

For a failure, retain the original source, full snapshot, candidate/prior roots,
restore history and Caddy storage. Inspect bounded diagnostics privately:

```console
sudo /usr/local/sbin/restore-static-host --status
sudo systemctl show lowerduckpond-host-restore.service --property=Result,ExecMainStatus,MemoryPeak
sudo journalctl --unit lowerduckpond-host-restore.service --no-pager --lines=30
sudo journalctl --unit lowerduckpond-host-restore-archive-private.service --unit lowerduckpond-host-restore-archive-installed.service --no-pager --lines=30
sudo nft list table inet lowerduckpond_restore
```

Fixed labels distinguish required archive absence, ambiguity/later timelines,
changed trust and TLS failures when those categories are established. Provider
failures retain the existing allowlisted archive diagnostics. Raw records,
coordinates and tenant data stay private; the journal and its immutable local
receipts identify the affected transaction. For unavailable exact versions,
choose a newer coherent backup on a fresh reviewed destination, independently
recover identical version evidence, or obtain a separately reviewed data-loss
recovery decision. There is no automatic tenant drop or replacement upload.
A source-selected emergency deletion with no existing authorized failure outcome
also stays closed; recovery does not invent an emergency result.

### P5 evidence and compatibility

| Invariant | Component checks | Installed group |
| --- | --- | --- |
| Original descriptor, repository/namespace/launch/artifact and authorization joins | `test_host_restore_snapshot`, `test_host_restore_validation`, `test_host_restore_verification` | `restore-reconstruction`, `restore-negative` |
| Source fence, cold bootstrap, durable gate, root/lock identity and phase resume | `test_host_restore_fence`, `test_host_restore_bootstrap`, `test_host_restore_journal`, `test_host_restore_install`, `test_host_restore_locks`, `test_host_restore_activation` | All three restore groups |
| Independent audit discovery, exact captured prefix, existing intent finalizers and immutable results | `test_host_restore_audit*`, operation-specific `test_host_restore_*`, `test_host_restore_local`, `test_host_restore_pending`, `test_host_restore_exports` | `restore-reconstruction` |
| Exact archive download/parse/full inventory and credential separation | `test_host_restore_archives`, `test_host_restore_archive_authority`, `test_host_restore_remote`, `test_host_restore_ipc`, `test_host_restore_units` | `restore-negative`, native reconstruction helper |
| Independent trusted generation, ordinary result replay and new bounded startup | `test_host_restore_mapping`, `test_host_restore_history`, `test_host_restore_runtime`, `test_caddy_startup` | `restore-reconstruction` |
| Empty certificate storage, real presented TLS, interrupted readiness and reboot | `test_host_restore_tls`, `test_host_restore_cold_storage`, `test_host_restore_coordinator` | `restore-tls-bootstrap` |

Run the three fixed cases with `just check-installed-group restore-reconstruction`,
`restore-negative` and `restore-tls-bootstrap`. Each owns a fenced source, second
fresh Ubuntu/ext4/systemd destination, MinIO service and controlled ACME/DNS
service. The pinned [Pebble](https://github.com/letsencrypt/pebble/releases/tag/v2.10.1)
fixture performs actual DNS-01 validation; validation bypass flags are not used.
Its private issuer/trust and endpoint routing exist only in those containers.
The negative case deliberately leaves recovery blocked and proves unchanged
installed roots, quiescent services, source fencing and independently empty
owned storage before whole-fixture retirement. It never reports a completed
restore. An unexpected failure retains all run-owned resources.

These local reports are diagnostic and do not qualify live Spaces/public-CA
behavior. P6 supplies the complete live combined drill, versioned report envelope,
production preflight/handoff and measured budget evidence. No local fixture or
component pass substitutes for that step. Restored provenance remains part of
future coherent backups. Keep the compatible reader and original artifact;
after reconstruction, older binaries lacking the runtime/history mapping cannot
safely replay restored results. Do not roll back by deleting provenance or
repointing `current` to such a binary.

## Combined live qualification

Run final qualification after the complete P6 implementation and production
handoff inputs have merged, on a clean supported x86-64 Linux secure workstation
with its local Unix-socket Docker daemon. Use the existing private environment
file/disposable shell and M3.10 provider inputs, including the independent Spaces
operator, separate archive and backup runtime keys from encrypted state, Caddy
DNS token, both Cloudflare zone IDs, and the temporary token-policy audit token.
The controller and Docker daemon must share the host network namespace used for
published SSH ports. A forwarded Unix socket from a different container host is
not that supported controller topology.

At the start of each fresh M3.11 attempt, the wrapper checks that the temporary
Account API Tokens Read and Page Rules tokens each have at least **12 hours
remaining from now**: the shared 600-minute run ceiling plus a two-hour cleanup
and reporting margin. It does this after dependency sync and before building
the storage fixture, allocating hosts, or writing qualification data to providers.
A short-lived token is named in the error with an instruction to roll it.
The existing eight-day audit-token and 91-day Page Rules maximum remaining
lifetimes still apply. Old issue/start dates retained by rolled tokens are valid;
these checks do not measure the original issue-to-expiry interval.

To check the same starting condition separately in the private environment shell:

```bash
uv run --frozen python -m scripts.m3_11_token_preflight
```

The qualification command always repeats this read-only check at startup, so an
earlier preflight cannot authorize starting with less time remaining. Later
provider checks still require active, unexpired tokens and the exact runtime
policy, without restarting the 12-hour minimum. The reserve cannot prevent
external revocation. Caddy's runtime token remains non-expiring.

```bash
just m3-11-spaces-qualification
```

This supervises the existing Spaces wrapper with `--milestone 3.11`, under a
600-minute full-run deadline, including wrapper setup. The
[live deadline amendment](../plans/milestone-3.11.md#live-qualification-deadline-amendment)
records the provisional budget and required follow-up measurement. The supervisor
signals the controller process group before collecting diagnostics separately for
at most five minutes. Shutdown allows 30 seconds after TERM and 30 after SIGKILL;
failure to reap the child is reported without replacing the result. A deadline exit remains
124 even if collection fails. `qualification-exit.json` records the actual
supervised duration and last entered phase; later observation cannot extend it.
See [qualification diagnostics](qualification-diagnostics.md) for report limits.
The wrapper's default invocation remains M3.10. The M3.11
mode allocates unique source, archive, destination and controlled-CA resources
and uses a fresh password and run-owned `m3-11-qualification/<run UUID>/restic`
prefix in the backup Space. It retains the existing provider acceptance,
complete lifecycle, idempotence, reboot, installed accounting, final independent
provider proof and outer destroy sequence. It never runs qualification retention
against the production Restic repository or changes the production host.

Immediately after creation, the controller captures the original clean public
trust bundle, hosts file and resolver before any controlled fixture inputs are
installed. It binds the original source revision, artifact, accepted storage run
and report bytes, target, distinct destination reservation, pinned Caddy binary
and four private disposable subjects before combined assertions begin.

The same installed journey then exercises backup/mutation overlap, two protected
audit rotations and interrupted retention, interrupted reconstruction, reboot
and ordinary replay. The public dependency phase uses the actual destination and
pinned Caddy binary with an empty isolated certificate/account store, production
Let's Encrypt DNS-01, the original public roots and independent observations of
both zones. It cancels real challenge activity through the disposable issuer's
private Unix socket, then independently observes Caddy finishing DNS cleanup
before stopping the process. No TCP admin listener or controller DNS deletion
is enabled. It preserves the acquired account, reboots behind the real ingress
gate and resumes the original immutable configuration under the original
coordinator deadline. Fresh TLS verification must precede opening ingress.
The DNS witness allows 368 observations: the full 30-minute deadline at the
shared five-second polling interval, an immediate sample for each of the three
polling loops, baseline and both cleanup checks, and both teardown checks.
The coordinator still enforces the original deadline; exhausting it fails with
ingress closed.

Final paired accounting preserves the fenced source's excluded pending input,
verifies the destination's protected history and independently proves archive
absence. Only complete pytest setup/call/teardown permits retirement: remove the
destination and controlled CA, delete exact owned backup versions and uploads,
remove the original ownership version last, stop/remove the source and unused
empty local archive fixture, and remove only the run's image tag. Independent
backup, archive and DNS absence must hold before the combined receipt is written.

Backup removal paginates the complete owned prefix, including historical Restic
lock versions and delete markers. Its inventory is bounded at 100,000 combined
current-object, version/delete-marker and multipart-upload entries; its private
deletion intent has a separate 32-MiB bound. Other private evidence retains its
256-KiB bound. Exceeding either removal bound stops before any backup deletion.

Share only `qualification.json` and `qualification.sha256` from the printed
private run directory. The [evidence contract](m3-11-qualification-evidence.md)
defines their original bindings and chronology. Private names, captured system
inputs, provider coordinates, phase details, teardown journals and logs remain
in that directory. Local tests and the complete MinIO journey remain diagnostic;
they do not establish live Spaces or public-CA qualification.

### Discarding abandoned qualification backups

After debugging every failed run, complete the mandatory
[local and DigitalOcean closeout](m3-11-debugging.md#required-closeout-after-debugging)
before starting its replacement. That command includes backup disposal and local
fixture removal. The standalone command below also handles selected remote
prefixes after their local run directories have already been discarded.

Once an abandoned attempt's diagnostics are no longer needed, permanently remove
its disposable backup repository with `scripts/m3-11-backup-discard`. Stop that
run's source and destination writers first. This is administrative disposal; it
does not complete a failed qualification or produce acceptance evidence.

In the private environment shell, use `SPACES_ACCESS_KEY_ID` and
`SPACES_SECRET_ACCESS_KEY` for the Spaces operator. `--region` defaults to
`SPACES_REGION`; `--bucket` defaults to `SPACES_BACKUP_BUCKET` if already loaded.
Otherwise supply the backup Space's name explicitly. This command needs no
OpenTofu state credentials or surviving local run directory.

Pass one or more run UUIDs or exact `m3-11-qualification/<UUID>/` prefixes. The
following uses example coordinates; substitute the abandoned run IDs and backup
Space name. Without `--discard`, it only previews the selected inventories:

```bash
scripts/m3-11-backup-discard --bucket example-backup-space \
    0198d17f-6f4a-7000-8000-000000000001 \
    m3-11-qualification/0198d17f-6f4a-7000-8000-000000000002/
```

Add `--discard` to the same command to delete permanently. It removes every
stored object version and delete marker, aborts unfinished multipart uploads,
removes ownership markers last, and verifies all three inventory views are
empty. All selected prefixes are inventoried before deletion begins.
The 100,000-entry bound applies to the combined current objects, versions/delete
markers and unfinished uploads for each prefix, before deletion begins.
Broad prefixes, production repository paths, URLs, and subdirectories are rejected.
An inventory change stops deletion; it does not repeatedly purge a live writer.
If interrupted, completed deletions remain permanent. Rerun the same selected
targets to finish, including when ownership markers are already gone.

### Interrupted combined teardown

A failed qualification retains its original attempt and cannot be rerun into a
pass. If `owned-teardown/intent.json` exists, the fixed installed test already
completed and deletion was authorized. In the same private environment, this
commands, from the repository root, reload the runtime keys from encrypted state
inside a disposable subshell and finish that exact cleanup after a lost response:

```bash
m3_11_run_directory=/absolute/original/private/run
(
    set -euo pipefail
    repository_root=$(pwd -P)
    unset DOCKER_CONTEXT
    export DOCKER_HOST
    DOCKER_HOST=$(jq --exit-status --raw-output '.environment.DOCKER_HOST' \
        "${m3_11_run_directory}/fixture.json")
    source "${repository_root}/scripts/lib/m3-10-production-state"
    uv run --frozen python -m scripts.m3_11_owned_teardown "${m3_11_run_directory}"
)
```

The cleanup takes the original run lock and verifies its original inputs and
step authorizations. It rejects replaced/restarted containers, changed ownership,
new backup objects and changed DNS coordinates. Already deleted ownership does
not authorize new writes or a new attempt. Cleanup appends a fresh DNS absence
observation and returns the private removal receipt; it never creates
`combined.json` or packages a qualification report. Without the prior teardown
intent, retain the fixture and use the existing bounded failure diagnostics to
resolve its outstanding authority before any removal.

### Failed-fixture archive retirement

If legacy restored-state validation cannot complete, workstation updates do not
repair the original fixture or create successful teardown authority. The
[accepted exception](../plans/m3-11-failed-fixture-retirement.md) supplies a
separate transaction for a failed disposable combined reconstruction before any
public-CA phase. It retires only exactly owned archive versions. The original
attempt stays failed and cannot resume with the retired version IDs.

Use clean, merged `main` on the secure workstation in the existing private
production environment shell. Keep the original run directory, selected artifact
and local Docker daemon. The wrapper reads current production state outputs to
verify the bound storage target; it does not converge or connect to production.
It requires distinct operator, archive and backup storage credentials plus the
Cloudflare token for read-only absence checks in both original zones. No bucket,
key, prefix or container override is accepted.

Before preparation, exclude production archive writers, manual provider writes
and live attempts on every workstation for the duration of preparation and
retirement. `--exclusive-archive-writers` acknowledges that prerequisite.
The tool and both live qualification entry points also share a nonblocking
workstation lease, keyed by region/archive bucket, under
`~/.local/share/lowerduckpond.net/storage-leases/`. This local lease cannot exclude
another workstation or provider client. Each invocation also holds the original
run lease; do not delete lock files to bypass an active controller.

Preparation requires `debugfs` from `e2fsprogs`, a private local filesystem with
durable no-replace rename/fsync, and at least 16 GiB plus the selected archive
sizes and 256 MiB reserve free. The fixed source/destination images are each
8 GiB; copies preserve sparse holes but capacity admission charges their full
logical size. Before stopping, each backing file must have one link and be
root-owned beneath verified root-owned, non-writable directory ancestry with
a root-only ancestor. This preserves the legacy destination file's original
`0666` mode inside `/root/restore-disks` (`0700`); the controller copy is always
`0600`. No original file or permission is repaired. Archive limits remain 25 versions, 120 MiB each, 3,000 MiB total.
Bounded provider reads and offline filesystem reads reject incomplete evidence.
The command has a 90-minute per-invocation safeguard.

Set the original absolute path, then prepare only when stopping the failed
fixture is intended:

```bash
failed_run=/absolute/path/to/original/private/spaces-run
just m3-11-failed-retirement prepare "$failed_run" --exclusive-archive-writers
```

Preparation validates original bindings, gated failed restore, canonical archive
ownership and matching independent provider inventories before any stop. It
writes a new intent, stops only the saved source, destination and controlled-ACME
IDs, privately copies their clean ext4 state images without mounting or repair,
and copies and verifies every exact archive version. It deletes no remote
bytes. A failed preparation leaves any stopped resources stopped; rerunning the
same command resumes its intent and rejects replacements or restarts.

The pre-public-CA attempt has no historical provider DNS baseline. The tool
records fresh absence observations for its original disposable subjects and
challenge names, without creating `public-dns/0000.json` or changing DNS. The
unused local MinIO service has no saved historical ID: fresh inspection must
prove its original local-server recipe/configuration excludes Spaces writes.
Its observed ID/configuration must remain unchanged, and it is left untouched.
Any public-CA progress, nonempty name or ambiguous exclusion rejects this path.

Review the shareable preparation output, especially `plan_sha256`, archive count
and preserved byte count. Raw keys, version IDs, state images and archive copies
remain private under `failed-archive-retirement/`. Software review or a merged
PR does not approve deletion. Obtain explicit operator approval of that concrete
plan and the loss of its original remote archive version IDs before running:

```bash
approved_plan_sha256=THE_EXACT_APPROVED_64_CHARACTER_DIGEST
just m3-11-failed-retirement retire "$failed_run" \
  --exclusive-archive-writers \
  --plan-sha256 "$approved_plan_sha256" \
  --acknowledge-failed-run-data-loss
```

Every delete uses its recorded key and version ID, after renewed writer, owner,
DNS, private-copy and two-principal inventory checks. Durable authorization and
pending deletion precede the provider call. If interrupted, use the same command
and digest: only an already authorized pending version can be reconciled from a
lost response. Foreign objects, changed bytes or restarted hosts stop progress.
There is no purge, replacement-version upload or automatic restart path.

Read progress without provider access, fixture mutation or credentials:

```bash
just m3-11-failed-retirement inspect "$failed_run"
```

The final shareable receipt has format
`lowerduckpond-m3-11-failed-fixture-archive-retirement-v1` and outcome
`archives-retired-fixture-retained`. It proves exact archive retirement and final
absence, with `qualification_authority: none`. It retains the three stopped
containers, untouched MinIO service, original failure/state, private copies and
entire backup prefix, including protected snapshots. It grants no later disposal
or restart authority. Preserve these resources and the original failure bytes.

Only after retirement succeeds may a **new** qualification on final merged inputs
attempt its unchanged empty-archive starting gate. The fresh run must complete
all lifecycle, reconstruction, public-CA, accounting and successful teardown
checks. Neither the retirement receipt nor a local MinIO test qualifies production.

## Production predecessor preflight

On the secure workstation, from clean, current `main` in the existing private
production environment shell, run:

```bash
just preflight-m3-11-production
```

This first-upgrade gate observes the accepted M3.10 deployment. It verifies the
original completion record and selected artifact, reproducible candidate build,
operator identity, closed publication, empty authoritative tenant history,
current Caddy generation, archive accounting, fresh provider/edge policy and
active firewall. It reads the actual encrypted Restic repository configuration
using the installed credentials, without a cache or repository lock, and binds
the full repository ID, production node and state-derived repository locator.
The backup Space must remain private and versioned with exactly its reviewed
`backups/` rule: abort incomplete uploads after seven days and expire superseded
versions after 30 days. Current repository objects have no age expiration;
protected Restic snapshots retain those objects indefinitely. Each state,
release, backup-workspace and artifact filesystem must retain
at least 5 GiB and 100,000 available inodes, and 10% available blocks and inodes.

The command does not stop services, change credentials, initialize a repository,
create migration authority, or write production files. It retains private
observations and failed-step output in the workstation directory named in its
result. That directory can contain production configuration details; the printed
pass/fail summary is the handoff result. Completion, configuration and repository
identity are checked again after the provider reads to detect concurrent drift.

Any existing M3.11 transaction, including a partial one, is refused by this
initial-predecessor gate. It must be handled using its original rollout authority,
never erased or treated as a new M3.10 deployment. A passed preflight does not
replace final combined qualification or authorize production convergence.

## Explicit production convergence and resume

After P6c merges and the final live qualification passes, run the following only
as the separately authorized production step. Use clean, current `main`, the
existing secure-workstation production environment and the original successful
qualification report. The normal `configure-production` wrapper verifies the
known SSH host key and reloads the separate runtime keys from encrypted state.

```bash
export M3_11_QUALIFICATION_REPORT=/absolute/original/private/run/qualification.json
export M3_11_PRODUCTION_STATE_DIRECTORY=/absolute/private/production-convergence
just configure-production
```

The state directory's parent must exist. The controller creates a mode-0700
directory owned by the invoking workstation account; an existing directory must
have that ownership and mode. If the state variable is omitted, the directory
defaults to `production-convergence` beside the report. Use that same directory
and report for every resume. The command refuses a combined M3.11/legacy-rollback
request. An existing M3.11 host journal also prevents the legacy path from
clearing completion or deploying another artifact.

The controller verifies the exact accepted report bytes, artifact, input digest,
storage target, revocations and source ancestry. It retains the qualified source
even when invoked from a later records-only commit. Before first mutation it
repeats the predecessor preflight and exercises current runtime credentials.
Each resume repeats the credential and provider/edge/firewall/storage-policy
checks, with archive accounting derived from the actual phase-bound empty host.
An unfinished convergence may have interrupted Caddy service; final acceptance
must restore service before completion can be recorded. Unfinished rollout
still requires the original evidence to be within its seven-day consumption
window. A retry never refreshes that window.

The workstation retains `qualification.json`, `artifact.tar`, `journal/`,
`proposals/` and a new private `attempts/attempt-*` directory for each invocation.
Every proposal becomes a complete, synced immutable file before publication to
either journal. Root stores the identical hash-linked record chain under
`/var/lib/lowerduckpond/convergence/m3-11`. The original M3.10 completion bytes
remain untouched. One local lock and one live SSH controller lease exclude
competing attempts. Closing the controller connection revokes its action and
drains its descendants before a successor can proceed.

| Phase | Action and interruption behavior |
| --- | --- |
| Original | Bind the original qualification, predecessor, repository, transaction UUID and namespace time. A lost reply resumes those exact bytes. |
| Drain | Install persistent service conditions, stop predecessor writers and verify empty installed authority. Reboot cannot admit static workers before lineage or backup/protection timers before the backup proof. |
| Namespace and lineage | Install the qualified artifact, publish the original namespace, and initialize/read back the unique repository-backed lineage and empty protected head. Partial publication resumes its original proposal. |
| Coherent convergence | Apply the actual site playbook twice with recovery enabled and rotation disabled. The second bound Ansible recap must report zero changes and no failed, unreachable, rescued or ignored work. |
| Backup verified | Retain the original compressed SQL dump and coherent capture, independently restore and verify it privately under the installed backup resource limits, and bind the full snapshot and proof to the original report. An interrupted upload can only retry the same capture; an acknowledged result is never replaced. |
| Rotation enabled | Apply the actual site playbook twice with rotation enabled after backup verification. The second pass must again be idempotent. |
| Accepted | Run the real host acceptance playbook and independently inspect repository protection, original empty authority and enabled active backup schedules. Publication remains false. |

Each phase has a synced `started` record before its action and a completed
receipt only after verification. If interrupted, repeat the same command above.
The controller reconciles only its last unacknowledged proposal; it does not
replay completed phases into a missing or truncated host journal. Unknown,
changed or missing authority stops the attempt and retains its diagnostics.
Changed inputs during an action prevent publication of a completion receipt.

After acceptance, the same command performs fresh inspection and current
provider/credential checks. It does not rebuild the artifact, run playbooks,
recapture the original backup, initialize metadata or rewrite original receipt
timestamps. The completed proof may be older than seven days; current inputs
must still be equivalent and unrevoked. Ordinary retention may have aged out
the original scheduled snapshot, while the permanent genesis and protected
inventory must remain available and verify. M3.12 publication remains a separate
milestone and is not enabled by this command.

### Production failure diagnostics and containment

The command prints the private attempt directory on failure. Inspect the failed
step's bounded observation and its private stdout/stderr there. The root action
retains the same resource limits as the installed backup operation; a timeout
is a failed attempt, not permission to raise its production limit. For bounded
host diagnostics, use the already verified production SSH connection:

```console
sudo systemctl show lowerduckpond-m3-11-action.service --property=Result,ExecMainStatus,MemoryPeak
sudo journalctl --unit lowerduckpond-m3-11-action.service --no-pager --lines=30
sudo systemctl show lowerduckpond-backup.timer lowerduckpond-backup-maintenance.timer lowerduckpond-audit-verify.timer lowerduckpond-audit-rotate.timer --property=LoadState,ActiveState,UnitFileState
```

Keep workstation attempts, original proposals, both host completion records,
retained SQL/capture/restore proof and repository evidence for diagnosis. Share
the fixed failure label and phase first; these private directories may contain
production configuration details and must not be committed as closeout records.
Do not delete a journal, service condition, namespace or lineage to restart the
migration. Expired unfinished qualification or changed input identity needs a
reviewed recovery decision using the retained original transaction.

If rotation or maintenance must be stopped for investigation, first end the
rollout controller and allow its action to drain. Then the explicit containment
step on the host is:

```console
sudo systemctl mask --now lowerduckpond-audit-rotate.timer lowerduckpond-audit-rotate.service lowerduckpond-backup-maintenance.timer lowerduckpond-backup-maintenance.service
```

This retains the compatible reader, original journals and protected history.
Completed-rollout inspection refuses the masked schedules. Re-enable them only
through the reviewed repair; containment is not a successful completion or an
artifact downgrade. Before any removal, an older implementation is usable only
after separately proving layout compatibility or restoring pre-migration state
on a fenced target. After archival/index use or local removal, retain the new
readers and deliver a forward repair or the qualified gated restoration. Never
repoint the artifact selector or erase protected metadata to make rollback pass.

## Investigate downstream failures before rerunning qualification

Use the [retained-run debugging workflow](m3-11-debugging.md) on the secure
workstation to explore the remaining reconstruction, public-CA and accounting
stages on a diagnostic branch. It retains the failed run and original backup
evidence while allowing targeted destination repairs and repeated stages.
Diagnostic completion cannot satisfy production handoff or qualification.
