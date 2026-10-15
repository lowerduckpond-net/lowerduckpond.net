# M3.11 backup and recovery operations

M3.11 implementation is in progress. The accepted [plan](../plans/milestone-3.11.md)
defines the complete qualification and production handoff. These P2–P6 commands
are preparation and verification tooling; production convergence remains an
explicit later operator step after the final M3.11 qualification. M3.12 is
unstarted and production publication stays disabled.

## Unattended qualification on the dedicated Docker host

The dedicated Coder/Docker host is a trusted credential-processing host. Docker
access and sibling containers are not a security boundary. The controller runs
the existing complete M3.11 runner, production/storage checks, Molecule phases,
combined recovery and report packager. Preparation consumes the original
600-minute ceiling; the runner still requires at least 12 hours of credential
validity at startup. Restart reconciles the original attempt and cannot replay
issuance or turn a diagnostic continuation into a passing qualification.

The [credential lifecycle plan](../plans/m3-11-credential-lifecycle-simplification.md)
defines the approved local replacement. Its runtime cutoff, credential lifetime,
cleanup reserve, native upstream expiries, configuration delivery, cutover and live
runs require separate explicit authorization. The seven-day examples used in local
tests grant no live authority. Missing policy inputs fail closed.

### Authority, policy and private setup

Use the existing dedicated provisioning, cleanup, production-input and journal
vaults through isolated native Connect readers. The shared server has separate
provisioning, cleanup and production clients. The existing independent cleanup
server has its own cleanup client and native server credentials; GitHub starts
that server without the issuance host's endpoint or volumes. The replacement uses
no service-account fallback, quota admission, per-event witness, encrypted
checkpoint registry or new datastore. Until approved cutover, the workflow
preserves the installed legacy cleaner and its pinned helper as described below.

The versioned `lowerduckpond-m3-11-lease-config-v1` bundle binds exact targets,
helper revision, approved policy digest, legacy import digest and authority
generations. Each generation records provider principal IDs, token fingerprints,
provider/client expiries and a calendar-month rotation date. The policy explicitly
records start and issuance cutoffs, child lifetime, cleanup reserve, failed-attempt
retention and approval reference. Cleanup authority must cover the full lease
plus reserve. Provider expiry and a Spaces deletion deadline are different:
Spaces removal depends on cleanup execution and provider availability.

```console
mise exec -- just m3-11-unattended setup-template > /private/setup.json
mise exec -- just m3-11-unattended setup \
  --manifest /private/setup.json --output /private/controller.json
```

Fill the template only from reviewed provider/operator metadata. Use immutable
`op://VAULT_ID/ITEM_ID/FIELD_ID` references and private mode-0600 files in owned
mode-0700 directories. Setup performs capability checks, creates no milestone
children and supplies no expiry default. DigitalOcean principal metadata must be
attested from the operator's approved provider context and bound to the exact token
hash and generation. An authenticated empty Spaces inventory is never team proof;
this procedure adds no `account:read` permission.

```console
mise exec -- just m3-11-unattended attest-digitalocean \
  --token-reference op://VAULT/ITEM/FIELD \
  --generation /private/generation.json --reader-config /private/provision-reader.json \
  --observed-principal APPROVED_TEAM_ID --attested-by OPERATOR \
  --principal-context APPROVED_PROVIDER_CONTEXT --attest-provider-console \
  --output /private/digitalocean-metadata.json
```

The same bound metadata procedure applies to cleanup's separate token. Import the
result into its dedicated metadata item through the operator's normal private
workflow. The production reader remains isolated: only the short production-check
process can read encrypted state and verify the existing non-expiring, exact-policy
production Caddy credential and production storage capabilities. Fixture credentials
cannot replace production proof or enter production state.

The production check validates the fresh fixture receipt against the controller's
approved policy digest before reading production inputs. Its audit child must match
the receipt's exact native identity and original expiry, including when an approved
lease is reused by a later attempt. This permits explicitly approved milestone
lifetimes beyond eight days; ordinary audit-token callers retain their eight-day
limit and production Caddy still requires its exact non-expiring policy.

Stage the independent bundle using its verified native reader document. Its URL
placeholder is `https://independent.invalid`; the action substitutes only the
endpoint of its own freshly started server.

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_setup \
  --configuration /private/controller.json \
  --independent-reader /private/independent-reader.json \
  --server-credentials /private/independent-server.json --output /private/staged
```

Staging retains separate `controller-connect.json` and `github-connect.json`
files. Only the second contains the independent native server credentials; it has
no provisioning or production reader. Retrying identical staging preserves bytes;
changed inputs require a new private staging directory.

### Initial operator assembly from receipts

For the initial migration, use the [operator input example](m3-11-operator-inputs.example.json)
and the local `operator_records`, `operator_assemble` and `operator_publish` entrypoints.
Keep all inputs, proposals, consent records, staging and pending state outside the
checkout in private directories. Placeholders are deliberately invalid; the tools
never supply human decisions, identities or times. Normal-account `op` reads must
use the explicitly selected account with service-account/Connect environment
variables removed.

Operator v2 still means an exact, independently recorded token fingerprint and
exact console observation/creation times, with its historical helper pin. V3 means
an operator-confirmed replacement at the exact Password reference, supported by
original receipt identifiers and truthful creation/confirmation upper bounds.
Only include optional exact times or a historical fingerprint when actually
recorded. Assembly reads that Password once, computes its current fingerprint,
and binds a new attestation to the original receipt basis, generation and assembly
time. This does not turn a receipt timestamp into a console observation.

Choose one reviewed full `runtime_revision`. It must be the clean, non-shallow
checkout HEAD and the prepared source/helper, independent bundle and live approval
revision. Prepare this helper before collecting host evidence. Preparation itself
uses the existing authorized Docker-host route. Preparation changes Docker
resources; run it only in the separately authorized execution phase. Historical
discovery then precedes issuer fencing:

```console
mise exec -- just m3-11-unattended prepare FULL_COMMIT_SHA --output /private/prepared.json
uv run --frozen python -m scripts.m3_11_unattended.connect_delivery \
  --operation discover-import --prepared /private/prepared.json \
  --daemon-socket /docker-sock/docker.sock --historical-reader /private/historical-reader.json \
  --journal-vault JOURNAL_VAULT_ID --declarations /private/legacy-declarations.json \
  --transport coder --coder-workspace OWNER/WORKSPACE --daemon-id APPROVED_DAEMON_UUID \
  --workspace-id APPROVED_WORKSPACE_UUID --output /private/legacy-discovery.json
uv run --frozen python -m scripts.m3_11_unattended.operator_records policy-proposal \
  --inputs /private/operator-draft.json --output /private/policy-proposal.json
```

V2 declarations use `format: lowerduckpond-m3-11-migration-declarations-v2`,
`retained_files`, `obligations`, `expiry_updates` and `actors`. Each actor has
`container_id`, `kind`, `run_id` and `directory`. Controller originals bind their
request/attempt and complete local and external issuance evidence. Empty failed
attempts need their actual failed journey result and no issuance evidence. A
`manual-page-rules` actor binds its actual worker/run/intent/creation records and
two-field retained key, without inventing a controller request. Every issuer must
appear, including the manual actor. Known retained local diagnostics use
`retained-diagnostic` with null run/directory and their reviewed program bindings;
they claim no journal run or successful outcome. Unknown programs fail discovery.

An obligation predating generation IDs uses `generation_id: null`, its original
`cleanup_authority_sha256`, and `original_status`. This representation is **terminal
evidence only**: neither a missing denial nor an outstanding restoration can use
replacement authority. Reconcile such obligations with retained old access during
the authorized cleanup phase, before the old authority deadline. Preserve every
local pending marker; an older denial covering a different marker is insufficient.
Expiry updates can likewise use null generation with exact original
`result_contents` and `result_files`. Embedded nonsecret result bytes can travel
across hosts; they do not assert that the original workspace path exists inside
the helper. Existing changed files or unsafe links still fail verification.

### Transitional readers and genuine recovery

Manual closure is **not an import prerequisite**. `legacy_terminal.validate_claims`
explicitly permits `original_status: unresolved`; `manual_original` permits that
state while the exact retained credential exists. It requires a terminal denial
only when the credential is missing. `publish_import` requires complete original
evidence and verified issuer fences, and recovers the already-existing manual
pending marker through `local_events` / `publish_original`. It does not require
a new terminal fact. `activate` subsequently requires `sweep_legacy` to be ready;
admission/retirement also require their original terminal proofs. Thus recovery
can follow import. There is no separate pre-import terminal publisher.

The installed host watchdog and GitHub Connect cleaner use helper
`0b5b198bf06443e61f01b1f7259fea827f79fc23`. Its reader rejects the migration item
before examining legacy obligations. Merely hiding the import from its listing
also fails: the native vault count still includes that item. The opt-in
`legacy_import_reader.py` bridge runs with the **unchanged legacy interpreter and
checkout**, verifies the exact legacy ledger source hash, and admits only the
approved v2 migration digest in the approved journal vault. Physical inventory,
native count, duplicate item IDs, item metadata and both snapshot boundaries
include the import. Only original events enter the old logical checkpoint,
anchor, event cache, native authorship and acknowledgement paths. Other unknown
formats remain rejected. The import body is reread on each inventory; a persistent
spool pins its native identity once observed. A cold GitHub spool does not prove
continuity with an earlier spool; retain its separate reader observation artifact.

Before either legacy entry point is imported, the bridge also checks the pinned
authentication source hash and backports exactly two `inspect` predicates: a
native audience string can match the identical signed string or its exact
singleton list, and native expiry can equal signed expiry or be exactly one
second later. Extra/duplicate audiences and all other offsets fail. Signed expiry
remains the runtime deadline. The legacy 48/496 permission contract, seven-day
lifetime limit, exact declared signed expiry, identities, vault scope and live
isolation checks remain unchanged. The newer 31-day clients are not substitutes
for these original legacy clients. The GitHub bootstrap must retain its original
checkpoint encryption token and active selection. The standalone launch removes
the bridge's adjacent-module directory from the import path so `http.py` cannot
shadow the standard library before loading the pinned helper.

Synthetic regressions execute the actual host CLI and Node action against the
clean pinned checkout, including configuration parsing, authentication, dispatch,
encrypted checkpoint recovery and the compatible ledger. Only external HTTP,
Docker and artifact transports are controlled; execution ends after observing a
real reader receipt. This proves startup compatibility, not live authentication,
CREATE, cross-server durability or cleanup readiness.

The original publication and reconciliation methods are unchanged. Pending POSTs
keep their identities and reconcile by reads; the bridge never retries a POST.
Reader receipts report `snapshot-verified`, **not cleanup readiness**. Require the
normal cleanup receipt as well. Diagnostic receipt failure must not suppress
original cleanup. This bridge is transitional: keep new lease issuance disabled
until both replacement cleaners are ready and legacy readers are retired.

The verified old cleanup-authority expiry is **October 16, 2026 at 21:38:38 UTC
(4:38:38 p.m. CDT)**. Its 62-hour readiness reserve was exhausted on October 14
at 07:38:38 UTC; unchanged retries and this representation backport cannot restore
it. Preserve fallback cleanup until replacement coverage is verified. Complete
old-authority recovery and the verified successor handoff before the actual
expiry; an unresolved old readiness receipt is not proof of lost fallback cleanup
or permission to retire it. Locally retained scheduled receipts establish old
GitHub authentication and checkpoint continuity; the original host configuration
still needs its separately bound execution observation.

Preparation consists of code review, offline tests, source/inventory bindings and
the final cutover proposal. Merging leaves the deployed readers, clients,
credentials, journal and workflow selection unchanged. Execution still requires
separate authorization, in this dependency order:

| Step | Operator execution and evidence | Retired process / cleanup coverage |
| --- | --- | --- |
| 1 | Refresh read-only discovery of originals and every owned actor. Resolve omissions before fencing. | None; existing host and GitHub cleanup continue. |
| 2 | Fence discovered issuers, including the manual diagnostic; verify restart disabled. Finalize and approve the exact migration, truthfully retaining any unresolved status. | Original issuance retires; both original cleaners and provider access remain. |
| 3 | Deploy the reviewed bridge beside the unchanged host helper, with the existing cleanup configuration/evidence mounts and read-only bridge/helper mounts. Use `legacy_import_reader.watchdog_command(vault, migration_sha256)` exactly, restart policy `unless-stopped` with `MaximumRetryCount: 0`, and name the container `ldp-m311-import-watchdog-` plus the bridge file hash's first 12 characters. Retain a fresh bound reader receipt and a completed ordinary cleanup receipt; distinguish the known manual unresolved result from new failures. | Stop/disable restart of the unbridged watchdog only after compatible coverage is observed. GitHub cleanup remains available during this switch. |
| 4 | Set protected-environment variable `M3_11_LEGACY_IMPORT_BRIDGE` to the closed object `{revision, journal_vault, migration_sha256}` using the reviewed full bridge revision and approved mapping. Run the existing `reconcile` workflow and retain its reader/cleanup receipts. Drain or cancel every queued/in-progress job using the old workflow/reader. | Replaces the GitHub reader only; retains its original helper pin, bootstrap secret, checkpoint token, artifact runtime and independent native identity. Host bridge continues throughout. |
| 5 | Verify every predecessor host watchdog is stopped with restart `no`, not merely currently exited. After publishing the legacy-safe originals, the first-import publisher checks this host gate immediately before retaining/submitting the import; it requires a running exact bridge with restart `unless-stopped` and the mount bindings below, even when no predecessor watchdog remains. An empty or controller-only inventory cannot authorize import. Separately verify the GitHub selection and drained jobs; the Docker gate cannot establish those facts. Publish/reconcile the exact required import through `publish_import`. | All executable legacy readers now accept that import; no original cleanup authority is retired. An uncertain original/import POST retains pending state and gets readback only. |
| 6 | Recover the genuine manual obligation after import with its retained original cleanup connection, original authority fingerprint and exact retained credential. Use the existing `Lifecycle.reconcile(intent, credential)` path with the complete imported journal. Retain fresh provider absence/negative-authentication evidence and any terminal record that real recovery requires. Reuse an existing sufficient terminal proof; do not request a new fact to prove CREATE. | The manual obligation closes only on real evidence. The old automatic watchdog does not discover the separate manual credential directory; it remains available for the other obligations while this explicit recovery uses the retained key. |
| 7 | Complete separately approved provider expiry repair, original-client readiness and configuration binding. Obtain replacement host and independent cleanup receipts, then complete handoff and launch admission. | Retire each bridge/old authority only after its successor and original terminal proofs are verified; never stop both cleanup paths together. |

Before execution, prepare and review the concrete Docker delivery bindings and
GitHub run/variable change from the refreshed inventory; the bridge itself neither
deploys nor changes those resources. After import, rollback must retain compatible
readers. Do not delete the import or start an unbridged predecessor to roll back.

The host bridge must use exactly these five mounts. Missing, extra or duplicate
mounts, different access modes, volume subpaths and mounts that hide any required
path are rejected. The helper revision is the full pinned
`0b5b198bf06443e61f01b1f7259fea827f79fc23`; the bridge digest is the full SHA-256 of
the reviewed `legacy_import_reader.py` file.

| Destination | Type and source | Access |
| --- | --- | --- |
| `/cleanup` | Named volume `ldp-m311-cleanup-config` | Read-only |
| `/evidence` | Named volume `ldp-m311-evidence` | Read/write |
| `/opt/lifecycle` | Named volume `ldp-m311-helper-` plus the full pinned helper revision | Read-only |
| `/opt/import-bridge` | Named volume `ldp-m311-import-bridge-` plus the full bridge file digest | Read-only |
| `/var/run/docker.sock` | Bind from daemon-host `/docker-sock/docker.sock`, propagation `rprivate` | Read/write |

The socket source comes from the retained Coder daemon inventory. It is not the
import utility's container-local socket path. The bridge must have exactly this
environment, taken from the pinned qualification Dockerfile and launcher:

```text
DOCKER_HOST=unix:///var/run/docker.sock
MISE_DATA_DIR=/opt/mise-data
MISE_CONFIG_DIR=/opt/mise-config
MISE_YES=1
MISE_TRUSTED_CONFIG_PATHS=/opt/qualification-tools:/opt/lifecycle:/work/source
PATH=/opt/mise-data/shims:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Duplicate keys and additional environment overrides are rejected, including
`DOCKER_CONTEXT`, which the pinned Docker client selects ahead of `DOCKER_HOST`.
The contract also requires the pinned mise entrypoint, `/opt/lifecycle` working
directory, default root user, observed `runc` runtime, host networking, writable
root filesystem and the launcher's default security/resource settings. Additional tmpfs/volumes-from,
DNS, security or resource overrides are rejected. Kernel path restrictions are
limited to reviewed proc/sys masks from
[Moby's defaults](https://github.com/moby/moby/blob/v28.5.1/oci/defaults.go);
they cannot hide cleanup inputs or make evidence read-only. Environment/startup
expectations come from pinned source. A read-only inspection of the original
watchdog confirmed that its deployed environment, launch settings and kernel masks
match this contract; the earlier retained inventory projection omitted those fields.

The immutable image ID must match the single image bound to the pinned original
controller in the approved v2 migration. The bridge cannot authorize its own image
or use a mutable tag; missing or ambiguous original bindings fail closed. The
v2-only reader bridge gains no image authority from a v1 import. Read-only Git
inspection checks the helper HEAD and clean tracked/untracked source, in addition
to the bridge, ledger and authentication file hashes.

All these bindings are checked again after original publication, before accepting
the bridge for import. A persistent watchdog can stay running while reporting
configuration errors: structural checks do not prove configuration contents,
socket connectivity, provider access or successful cleanup. Retain the fresh
reader and ordinary cleanup receipts required by step 3. Keep fallback cleanup
until replacement coverage is verified.

The existing clients remain unchanged. `reader_access` accepts the exact observed
496 profile only on the journal vault for provision and cleanup roles (including
independent cleanup). Their own secret vault stays exactly READ/48; production
stays READ/48 on its sole vault. Native view/edit labels, signed identity, audience,
expiry, exact vault scope and authenticated forbidden-vault checks remain required.
The signed mask is retained as 496 in `Access` and hashed-vault receipts, never
reported as full WRITE/1008. The general full-WRITE validator still rejects 496.

| Actor | Journal operations in the implementation | Effect of the existing profile |
| --- | --- | --- |
| Provision client | None. `LeaseBootstrap.providers` reads its own bootstrap vault; `Worker._inventory` selects the cleanup reader. | Keep its existing 496 journal grant without a write probe. |
| Production client | None. Production references are read from its own vault. | Keep its sole 48 grant; no journal access is accepted. |
| Shared cleanup client | GET inventory/items and POST Secure Notes via `publish_original`, `publish_import`, `ConnectObligations.append` and `ConnectInventory.publish`. | 496 declares read/reveal and CREATE. UPDATE/archive are present but unused; DELETE is absent and unused. |
| Independent cleanup client | Authentication/isolation GETs first, then journal GETs; POST only for genuine recovery, lease confirmation or closure through the same lifecycle/publication code. | Same declared coverage as shared cleanup. Acceptance of 496 does not verify authentication or CREATE. |

The [pinned vendor SDK bit definitions](https://github.com/1Password/onepassword-sdk-go/blob/5866f43111ffeee5952e43a13da1aafef98200c8/types.go#L1306-L1319)
identify read/reveal as 32/16, CREATE as 128, UPDATE/archive as 64/256 and DELETE as
512. This is the basis for declared operation coverage, not a live request result
or a claim that 496 equals vendor full WRITE. `Connect.request` only permits GET
and item-creation POST; provider credential deletion uses the separate provider
authority. No journal PUT/PATCH/DELETE is required by these actors. Unknown masks,
partial subsets, numeric strings, extra vaults and expanded own-vault access fail.

Every independent execution authenticates the original token against its separate
cache and verifies exact visibility plus forbidden-vault denials **before** opening
the journal or reading provider secrets. Its separate `authentication.json` receipt
starts pending and records success only after all checks pass. The protected workflow
retains that observation; failed authentication stops subsequent work. Policy and
authentication receipts always say `create_verified: false`. Successful publication
is evidenced by the actual fact's exact readback and ordinary lifecycle receipts.

The retained Studio result from October 14 at 11:04 UTC verified shared and
independent cleanup authentication with exact forbidden-vault isolation (seven GETs,
zero POSTs); the owned local cache was removed afterward. Earlier shared diagnostics
also verified eleven secret reads. Every later independent use must authenticate
on its separate cache (Studio's default local Docker context for an approved Studio
execution, or the protected GitHub runner); its master credential stays off the
controller host. No replacement client or prerequisite test write is needed. If
real recovery produces no independent write, independent CREATE remains unverified. That limits
publication claims, not an otherwise verified read-only cleanup receipt. The real
lease's required independent confirmation still gates issuance; failure to publish
that confirmation blocks issuance without fabricating a replacement fact.

The dependency check is: reader bridge → import (unresolved obligations allowed) →
original-authority recovery → activation → replacement-cleaner delivery and handoff
→ real lease manifest/independent confirmation → issuance. Standard assembly accepts
496 and does not require prior CREATE success, import or cleanup readiness. Import
does not require activation; original recovery does not require replacement cleaner
delivery. Thus those checks do not form a cycle. Do not call `connect_delivery.install`
before its activation receipt, or require independent CREATE before the real manifest.
Keep the existing cleaners available until successor receipts and terminal proofs
permit their retirement. Preserve the same durable spool on uncertain writes; use
exact readback, never a new spool or an indiscriminate rerun to bypass pending state.
The Cloudflare finite-expiry repair remains separately pending approval; it is a
provider activation prerequisite, not a journal CREATE test or import-closure claim.

For this cutover, old-authority work and verified successor handoff must finish
before **October 16, 2026 at 21:38:38 UTC (4:38:38 p.m. CDT)**. Review/deployment
delays, the manual negative probe, independent authentication, or waiting for an unnecessary CREATE test can
consume that window. Prioritize genuine original-authority recovery and retain its
access until verified. A missed deadline cannot be repaired by relabeling the
obligation or silently substituting replacement credentials. The closed disposable
compatibility exercise and its unresolved concurrency finding remain closed/carried
forward; neither is a reason to manufacture a journal fact.

### Final migration approval

Discovery uses GETs and read-only Docker inspection/copy; it neither fences nor
produces an approvable import. Two collections must agree on originals, file
hashes, actor identity, commands, mounts and declarations. Cleanup facts may append;
new run/intent/creation records require rediscovery. Resolve discovery failures
before stopping issuance. Keep old cleanup operational.

After separately authorized fencing, create a private object with
`format: lowerduckpond-m3-11-migration-fences-v2`, the exact `discovery` object, and
`fences`: one `{container_id, stopped_at, issuance_disabled: true}` per discovered
actor. Final collection independently observes each stopped, nonrestarting actor,
records conservative observation times and start/finish timestamps, and rechecks
all originals. Any required restoration proof must follow the observed fence.

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_delivery \
  --operation inspect-import --prepared /private/prepared.json \
  --daemon-socket /docker-sock/docker.sock --historical-reader /private/historical-reader.json \
  --journal-vault JOURNAL_VAULT_ID --declarations /private/legacy-fences.json \
  --transport coder --coder-workspace OWNER/WORKSPACE --daemon-id APPROVED_DAEMON_UUID \
  --workspace-id APPROVED_WORKSPACE_UUID --output /private/migration-evidence.json
uv run --frozen python -m scripts.m3_11_unattended.operator_records migration-proposal \
  --evidence-index /private/migration-evidence.json --output /private/migration-proposal.json
```

The earlier `lowerduckpond-m3-11-migration-declarations-v1` remains supported for
collection and reconciliation of existing imports, but lacks the approved source
image needed to authorize a bridge for first publication. Use v2 for new imports.
In v1,
`retained_files` lists canonical original host paths; `obligations` maps each intent
digest to its declared `generation_id` and `original_status`; `expiry_updates`
contains the original approved plans/results; `issuers` gives exact `container_id`,
actual `stopped_at` and explicit `issuance_disabled: true`. The collector reads
original files/events and current issuer state twice, refusing drift. It cannot
stop or fence issuers. Historical reader access is supplied separately before the
new configuration exists; retained secrets stay on the host.

Migration transport and private evidence have a 16 MiB ceiling; utility execution
is bounded at 1,200 seconds. Other delivery commands retain a 90-second limit.
An interrupted import preserves its original pending state and requires readback;
it never authorizes a fresh write retry.

Review both proposals, then record each actual external consent. The expected
proposal digest prevents drift; possession of it is not approval. `approved_at`
and `approval_reference` must come from the decision being recorded.

```console
uv run --frozen python -m scripts.m3_11_unattended.operator_records record-policy \
  --proposal /private/policy-proposal.json --expected-proposal-sha256 POLICY_PROPOSAL_SHA256 \
  --approved-at APPROVED_UTC --approval-reference POLICY_CONSENT_REFERENCE \
  --output /private/policy
uv run --frozen python -m scripts.m3_11_unattended.operator_records record-migration \
  --proposal /private/migration-proposal.json --expected-proposal-sha256 MIGRATION_PROPOSAL_SHA256 \
  --approved-at APPROVED_UTC --approval-reference MIGRATION_CONSENT_REFERENCE \
  --output /private/migration
uv run --frozen python -m scripts.m3_11_unattended.operator_records bind-inputs \
  --draft /private/operator-draft.json --policy /private/policy/policy.json \
  --migration /private/migration/legacy-import.json --runtime-revision FULL_COMMIT_SHA \
  --output /private/bound-inputs.json
uv run --frozen python -m scripts.m3_11_unattended.operator_assemble check \
  --manifest /private/bound-inputs.json
uv run --frozen python -m scripts.m3_11_unattended.operator_assemble assemble \
  --manifest /private/bound-inputs.json --server-credentials /private/independent-server.json \
  --output /private/staged
```

`policy-proposal` extracts the five policy choices from the draft. Before binding,
leave approval-derived `policy`, `approved_policy_sha256`, `migration_sha256` and
`runtime_revision` absent or null, or supply their exact approved values; conflicting
values are rejected. Retain the original policy draft separately when clearing
these bindings. Record writers re-read and hash every indexed input, write immutable
companions first and expose the consumable approval last. Identical complete
records remain readable after expiry; partial or changed outputs cannot be adopted.
Assembly only stages files and performs no publication or activation.

Publication is a separate authorized operation. Each role's metadata reference is
a `digitalocean_metadata` STRING field on its existing Password item. The publisher
requires an exclusive editing interval for those two items: CLI edit has no
conditional version/CAS guarantee. It reads the full item twice, preserves supported
fields/sections/URLs/notes/tags, refuses unknown or conflicting content, writes the
full template through private stdin, then checks exact native and Connect readback.
Its private persistent state must survive interruption. A pending uncertain edit
is never replayed; later exact visibility reconciles it. Keep unresolved state and
stop for operator reconciliation if an external edit conflicts.

```console
uv run --frozen python -m scripts.m3_11_unattended.operator_publish publish-attestations \
  --manifest /private/bound-inputs.json --staged /private/staged \
  --expected-controller-sha256 REVIEWED_CONTROLLER_SHA256 --state /private/publication
uv run --frozen python -m scripts.m3_11_unattended.operator_publish publish-attestations \
  --manifest /private/bound-inputs.json --staged /private/staged \
  --expected-controller-sha256 REVIEWED_CONTROLLER_SHA256 --state /private/publication \
  --apply --expected-proposal-sha256 REVIEWED_PUBLICATION_SHA256
uv run --frozen python -m scripts.m3_11_unattended.connect_delivery \
  --operation import --output /private/staged --prepared /private/prepared.json \
  --daemon-socket /var/run/docker.sock --approved-import /private/migration/legacy-import.json \
  --destination coder@APPROVED_HOST --workspace APPROVED_WORKSPACE \
  --workspace-id APPROVED_WORKSPACE_UUID --apply
uv run --frozen python -m scripts.m3_11_unattended.connect_activate preflight \
  --output /private/staged
```

The host import receives only cleanup configuration and the approved mapping.
The exact prepared helper mounts original evidence read-only and uses a private,
persistent mapping-bound pending directory in the existing cleanup volume. A lost
POST cannot cause a second POST on restart. Activation remains on Studio, followed
by the existing delivery command below; the independent server document is never
sent to the controller host. Initial admission uses a read-only projection from
that same helper to verify terminal legacy originals, retained hashes, issuer
fencing, separate audit restoration and target-bound expiry outcomes. Stale local
`unresolved` status is preserved; it is not rewritten into permission.

The vendored Connect 1.8.1 schema is an authoritative artifact; committed CLI
and HTTP response examples remain explicitly synthetic. An operator-reported
diagnostic on 2026-10-12 paired CLI 2.33.0 native permissions with exact signed
grants: `48` for read-only and `1008` for journal read/write. Connect's documented
write permission includes item deletion (`512` in the vendor SDK); `496` omits
deletion and is rejected by the generic full-WRITE inspection path. The role-aware
journal profile described above accepts `496` without treating it as `1008`. The
[contract provenance](../../tests/infrastructure/fixtures/onepassword/provenance.json)
records vendor sources and observation limits. This numeric JWT mapping is an
observed compatibility dependency, not a published stable vendor schema. The
native publication adapter pins CLI 2.33.0; Connect image digests remain in
`connect_host.py`.

Read-only production discovery on 2026-10-14 observed a native audience string
and a signed singleton audience array containing that exact string. The reader
accepts both exact single-audience representations; additional or duplicate
audiences remain rejected. All four native expiry timestamps were one second
later than the JWT expiry. The reader permits only equal native expiry or this
exact one-second offset. Operator inputs and approvals must use the earlier
signed deadline, which remains the deadline for authentication, generation
coverage and cleanup. No expiry grace period is added.

That discovery also found genuine journal grants of `496` on three existing
clients. The three shared clients authenticated with exact vault isolation, and
all eleven dependent item reads passed. These GET observations do not establish
CREATE or equivalence with `1008`. The role-aware reader contract accepts `496`
only for the declared provision/cleanup journal scopes; generic full-WRITE
inspection still rejects it. During that discovery, the independent client had
matching native identity and claim shapes but was not contacted through an
independent service. This discovery does not reopen the closed compatibility
exercise or authorize production activation.

A direct user-run cycle completed on 2026-10-12 at 21:51:37 UTC with no reported
findings. The allowlisted report confirmed all four clients' exact `48`/`1008`
grants, expected vault visibility, forbidden-vault and read-only-write `403`
responses, and a `401` response after signature tampering. A dummy Password item
retained the selected properties listed in the provenance report through a native
JSON edit; its added field kept the requested ID and value and was visible through
Connect. In the journal vault, Password-item POST/PUT/DELETE returned
`200`/`200`/`204`; the write was visible through native `op` and a fresh independent
cache, which returned `404` after deletion. The probe's items were absent from
active inventory and its owned cache was removed. Original shared-cache state and
private evidence were preserved. No genuine response captures are committed.

A supplemental cycle completed at 22:26:13 UTC using the application's
`SECURE_NOTE`/`notesPlain` field structure with dummy ownership tags and content.
Create/get/list/update returned `200`, canonical note content survived the actual
note reader, versions advanced from 1 to 2, and delete returned `204` followed by
GET `404`. The list entry omitted full fields. A PUT carrying the earlier version
also returned `200` and its value became visible; that operation did not enforce
CAS. Application transport remains limited to GET and POST, and native publication
still requires the exclusive editing interval described above.

The supplemental native edit preserved the actual publisher's complete protected
comparison, but its strict parser rejected `password_details`. A read-only
diagnostic of the retained before/after responses identified exactly an object
containing `strength` as a string; no values were shared. The adapter now permits
that optional shape only on concealed password fields, carries it unchanged in
the full JSON template, and retains it in the protected comparison. Additional
keys or different types remain unsupported. The provenance records the official
template guidance, a vendor employee's example, and the limits of the available
schema documentation. The regression fixture's strength value is synthetic.

The corrected parser can be replayed offline against those retained responses;
no additional live edit is needed for that check. These observations still do not
exercise the full assembly/publication/import/confirmation route. Expiry/revocation
enforcement and interrupted edit/POST recovery, including lost replies and
429/5xx/truncation, remain untested on real services. Neither cycle qualifies the
application or authorizes production cutover. Both probes' owned items were removed
from active inventory; the supplemental cycle created no cache resources.

Continue application compatibility from the retained failed assembly after review
of its exact runtime and proposal bindings. Preserve the original inputs, receipts,
failed captures and staging directory. A corrected runtime needs new derived inputs,
an explicitly reviewed proposal transition and a fresh output path; do not overwrite
old state or replay completed setup. Exercise the actual application route with the
existing disposable identities and preserve pending state during recovery checks.
Do not start qualification or create provider credentials for this exercise.

### Migration, activation and cleanup-only rollback

Merging the implementation does not switch scheduled cleanup. The temporary
workflow bridge preserves `M3_11_CLEANUP_BACKEND`: an empty value or
`service-account` uses `M3_11_CLEANUP_REVISION` and `M3_11_CLEANUP_CONFIG`;
`connect-initializing` retains that cleaner with the configured `active_helper`
and quiet-empty behavior. With `connect`, the existing
`lowerduckpond-m3-11-connect-bootstrap-v1` secret still uses
`M3_11_CONNECT_CONFIGURATION`, its `active_helper`, the pinned legacy JavaScript
action, checkpoint permissions/transport and the `reconcile` operation. Preserve
these settings and old cleanup access while preparing migration. The bridge
offers no legacy discovery, genesis or issuance-witness dispatch.

For `connect`, the separately approved replacement of the single
`M3_11_CONNECT_BOOTSTRAP` secret with a validated
`lowerduckpond-m3-11-independent-lease-bundle-v1` bundle is the explicit switch.
That bundle selects its own helper and cleanup-only configuration; it does not
reuse the old selection document. Scheduled/default `reconcile` maps to
`confirm`, which also runs cleanup; explicit `cleanup` only reconciles. Unknown backends,
unsupported formats, missing pins and incompatible operations fail closed;
the selected pinned helper validates the full private configuration before
accessing providers. A malformed replacement never falls back to legacy cleanup.
Remove this temporary bridge in the separately reviewed cutover/removal change
only after the replacement has verified all retained obligations; it is not a
second supported runtime.

Before cutover, inventory every original journal event and retained local ID,
abort, secret, audit-restoration and expiry-update file. The reviewed
`lowerduckpond-m3-11-legacy-import-v1` mapping pins event/file hashes, every intent's
original status and provider ID, required generation, exact stopped original issuer
IDs, daemon identity and disabled restart/issuance state. Preserve the source
files, private volumes, failed results and pinned historical source.

The operator must separately stop old issuance and disable its restart/start
routes before import. Import only inspects those original containers. It publishes
exact original locally retained creation/abort events before the mapping, preserves
lost-publication uncertainty and never invents an abort or retries CREATE. Every
existing restoration obligation remains active; historical expiry updates are
read-only observations. Old audit grants and expiry-extension routes are disabled.

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_activate import \
  --configuration /private/controller.json --approved-import /private/legacy-import.json \
  --spool /private/import-pending
uv run --frozen python -m scripts.m3_11_unattended.connect_activate preflight \
  --output /private/staged
```

The local import command above is for operators already on the evidence host;
use the SSH import route for Studio. Preflight reconciles legacy obligations and verifies that staged configuration
retains every active lease's required cleanup generation. Its private activation
receipt binds both bundle byte digests. It authorizes no live qualification.
Delivery checks the exact workspace identity, persistent home and main-only GitHub
cleanup environment, then uses private stdin and immutable destination filenames.
After separately authorizing that concrete delivery, use:

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_delivery \
  --output /private/staged --destination root@APPROVED_HOST \
  --workspace APPROVED_WORKSPACE --workspace-id APPROVED_WORKSPACE_UUID --apply
```

Omitting `--apply` checks the destination only. The independent protected environment
receives the single `M3_11_CONNECT_BOOTSTRAP` secret. Enable the replacement cleanup
path and demonstrate independent access before enabling new issuance; retain old
cleanup until that handoff is verified. Do not operate two active issuance paths.

For a Coder-only destination, replace `--destination` and `--workspace` with
`--transport coder --coder-workspace OWNER/WORKSPACE --daemon-id APPROVED_DAEMON_UUID`
for discovery, import and delivery; keep the exact `--workspace-id`. The existing
workspace must already be running with one connected agent. Coder uses its
forwarded `/docker-sock/docker.sock`, verifies the workspace UUID, build/agent,
UID 1000, persistent `/home/coder` volume and daemon before and after transfer,
and checks runtime identity again immediately before receiving private stdin.
Autostart, terminal allocation and agent/GPG forwarding are disabled. The remote
command is one shell-quoted argument, matching Coder's argument-joining contract.

Rollback retains the new helper's inventory reader and all required cleanup access:

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_recovery \
  --configuration /private/controller.json --output /private/cleanup-only.json
uv run --frozen python -m scripts.m3_11_unattended.cleanup \
  --config /private/cleanup-only.json --actor watchdog --runs /evidence/runs
```

The cleanup-only bundle cannot start qualification or provision children. Never
restore an obsolete issuer, discard obligations or roll back provider deletion.
If required access is unavailable, retain unresolved status and obtain separate
authorization for recovery.

### Manifest confirmation, start and reuse

One immutable complete manifest records all seven roles, exact scope, baseline IDs,
unique names, source/helper, original generations, policy and deadline before any
CREATE. The independent action authenticates its own cleanup access and observes that
manifest before publishing a confirmation. A local write acknowledgement cannot substitute.
The protected workflow's hourly schedule can confirm a pending approved manifest;
an explicit request avoids waiting for the next schedule:

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_control confirm
```

Equivalent confirmations may differ only in their actual observation timestamp
and GitHub run/attempt. Every raw observation is independently validated before a
deterministic original record is selected; helper/server/deadline and all other
substantive fields remain exact. Older helpers reject differing observations, so
new observations require the corrected matching pins. Persistent pending state
prevents replay on one runner; a fresh scheduled runner can add a truthful new
observation after lost visibility. No GitHub artifact recovery protocol is used.

Dispatch itself grants no issuance authority. The original uninterrupted controller
waits until the explicit cutoff and submits each role once. Returned IDs are retained
locally and externally before policy validation. Lost responses remain obligations;
restarted/restored controllers only reconcile. An issuer that could resume blocks
terminal closure, even if a provider currently lists no matching child.

The seven roles retain their original policies: separate archive/backup bucket
`readwrite` keys, a controller-only Spaces `fullaccess` operator, account-owned
fixture Caddy Zone Read + DNS Write, observer Zone Read + DNS Read, account-owned
Account API Tokens Read audit, and user-owned Page Rules Read on exactly both zones.
Scope, ownership, status and applicable native expiry must match exactly. Bucket
and DNS permissions cover whole approved targets; a run prefix is not an IAM boundary.

Prepare a clean reviewed commit and obtain explicit live approval of source/helper,
artifact, controller image, daemon, targets, scopes, policy digest and independent
cleanup access. A `lowerduckpond-m3-11-live-approval-v2` document has `lease_id: null`
for new issuance or the exact existing lease UUID for approved reuse. Its own expiry
is at most one day; it does not renew a lease deadline.

Use the actual attempt writer before launch; supply `--reuse-status` only for a
retry, using the exported status of the released prior attempt. It carries the
validated original manifest and deadline. Obtain fresh attempt consent, without
changing its policy or extending the lease:

```console
uv run --frozen python -m scripts.m3_11_unattended.operator_records attempt-proposal \
  --inputs /private/bound-inputs.json --prepared /private/prepared.json \
  --source FULL_COMMIT_SHA --mode qualification --expires-at APPROVAL_EXPIRY_UTC \
  --output /private/attempt-proposal.json
uv run --frozen python -m scripts.m3_11_unattended.operator_records record-attempt \
  --proposal /private/attempt-proposal.json --expected-proposal-sha256 ATTEMPT_PROPOSAL_SHA256 \
  --approved-at APPROVED_UTC --approval-reference ATTEMPT_CONSENT_REFERENCE \
  --output /private/attempt
mise exec -- just m3-11-unattended start FULL_COMMIT_SHA \
  --mode qualification --approval /private/attempt/live-approval.json \
  --config /private/controller.json --daemon-socket /docker-sock/docker.sock
mise exec -- just m3-11-unattended status RUN_UUID
mise exec -- just m3-11-unattended evidence RUN_UUID
```

Start reserves the daemon-wide admission container before allocating an attempt.
A concurrent start fails. A stale reservation requires inspection of its exact
owner and outstanding obligations before separately authorized removal; never
prune the daemon. The controller uses the daemon's host network and exact approved
Unix socket. Source/helper and Ansible collection volumes are revision-bound.
Private evidence and storage leases remain on the persistent Docker volume.
Mount inspection alone does not demonstrate actual stop/rebuild survival.

Successful qualification finishes and revokes its lease. A failed started attempt
may retain it only under the explicit approved retention policy and before its
original deadline. Preparation/delivery failures, rehearsal cancellation and
explicit lease cancellation trigger cleanup. `stop-attempt` stops the current
journey while allowing approved failure retention; `cancel` closes the entire lease:

```console
mise exec -- just m3-11-unattended stop-attempt RUN_UUID
mise exec -- just m3-11-unattended cancel RUN_UUID
mise exec -- just m3-11-unattended quiesce RUN_UUID
```

Reuse requires a fresh approval and attempt, fresh provider/production receipts and
exclusive runtime ownership before the first child probe. Diagnostic attachment
holds that ownership. Quiescence verifies the original daemon and complete original
host/archive/restore/ACME container graph, requires proof that the host process group was drained, disables
restart, stops and rereads the exact containers. It preserves containers and data.
A new consumer checks those stopped identities again before use. Missing evidence,
a lingering process, changed image, restarted container or interrupted stop keeps
ownership held. The previous failed result is immutable and cannot be promoted.

### Monthly generation handover and independent cleanup

Stage an explicitly approved successor generation while old cleanup access remains
available. Bind the same logical provider principals and targets, new fingerprints,
new native expiries and its next calendar-month rotation date. Do not extend an old
bootstrap token's expiry. Verify handover with the previous and replacement bundles:

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_renewal_setup \
  --previous /private/previous.json --replacement /private/replacement.json \
  --evidence /private/handover
```

Both generations must positively read every transferred child by exact ID and
policy while the old authority is usable. Unknown IDs retain their original
generation; authenticated absence never proves transfer. The staged replacement
retains old access until verified delivery and coverage permit removal. During
staging, old cleanup still works along its explicitly verified handover chain.
Active leases do not require new issuance or replacement child credentials.

Controller, persistent watchdog and independent GitHub execution reconcile the same
compact inventory. Local death/deadline checks run every minute. Newly terminal
work triggers immediate cleanup; unresolved cleanup retries after five minutes,
then 10, 20, 40 minutes and hourly. Routine remote reconciliation and GitHub schedules
are hourly and may be delayed. Finish/cancel publication precedes the nonblocking
local provider-cleanup lock. Publication failure still permits exact-ID deletion,
but cannot claim durable closure.

```console
uv run --frozen python -m scripts.m3_11_unattended.connect_control cleanup
```

DELETE success alone is insufficient: require authenticated inventory/detail
absence and denied authentication when the original secret remains available.
A cold independent actor can delete without that secret, but cannot erase an
outstanding retained-secret probe. Secret loss is reported as unavailable, never
as denied. Changed scope with a known returned ID still requires deletion; ambiguous
or unknown ownership remains unresolved. Cleanup removes credentials only, retaining
failed logs, fixture volumes, backups, DNS records and remote objects. Retained
storage ownership records do not authorize destructive retirement.

The only accepted historical uncertainty remains Page Rules intent
`ccdc7926243530cf6dd6615745f8520440d29531f28869a226f432b31a64b574`
in failed run `01a11021-76d1-775a-adb1-fe00b6fd6152`. Fresh absence and the original
exact exception checks remain required. It is not verified revocation, expiry or
proof of non-creation; late discovery still requires cleanup. No later credential
inherits that exception.

Sanitized evidence binds attempt/source/helper, production and fixture receipts,
cleanup status and the existing complete report checks. Raw provider responses,
credentials and private diagnostics never enter exported evidence. Local component
checks do not replace separately approved independent live cleanup, handover,
complete M3.11 qualification or production acceptance.

### Authenticated public image downloads

GitHub runners do not inherit a workstation's Docker Hub login. CI's five
Docker-using job definitions and independent Connect cleanup support an optional
`DOCKERHUB_USERNAME` variable and `DOCKERHUB_PUBLIC_READ_TOKEN` secret. Use a
dedicated Docker Hub token with **Repo Public Read-only** permission and an
explicit native expiry that covers the approved operation. This grants no private
image access or push/delete permission. Additional credential delivery requires
operator authorization; it does not extend the approved qualification start window.

Save that token in a dedicated 1Password item. On the **secure workstation**, in
normal Bash outside the production shell, use the reviewed clean checkout and
normal `op` and `gh` logins:

```console
mise exec --locked -- uv run --no-sync --frozen python -m scripts.m3_11_unattended.registry_setup \
  --revision FULL_REVIEWED_COMMIT_SHA --username DOCKER_ID \
  --token-reference op://VAULT/ITEM/FIELD --expires-at NATIVE_UTC_EXPIRY \
  --confirm-public-read-only
```

Add `--apply` after reviewing the destination. The helper reads the token through
the operator's normal 1Password login, verifies Docker Hub authentication using
an automatically removed private configuration, and pipes the token to GitHub.
It installs repository access for CI and an explicit copy in the existing protected
`m3-11-credential-cleanup` environment. Repository secrets are available to trusted
repository workflows, not just these jobs. Fork and Dependabot PRs receive no
token and retain public anonymous pulls. No new Connect grants are required.
Setup never prints the token or places it in command arguments. If delivery is
interrupted, repeat with the same item to finish both destinations.

The operator confirms policy and expiry in Docker Hub; a successful login alone
does not audit them. `DOCKERHUB_EXPIRES_AT` records that attestation for operators,
while Docker Hub enforces expiry. Native CI and cleanup still need successful
executions after installation. Each job uses its own registry configuration under
the runner's temporary directory and logs out at job completion. The configuration
is not mounted in fixtures, copied into controller images or exported as evidence.
Production and live qualification retain their isolated empty Docker configurations.

An expired or unavailable registry login must not suppress revocation: independent
cleanup visibly records login failure and still attempts public pulls and normal
reconciliation. It cannot claim readiness unless reconciliation succeeds. Registry
authentication addresses anonymous pull allowances; it does not establish recovery
from authentication-endpoint outages. When access is no longer needed, first
remove the login selector at **both** scopes so later CI runs return to anonymous
pulls. Then revoke the dedicated token in Docker Hub and remove both GitHub secret
copies and expiry metadata. Delivery removal alone is not revocation. Use normal
`gh` login on the secure workstation for each of these cleanup phases:

```bash
# Disable authenticated pulls before removing the credential.
gh variable delete DOCKERHUB_USERNAME --repo lowerduckpond-net/lowerduckpond.net
gh variable delete DOCKERHUB_USERNAME --repo lowerduckpond-net/lowerduckpond.net --env m3-11-credential-cleanup
```

Revoke the dedicated token in Docker Hub and confirm its revoked status there.
Then remove delivery and metadata:

```bash
gh secret delete DOCKERHUB_PUBLIC_READ_TOKEN --repo lowerduckpond-net/lowerduckpond.net
gh secret delete DOCKERHUB_PUBLIC_READ_TOKEN --repo lowerduckpond-net/lowerduckpond.net --env m3-11-credential-cleanup
gh variable delete DOCKERHUB_EXPIRES_AT --repo lowerduckpond-net/lowerduckpond.net
gh variable delete DOCKERHUB_EXPIRES_AT --repo lowerduckpond-net/lowerduckpond.net --env m3-11-credential-cleanup
```

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

A failed functional test retains its original attempt and cannot be rerun into a
pass. If `owned-teardown/intent.json` exists, the fixed installed test already
completed and deletion was authorized. In the same private environment, these
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

### Same-run finalization recovery

For a managed qualification whose functional assertions completed successfully,
use the original clean checkout and original private run directory:

```bash
uv run --frozen python -m scripts.m3_11_finalization /absolute/original/private/run --seconds 7200
```

The command requires the original `functional-completion.json`, including the
exact collection, setup/call/teardown reports and zero pytest exit status. It
verifies unchanged original inputs, artifact and phase receipts, takes the
controller, credential-use, storage-target and run locks, and requires the
original controller's host commands to have drained. It reuses only the
original credential identities under approved failure retention, before their expiry and without
issuance, lease extension or a new delivery bundle. Cancellation, closure,
release or changed ownership stops recovery, including between cleanup mutations.

Select an explicit execution allowance with `--seconds` (7,200 seconds in the
example); each invocation records that choice and uses bounded shutdown. This
resource budget grants no additional credential validity. Timeout leaves the
original retained lease resumable and never requests cancellation. Recovery
resumes authorized deletion, or freshly authorizes deletion when no committed
intent exists, then obtains fresh absence observations, completes remaining
wrapper checks and packages the report. Original failures and timestamps stay
intact; each recovery invocation appends a private `finalization-*` directory.
The original controller status remains failed/interrupted. The completed report
records recovery separately. Credential closure/release still uses the existing
lease lifecycle; finalization does not retire credentials or cleanup authorities.

If a complete `qualification.json` already exists, recovery validates it against
its original evidence and only completes the report/checksum publication pair.
That path matches the report to retained original combined/context, storage,
artifact, managed receipt and observation evidence without recreating it. It
needs no credentials or new provider observations. It preserves report
bytes and `packaged_at`. Existing conflicting or truncated published files are
not overwritten. Checksum-only repair validates the original packaging chronology
and current candidate inputs/revocations even after evidence ages out; repairing
a checksum does not make an expired report consumable. Legacy M3.10 reports
without `packaged_at` must retain observations that fit an original 24-hour
packaging window with their existing five-minute clock tolerance, including the
destroy observation; that feasible window cannot lie entirely in the future.

Managed recovery can bridge a multi-day interruption within the original approved
retained lease and actual child credential deadlines. The cleanup reserve never
extends child access. Original functional proof must have met the existing
24-hour span at its recorded completion. Fresh cleanup, DNS and private-empty
storage proof must all come from one recovery invocation, before child expiry.
Report bytes must be complete and publication authorized before that expiry.
The final guard runs after staging/fsync, immediately before atomic rename; an
operating-system pause after authorization can delay directory-entry visibility.
The same final guard rechecks the 24-hour observation age after staging.
That invocation appends `final-observation.json`; an earlier recovery summary and
all original evidence remain unchanged. Packaging requires those observations to
be at most 24 hours old, measured from the invocation's earliest observation.
Recovered report consumption and unfinished production work use seven days from
that same earliest time. They do not refresh original functional timestamps.
Ordinary reports retain their existing 24-hour packaging span and seven-day
consumption freshness policy.

This is not functional phase retry: public-CA, reconstruction and all other
assertions remain one ordered shared-history journey. A missing completion
checkpoint, failed pytest teardown, altered input, diagnostic workspace, released
lease or expired runtime credential cannot be promoted into qualification.
Older manually supplied runs retain the cleanup-only command above; the managed
finalizer does not infer their credential authority.

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

### Partial managed fixtures and release evidence

New attempts reserve a fixture owner before starting the journey. Each host,
archive, destination and ACME allocation records the original image inputs before
CREATE, then records a drained command outcome and exact observed identity or a
positively empty result. An uncertain submission is never replayed. A reserved,
stopped destination remains part of the fixture even if later restoration phases
never started. Retention requires successful process spawn plus durable start
bookkeeping; failures before spawn revoke instead. Post-spawn errors drain the
process group before terminal cleanup.

Quiescence verifies the original daemon, binding, all present phase receipts and
the complete owner-labelled container inventory. It disables restart, stops each
exact allocated container, and checks them again without removing them. A proven
empty allocation can release use; a missing or uncertain ledger cannot. Retry
freshly checks released containers and the owner inventory, including empty
proofs, before reusing the original lease. Old complete nonempty quiescence proofs
remain supported. Retained finalization keeps the original exclusive owner and
credential IDs until the original expiry, including days later; exactly at expiry,
after cancellation/release or after a binding/identity change it rejects. It writes
recovery reports without changing the original failed journey result.
