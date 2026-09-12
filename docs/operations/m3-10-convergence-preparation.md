# M3.10 convergence preparation

Status: preparation only; the convergence starting gate has not passed.
The [implementation plan](../plans/milestone-3.10.md) and
[component evidence](../threat-model/m3-10-evidence.md) identify the implemented
lifecycle and recovery paths. Local and disposable installed qualification are
complete; live provider, production preflight, and reviewed-release evidence
remain outstanding.
Publication remains `static_publication_enabled: false`.

## Secure-workstation workflow

Production credentials remain on the operator's secure workstation. They are
not supplied to the coder workspace. The coder task implements the tooling,
completes local qualification, opens the dependent PRs, and iterates review.
The operator runs the live steps below and returns sanitized evidence.

After the dependent reviews are accepted and merged, synchronize a clean `main`
on the supported x86-64 Linux secure workstation. Use a local Unix-socket Docker
daemon for the disposable installed-host qualification. The live wrapper refuses
a remote Docker daemon and existing qualification containers before reading
production state or installing a credential.

Open the existing production environment with the additional read-only gate
inputs enabled:

```bash
scripts/production-environment-shell --m3-10
```

Existing exported values are retained; missing secret inputs use hidden prompts.
The ordinary host inputs remain documented in
[host configuration](host-configuration.md#credential-boundaries). M3.10 also
uses these existing infrastructure inputs:

| Input | Purpose |
| --- | --- |
| `OPENTOFU_STATE_ACCESS_KEY_ID`, `OPENTOFU_STATE_SECRET_ACCESS_KEY`, `OPENTOFU_STATE_BUCKET`, `SPACES_REGION`, `OPENTOFU_ENCRYPTION_PASSPHRASE` | Read and decrypt existing production state. |
| `SPACES_ACCESS_KEY_ID`, `SPACES_SECRET_ACCESS_KEY` | Existing workstation Spaces operator key for read-only bucket ACL, policy, and lifecycle inspection. |
| `CLOUDFLARE_API_TOKEN` | Existing infrastructure token for read-only current edge policy checks. |
| `CLOUDFLARE_ZONE_ID`, `CLOUDFLARE_TENANT_ZONE_ID` | Exact production zone identities. |
| `CLOUDFLARE_ORIGIN_PULL_CERTIFICATE_ID`, `CLOUDFLARE_TENANT_ORIGIN_PULL_CERTIFICATE_ID` | Exact accepted active origin-pull leaves. |

The separate archive and backup runtime keys are derived from encrypted state
inside the wrapper process; do not copy them into inventory or artifact files.
Use the existing state passphrase. No new passphrase or credential storage
convention is needed. Bucket-configuration reads use the existing operator key:
[DigitalOcean distinguishes those permissions from limited object access](https://docs.digitalocean.com/reference/api/spaces/).
An access-denied response never proves that a policy is absent.

Run these commands in that secure shell:

```bash
just preflight-m3-10-production
just m3-10-spaces-qualification
just preflight-m3-10-production
```

The read-only preflight retains the existing verified-host, operator-identity,
reproducible-build, artifact-manifest, disabled-publication, and empty-history
checks. It additionally requires the exact preceding M3.9 artifact, no partial
M3.10 installation or pending Caddy work, enforced origin pulls, the complete
active host firewall, both current Cloudflare edge policies, and a private,
versioned archive bucket with no bucket policy, lifecycle configuration,
objects, historical versions, delete markers, or multipart uploads. Unknown
inventory fails the gate and grants no cleanup authority.

The live qualification first checks the entire empty archive bucket, then runs
mutual archive/backup denial and exact-version storage acceptance. It installs
the candidate on a disposable local systemd host and runs the existing full
M3.8–M3.10 lifecycle, races, emergency recovery, reboot, and quarantine matrix
against real Spaces using the packaged private services. New installed probes
exercise the complete service policy: only the archive network boundary can
read its credential, while ordinary accounts, the worker, the reconciler, and
backup units cannot. Production host state and publication are unchanged.

The live run is deliberately paced by the production admission limit and can
take several hours. It creates and retires its own archive objects and storage
qualification prefixes. It requires an entirely empty archive bucket before
starting; never empty a populated bucket to satisfy that guard. A separately
reviewed workflow is required after production tenant archival begins.

Evidence is retained beneath
`${XDG_DATA_HOME:-$HOME/.local/share}/lowerduckpond.net/m3-10`, or the private
`M3_10_EVIDENCE_ROOT` override. Only a successful installed run, independent final
whole-bucket absence check, artifact match, and completed container destruction
produce `qualification.json` and `qualification.sha256`. Return those two
sanitized files and the final preflight success lines. Phase logs, state,
credentials, and diagnostic inventories stay on the secure workstation.

If a phase fails, no passing report is created and the disposable host is
preserved. Its intents and tenant records may still own remote bytes. Diagnose
and resume the exact failed lifecycle group in that retained Molecule
environment, using the same source and ordinary recovery authority. Do not run
a fresh-baseline qualification or destroy the host until recovery proves the
archive bucket empty. Never remove journals, quarantine, or provider objects
to force a successful run. Record the failed stage and sanitized error for
review; private phase logs support workstation-side diagnosis.

## Closing the starting gate

Record the accepted PRs and required CI, merged source, reproducible artifact,
live report checksum, final read-only preflight, and confirmation that the
dedicated archive credential is retained in the established independent
workstation backup. The report's source and artifact must exactly match the
candidate, with completion within the preceding 24 hours. Repeat qualification
if the source/artifact changes or evidence expires.

Stop here for the requested convergence starting gate. When production
convergence is separately requested, retain these non-secret gate inputs in the
secure shell and use the existing guarded runner:

```bash
export M3_10_QUALIFICATION_REPORT=/absolute/private/run/qualification.json
# Set only after confirming the established credential backup is complete.
export M3_10_ARCHIVE_CREDENTIAL_BACKUP_CONFIRMED=true
just configure-production
```

For an artifact upgrade, that runner validates the report against the actual
built artifact and clean current source, and repeats the M3.10 preflight before
its first host mutation. An unchanged selected artifact permits ordinary
idempotent reconfiguration. The explicit reviewed rollback workflow retains
its existing checks. After an actual convergence, record the new production
identity and update the preflight pins through review before another upgrade;
do not add broad candidate allowances to the first-convergence gate.

## Installed credential boundary

The implementation uses `/etc/lowerduckpond/archive/credentials.json` inside a
root-owned `0700` directory, with the file at `0600`. The production convergence
wrapper derives its dedicated archive values from encrypted OpenTofu outputs,
separately from the backup key, and passes them to Ansible through environment
lookups. Credential installation suppresses task logging and diffs. This is the
host runtime credential location; the workstation source remains unchanged.

The read, construction, and cleanup services receive that configuration through
separate root-only sockets under `/run/lowerduckpond-archive`. The parser worker
sees those sockets while retaining its network isolation and cannot see the
credential file. Backup and maintenance units hide the credential directory
and archive sockets. Each service derives the permitted object operation from
its durable job, source binding, and journal; requests cannot supply credentials
or arbitrary storage locations.

The full installed-unit policy is tested, including filesystem isolation,
credential denial, descriptor lifetime, and the root emergency recovery service.
Record the final artifact and installed lifecycle results in the evidence map;
earlier component or service-only results do not prove the final milestone.

## Emergency deletion and recovery

The administrator-only command is installed root-owned at mode `0700` and has
no provisioner sudo entry. Invoke it from the established `ldp-admin` session:

```bash
sudo /usr/local/libexec/lowerduckpond/emergency-delete-tenant \
  --tenant TENANT_UUID --correlation NEW_UUID_V7 --reason 'Operator reason'
```

Use the same tenant, correlation, and reason to replay an interrupted command.
The command writes distinct administrator authority before changing routes or
removing state, then preserves a permanent audited tombstone/result. It never
creates an ordinary authorization job. The
`lowerduckpond-static-emergency-reconcile.timer` starts bounded root recovery
at boot and periodically; the service can also be started by the administrator.
A failed integrity or remote-absence proof preserves recovery evidence. Inspect
the service result and sanitized journal before retrying; do not remove intents,
quarantine, tenant records, or provider objects manually to force success.

Ordinary archive/restore/delete jobs recover through the existing static
reconciler. Archive rollback retains the exact preceding active or suspended
state. After committed restore/delete, remote retirement must finish and prove
absence before an execution is validated. A still-bound version is preserved.

Do not run production convergence merely to supply credentials for development
checks. The implementation and evidence gates below must be complete first.

## Evidence required before convergence

The recorded preceding production artifact, selected by the 2026-09-12 M3.9
convergence, has SHA-256
`4e32c4a88d729b371b8cd5da96e5fedbc9f30266acb0984599c1d645939bef85`.
Verify that exact selection and its complete artifact manifest during the
read-only preflight. This recorded identity is not a fresh observation of the
production host. Reconcile any later reviewed production change before using
the starting gate; do not widen the accepted identities to bypass drift.

1. Complete the implementation and its local and disposable installed-host
   acceptance matrix. Cover active and suspended archival, exact archived
   export, fresh-deployment restore, rearchive, ordinary and never-deployed
   deletion, emergency deletion, interrupted workers, autonomous recovery,
   quarantine, and the deferred M3.8/M3.9 races. Preserve the existing parser
   sandbox and qualify network-service lock and descriptor ownership.
2. Record the reviewed merged source and a reproducible artifact digest.
   Keep the development artifact in the component evidence distinguishable
   from that release. Production preparation requires clean, current `main`.
3. Read-only host checks must prove the verified host identity, the exact
   preceding artifact recorded in [routine operations](host-configuration.md#routine-operations),
   disabled publication, empty tenant/deployment/history/intent state, and
   unchanged Caddy, origin-pull, and edge controls. Add M3.10-specific checks to
   the guarded workflow; the old milestone gates alone do not prove archive
   readiness.
4. Read-only storage checks must prove the dedicated archive bucket is private,
   versioning is enabled, and no lifecycle expiration policy exists. Account
   every managed version and marker, confirm there are no incomplete multipart
   uploads, and reconcile all intents and quarantine before admission. Unknown
   or ambiguous inventory is a failed gate, not permission to purge it.
5. Complete the live expendable-prefix qualification and mutual archive/backup
   credential denial. Prove installed credential access is confined to the
   dedicated root-owned network boundary and unavailable to the ordinary
   service accounts. Retain the credential in the established workstation
   backup workflow.
6. Assemble a dated gate record linking those results, the exact source and
   artifact, and recovery instructions. State every outstanding condition.
   Stop at the convergence starting gate requested for M3.10; host convergence
   and production publication enablement are later actions.

Do not retire remote bytes merely because a result or journal exists. Preserve
every still-bound version; resolve related lifecycle transactions before remote
cleanup. Exact-key, version-aware absence is required before removing retirement
evidence or releasing its charge. A failed proof retains evidence and closes
archive admission. These rules apply during rollback and recovery as well as
the ordinary path.
