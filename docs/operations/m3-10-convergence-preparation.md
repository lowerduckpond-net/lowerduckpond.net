# M3.10 convergence preparation

Status: preparation only; the convergence starting gate has not passed.
The [implementation plan](../plans/milestone-3.10.md) and
[component evidence](../threat-model/m3-10-evidence.md) identify the implemented
lifecycle and recovery paths. Local and disposable installed qualification are
complete; live provider, production preflight, and reviewed-release evidence
remain outstanding.
Publication remains `static_publication_enabled: false`.

## Workstation inputs

Use the existing trusted-workstation production environment. The
[archive qualification wrapper](../../scripts/m3-archive-qualification)
retrieves the separate archive and backup credentials from encrypted production
OpenTofu state into its process environment. It requires these initial inputs:

| Input | Purpose |
| --- | --- |
| `OPENTOFU_STATE_ACCESS_KEY_ID`, `OPENTOFU_STATE_SECRET_ACCESS_KEY` | Access the production state bucket. |
| `OPENTOFU_STATE_BUCKET`, `SPACES_REGION` | Identify that bucket and regional endpoint. |
| `OPENTOFU_ENCRYPTION_PASSPHRASE` | Decrypt the existing production state. |

Use the existing passphrase and credentials. Creating a replacement passphrase
does not grant access to the state. No new credential file or storage convention
is needed. Keep secret values out of repository files, inventory, artifacts,
command arguments, reports, and chat.

The [production environment shell](../../scripts/production-environment-shell)
can populate this environment with hidden secret prompts. It also requests the
broader production host inputs documented in
[host configuration](host-configuration.md#credential-boundaries).
If the environment is already populated, the existing qualification command is:

```bash
just m3-archive-qualification
```

Run it from a clean revision. This is an expendable-prefix storage test: it
creates and removes qualification objects and markers in the dedicated Spaces.
It requires an entirely empty archive bucket before starting, matching this
pre-publication gate. Do not empty a populated bucket to satisfy that guard;
qualification after tenant archival needs a separately reviewed workflow.
It is not a read-only production preflight. The wrapper verifies its sanitized
report and stores the report plus checksum under
`${XDG_DATA_HOME:-$HOME/.local/share}/lowerduckpond.net/m3-archive-qualification`,
unless `M3_ARCHIVE_QUALIFICATION_EVIDENCE_ROOT` selects another private location.
Record the reported revision, run ID, report digest, and cleanup outcome.

The existing wrapper qualifies the M3.1 storage contract and mutual credential
denial. It does not execute the new packaged M3.10 lifecycle or qualify its
installed credential boundary. Those additional live checks remain to be
implemented and recorded before this gate can pass.

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
