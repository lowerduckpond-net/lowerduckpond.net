# M3.1 archive storage migration and qualification

This runbook performs the one-time production migration from shared lifecycle
configuration to an isolated tenant-archive Space. It does not enable static
publication, install an archive credential on the production host, or create
tenant data.

## Durable resource and credential

Set the GitHub `production` environment variable `ARCHIVE_BUCKET_NAME` to
`lowerduckpond-net-production-tenant-archives-4f3e6b91`. OpenTofu creates the
bucket; do not create it in the DigitalOcean UI. The bucket is a durable,
service-lifetime resource with versioning, `force_destroy = false`, a destroy
guard, and no lifecycle rule.

The migration also generates one key with `readwrite` access to only that
bucket. Retain its ID and secret in the established Lower Duck Pond 1Password
entry for the service lifetime, or until a deliberate credential rotation
replaces it. M3.1 does not install the credential on the host. That handoff is
deferred to the root-owned archive component in M3.10.

## Protected plan and apply

Run **Infrastructure** from `main` with:

- `operation`: `plan`
- `initialize_archive_storage`: enabled
- `replace_droplet`: disabled

The accepted plan must contain exactly two creates and two updates:

- create the private, versioned archive bucket;
- create its one-bucket key;
- update the backup bucket by removing only `archives-retention`; and
- update the durable project assignment by adding only the archive bucket URN.

It must show zero destroys or replacements. The dedicated migration policy
rejects any other action or field change.

After reviewing that result, run **Infrastructure** again from the same `main`
revision with:

- `operation`: `apply`
- `plan_run_id`: the reviewed plan run ID
- `initialize_archive_storage`: enabled
- `replace_droplet`: disabled

The apply job authenticates the reviewed plan and repeats the selected migration
flag. Immediately before apply, it uses the existing protected Spaces operator
credential to prove that `archives/` in the backup bucket has no current object,
version, null version, delete marker, or incomplete multipart upload. It repeats
the same fully paginated proof after apply. Any ambiguous response fails closed.

## Back up the generated archive credential

From the trusted workstation, initialize the production backend using the
procedure in [Infrastructure operations](infrastructure.md). With shell tracing
disabled, retrieve these sensitive outputs one at a time and save them directly
into distinct fields in the established Lower Duck Pond 1Password entry:

```bash
set +x
tofu -chdir=infra/opentofu/environments/production \
  output -raw archive_runtime_access_key_id
tofu -chdir=infra/opentofu/environments/production \
  output -raw archive_runtime_secret_access_key
```

Do not paste either value into chat, a repository file, a workflow artifact, or
the production host. Clear the terminal scrollback after the values are stored.

## Live acceptance

Use a clean, current `main` checkout in the trusted workstation. Set only the
state-access variables needed to read encrypted production outputs:

```bash
export OPENTOFU_STATE_ACCESS_KEY_ID='...'
export OPENTOFU_STATE_SECRET_ACCESS_KEY='...'
export OPENTOFU_STATE_BUCKET='...'
export OPENTOFU_ENCRYPTION_PASSPHRASE='...'
export SPACES_REGION='nyc3'
```

Then run:

```bash
just m3-archive-qualification
```

The wrapper disables tracing, reads both bucket-scoped credentials from
encrypted state without exporting them back to the calling shell, and exercises
the following live contract:

- both buckets have versioning enabled;
- each credential can use its own bucket;
- list, read, and a unique-prefix write are all denied in both cross-bucket
  directions with the exact access-denied response;
- the archive bucket begins empty across current objects, versions, delete
  markers, and incomplete multipart uploads;
- an exact small object version survives an unversioned delete behind a
  non-null delete marker;
- a one-entry `ListObjectVersions` page follows both continuation markers and
  observes the data version and marker exactly once; and
- exact-version cleanup leaves the entire archive bucket and both expendable
  qualification prefixes empty.

Unexpected success or an ambiguous remote response fails the gate. Cleanup is
attempted on every terminal path. If cleanup itself cannot prove absence, stop
and account for the exact version, marker, or multipart upload before proceeding.

Passing evidence is written with mode `0600` beneath
`~/.local/share/lowerduckpond.net/m3-archive-qualification/` in a directory named
for its UUIDv7 run ID and source revision. The directory contains the sanitized
JSON report and its SHA-256 file. Back up that directory exactly; it contains no
bucket names, object keys, version IDs, endpoints, or credentials.

## Completion and rollback

Finish with a protected production plan using
`initialize_archive_storage` disabled. It must report no changes. M3.1 is
complete only after that no-change plan, the archived sanitized report, and an
independent check that the archive bucket is empty.

Do not destroy the archive bucket to roll back application work. If acceptance
fails, leave the durable bucket in place and revoke its dedicated key if needed.
Preserve and account for any ambiguous remote state until version-aware cleanup
proves absence.
