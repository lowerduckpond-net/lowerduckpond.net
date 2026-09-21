# M3.11 backup and recovery operations

M3.11 implementation is in progress. The accepted [plan](../plans/milestone-3.11.md)
defines the complete qualification and production handoff. These P2 commands
are preparation and verification tooling; production convergence remains an
explicit later operator step after the final M3.11 qualification. M3.12 is
unstarted and production publication stays disabled.

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
repair or retagging. P3 supplies protected audit-segment verification and guarded
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
repository-backed lineage. Enabling it verifies existing lineage; convergence
does not initialize or rebind identity. Production activation remains part of
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
The recovery root currently admits only an empty committed namespace; P5 adds
exact journal/receipt schemas. Safe publication temporaries are ignored intact.

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
| Recovery directory metadata | The same guarded Ansible task creates/maintains it. No committed recovery records are accepted until P5 defines their writers and schemas. |
| SQL and descriptor staging | Root backup command under the exclusive repository lease; neither staging path belongs to the static authority tree. SQL retains the consistent database dump protocol. |

The Ansible wrapper validates all four existing kernel lock inodes and never
replaces them. First bootstrap is allowed only before any selected artifact,
backup configuration, genesis or authoritative history exists, allowing the
original create-only-missing lock tasks to finish. An existing host with missing,
linked, nonempty, misowned or incorrectly protected locks refuses convergence.
Kernel lock creation precedes artifact selection. This 0700 interpreter accepts
privileged Ansible modules; it grants no ordinary-user command capability.

Run `just check-installed-group backup-coherence` for its independently owned
fixture. It creates active, suspended, archived and undeployed tenants, migrates
explicitly, verifies idempotence and service failure/health boundaries, and uses
real Restic capture/restore while writers contend. It covers create/deploy/import/
rollback/rename/suspend/resume/archive/restore/delete/export/emergency/reconcile,
authorization repair, release cleanup, Caddy restart and Ansible writes. Every
restored tree is measured against its descriptor. Exclusion canaries and a
temporary-looking authoritative file check the actual source policy. Accounting
and teardown remain mandatory. Results are diagnostic local/MinIO evidence;
live Spaces and host reconstruction require later qualification.
