# M3.11 backup and recovery operations

M3.11 implementation is in progress. The accepted [plan](../plans/milestone-3.11.md)
defines the complete qualification and production handoff. These P2a commands
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

The service explicitly initializes a missing lineage once. It first publishes
and syncs an independent immutable genesis record under
`static/locks/audit-lineage-genesis.json`, then publishes the exact same canonical
bytes under `static/platform/audit-lineage.json`. Subsequent invocations preserve
the original identity. If the primary record is lost, `--initialize` can only
restore those original bytes from the validated genesis record, even before any
tagged snapshot exists. It cannot allocate another UUID. `--verify` refuses a
missing primary and never repairs or initializes it. Both require the original
namespace and repository binding and verify the complete local audit chain, including its
recorded initialization prefix. A missing or corrupt record is not permission
to regenerate identity. A primary without its genesis, a corrupt record or
disagreement between the records fails closed. Existing protected or
lineage-tagged repository history also blocks initialization when both local
records are missing. Never delete either record, an index or a snapshot to make
initialization succeed.

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

The command serializes repository access before leasing the selected artifact
and taking exclusive tenant-state. Restic config and snapshot metadata reads
complete before the state lock is acquired. Initialization validates the whole
pre-migration chain before publishing genesis with file and parent-directory
sync, then publishing the primary with its own file and parent-directory sync.
Interruption after either rename resumes that same identity. It does
not renumber or rewrite audit entries. An abandoned pre-publication temporary
does not grant authority. No network access or backup credential is added to
ordinary workers or the provisioner.

The service is manual, has no timer and is not started by convergence in P2a.
Its bounds are 30 minutes, 512 MiB, no swap, 32 tasks and one CPU; each Restic
metadata read has a five-minute deadline. Snapshot discovery is limited to
16 MiB and 16,384 complete-ID records. Oversized, duplicate or malformed metadata
fails closed without displaying provider output. It never runs forget, prune,
unlock, repair or retagging. P3 supplies protected-content verification and
retention enforcement; metadata discovery here does not establish those proofs.

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
