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
and 16,384 complete-ID records. Genesis content is limited to 16 KiB, with 32 KiB
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
