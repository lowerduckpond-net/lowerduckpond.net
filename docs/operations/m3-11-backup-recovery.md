# M3.11 backup and recovery operations

M3.11 implementation is in progress. The accepted [plan](../plans/milestone-3.11.md)
defines the complete qualification and production handoff. These P2–P6 commands
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

```bash
just m3-11-spaces-qualification
```

This invokes the existing Spaces wrapper with `--milestone 3.11`, under the
330-minute full-run safeguard. Its default invocation remains M3.10. The new
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
both zones. It interrupts real challenge activity, preserves the acquired
account, reboots behind the real ingress gate and resumes under the original
coordinator deadline. Fresh TLS verification must precede opening ingress.

Final paired accounting preserves the fenced source's excluded pending input,
verifies the destination's protected history and independently proves archive
absence. Only complete pytest setup/call/teardown permits retirement: remove the
destination and controlled CA, delete exact owned backup versions and uploads,
remove the original ownership version last, stop/remove the source and unused
empty local archive fixture, and remove only the run's image tag. Independent
backup, archive and DNS absence must hold before the combined receipt is written.

Share only `qualification.json` and `qualification.sha256` from the printed
private run directory. The [evidence contract](m3-11-qualification-evidence.md)
defines their original bindings and chronology. Private names, captured system
inputs, provider coordinates, phase details, teardown journals and logs remain
in that directory. Local tests and the complete MinIO journey remain diagnostic;
they do not establish live Spaces or public-CA qualification.

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
