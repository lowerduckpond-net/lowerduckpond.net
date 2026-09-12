# M3.10 implementation evidence and remaining gates

Archive, restore, ordinary deletion, and separate root emergency deletion are
implemented. Final installed qualification is in progress. The convergence
starting gate has not passed. Production publication remains disabled and no
production convergence has occurred. The
[plan](../plans/milestone-3.10.md) and
[preparation runbook](../operations/m3-10-convergence-preparation.md) define the
remaining evidence and the established encrypted-state credential workflow.

## Invariant traceability

| Proof obligation | Evidence | Scope and limitations |
| --- | --- | --- |
| One known-length upload, no hidden retry, fixed regional HTTPS and dedicated credentials | [Remote tests](../../packages/static-host-agent/tests/test_archive_remote.py) | Real SDK request-pipeline tests reject redirects, implicit HeadBucket, second transmissions, multipart/high-level operations, ambient endpoint/proxy/CA configuration, and malformed responses. |
| Exact version and bytes, bounded whole-bucket inventory, capacity, marker and multipart accounting | [Remote tests](../../packages/static-host-agent/tests/test_archive_remote.py), [verification tests](../../packages/static-host-agent/tests/test_archive_verification.py) | Reserve the full 120-MiB ceiling; count unknown keys outside the managed namespace. Unknown, missing, or ambiguous inventory closes admission. |
| Construction precedes remote I/O; lost responses cannot repeat an upload | [Journal tests](../../packages/static-host-agent/tests/test_archive_journal.py), [construction service tests](../../packages/static-host-agent/tests/test_archive_construction_service.py) | Fresh sessions precede local preparation. Exact receipts bind the whole intent; interrupted prepared work discovers/purges its unique unbound key and retains evidence until audited failure. |
| Remote retirement follows durable unbinding and preserves bound objects | [Journal tests](../../packages/static-host-agent/tests/test_archive_journal.py), [cleanup service tests](../../packages/static-host-agent/tests/test_archive_cleanup_service.py) | Independent source/terminal verification, version/marker purge, repeated absence checks, quarantine, and failed-cleanup recovery. Quarantine resolution verifies complete inventories and every retained version; it grants no deletion authority. |
| Descriptor transfer preserves exclusion across process death and connection loss | [Lock tests](../../packages/static-host-agent/tests/test_locks.py), [transport tests](../../packages/static-host-agent/tests/test_archive_transport.py) | Borrowed descriptors retain the same open-file description and already-held flock, including queued descriptors. Inner-lock lending, replaced inodes, hostile peers, and invalid frames fail closed. |
| A worker cannot select credentials, storage locations, or arbitrary paths | [Read service tests](../../packages/static-host-agent/tests/test_archive_service.py), [configuration tests](../../packages/static-host-agent/tests/test_archive_configuration.py) | Root-only service derives authority from durable jobs and exact descriptors. Parser worker and ordinary reconciler retain network isolation. |
| Archive preserves active/suspended rollback source and commits absent routes with exact evidence | [Handler tests](../../packages/static-host-agent/tests/test_archive_handler.py), [commit tests](../../packages/static-host-agent/tests/test_archive_commit.py), [recovery tests](../../packages/static-host-agent/tests/test_archive_recover.py) | Source/proposed manifests, independent remote proof, stale source, every durable boundary, interrupted publication, archived revalidation, and retained bounded local history. |
| Restore creates a fresh deployment and retires the old bound archive | [Restore handler tests](../../packages/static-host-agent/tests/test_restore_handler.py), [commit tests](../../packages/static-host-agent/tests/test_restore_commit.py), [staging tests](../../packages/static-host-agent/tests/test_restore_staging.py) | Exact bundle inspection, retirement before unbinding, transactional route activation, source rollback/forward recovery, retention, and absence before execution validation. |
| Repeated archive/restore cannot accumulate releases or retired objects | [Cycle test](../../packages/static-host-agent/tests/test_archive_cycles.py) | Four private-service cycles, unique archive keys and fresh deployments, selected-plus-two-predecessors retention, final deletion, and replay of every earlier result. Uses a fake provider behind the real private protocol. |
| Ordinary deletion requires a distinct post-archive job or complete never-deployed proof | [Delete handler tests](../../packages/static-host-agent/tests/test_delete_handler.py), [commit tests](../../packages/static-host-agent/tests/test_delete_commit.py) | Exact remote evidence is rechecked before tombstoning. Verified complete audit/history and namespace prechecks precede descriptor-relative removal. Faults cover audit, unlink/rmdir, parent fsync, result/job, and journal boundaries. |
| Emergency deletion remains distinct administrator authority | [Emergency tests](../../packages/static-host-agent/tests/test_emergency_delete.py), [entry-point tests](../../packages/static-host-agent/tests/test_emergency_entrypoint.py) | Strict separate intent/result provenance, root and sudo-administrator checks, mandatory reason, no ordinary job, tombstone-before-removal, recovery, remote retirement, and historical ordinary result replay. |
| Archived export delivers exact bytes and import preserves target identity/policy | [Export tests](../../packages/static-host-agent/tests/test_export_handler.py), [installed lifecycle](../../config/ansible/molecule/m3_8/tests/test_archive_lifecycle.py) | Private exact-version delivery and commit/retry faults are covered locally. Installed TLS archived-export/import qualification is tracked separately below. |
| Actual SDK/XML behavior from the packaged artifact | [MinIO test](../../packages/static-host-agent/tests/test_archive_remote_minio.py), [runner](../../scripts/check-m3-archive-storage) | Exact upload/read, marker-hidden reads, forced pagination, bound-object denial, permanent purge, and multipart detection against pinned MinIO. Local storage does not substitute for Spaces. |
| Effective installed sandbox and recovery command | [Default host tests](../../config/ansible/molecule/default/tests/test_host.py) | Clone complete installed unit policy to verify path/credential denial and positive operation. Emergency helper permission/sudo denial and actual recovery-service invocation are included. |
| Deferred archive/restore/delete snapshot and activation races | [Installed capture support](../../config/ansible/molecule/m3_8/tests/archive_capture_support.py), [installed lifecycle](../../config/ansible/molecule/m3_8/tests/test_archive_lifecycle.py) | Actual worker waits on verified export-lock inode; source remains unchanged until capture completes. Restore/delete Caddy-fault recovery and Ansible overlap are implemented as installed checks; passing results remain required. |

## Recorded qualification

The plan is first commit `a70f107`, based on current `main` at `8d9adc1`.
All identities below are development checkpoints on
`feat/m3.10-archive-restore-deletion`, not reviewed merged production releases.

| Revision | Check and result |
| --- | --- |
| `57f0a81` | Full installed M3.8/M3.9 core lifecycle, large export/import, snapshot races, exact reboot-state, transport/recovery, and Caddy/systemd/Ansible overlap passed. Disposable host was destroyed. This predates M3.10 lifecycle integration. |
| `470c575` | Complete Python suite: 2,280 passed, two dedicated MinIO skips. Default convergence/idempotence and all 44 installed tests passed. Packaged local storage: two passed. |
| `f084475` | Complete Python suite: 2,435 passed, three skips in 570.05 seconds. Skips are two separately scheduled MinIO checks and one inapplicable never-deployed archives-directory fsync parameter. Includes integrated ordinary/emergency lifecycle, strict contracts, recovery, and historical replay. |
| `fb69cd8` | Default convergence and idempotence passed; all 45 installed checks passed in 90.53 seconds, including complete emergency unit policy. Disposable host destruction passed. |
| `434331e` | Four repeated private archive/restore cycles, retention, final deletion, and every historical result replay passed. |
| `0f4e804` | Fixed system trust bundle: 41 remote tests passed; strict type checking passed for 226 files. |

Artifact at the `470c575` installed checkpoint:
`a079e9fde6f5cf9f8ae1bdbb464870168f6848e880690b845610369d0eb67e1d`.
It does not qualify later restore/delete/emergency code.

The `fb69cd8` installed artifact has SHA-256
`e74efe5ddcc3cea83314452a0fcf9ef6f3741ba8dc9d96c998f8408c675f6eb4`.
The final Python run is in progress. All three wheel checks, local qualification
and browser-boundary checks, both packaged MinIO checks, 222 infrastructure
checks, Ansible lint (136 files), workflow lint, and secret scans passed. The full installed
M3.8–M3.10 lane now includes pinned private TLS MinIO, genuinely distinct test
bucket credentials, four restore/rearchive cycles, exact archived export/import,
final deletion, deferred races, and administrator recovery. These tests must
actually pass before they are counted as evidence. The disposable credentials
are public fixture values; production credentials are never used in that lane.

## Installed defects found and corrected

- `ProtectSystem=strict` overlaid the intended empty tmpfs root with the host
  root on the tested Ubuntu 26.04 systemd. Full-unit probes demonstrated exposed
  paths. The corrected explicit-mount policy uses `ProtectSystem=false` with the
  read-only empty root. Fresh default and full M3.8/M3.9 checks passed after the
  correction at `57f0a81`.
- The SDK's one-attempt setting still allowed a second PUT on an S3 region
  redirect. The request-creation guard refuses the second transmission and any
  implicit operation; real SDK pipeline regression tests reproduce this case.
- The first emergency installed run passed convergence/idempotence and 44 of 45
  tests. Its full sandbox lost effective `CAP_SETUID` despite the bounding set,
  preventing the controlled Caddy socket-owner switch. `fb69cd8` retains it with
  `AmbientCapabilities=CAP_SETUID`, preserving `NoNewPrivileges=true` and the
  bounded capability set. A full-policy disposable probe verified identity
  switch and restoration; the fresh complete installed rerun passed all 45 checks.

## Outstanding convergence gates

1. Finish and record the final complete local and installed qualification,
   including deferred races, actual service recovery, and artifact identity.
2. Run live expendable-prefix Spaces qualification and mutual archive/backup
   credential denial. The existing M3.1 wrapper was invoked and exited 2 at its
   missing `OPENTOFU_ENCRYPTION_PASSPHRASE` guard before provider requests. It uses
   the established encrypted production state; the necessary state access and
   decryption inputs are absent in this session. It does not itself execute the
   new installed M3.10 lifecycle.
3. Complete a guarded read-only production preflight covering dark host identity,
   exact preceding artifact, disabled publication, empty tenant history, unchanged
   edge controls, private/versioned/no-expiration archive policy, accounted
   contents, and no multipart uploads. Unknown objects are never permission to
   purge the bucket.
4. Record reviewed merged source and a reproducible release artifact on clean,
   current `main`, then assemble the convergence gate record. Stop before host
   convergence and publication enablement.

An unavailable live input blocks its dependent gate. Component and disposable
provider results do not make the production convergence starting gate pass.
